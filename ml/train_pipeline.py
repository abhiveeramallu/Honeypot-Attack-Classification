"""Phase 2: ground-truth dataset creation + model training.

Builds an initial labeled dataset by running the Phase 3 rule engine over
parsed sessions (a *bootstrap* label, not human-verified — see the WARNING
this script prints), optionally overridden per-session by a human-confirmed
CSV from `ml/labeling_schema.py`, trains a multi-label classifier with
K-Fold cross-validation, and serializes the model + TF-IDF vectorizer +
feature metadata to `--model-dir` (default `../models/`) for
`ml/ml_classifier.py` to load at inference time.

Usage:
    # From already-parsed sessions in SQLite:
    python train_pipeline.py --db ../data/sqlite/sessions.db --model-dir ../models

    # Or parse raw Cowrie logs first:
    python train_pipeline.py --raw-logs ../data/sample_cowrie_logs --model-dir ../models

    # With human-confirmed labels overriding the rule-engine bootstrap:
    python train_pipeline.py --db ../data/sqlite/sessions.db \
        --labels-csv ../data/labels_for_annotation.csv --model-dir ../models
"""
from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import KFold
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.svm import LinearSVC

sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
sys.path.append(str(Path(__file__).resolve().parent.parent / "etl"))
from attack_rules import technique_lookup  # noqa: E402
from feature_extractor import build_feature_matrix, FLAG_COLUMNS, METRIC_COLUMNS  # noqa: E402
from rule_classifier import classify_dataframe  # noqa: E402
from labeling_schema import import_labels  # noqa: E402

logger = logging.getLogger(__name__)


def _build_base_model(model_type: str):
    if model_type == "rf":
        return RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42, class_weight="balanced")
    if model_type == "svm":
        return CalibratedClassifierCV(LinearSVC(class_weight="balanced", max_iter=5000), cv=3)
    raise ValueError(f"Unknown model_type: {model_type}")


def load_sessions(db: Path | None, table: str, raw_logs: Path | None) -> pd.DataFrame:
    if db is not None:
        with sqlite3.connect(db) as conn:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
    elif raw_logs is not None:
        sys.path.append(str(Path(__file__).resolve().parent.parent / "etl"))
        from etl_parser import load_logs, to_dataframe  # noqa: E402
        sessions = load_logs(raw_logs)
        df = to_dataframe(sessions)
    else:
        raise ValueError("Provide either --db or --raw-logs.")

    if "rule_techniques" not in df.columns:
        logger.info("No rule_techniques column found; running the rule engine to bootstrap labels.")
        df = classify_dataframe(df)

    return df


def build_bootstrap_labels(df: pd.DataFrame, labels_csv: Path | None) -> dict[str, list[str]]:
    labels: dict[str, list[str]] = {}
    for _, row in df.iterrows():
        try:
            labels[row["session_id"]] = json.loads(row["rule_techniques"]) if row["rule_techniques"] else []
        except (TypeError, json.JSONDecodeError):
            labels[row["session_id"]] = []

    n_bootstrap = len(labels)
    n_human = 0
    if labels_csv is not None and labels_csv.exists():
        human_df = import_labels(labels_csv)
        for _, row in human_df.iterrows():
            sid = row["session_id"]
            confirmed = row["labels"]
            # A human annotation row with confirmed_techniques left blank means
            # "not yet reviewed", not "confirmed empty" — only override sessions
            # that actually have annotator input, so an un-annotated CSV row
            # doesn't silently wipe out the rule-engine bootstrap label for it.
            if confirmed and sid in labels:
                labels[sid] = confirmed
                n_human += 1

    logger.warning(
        "Training labels: %d sessions bootstrapped from the rule engine (unverified), %d overridden by "
        "human-confirmed annotations. Bootstrap-only labels mean the model is learning to reproduce the "
        "rule engine, not to generalize beyond it — label more sessions via ml/labeling_schema.py + "
        "a human reviewer before trusting this model on traffic the rules don't already cover.",
        n_bootstrap - n_human, n_human,
    )
    return labels


def run_kfold_cv(X: pd.DataFrame, y_df: pd.DataFrame, model_type: str, n_splits: int) -> None:
    n_samples = len(X)
    n_splits = max(2, min(n_splits, n_samples))
    if n_samples < 2 * n_splits:
        logger.warning(
            "Only %d labeled sessions for %d-fold CV — these metrics are a pipeline sanity check, "
            "not a reliable performance estimate. Label more sessions before trusting them.",
            n_samples, n_splits,
        )

    kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_metrics: list[pd.DataFrame] = []

    for fold_idx, (train_idx, val_idx) in enumerate(kf.split(X), start=1):
        model = OneVsRestClassifier(_build_base_model(model_type))
        model.fit(X.iloc[train_idx], y_df.iloc[train_idx].values)
        y_pred = model.predict(X.iloc[val_idx])

        precision, recall, f1, support = precision_recall_fscore_support(
            y_df.iloc[val_idx].values, y_pred, average=None, zero_division=0, labels=range(y_df.shape[1])
        )
        fold_metrics.append(pd.DataFrame({
            "technique": y_df.columns, "precision": precision, "recall": recall, "f1": f1, "support": support,
        }))
        logger.info("Fold %d/%d: macro F1 = %.3f", fold_idx, n_splits, f1.mean())

    combined = pd.concat(fold_metrics).groupby("technique").mean(numeric_only=True).reset_index()
    lookup = technique_lookup()
    combined["technique_name"] = combined["technique"].map(lambda t: lookup.get(t, (t, "?"))[0])

    print(f"\n=== {n_splits}-Fold Cross-Validation ({model_type}, mean over folds) ===")
    print(combined[["technique", "technique_name", "precision", "recall", "f1", "support"]]
          .to_string(index=False, float_format=lambda v: f"{v:.3f}"))
    print(f"\nMacro-average F1 across techniques: {combined['f1'].mean():.3f}")


def train(
    df: pd.DataFrame,
    labels: dict[str, list[str]],
    model_type: str,
    model_dir: Path,
    n_splits: int,
    max_features: int,
) -> None:
    mlb = MultiLabelBinarizer()
    y = mlb.fit_transform([labels.get(sid, []) for sid in df["session_id"]])
    y_df = pd.DataFrame(y, columns=mlb.classes_, index=df.index)

    if y_df.shape[1] == 0:
        raise RuntimeError("No techniques present across any session's labels — nothing to train on.")

    features, vectorizer = build_feature_matrix(df, max_features=max_features)
    feature_columns = [c for c in features.columns if c != "session_id"]
    X = features[feature_columns]

    run_kfold_cv(X, y_df, model_type, n_splits)

    logger.info("Fitting final model on all %d labeled sessions.", len(X))
    final_model = OneVsRestClassifier(_build_base_model(model_type))
    final_model.fit(X, y_df.values)

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, model_dir / "model.joblib")
    joblib.dump(vectorizer, model_dir / "vectorizer.joblib")
    joblib.dump({
        "feature_columns": feature_columns,
        "flag_columns": FLAG_COLUMNS,
        "metric_columns": METRIC_COLUMNS,
        "mlb_classes": list(mlb.classes_),
        "model_type": model_type,
    }, model_dir / "feature_meta.joblib")

    print(f"\nArtifacts saved -> {model_dir}/ (model.joblib, vectorizer.joblib, feature_meta.joblib)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Phase 4 ATT&CK classifier with K-Fold CV.")
    parser.add_argument("--db", type=Path, help="SQLite sessions DB (from etl_parser.py)")
    parser.add_argument("--table", default="sessions")
    parser.add_argument("--raw-logs", type=Path, help="Raw cowrie.json file/dir, parsed inline if --db is omitted")
    parser.add_argument("--labels-csv", type=Path, help="Human-confirmed labels from ml/labeling_schema.py")
    parser.add_argument("--model-type", choices=["rf", "svm"], default="rf")
    parser.add_argument("--model-dir", type=Path, default=Path(__file__).resolve().parent.parent / "models")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--max-features", type=int, default=300)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    df = load_sessions(args.db, args.table, args.raw_logs)
    labels = build_bootstrap_labels(df, args.labels_csv)
    train(df, labels, args.model_type, args.model_dir, args.folds, args.max_features)


if __name__ == "__main__":
    main()
