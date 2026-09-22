"""Phase 4: supervised multi-label ATT&CK technique classifier.

Trains a OneVsRest Random Forest (default) or Linear SVM over the Phase 3
feature matrix (TF-IDF + boolean flags + session metrics), evaluates with
per-technique precision/recall/F1, and falls back to the Phase 3 rule engine
for any technique whose predicted confidence is below `--threshold`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.svm import LinearSVC

sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
from attack_rules import technique_lookup  # noqa: E402
from rule_classifier import classify_session  # noqa: E402

DEFAULT_CONFIDENCE_THRESHOLD = 0.70
NON_FEATURE_COLS = {"session_id"}


def _build_model(model_type: str):
    if model_type == "rf":
        base = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42, class_weight="balanced")
    elif model_type == "svm":
        base = CalibratedClassifierCV(LinearSVC(class_weight="balanced", max_iter=5000), cv=3)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")
    return OneVsRestClassifier(base)


def load_training_data(features_parquet: Path, labels_csv: Path) -> tuple[pd.DataFrame, pd.DataFrame, MultiLabelBinarizer]:
    features = pd.read_parquet(features_parquet)
    labels_df = pd.read_csv(labels_csv, dtype=str).fillna("")

    def _parse(s: str) -> list[str]:
        s = s.strip()
        if not s or s.upper() == "NONE":
            return []
        return [t.strip() for t in s.split(",") if t.strip()]

    labels_df["labels"] = labels_df["confirmed_techniques"].apply(_parse)
    merged = features.merge(labels_df[["session_id", "labels"]], on="session_id", how="inner")

    mlb = MultiLabelBinarizer()
    y = mlb.fit_transform(merged["labels"])
    y_df = pd.DataFrame(y, columns=mlb.classes_, index=merged.index)

    feature_cols = [c for c in features.columns if c not in NON_FEATURE_COLS]
    X = merged[feature_cols]
    return X, y_df, mlb


def train(features_parquet: Path, labels_csv: Path, model_type: str, model_out: Path, test_size: float = 0.25) -> None:
    X, y_df, mlb = load_training_data(features_parquet, labels_csv)

    if len(X) < 4:
        print(
            f"WARNING: only {len(X)} labeled sessions available. This is far too "
            "few for a real train/test split or reliable metrics — treat this "
            "run as a pipeline smoke test, not a validated model. Label more "
            "sessions via ml/labeling_schema.py before trusting the numbers below."
        )

    stratify = None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_df, test_size=test_size, random_state=42, stratify=stratify
    )

    model = _build_model(model_type)
    model.fit(X_train, y_train.values)

    y_pred = model.predict(X_test)
    report = classification_report(
        y_test.values, y_pred, target_names=list(y_df.columns), zero_division=0
    )
    print(f"\n=== Evaluation ({model_type}, {len(X_test)} held-out sessions) ===")
    print(report)

    lookup = technique_lookup()
    print("Technique reference:")
    for tid in y_df.columns:
        name, tactic = lookup.get(tid, (tid, "?"))
        print(f"  {tid:12s} {name} ({tactic})")

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "mlb": mlb, "feature_columns": list(X.columns), "model_type": model_type}, model_out)
    print(f"\nModel saved -> {model_out}")


def predict_with_fallback(
    features: pd.DataFrame,
    sessions_df: pd.DataFrame,
    model_bundle_path: Path,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> pd.DataFrame:
    """Return per-session technique predictions, falling back to the rule
    engine for any session where max predicted probability < threshold.
    """
    bundle = joblib.load(model_bundle_path)
    model, mlb, feature_columns = bundle["model"], bundle["mlb"], bundle["feature_columns"]

    X = features.reindex(columns=feature_columns, fill_value=0)
    probs = model.predict_proba(X)  # shape (n_samples, n_classes) for OneVsRest w/ predict_proba-capable base

    results = []
    for i, session_id in enumerate(features["session_id"]):
        max_prob = float(probs[i].max()) if len(probs[i]) else 0.0
        if max_prob >= threshold:
            predicted = [mlb.classes_[j] for j, p in enumerate(probs[i]) if p >= 0.5]
            source = "ml"
        else:
            row = sessions_df.loc[sessions_df["session_id"] == session_id]
            commands = json.loads(row.iloc[0]["command_sequence"]) if not row.empty else []
            attempts = int(row.iloc[0].get("login_attempts", 0)) if not row.empty else 0
            predicted = classify_session(commands, attempts)
            source = "rule_fallback"

        results.append({
            "session_id": session_id,
            "predicted_techniques": json.dumps(predicted),
            "confidence": round(max_prob, 4),
            "source": source,
        })

    return pd.DataFrame(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train or run the Phase 4 ML ATT&CK classifier.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train")
    p_train.add_argument("--features", required=True, type=Path)
    p_train.add_argument("--labels", required=True, type=Path)
    p_train.add_argument("--model-type", choices=["rf", "svm"], default="rf")
    p_train.add_argument("--model-out", required=True, type=Path)

    p_predict = sub.add_parser("predict")
    p_predict.add_argument("--features", required=True, type=Path)
    p_predict.add_argument("--sessions-db", required=True, type=Path)
    p_predict.add_argument("--sessions-table", default="sessions")
    p_predict.add_argument("--model", required=True, type=Path)
    p_predict.add_argument("--threshold", type=float, default=DEFAULT_CONFIDENCE_THRESHOLD)
    p_predict.add_argument("--out-csv", required=True, type=Path)

    args = parser.parse_args()

    if args.cmd == "train":
        train(args.features, args.labels, args.model_type, args.model_out)
    elif args.cmd == "predict":
        import sqlite3
        features = pd.read_parquet(args.features)
        with sqlite3.connect(args.sessions_db) as conn:
            sessions_df = pd.read_sql_query(f"SELECT * FROM {args.sessions_table}", conn)
        result = predict_with_fallback(features, sessions_df, args.model, args.threshold)
        args.out_csv.parent.mkdir(parents=True, exist_ok=True)
        result.to_csv(args.out_csv, index=False)
        print(result.to_string(index=False))
        print(f"\nSaved -> {args.out_csv}")


if __name__ == "__main__":
    main()
