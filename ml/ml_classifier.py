"""Phase 4: inference-time ATT&CK technique classifier.

Loads pre-trained artifacts produced by `ml/train_pipeline.py` (model,
TF-IDF vectorizer, and feature metadata, all under a single `--model-dir`)
and scores incoming sessions directly from the sessions table/dataframe —
no separate offline `feature_extractor.py` parquet export required, and no
train/inference feature-column skew since the same fitted vectorizer is
reused for both.

Falls back to the Phase 3 rule engine on a per-session basis whenever the
model's max predicted probability is below `--threshold`.
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

sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
from attack_rules import technique_lookup  # noqa: E402
from feature_extractor import build_boolean_flags, build_session_metrics, build_tfidf_features  # noqa: E402
from rule_classifier import classify_session  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.70
MODEL_FILENAME = "model.joblib"
VECTORIZER_FILENAME = "vectorizer.joblib"
FEATURE_META_FILENAME = "feature_meta.joblib"


class ModelArtifactsMissing(RuntimeError):
    """Raised when a model directory doesn't have a full artifact set."""


def artifacts_available(model_dir: Path) -> bool:
    return all((model_dir / f).exists() for f in (MODEL_FILENAME, VECTORIZER_FILENAME, FEATURE_META_FILENAME))


def load_artifacts(model_dir: Path) -> dict:
    if not artifacts_available(model_dir):
        raise ModelArtifactsMissing(
            f"{model_dir} is missing one of {MODEL_FILENAME}/{VECTORIZER_FILENAME}/{FEATURE_META_FILENAME}. "
            "Run ml/train_pipeline.py first."
        )
    return {
        "model": joblib.load(model_dir / MODEL_FILENAME),
        "vectorizer": joblib.load(model_dir / VECTORIZER_FILENAME),
        "feature_meta": joblib.load(model_dir / FEATURE_META_FILENAME),
    }


def build_inference_features(sessions_df: pd.DataFrame, vectorizer, feature_meta: dict) -> pd.DataFrame:
    """Deterministic flags/metrics need no fitting; TF-IDF reuses the
    vectorizer fit at training time so columns line up exactly."""
    flags = build_boolean_flags(sessions_df)
    metrics = build_session_metrics(sessions_df)
    tfidf_df, _ = build_tfidf_features(sessions_df, vectorizer=vectorizer)

    features = pd.concat(
        [sessions_df[["session_id"]].reset_index(drop=True),
         flags.reset_index(drop=True),
         metrics.reset_index(drop=True),
         tfidf_df.reset_index(drop=True)],
        axis=1,
    )
    return features.reindex(columns=["session_id"] + feature_meta["feature_columns"], fill_value=0)


def predict_with_fallback(
    sessions_df: pd.DataFrame,
    model_dir: Path,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> pd.DataFrame:
    """Return per-session technique predictions, falling back to the rule
    engine for any session where max predicted probability < threshold.
    """
    artifacts = load_artifacts(model_dir)
    model, vectorizer, feature_meta = artifacts["model"], artifacts["vectorizer"], artifacts["feature_meta"]

    features = build_inference_features(sessions_df, vectorizer, feature_meta)
    X = features[feature_meta["feature_columns"]]

    try:
        probs = model.predict_proba(X)
    except Exception:
        logger.exception("Model prediction failed; falling back to the rule engine for all sessions.")
        probs = [[0.0]] * len(features)

    mlb_classes = feature_meta["mlb_classes"]
    results = []
    for i, session_id in enumerate(features["session_id"]):
        row_probs = probs[i] if len(probs) else []
        max_prob = float(max(row_probs)) if len(row_probs) else 0.0

        if max_prob >= threshold:
            predicted = [mlb_classes[j] for j, p in enumerate(row_probs) if p >= 0.5]
            source = "ml"
        else:
            row = sessions_df.loc[sessions_df["session_id"] == session_id]
            commands, attempts = [], 0
            if not row.empty:
                try:
                    commands = json.loads(row.iloc[0]["command_sequence"])
                except (TypeError, json.JSONDecodeError):
                    logger.warning(
                        "session %s has unparsable command_sequence; treating as empty for rule fallback.",
                        session_id,
                    )
                attempts = int(row.iloc[0].get("login_attempts", 0) or 0)
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
    parser = argparse.ArgumentParser(description="Run the Phase 4 ML ATT&CK classifier over parsed sessions.")
    parser.add_argument("--sessions-db", required=True, type=Path)
    parser.add_argument("--sessions-table", default="sessions")
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--threshold", type=float, default=DEFAULT_CONFIDENCE_THRESHOLD)
    parser.add_argument("--out-csv", required=True, type=Path)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    with sqlite3.connect(args.sessions_db) as conn:
        sessions_df = pd.read_sql_query(f"SELECT * FROM {args.sessions_table}", conn)

    result = predict_with_fallback(sessions_df, args.model_dir, args.threshold)

    lookup = technique_lookup()

    def _describe(techniques_json: str) -> str:
        techniques = json.loads(techniques_json)
        return ", ".join(f"{t} ({lookup.get(t, (t, '?'))[0]})" for t in techniques) or "(none)"

    for _, row in result.iterrows():
        print(f"{row['session_id']}: {_describe(row['predicted_techniques'])}  "
              f"[{row['source']}, confidence={row['confidence']}]")

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.out_csv, index=False)
    print(f"\nSaved -> {args.out_csv}")


if __name__ == "__main__":
    main()
