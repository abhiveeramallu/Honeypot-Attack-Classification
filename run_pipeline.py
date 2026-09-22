"""End-to-end orchestrator: raw Cowrie logs -> parsed sessions -> rule engine
-> ML classification (with rule-engine fallback, if a trained model is
available) -> SQLite/Parquet datastore -> Sigma rules + IoC feed.

Usage:
    python run_pipeline.py --raw-logs data/sample_cowrie_logs \
        --db data/sqlite/sessions.db \
        --parquet data/parquet/sessions.parquet \
        --model-dir models \
        --sigma-out-dir detection/sigma_rules \
        --ioc-out-csv data/ioc_feed.csv

If `--model-dir` has no trained artifacts yet (see ml/train_pipeline.py),
the pipeline logs a warning and falls back to rule-engine-only
classification rather than failing — the rule engine alone is a fully
functional baseline pipeline.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for sub in ("etl", "features", "ml", "detection"):
    sys.path.append(str(ROOT / sub))

from etl_parser import load_logs, to_dataframe, write_sqlite, write_parquet  # noqa: E402
from rule_classifier import classify_dataframe  # noqa: E402
from ml_classifier import predict_with_fallback, artifacts_available, ModelArtifactsMissing  # noqa: E402
from generate_sigma import generate_sigma_rules, generate_ioc_feed  # noqa: E402

logger = logging.getLogger("run_pipeline")


def run(args: argparse.Namespace) -> None:
    logger.info("Step 1/5: parsing raw logs from %s", args.raw_logs)
    sessions = load_logs(args.raw_logs)
    if not sessions:
        logger.warning("No sessions parsed from %s — nothing further to do.", args.raw_logs)
        return
    df = to_dataframe(sessions)
    logger.info("Parsed %d sessions.", len(df))

    logger.info("Step 2/5: running the rule engine.")
    df = classify_dataframe(df)

    technique_col = "rule_techniques"
    if args.skip_ml:
        logger.info("Step 3/5: --skip-ml set, skipping ML classification.")
    else:
        logger.info("Step 3/5: running ML classification (model-dir=%s, threshold=%.2f).", args.model_dir, args.threshold)
        if not artifacts_available(args.model_dir):
            logger.warning(
                "No trained model found in %s — run ml/train_pipeline.py first. "
                "Continuing with rule-engine-only classification.", args.model_dir,
            )
        else:
            try:
                predictions = predict_with_fallback(df, args.model_dir, args.threshold)
                df = df.merge(predictions, on="session_id", how="left")
                technique_col = "predicted_techniques"
                ml_count = (df["source"] == "ml").sum()
                fallback_count = (df["source"] == "rule_fallback").sum()
                logger.info("ML classified %d session(s), rule-fallback for %d session(s).", ml_count, fallback_count)
            except ModelArtifactsMissing as exc:
                logger.warning("%s Continuing with rule-engine-only classification.", exc)

    logger.info("Step 4/5: writing sessions to %s and %s.", args.db, args.parquet)
    write_sqlite(df, args.db)
    write_parquet(df, args.parquet)

    logger.info("Step 5/5: generating Sigma rules (min_sessions=%d) and IoC feed.", args.min_sessions)
    written = generate_sigma_rules(df, technique_col, args.min_sessions, args.sigma_out_dir)
    generate_ioc_feed(df, args.ioc_out_csv)
    logger.info("Wrote %d Sigma rule(s) -> %s", len(written), args.sigma_out_dir)
    logger.info("IoC feed -> %s", args.ioc_out_csv)

    total_techniques = sum(len(json.loads(v)) for v in df[technique_col].dropna() if v)
    print(
        f"\nPipeline complete: {len(df)} sessions, {total_techniques} technique tags "
        f"(source column: {technique_col}), {len(written)} Sigma rule(s), IoC feed at {args.ioc_out_csv}."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full honeypot -> ATT&CK classification pipeline.")
    parser.add_argument("--raw-logs", required=True, type=Path, help="cowrie.json file or directory of log files")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--parquet", required=True, type=Path)
    parser.add_argument("--model-dir", type=Path, default=ROOT / "models")
    parser.add_argument("--threshold", type=float, default=0.70)
    parser.add_argument("--skip-ml", action="store_true", help="Rule-engine-only run, even if a model exists")
    parser.add_argument("--sigma-out-dir", type=Path, default=ROOT / "detection" / "sigma_rules")
    parser.add_argument("--ioc-out-csv", type=Path, default=ROOT / "data" / "ioc_feed.csv")
    parser.add_argument("--min-sessions", type=int, default=2, help="Min. sessions before a Sigma rule is emitted")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    run(args)


if __name__ == "__main__":
    main()
