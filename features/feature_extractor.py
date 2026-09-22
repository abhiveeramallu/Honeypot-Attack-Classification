"""Phase 3: build the feature matrix used by both the rule engine's boolean
flags and the Phase 4 ML classifier's TF-IDF + engineered features.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

# Boolean "critical command" flags — cheap, interpretable signals that feed
# both the rule engine and the ML model as extra columns.
CRITICAL_PATTERNS: dict[str, str] = {
    "has_wget": r"\bwget\b",
    "has_curl": r"\bcurl\b",
    "has_chmod_x": r"\bchmod\s+(\+x|[0-7]{3,4})\b",
    "has_etc_shadow": r"/etc/shadow",
    "has_etc_passwd": r"/etc/passwd",
    "has_base64_decode": r"\bbase64\s+(-d|--decode)\b",
    "has_crontab": r"\bcrontab\b|/etc/cron",
    "has_history_clear": r"\bhistory\s+-c\b",
    "has_rm_rf": r"\brm\s+-rf?\b",
    "has_nc_or_reverse_shell": r"\bnc\s+-[a-z]*e\b|/dev/tcp/",
    "has_python_exec": r"\bpython[23]?\b",
    "has_scp_exfil": r"\bscp\s+\S+\s+\S+@",
    "has_ip_literal_url": r"https?://\d{1,3}(\.\d{1,3}){3}",
}
_COMPILED_CRITICAL = {name: re.compile(p, re.IGNORECASE) for name, p in CRITICAL_PATTERNS.items()}


def _load_commands(command_sequence_json: str) -> list[str]:
    try:
        return json.loads(command_sequence_json)
    except (TypeError, json.JSONDecodeError):
        return []


def build_boolean_flags(df: pd.DataFrame) -> pd.DataFrame:
    flags = {name: [] for name in CRITICAL_PATTERNS}
    for cmd_json in df["command_sequence"]:
        commands = _load_commands(cmd_json)
        joined = " \n ".join(commands)
        for name, pattern in _COMPILED_CRITICAL.items():
            flags[name].append(bool(pattern.search(joined)))
    return pd.DataFrame(flags, index=df.index)


def build_session_metrics(df: pd.DataFrame) -> pd.DataFrame:
    metrics = pd.DataFrame(index=df.index)
    metrics["command_count"] = df["command_sequence"].apply(lambda s: len(_load_commands(s)))
    metrics["session_duration"] = pd.to_numeric(df.get("session_duration"), errors="coerce").fillna(0.0)
    metrics["avg_seconds_between_commands"] = metrics.apply(
        lambda r: (r["session_duration"] / r["command_count"]) if r["command_count"] > 0 else 0.0,
        axis=1,
    )
    metrics["login_attempts"] = pd.to_numeric(df.get("login_attempts"), errors="coerce").fillna(0).astype(int)
    metrics["login_success"] = df.get("login_success", False).astype(bool).astype(int)
    metrics["url_count"] = df["urls_downloaded"].apply(lambda s: len(_load_commands(s)))
    return metrics


def build_tfidf_features(
    df: pd.DataFrame, max_features: int = 300, ngram_range: tuple[int, int] = (1, 2)
) -> tuple[pd.DataFrame, TfidfVectorizer]:
    """TF-IDF over whitespace-joined command sequences, with word n-grams
    (n-grams over *commands*, not characters, since a command like
    `chmod +x` is the meaningful unit)."""
    corpus = [" | ".join(_load_commands(s)) for s in df["command_sequence"]]
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=ngram_range,
        token_pattern=r"(?u)\b\w[\w./+-]*\b",
    )
    matrix = vectorizer.fit_transform(corpus)
    feature_names = [f"tfidf_{t}" for t in vectorizer.get_feature_names_out()]
    tfidf_df = pd.DataFrame(matrix.toarray(), columns=feature_names, index=df.index)
    return tfidf_df, vectorizer


def build_feature_matrix(df: pd.DataFrame, max_features: int = 300) -> tuple[pd.DataFrame, TfidfVectorizer]:
    flags = build_boolean_flags(df)
    metrics = build_session_metrics(df)
    tfidf_df, vectorizer = build_tfidf_features(df, max_features=max_features)

    features = pd.concat(
        [df[["session_id"]].reset_index(drop=True),
         flags.reset_index(drop=True),
         metrics.reset_index(drop=True),
         tfidf_df.reset_index(drop=True)],
        axis=1,
    )
    return features, vectorizer


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract features from parsed Cowrie sessions.")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--table", default="sessions")
    parser.add_argument("--out-parquet", required=True, type=Path)
    parser.add_argument("--max-features", type=int, default=300)
    args = parser.parse_args()

    with sqlite3.connect(args.db) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {args.table}", conn)

    features, _ = build_feature_matrix(df, max_features=args.max_features)
    args.out_parquet.parent.mkdir(parents=True, exist_ok=True)
    features.to_parquet(args.out_parquet, index=False)
    print(f"Feature matrix: {features.shape[0]} sessions x {features.shape[1]} columns -> {args.out_parquet}")


if __name__ == "__main__":
    main()
