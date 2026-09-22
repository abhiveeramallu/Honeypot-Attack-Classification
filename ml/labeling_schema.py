"""Phase 4: human-in-the-loop labeling schema.

Exports sessions to a flat CSV that a human annotator (or a Label Studio
import) can fill in with confirmed ATT&CK technique IDs, and re-imports the
completed annotations back into the training set.

CSV columns:
    session_id        - primary key, matches etl_parser.py output
    src_ip
    username, password
    command_sequence  - pipe-joined commands, read-only for the annotator
    rule_techniques    - the Phase-3 rule engine's suggestion, pre-filled
    confirmed_techniques - ANNOTATOR FILLS THIS IN: comma-separated technique IDs
                           (e.g. "T1110,T1105,T1082"), or leave blank / "NONE"
    notes              - free text, optional

Label Studio equivalent: import the same CSV as tasks, with a multi-select
"confirmed_techniques" choice field populated from features/attack_rules.py
technique_lookup(), and export completed annotations back to this format
before running ml_classifier.py --train.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import pandas as pd

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
from attack_rules import technique_lookup  # noqa: E402


def export_for_labeling(db_path: Path, table: str, out_csv: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)

    def _commands(s: str) -> str:
        try:
            return " | ".join(json.loads(s))
        except (TypeError, json.JSONDecodeError):
            return ""

    def _rule_suggestion(s: str) -> str:
        try:
            return ",".join(json.loads(s)) if s else ""
        except (TypeError, json.JSONDecodeError):
            return ""

    export_df = pd.DataFrame({
        "session_id": df["session_id"],
        "src_ip": df.get("src_ip", ""),
        "username": df.get("username", ""),
        "password": df.get("password", ""),
        "command_sequence": df["command_sequence"].apply(_commands),
        "rule_techniques": df.get("rule_techniques", "").apply(_rule_suggestion)
        if "rule_techniques" in df.columns else "",
        "confirmed_techniques": "",  # annotator fills this in
        "notes": "",
    })

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    export_df.to_csv(out_csv, index=False)
    print(f"Exported {len(export_df)} sessions for labeling -> {out_csv}")
    print("Valid technique IDs:")
    for tid, (name, tactic) in sorted(technique_lookup().items()):
        print(f"  {tid:12s} {name} ({tactic})")


def import_labels(labeled_csv: Path) -> pd.DataFrame:
    """Read a completed annotation CSV back into a (session_id, labels[]) frame."""
    df = pd.read_csv(labeled_csv, dtype=str).fillna("")

    def _parse(s: str) -> list[str]:
        s = s.strip()
        if not s or s.upper() == "NONE":
            return []
        return [tid.strip() for tid in s.split(",") if tid.strip()]

    df["labels"] = df["confirmed_techniques"].apply(_parse)
    return df[["session_id", "labels"]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Export sessions for human ATT&CK labeling.")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--table", default="sessions")
    parser.add_argument("--out-csv", required=True, type=Path)
    args = parser.parse_args()
    export_for_labeling(args.db, args.table, args.out_csv)


if __name__ == "__main__":
    main()
