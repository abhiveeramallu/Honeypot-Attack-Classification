"""Phase 3: deterministic rule engine mapping a session's commands to
MITRE ATT&CK technique IDs. This is the baseline classifier and the Phase 4
ML fallback when model confidence is low.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import pandas as pd

from attack_rules import BRUTE_FORCE_MIN_ATTEMPTS, classify_command, technique_lookup


def classify_session(command_sequence: list[str], login_attempts: int = 0) -> list[str]:
    """Return the sorted, de-duplicated list of technique IDs for a session."""
    techniques: set[str] = set()

    if login_attempts >= BRUTE_FORCE_MIN_ATTEMPTS:
        techniques.add("T1110")

    for command in command_sequence:
        techniques.update(classify_command(command))

    return sorted(techniques)


def classify_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Add a `rule_techniques` (JSON list) column to a sessions dataframe.

    Expects `command_sequence` as a JSON-encoded list string (as written by
    etl_parser.py) and a `login_attempts` integer column.
    """
    out = df.copy()

    def _row_classify(row) -> str:
        try:
            commands = json.loads(row["command_sequence"])
        except (TypeError, json.JSONDecodeError):
            commands = []
        attempts = int(row.get("login_attempts", 0) or 0)
        return json.dumps(classify_session(commands, attempts))

    out["rule_techniques"] = out.apply(_row_classify, axis=1)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply the ATT&CK rule engine to parsed sessions.")
    parser.add_argument("--db", required=True, type=Path, help="SQLite DB written by etl_parser.py")
    parser.add_argument("--table", default="sessions")
    args = parser.parse_args()

    with sqlite3.connect(args.db) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {args.table}", conn)
        classified = classify_dataframe(df)
        classified.to_sql(args.table, conn, if_exists="replace", index=False)

    lookup = technique_lookup()
    print(f"Classified {len(classified)} sessions.")
    for _, row in classified.iterrows():
        techniques = json.loads(row["rule_techniques"])
        if not techniques:
            continue
        names = ", ".join(f"{t} ({lookup.get(t, (t, '?'))[0]})" for t in techniques)
        print(f"  session {row['session_id']}: {names}")


if __name__ == "__main__":
    main()
