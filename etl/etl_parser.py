"""Parse raw Cowrie JSON logs into structured, per-session records.

Cowrie writes one JSON object per line (`cowrie.json`), with events for a
given session interleaved with events from other concurrent sessions. This
module groups events by `session`, reconstructs an ordered command sequence
per session, and exports the result to SQLite + Parquet.

Usage:
    python etl_parser.py --input ../data/sample_cowrie_logs --out-db ../data/sqlite/sessions.db \
        --out-parquet ../data/parquet/sessions.parquet
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

import pandas as pd

CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class Session:
    session_id: str
    src_ip: str | None = None
    protocol: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    session_duration: float | None = None
    username: str | None = None
    password: str | None = None
    login_attempts: int = 0
    login_success: bool = False
    command_sequence: list[str] = field(default_factory=list)
    urls_downloaded: list[str] = field(default_factory=list)
    file_hashes: list[str] = field(default_factory=list)


def _clean_command(raw: str) -> str:
    """Strip terminal control chars/escape sequences and surrounding noise."""
    text = CONTROL_CHARS_RE.sub("", raw)
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)  # ANSI escape sequences
    return text.strip()


def parse_log_file(path: Path) -> dict[str, Session]:
    sessions: dict[str, Session] = {}

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed lines rather than aborting the run

            session_id = event.get("session")
            if not session_id:
                continue

            sess = sessions.setdefault(session_id, Session(session_id=session_id))
            eventid = event.get("eventid", "")

            if "src_ip" in event and sess.src_ip is None:
                sess.src_ip = event["src_ip"]

            if eventid == "cowrie.session.connect":
                sess.protocol = event.get("protocol")
                sess.start_time = event.get("timestamp")

            elif eventid == "cowrie.login.failed":
                sess.login_attempts += 1
                sess.username = sess.username or event.get("username")
                sess.password = sess.password or event.get("password")

            elif eventid == "cowrie.login.success":
                sess.login_attempts += 1
                sess.login_success = True
                sess.username = event.get("username", sess.username)
                sess.password = event.get("password", sess.password)

            elif eventid == "cowrie.command.input":
                raw = event.get("input", "")
                cleaned = _clean_command(raw)
                if cleaned and (
                    not sess.command_sequence or sess.command_sequence[-1] != cleaned
                ):
                    sess.command_sequence.append(cleaned)

            elif eventid == "cowrie.session.file_download":
                url = event.get("url")
                if url:
                    sess.urls_downloaded.append(url)
                shasum = event.get("shasum")
                if shasum:
                    sess.file_hashes.append(shasum)

            elif eventid == "cowrie.session.closed":
                sess.end_time = event.get("timestamp")
                sess.session_duration = event.get("duration")

    # Backfill duration if session.closed didn't carry it explicitly.
    for sess in sessions.values():
        if sess.session_duration is None and sess.start_time and sess.end_time:
            try:
                t0 = datetime.fromisoformat(sess.start_time.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(sess.end_time.replace("Z", "+00:00"))
                sess.session_duration = (t1 - t0).total_seconds()
            except ValueError:
                pass

    return sessions


def load_logs(input_path: Path) -> dict[str, Session]:
    """Accept either a single log file or a directory of them."""
    all_sessions: dict[str, Session] = {}
    files = [input_path] if input_path.is_file() else sorted(input_path.glob("*.json*"))
    for f in files:
        for sid, sess in parse_log_file(f).items():
            if sid in all_sessions:
                # Merge in case the same session spans multiple rotated log files.
                existing = all_sessions[sid]
                existing.command_sequence.extend(
                    c for c in sess.command_sequence if c not in existing.command_sequence
                )
                existing.urls_downloaded.extend(sess.urls_downloaded)
                existing.file_hashes.extend(sess.file_hashes)
                existing.login_attempts += sess.login_attempts
                existing.end_time = sess.end_time or existing.end_time
                existing.session_duration = sess.session_duration or existing.session_duration
            else:
                all_sessions[sid] = sess
    return all_sessions


def to_dataframe(sessions: dict[str, Session]) -> pd.DataFrame:
    rows = []
    for sess in sessions.values():
        d = asdict(sess)
        d["command_sequence"] = json.dumps(d["command_sequence"])
        d["urls_downloaded"] = json.dumps(d["urls_downloaded"])
        d["file_hashes"] = json.dumps(d["file_hashes"])
        d["command_count"] = len(sess.command_sequence)
        rows.append(d)
    return pd.DataFrame(rows)


def write_sqlite(df: pd.DataFrame, db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        df.to_sql("sessions", conn, if_exists="replace", index=False)


def write_parquet(df: pd.DataFrame, parquet_path: Path) -> None:
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(parquet_path, index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Cowrie JSON logs into structured sessions.")
    parser.add_argument("--input", required=True, type=Path, help="cowrie.json file or directory of log files")
    parser.add_argument("--out-db", required=True, type=Path, help="SQLite output path")
    parser.add_argument("--out-parquet", required=True, type=Path, help="Parquet output path")
    args = parser.parse_args()

    sessions = load_logs(args.input)
    df = to_dataframe(sessions)

    write_sqlite(df, args.out_db)
    write_parquet(df, args.out_parquet)

    print(f"Parsed {len(df)} sessions from {args.input}")
    print(f"  -> SQLite:  {args.out_db}")
    print(f"  -> Parquet: {args.out_parquet}")


if __name__ == "__main__":
    main()
