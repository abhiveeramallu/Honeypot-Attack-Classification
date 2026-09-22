"""Phase 6: turn recurring high-confidence ATT&CK detections into Sigma
detection rules, plus an IoC feed (malicious IPs + payload URLs) for SIEM/
firewall ingestion.

A pattern is "recurring" if it was observed across >= `--min-sessions`
distinct sessions/source IPs at high confidence, to avoid promoting a single
honeypot interaction into a production detection rule.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
from attack_rules import technique_lookup  # noqa: E402

# Maps a technique ID to a Sigma-friendly detection over process command
# lines (Sysmon EventID 1 / auditd style), since that's what a real endpoint
# would emit for the same behavior the honeypot observed.
SIGMA_KEYWORD_TEMPLATES: dict[str, list[str]] = {
    "T1105": ["*wget *http*", "*curl *http*", "*tftp -g*"],
    "T1140": ["*base64 -d*", "*base64 --decode*"],
    "T1222": ["*chmod +x*", "*chmod 7[0-7][0-7]*"],
    "T1003.008": ["*/etc/shadow*"],
    "T1053.003": ["*crontab -*", "*/etc/cron.d/*", "*>> /etc/crontab*"],
    "T1070.003": ["*history -c*", "*bash_history*"],
    "T1070.002": ["*rm -rf /var/log*", "*> /var/log/*"],
    "T1041": ["*scp * @*:*"],
    "T1489.001": ["*rm -rf /*"],
    "T1496": ["*xmrig*", "*stratum+tcp*"],
}


def build_sigma_rule(technique_id: str, technique_name: str, tactic: str, session_count: int) -> dict:
    keywords = SIGMA_KEYWORD_TEMPLATES.get(technique_id)
    if not keywords:
        return {}

    rule_id_slug = technique_id.lower().replace(".", "-")
    return {
        "title": f"Honeypot-Derived Detection: {technique_name}",
        "id": f"hp-derived-{rule_id_slug}",
        "status": "experimental",
        "description": (
            f"Command pattern observed across {session_count} independent honeypot "
            f"sessions and auto-tagged as MITRE ATT&CK {technique_id} ({technique_name})."
        ),
        "references": [f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"],
        "tags": [f"attack.{tactic.lower().replace(' ', '_')}", f"attack.{technique_id.lower()}"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {"CommandLine|contains": keywords},
            "condition": "selection",
        },
        "falsepositives": ["Legitimate sysadmin use of the same commands — tune before deploying to production."],
        "level": "medium",
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
    }


def generate_sigma_rules(sessions_df: pd.DataFrame, technique_col: str, min_sessions: int, out_dir: Path) -> list[Path]:
    lookup = technique_lookup()
    technique_session_count: dict[str, set[str]] = defaultdict(set)

    for _, row in sessions_df.iterrows():
        try:
            techniques = json.loads(row[technique_col]) if row[technique_col] else []
        except (TypeError, json.JSONDecodeError):
            techniques = []
        for tid in techniques:
            technique_session_count[tid].add(row["session_id"])

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for tid, sessions in technique_session_count.items():
        if len(sessions) < min_sessions:
            continue
        name, tactic = lookup.get(tid, (tid, "Unknown"))
        rule = build_sigma_rule(tid, name, tactic, len(sessions))
        if not rule:
            continue
        out_path = out_dir / f"{rule['id']}.yml"
        with out_path.open("w") as f:
            yaml.dump(rule, f, sort_keys=False)
        written.append(out_path)

    return written


def generate_ioc_feed(sessions_df: pd.DataFrame, out_csv: Path) -> None:
    rows = []
    seen = set()
    for _, row in sessions_df.iterrows():
        try:
            urls = json.loads(row["urls_downloaded"]) if row.get("urls_downloaded") else []
        except (TypeError, json.JSONDecodeError):
            urls = []
        try:
            hashes = json.loads(row["file_hashes"]) if row.get("file_hashes") else []
        except (TypeError, json.JSONDecodeError):
            hashes = []

        src_ip = row.get("src_ip")
        if src_ip and src_ip not in seen:
            rows.append({"ioc_type": "ip", "value": src_ip, "session_id": row["session_id"], "context": "honeypot_source_ip"})
            seen.add(src_ip)
        for url in urls:
            key = ("url", url)
            if key not in seen:
                rows.append({"ioc_type": "url", "value": url, "session_id": row["session_id"], "context": "payload_download"})
                seen.add(key)
        for h in hashes:
            key = ("hash", h)
            if key not in seen:
                rows.append({"ioc_type": "sha256", "value": h, "session_id": row["session_id"], "context": "downloaded_payload"})
                seen.add(key)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out_csv, index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Sigma rules + IoC feed from classified sessions.")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--table", default="sessions")
    parser.add_argument("--technique-col", default="rule_techniques",
                         help="Column holding the JSON technique-ID list (rule_techniques or predicted_techniques)")
    parser.add_argument("--min-sessions", type=int, default=2)
    parser.add_argument("--sigma-out-dir", required=True, type=Path)
    parser.add_argument("--ioc-out-csv", required=True, type=Path)
    args = parser.parse_args()

    with sqlite3.connect(args.db) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {args.table}", conn)

    written = generate_sigma_rules(df, args.technique_col, args.min_sessions, args.sigma_out_dir)
    print(f"Wrote {len(written)} Sigma rule(s):")
    for p in written:
        print(f"  {p}")

    generate_ioc_feed(df, args.ioc_out_csv)
    print(f"IoC feed -> {args.ioc_out_csv}")


if __name__ == "__main__":
    main()
