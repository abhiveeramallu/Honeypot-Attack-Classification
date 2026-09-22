"""Regex -> MITRE ATT&CK technique mapping used by both the rule engine
(Phase 3) and as ground-truth bootstrapping for ML labeling (Phase 4).

Each rule is checked against every cleaned command in a session. A single
command may match multiple rules (e.g. `curl ... | bash` is both Ingress
Tool Transfer and a scripting interpreter invocation).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AttackRule:
    technique_id: str
    technique_name: str
    tactic: str
    pattern: re.Pattern


_RULES_RAW: list[tuple[str, str, str, str]] = [
    # technique_id, technique_name, tactic, regex
    ("T1110", "Brute Force", "Credential Access",
     r"^$"),  # handled at session level (login_attempts), placeholder pattern
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution",
     r"\b(bash|sh|/bin/sh|/bin/bash)\b"),
    ("T1059.006", "Command and Scripting Interpreter: Python", "Execution",
     r"\bpython[23]?\b"),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     r"\b(wget|curl|tftp|scp\s+.*@.*:|ftpget)\b.*(https?://|ftp://)|https?://\S+"),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
     r"\bbase64\s+-d\b|\bbase64\s+--decode\b"),
    ("T1222", "File and Directory Permissions Modification", "Defense Evasion",
     r"\bchmod\s+(\+x|[0-7]{3,4})\b"),
    ("T1082", "System Information Discovery", "Discovery",
     r"\buname\s+-a\b|/proc/cpuinfo|/proc/meminfo|\blscpu\b|\bhostnamectl\b"),
    ("T1083", "File and Directory Discovery", "Discovery",
     r"\bls\s+-la?\b|\bfind\s+/|\btree\b"),
    ("T1057", "Process Discovery", "Discovery",
     r"\bps\s+(aux|-ef|-elf)\b|\btop\b|\bpgrep\b"),
    ("T1087", "Account Discovery", "Discovery",
     r"/etc/passwd|\bwho\b|\blast\b|\bw\b\s*$"),
    ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access",
     r"/etc/shadow"),
    ("T1053.003", "Scheduled Task/Job: Cron", "Persistence",
     r"\bcrontab\b|/etc/crontab|/etc/cron\.\w+"),
    ("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion",
     r"\bhistory\s+-c\b|>\s*~?/\.bash_history|rm\s+.*bash_history"),
    ("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion",
     r"rm\s+-rf?\s+/var/log|>\s*/var/log/\S+|\btruncate\b.*log"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     r"\bscp\s+\S+\s+\S+@\S+:|\bnc\s+.*\d+\.\d+\.\d+\.\d+|\brsync\s+.*@"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
     r"https?://\d{1,3}(\.\d{1,3}){3}"),
    ("T1496", "Resource Hijacking", "Impact",
     r"\bxmrig\b|\bminerd\b|stratum\+tcp"),
    ("T1489", "Service Stop", "Impact",
     r"\bservice\s+\w+\s+stop\b|\bsystemctl\s+stop\b|\bkill\s+-9\b"),
    ("T1489.001", "Data Destruction (rm -rf)", "Impact",
     r"\brm\s+-rf\s+/(?!var/log)"),
]

RULES: list[AttackRule] = [
    AttackRule(tid, name, tactic, re.compile(pattern, re.IGNORECASE))
    for tid, name, tactic, pattern in _RULES_RAW
    if pattern != r"^$"
]

# T1110 is derived from session-level login_attempts rather than a command regex.
BRUTE_FORCE_RULE = AttackRule("T1110", "Brute Force", "Credential Access", re.compile(r"^$"))
BRUTE_FORCE_MIN_ATTEMPTS = 3


def classify_command(command: str) -> list[str]:
    """Return all technique IDs whose pattern matches this single command."""
    return [rule.technique_id for rule in RULES if rule.pattern.search(command)]


def technique_lookup() -> dict[str, tuple[str, str]]:
    """technique_id -> (technique_name, tactic), including T1110."""
    lookup = {r.technique_id: (r.technique_name, r.tactic) for r in RULES}
    lookup[BRUTE_FORCE_RULE.technique_id] = (BRUTE_FORCE_RULE.technique_name, BRUTE_FORCE_RULE.tactic)
    return lookup
