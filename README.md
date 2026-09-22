# Honeypot & Automated ATT&CK Technique Classification System

End-to-end pipeline: Cowrie honeypot capture -> ETL -> rule-based and ML
MITRE ATT&CK auto-tagging -> Streamlit dashboard -> Sigma/IoC detection output.

## Layout

```
run_pipeline.py     Orchestrates the full ETL -> classify -> Sigma/IoC run
infra/               Cloud-init + hardening scripts to deploy Cowrie on a VPS
infra/log_shipping/  rsync-over-SSH + systemd timers (+ Filebeat alt.) to
                     ship logs from the honeypot to the processing server
etl/                 etl_parser.py — cowrie.json -> SQLite/Parquet sessions
features/            attack_rules.py, rule_classifier.py, feature_extractor.py
ml/                  labeling_schema.py, train_pipeline.py, ml_classifier.py
dashboard/           app.py — Streamlit multi-page analytics UI
detection/           generate_sigma.py — Sigma rules + IoC feed
tests/               pytest suite (etl / rule engine / ML fallback)
data/                sample_cowrie_logs (synthetic), sqlite/, parquet/ outputs
models/              trained model.joblib + vectorizer.joblib + feature_meta.joblib
```

## Quickstart (local, using the bundled synthetic sample logs)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt   # requirements.txt + pytest

# Run the tests
python -m pytest tests/ -v

# Bootstrap a model from the rule engine's own output (see "Ground truth
# and training" below for why this is a smoke-test model, not a trustworthy
# one, until real sessions get human-reviewed labels).
cd ml && python train_pipeline.py \
  --raw-logs ../data/sample_cowrie_logs \
  --model-dir ../models \
  --folds 3 && cd ..

# One-shot: parse raw logs -> rule engine -> ML (with rule fallback) ->
# SQLite/Parquet -> Sigma rules + IoC feed.
python run_pipeline.py \
  --raw-logs data/sample_cowrie_logs \
  --db data/sqlite/sessions.db \
  --parquet data/parquet/sessions.parquet \
  --model-dir models \
  --sigma-out-dir detection/sigma_rules \
  --ioc-out-csv data/ioc_feed.csv
# (--skip-ml, or simply an empty/missing --model-dir, runs rule-engine-only)

# Dashboard
cd dashboard && streamlit run app.py -- --db ../data/sqlite/sessions.db && cd ..
```

`run_pipeline.py` is idempotent — `etl_parser.py`'s session merge means
re-running it over the same (or overlapping) raw logs just reprocesses the
same sessions, so it's safe to schedule on a timer (see log shipping below)
without deduping logs yourself first.

## Ground truth and training (Phase 4)

`ml/train_pipeline.py` builds its training labels by running the Phase 3
rule engine over parsed sessions — this is a **bootstrap label**, not a
human-verified one. A model trained only on bootstrap labels has learned to
reproduce the rule engine's own regexes, not to generalize past them; it
will not catch anything the rules don't already catch. Treat a
rule-engine-bootstrapped model as a pipeline smoke test.

To get a model that's actually worth trusting:

1. `cd ml && python labeling_schema.py --db ../data/sqlite/sessions.db --out-csv ../data/labels_for_annotation.csv`
2. Have a human fill in (or correct) the `confirmed_techniques` column —
   directly in the CSV, or via a Label Studio import/export round-trip.
3. `python train_pipeline.py --db ../data/sqlite/sessions.db --labels-csv ../data/labels_for_annotation.csv --model-dir ../models`
   — sessions present in the labels CSV with a non-blank
   `confirmed_techniques` override the rule-engine bootstrap; sessions not
   yet reviewed keep the bootstrap label rather than being silently wiped.

`train_pipeline.py` reports K-Fold cross-validated precision/recall/F1 per
ATT&CK technique (folds auto-shrink for tiny datasets, with a warning) and
serializes `model.joblib`, `vectorizer.joblib`, and `feature_meta.joblib` to
`--model-dir`. `ml/ml_classifier.py` loads that exact fitted TF-IDF
vectorizer at inference time — inference features are computed in the same
column space training used, rather than each run re-fitting its own
vectorizer on whatever's on hand (a real train/inference skew that existed
before `train_pipeline.py` was split out — see git history if curious).
`predict_with_fallback()` falls back to the rule engine per-session when the
model's max predicted probability is below `--threshold` (default 0.70).

## Deploying the real honeypot (Phase 1)

1. Provision an Ubuntu 22.04 VPS **inside an isolated VPC/VLAN with no route
   to any internal/production network.** This is the single most important
   control — everything else in `infra/` is defense in depth on top of it.
2. Pass `infra/cloud-init.yaml` as user-data (replace the placeholder SSH
   public key first). This moves the real admin SSH to port 22222 and opens
   only 22222/22/23 at the firewall.
3. SSH in on 22222, then as the `cowrie` user run `infra/setup_cowrie.sh` to
   install and configure Cowrie (binds to 2222/2223 internally, JSON logging
   enabled).
4. As root, run `infra/iptables-nat.sh` (forwards 22->2222, 23->2223) then
   `infra/egress-restrict.sh` (default-deny outbound except DNS/NTP/HTTP/S —
   stops the box being usable for outbound DDoS or lateral pivoting even if
   an attacker gets a real shell).

## Automated log shipping (Phase 1)

`infra/log_shipping/` has two options to get `cowrie.json` + captured
payloads from the honeypot to wherever `run_pipeline.py` runs:

- **rsync over SSH (default, recommended)** — `rsync_pull_logs.sh` runs ON
  THE PROCESSING SERVER and *pulls* from the honeypot, using a key
  restricted on the honeypot side to read-only rsync of Cowrie's `var/`
  directory (`honeypot_authorized_keys_snippet.txt` — via `rrsync`, no
  shell, no port/agent/X11 forwarding). Pull-based means a compromised
  honeypot never holds credentials that can write to the processing server.
  `cowrie-log-sync.{service,timer}` runs it every 5 minutes via systemd;
  `honeypot-pipeline.{service,timer}` runs `run_pipeline.py` itself every 10
  minutes after that. Install both pairs under `/etc/systemd/system/` on the
  processing server and `systemctl enable --now` the timers.
- **Filebeat (alternative, real-time)** — `filebeat-cowrie.yml`, installed
  ON THE HONEYPOT, ships events as they're written instead of polling. This
  needs *outbound* network access from the honeypot to the processing
  server, which means carving an explicit exception into
  `egress-restrict.sh`'s default-deny — noted inline in the config.

## Notes

- `data/sample_cowrie_logs/cowrie.json` is synthetic data for pipeline
  development/testing — replace with real captures before drawing
  conclusions from the dashboard or shipping Sigma rules.
- Sigma rules in `detection/generate_sigma.py` are `status: experimental` —
  tune false-positive scope (especially around `wget`/`curl`/`chmod`, which
  are common in legitimate sysadmin activity) before deploying to a
  production SIEM. `run_pipeline.py --min-sessions` controls how many
  independent sessions must show a pattern before a rule is emitted at all.
- The dashboard (`dashboard/app.py`) reads directly from the SQLite sessions
  table, cached for 60s (or refreshed immediately via the sidebar button),
  so it picks up whatever `run_pipeline.py` last wrote — including
  `predicted_techniques`/`confidence`/`source` when a model was used, or
  `rule_techniques` alone in rule-only mode.
