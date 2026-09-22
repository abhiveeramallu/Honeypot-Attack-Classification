# Honeypot & Automated ATT&CK Technique Classification System

End-to-end pipeline: Cowrie honeypot capture -> ETL -> rule-based and ML
MITRE ATT&CK auto-tagging -> Streamlit dashboard -> Sigma/IoC detection output.

## Layout

```
infra/          Cloud-init + hardening scripts to deploy Cowrie on a VPS
etl/            etl_parser.py — cowrie.json -> SQLite/Parquet sessions
features/       attack_rules.py, rule_classifier.py, feature_extractor.py
ml/             labeling_schema.py, ml_classifier.py
dashboard/      app.py — Streamlit multi-page analytics UI
detection/      generate_sigma.py — Sigma rules + IoC feed
data/           sample_cowrie_logs (synthetic), sqlite/, parquet/ outputs
```

## Quickstart (local, using the bundled synthetic sample logs)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Phase 2: ETL
python etl/etl_parser.py \
  --input data/sample_cowrie_logs \
  --out-db data/sqlite/sessions.db \
  --out-parquet data/parquet/sessions.parquet

# Phase 3: rule engine (writes rule_techniques column back into the DB)
cd features && python rule_classifier.py --db ../data/sqlite/sessions.db && cd ..

# Phase 3: feature matrix (TF-IDF + boolean flags + session metrics)
cd features && python feature_extractor.py \
  --db ../data/sqlite/sessions.db \
  --out-parquet ../data/parquet/features.parquet && cd ..

# Phase 4: export sessions for human labeling, then fill in confirmed_techniques
cd ml && python labeling_schema.py \
  --db ../data/sqlite/sessions.db \
  --out-csv ../data/labels_for_annotation.csv && cd ..
# (edit data/labels_for_annotation.csv by hand, or import into Label Studio)

# Phase 4: train + evaluate
cd ml && python ml_classifier.py train \
  --features ../data/parquet/features.parquet \
  --labels ../data/labels_for_annotation.csv \
  --model-type rf \
  --model-out ../data/model.joblib && cd ..

# Phase 5: dashboard
cd dashboard && streamlit run app.py -- --db ../data/sqlite/sessions.db && cd ..

# Phase 6: Sigma rules + IoC feed from the rule engine's output
cd detection && python generate_sigma.py \
  --db ../data/sqlite/sessions.db \
  --technique-col rule_techniques \
  --min-sessions 1 \
  --sigma-out-dir sigma_rules \
  --ioc-out-csv ../data/ioc_feed.csv && cd ..
```

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
5. Pull `var/log/cowrie/cowrie.json` and `var/lib/cowrie/downloads/` down to
   wherever you run the ETL pipeline (rsync/scp over the admin port, not
   through the honeypot).

## Notes

- The rule engine (`features/attack_rules.py`) is the ground truth used to
  bootstrap labels — start there, confirm/correct with a human via
  `ml/labeling_schema.py`, then train the ML classifier on the confirmed
  labels. The ML classifier falls back to the rule engine per-session when
  its confidence is below `--threshold` (default 0.70).
- `data/sample_cowrie_logs/cowrie.json` is synthetic data for pipeline
  development/testing — replace with real captures before drawing
  conclusions from the dashboard or shipping Sigma rules.
- Sigma rules in `detection/generate_sigma.py` are `status: experimental` —
  tune false-positive scope (especially around `wget`/`curl`/`chmod`, which
  are common in legitimate sysadmin activity) before deploying to a
  production SIEM.
