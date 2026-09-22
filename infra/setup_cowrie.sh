#!/usr/bin/env bash
# Install and configure Cowrie under the unprivileged `cowrie` user.
# Run as: sudo -u cowrie bash setup_cowrie.sh
set -euo pipefail

COWRIE_HOME="/home/cowrie/cowrie"
COWRIE_REPO="https://github.com/cowrie/cowrie.git"

if [[ "$(whoami)" == "root" ]]; then
  echo "Run this as the 'cowrie' user, not root (Cowrie refuses to start as root)." >&2
  exit 1
fi

git clone "$COWRIE_REPO" "$COWRIE_HOME"
cd "$COWRIE_HOME"

python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

cp etc/cowrie.cfg.dist etc/cowrie.cfg

# --- Bind Cowrie to unprivileged high ports; iptables NAT (run as root
# separately) forwards the real 22/23 down to these. ---
python3 - <<'PYEOF'
import configparser
cfg = configparser.ConfigParser()
cfg.read("etc/cowrie.cfg")

cfg["ssh"]["enabled"] = "true"
cfg["ssh"]["listen_endpoints"] = "tcp:2222:interface=0.0.0.0"

cfg["telnet"]["enabled"] = "true"
cfg["telnet"]["listen_endpoints"] = "tcp:2223:interface=0.0.0.0"

cfg["honeypot"]["hostname"] = "svr04"
cfg["honeypot"]["log_path"] = "var/log/cowrie"
cfg["honeypot"]["download_path"] = "var/lib/cowrie/downloads"
cfg["honeypot"]["state_path"] = "var/lib/cowrie"

# Structured JSON logging for the ETL pipeline.
if "output_jsonlog" not in cfg:
    cfg["output_jsonlog"] = {}
cfg["output_jsonlog"]["enabled"] = "true"
cfg["output_jsonlog"]["logfile"] = "var/log/cowrie/cowrie.json"
cfg["output_jsonlog"]["epoch_timestamp"] = "false"

with open("etc/cowrie.cfg", "w") as f:
    cfg.write(f)
PYEOF

mkdir -p var/log/cowrie var/lib/cowrie/downloads var/lib/cowrie/tty

bin/cowrie start

echo "Cowrie started. JSON logs: $COWRIE_HOME/var/log/cowrie/cowrie.json"
echo "Next (as root): iptables-nat.sh then egress-restrict.sh"
