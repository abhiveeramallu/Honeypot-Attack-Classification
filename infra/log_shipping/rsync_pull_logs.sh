#!/usr/bin/env bash
# Pull cowrie.json + downloaded payloads from the honeypot to the processing
# server. Runs ON THE PROCESSING SERVER (pull, not push) so a compromised
# honeypot never holds credentials that can write to the processing server —
# it can, at worst, serve the restricted rsync key stale/tampered log data,
# which the ETL's malformed-line handling already tolerates.
#
# Install: place this under /opt/honeypot-pipeline/log_shipping/, then wire
# up cowrie-log-sync.{service,timer} to run it every 5 minutes.
set -euo pipefail

HONEYPOT_HOST="${HONEYPOT_HOST:?Set HONEYPOT_HOST, e.g. cowrie-hp01.internal}"
HONEYPOT_USER="${HONEYPOT_USER:-cowrie}"
HONEYPOT_SSH_PORT="${HONEYPOT_SSH_PORT:-22222}"          # the *admin* SSH port, not the honeypot's fake 22
SSH_KEY="${SSH_KEY:-/opt/honeypot-pipeline/keys/log_puller_ed25519}"

REMOTE_LOG_DIR="${REMOTE_LOG_DIR:-/home/cowrie/cowrie/var/log/cowrie/}"
REMOTE_DOWNLOADS_DIR="${REMOTE_DOWNLOADS_DIR:-/home/cowrie/cowrie/var/lib/cowrie/downloads/}"

LOCAL_LOG_DIR="${LOCAL_LOG_DIR:-/opt/honeypot-pipeline/data/raw_logs/${HONEYPOT_HOST}/}"
LOCAL_DOWNLOADS_DIR="${LOCAL_DOWNLOADS_DIR:-/opt/honeypot-pipeline/data/payloads/${HONEYPOT_HOST}/}"

LOCK_FILE="/tmp/cowrie-log-sync-${HONEYPOT_HOST}.lock"
SSH_OPTS=(-i "$SSH_KEY" -p "$HONEYPOT_SSH_PORT" -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o BatchMode=yes)

mkdir -p "$LOCAL_LOG_DIR" "$LOCAL_DOWNLOADS_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date -Is) Another sync for ${HONEYPOT_HOST} is already running; exiting." >&2
  exit 0
fi

echo "$(date -Is) Syncing logs from ${HONEYPOT_USER}@${HONEYPOT_HOST}:${HONEYPOT_SSH_PORT} ..."

rsync -az --partial \
  -e "ssh ${SSH_OPTS[*]}" \
  "${HONEYPOT_USER}@${HONEYPOT_HOST}:${REMOTE_LOG_DIR}" \
  "$LOCAL_LOG_DIR"

rsync -az --partial \
  -e "ssh ${SSH_OPTS[*]}" \
  "${HONEYPOT_USER}@${HONEYPOT_HOST}:${REMOTE_DOWNLOADS_DIR}" \
  "$LOCAL_DOWNLOADS_DIR"

echo "$(date -Is) Sync complete: ${LOCAL_LOG_DIR}, ${LOCAL_DOWNLOADS_DIR}"

# Optional: trigger the pipeline right after a successful sync instead of
# waiting for its own schedule. Uncomment if you want sync-triggers-pipeline
# rather than two independent timers.
# /opt/honeypot-pipeline/.venv/bin/python /opt/honeypot-pipeline/run_pipeline.py \
#   --raw-logs "$LOCAL_LOG_DIR" \
#   --db /opt/honeypot-pipeline/data/sqlite/sessions.db \
#   --parquet /opt/honeypot-pipeline/data/parquet/sessions.parquet \
#   --model-dir /opt/honeypot-pipeline/models
