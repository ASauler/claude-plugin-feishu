#!/usr/bin/env bash
# Forward hook stdin JSON to the Feishu plugin's local HTTP server.
# Never blocks Claude Code: short timeout, failures swallowed.
set -u
PORT_FILE="${FEISHU_STATE_DIR:-$HOME/.claude/channels/feishu}/hook.port"
if [ ! -s "$PORT_FILE" ]; then
  exit 0
fi
PORT=$(cat "$PORT_FILE")
# Pipe stdin straight to curl. --max-time 2 so a wedged server never stalls Claude.
curl -sS --max-time 2 \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "http://127.0.0.1:${PORT}/event" \
  >/dev/null 2>&1 || true
exit 0
