#!/bin/sh
# Supervisor for the mcp-pacemaker bridge (macOS/Linux). Restarts it if it exits.
# Exit code 3 = another bridge already on this port -> stop (no thrash). Arg 1 = port.
PORT="${1:-8791}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BRIDGE="$DIR/bin/mcp-bridge.mjs"

if ! command -v node >/dev/null 2>&1; then
  echo "node is not on PATH. Install Node.js (>=18) and retry." >&2
  exit 1
fi

while true; do
  node "$BRIDGE" --port "$PORT"
  code=$?
  [ "$code" -eq 3 ] && break   # another bridge already running on this port
  sleep 2                      # backoff so a crash-loop doesn't spin
done
