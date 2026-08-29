#!/bin/sh
# mcp-pacemaker bootstrap (macOS/Linux). Imports your client servers, wires the client, starts the bridge.
# Usage: ./install.sh [client] [port]   (client = vscode|cursor|claude, default vscode; port default 8791)
CLIENT="${1:-vscode}"
PORT="${2:-8791}"
DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$DIR/bin/cli.mjs"

if ! command -v node >/dev/null 2>&1; then
  echo "node is not on PATH. Install Node.js (>=18)." >&2
  exit 1
fi

node "$CLI" import  --from "$CLIENT"
node "$CLI" install --client "$CLIENT" --port "$PORT"
node "$CLI" status
