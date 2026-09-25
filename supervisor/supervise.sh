#!/bin/sh
# Starts the managed supervisor. Arg 1 = port.
PORT="${1:-8791}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "node is not on PATH. Install Node.js (>=20) and retry." >&2
  exit 1
fi

exec node "$DIR/supervisor/supervise.mjs" --port "$PORT"
