# Cross-host live validation (E2)

Goal: prove multiple **real** MCP hosts drive one mcp-pacemaker bridge together — editors and
CLIs, side by side — and that the bridge attributes each session to its host.

## What was validated live

One bridge (`--port 8812`) fronting a stdio server, with each host wired into an **isolated**
config dir (real `~/.claude.json`, `~/.copilot/…`, VS Code `mcp.json` untouched):

| Host | Wiring (real CLI / adapter) | Live result |
|------|-----------------------------|-------------|
| **Claude Code** (`claude` 2.1.212) | `claude mcp add --transport http echo http://127.0.0.1:8812/echo/mcp` | `claude mcp list` → `echo … (HTTP) - ✔ Connected` |
| **Copilot CLI** (`copilot`) | `copilot mcp add --transport http echo http://127.0.0.1:8812/echo/mcp` | `copilot -p "list the echo tools"` connected through the bridge and listed `echo-ping`; bridge logged a real Streamable-HTTP session |
| **VS Code** | `mcp-pacemaker emit --client vscode` → isolated `mcp.json` (`{type:"sse", url:".../echo/sse"}`) | adapter wiring verified by read-back (GUI session not scripted) |

Both real CLIs connected to the **same** bridge via `POST /<name>/mcp` (Streamable HTTP), each
opening its own child session. The bridge captures `initialize.params.clientInfo.name` per session
and surfaces distinct hosts in `/api/status` → `servers[].clients[]`.

## Regression guard (CI-safe)

`test/cross-host.test.mjs` reproduces the concurrent-attribution path deterministically with the
echo fixture (no real CLIs, no credits): three sessions with `clientInfo.name` of
`Visual Studio Code`, `GitHub Copilot`, and `Claude Code` open concurrently on one bridged server,
and the snapshot asserts `sessions === 3` with all three hosts in `clients[]`.

The live claude+copilot connect above is an out-of-band gate (needs the real CLIs) and is not run
in CI.
