# mcp-pacemaker — roadmap

Tracks the work to make pacemaker wire *any* MCP host (editors **and** CLIs), support
one-shared-bridge **and** bridge-per-host topologies, and serve multiple concurrent agents
efficiently.

## Goal
Auto-detect **every installed MCP host** on the machine — VS Code, Cursor, Claude Desktop,
Claude Code, Copilot CLI, Codex CLI, Gemini CLI — and wire each to a pacemaker bridge over one
universal transport, with the bridge centralizing auth. A one-shot CLI (`copilot -p "…"`) hits a
warm, pre-authenticated server instead of cold-spawning one per run.

## Principles
1. **Hosts are data, not branches** — a host-adapter registry replaces per-host switches.
2. **One universal transport** — wire every host to the bridge's Streamable HTTP endpoint
   `http://127.0.0.1:<port>/<name>/mcp`. It's the modern MCP standard and the only remote
   transport Codex supports. No per-host transport logic.
3. **Bridge owns auth** — hosts talk to the bridge unauthenticated over loopback; the bridge
   injects the real token. Zero per-host auth config.
4. **Safe writes** — `.bak` before every rewrite; prefer a host's native `mcp add` where
   hand-editing its config is risky.

## Bridge topologies — both supported
| Topology | Meaning | State |
|---|---|---|
| **Shared bridge** | all hosts point at one bridge (one port, one `servers.json`) | every host row has the same `port` |
| **Bridge-per-host** | each host gets its own bridge (own port, own config) | host rows have different `port`s |
| **Mix** | two hosts share a port; a third is isolated on another | rows grouped by `port` |

This falls out of a **per-host state model** where each wired host records its own `port`.

### State model (`~/.mcp-pacemaker/state.json`)
```jsonc
{
  "hosts": [
    { "id": "vscode",      "path": ".../Code/User/mcp.json",     "port": 8791, "wiredAt": "…", "servers": ["…"] },
    { "id": "copilot-cli", "path": "~/.copilot/mcp-config.json", "port": 8791, "wiredAt": "…", "servers": ["…"] },
    { "id": "claude-code", "path": "native (claude mcp)",        "port": 8792, "wiredAt": "…", "servers": ["…"] }
  ]
}
```
A legacy single-host `{client,path,port,servers}` is read and folded into `hosts[]`.

## Host capability matrix
| Host | Config file | Format | Key | HTTP entry | Native add | Wiring |
|---|---|---|---|---|---|---|
| VS Code | `…/Code/User/mcp.json` | JSON | `servers` | `{type:http,url}` | — | direct edit |
| Cursor | `~/.cursor/mcp.json` | JSON | `mcpServers` | `{url}` | — | direct edit |
| Claude Desktop | `claude_desktop_config.json` | JSON | `mcpServers` | `{url}` | — | direct edit |
| Claude Code | `~/.claude.json` / `.mcp.json` | JSON | `mcpServers` | `{type:http,url}` | `claude mcp add --scope user --transport http` | native shell-out |
| Codex CLI | `~/.codex/config.toml` | **TOML** | `[mcp_servers.<n>]` | `url="…"` (streamable only) | stdio-only | TOML edit |
| Gemini CLI | `~/.gemini/settings.json` | JSON | `mcpServers` | `{httpUrl}` | `gemini mcp add --transport http` | native / JSON merge |
| Copilot CLI | `~/.copilot/mcp-config.json` | JSON | `mcpServers` | `{type:http,url}` | `copilot mcp add` | direct edit / native |

Gotchas: Codex is TOML + streamable-only; Gemini uses `httpUrl` not `url`; Claude Code's
`~/.claude.json` is large and stateful, so use `claude mcp add`.

## Multi-agent / concurrency
The bridge isolates per session (child keyed by session id, responses routed per JSON-RPC id), so
multiple hosts/agents coexist with no cross-talk, and HTTP servers share the token cache.

- **Sharing policy** per server: `isolated` (default) · `pool` (bounded warm pool) ·
  `shared` (one child multiplexed across agents — R&D).
- **Concurrency caps** so agent fan-out can't exhaust the machine.
- **Keep-warm linger** = `pool` with `minWarm`; idle children are reaped.
- **Per-agent observability** — `clientInfo` captured at `initialize`, surfaced per server.

## Delivered
| Phase | Scope |
|---|---|
| **C0** | host-adapter registry + multi-host/multi-bridge state model |
| **C1** | Gemini + Copilot CLI adapters (JSON); `clientInfo` session tagging |
| **C2** | Claude Code (native) + Codex (TOML) |
| **C3** | multi-host wizard; doctor/status/emit/uninstall iterate all hosts |
| **C4** | multi-agent observability + opt-in idle reaper |
| **A** | resource controls (`MCP_MAX_SESSIONS_PER_SERVER`, per-server `maxSessions`) |
| **B** | multi-bridge lifecycle (`start`/`stop` by port, per-port autostart) |
| **C** | keep-warm pool (`sharing:"pool"` + `minWarm`) |
| **E1** | expanded tests + CI (controls, adapters/TOML, TUI) |
| **E2** | cross-host test — two CLI hosts on one bridge, attributed by `clientInfo` |

---

# Backlog

## Release track
| # | Item | Detail |
|---|---|---|
| **B1** | Publish polish | `homepage` + `bugs` in `package.json`; tag `v1.0.0`; CHANGELOG |
| **B2** | npm publish | Optional — only shortens `npx github:<owner>/mcp-pacemaker` to `npx mcp-pacemaker` |

## Feature backlog
| # | Item | Detail |
|---|---|---|
| **B5** | MCP SDK adoption | Replace hand-rolled JSON-RPC framing with the official SDK. |
| **B6** | `shared` sharing mode | True multiplex of one child across agents. Risky for a 24/7 bridge — R&D. |
| **B9** | Bridge-side OAuth broker | For `auth: none` servers whose resource does not pre-authorize the Azure CLI, so no `audience` token can be minted. The bridge would run the OAuth flow itself and share one credential across clients. Adds a callback listener and refresh-token storage to a 24/7 daemon — needs a threat-model review first. |
| **B10** | `mcp-pacemaker logs` | Tail and filter `bridge.log` from the CLI, with `--server` and `--since`. The file exists as of 1.1.0; only the reader is missing. |
| **B11** | Reap orphans from a previous instance | On Windows, force-killing the bridge (Task Manager, `Stop-Process -Force`, a hard reboot) terminates it without running its `SIGTERM` shutdown, so **children it spawned can survive indefinitely** — real servers have no self-destruct, and they hold their ports and credentials. Measured directly with a heartbeat file: after `taskkill /F` on the bridge, a directly-spawned server kept running (the `cmd.exe`-wrapped one did not). The test suite hit the same thing and leaked 24 processes per run until teardown was changed to kill the tree. A Job Object with `KILL_ON_JOB_CLOSE` is the proper fix but needs native code; the pure-Node alternative is to record child pids alongside `sessions.json` and, on startup, kill any that survived — guarded by a command-line match, since Windows reuses pids. |

## Shipped
| # | Item | Where |
|---|---|---|
| **B3** | Bridge-side scheduled recycle | per-server `recycleMinutes`, `MCP_RECYCLE_MINUTES` |
| **B3a** | Autostart parity | OS auto-start (`autostart/`) + supervisor + warm pooling |
| **B4** | Retire `vscode-extension/` | removed — see the decision record below |
| **B7** | Concurrency queue | `awaitSlot`, `MCP_QUEUE_TIMEOUT_MS`; over-cap requests queue briefly instead of `503` |
| **B8** | Surface `warm` in the TUI | `WARM` column in `mcp-pacemaker top` |
| **B12** | Config hot-reload | `mcp-pacemaker reload`, `POST /admin/reload`, `MCP_CONFIG_WATCH`; diffed so unchanged servers keep their sessions |
| **B13** | Server health | `health` in `/api/status`, `doctor`, `top` and the dashboard; optional probing via `MCP_HEALTH_INTERVAL_MS` |

---

# Decision record — the editor companion was retired

`vscode-extension/` has been **removed**. This section records why, so the question is not
reopened from scratch.

## What it did

The companion did two independent jobs, and retiring it required parity on **both**:

| Job | What it did | Scope |
|---|---|---|
| **Autostart** | called the editor's "start MCP server" command for each configured id, a few seconds after startup | every bridged server |
| **Recycle** | stop, pause, start on a timer | only servers holding their own interactive token |

**Recycle** existed because some MCP servers hold an interactive OS-broker token acquired once
via a desktop sign-in. The running process cannot re-authenticate headlessly and goes stale after
roughly a day, while a freshly spawned process re-acquires silently from the broker cache. The
only known fix is to force a fresh process on a timer.

A stdio-to-SSE bridge that ties child lifetime to the connection cannot do that alone: the child
dies when the stream closes, so something has to make the *client* drop and reopen — and only
in-editor code could. Hence a companion.

## Why it is no longer needed

**Recycle** moved into the bridge. Because an unknown session id is now transparently
re-established (`resumeSession`), replacing a child no longer disturbs a connected client, so the
bridge recycles on its own timer — headless, and for every host rather than one editor.

**Autostart** turned out to be unnecessary. The companion was written when servers were stdio
children the editor had to spawn and interactively authenticate. Under pacemaker every server is
a remote (`sse` / `http`) entry and the bridge holds the auth, so editors connect lazily on first
tool use. OS auto-start keeps the bridge itself up, and warm pooling absorbs the cold start.

## What was rejected

- **Keeping an autostart-only companion** — proven, but still editor-only and still a sideloaded
  component that does nothing when the editor is closed.
- **Adopting it as a supported optional extra** — turns "retire the companion" into "own the
  companion" permanently.

## Related external issue

Some VS Code builds auto-stop MCP servers after tool discovery
([microsoft/vscode#327970](https://github.com/microsoft/vscode/issues/327970)). While that is
live, any client-side lifetime assumption on VS Code is unreliable — an additional reason the
recycle is server-side rather than driven by the editor.

The companion source is preserved in git history if it is ever needed again.
