# mcp-pacemaker — roadmap

Tracks the work to make pacemaker wire *any* MCP host (editors **and** CLIs), support
one-shared-bridge **and** bridge-per-host topologies, and serve multiple concurrent agents
efficiently.

## 2.0.0 pooling compatibility gate

Permanent CI gates cover only **1.3.0 ↔ 2.0.0** with immutable 1.3.0 source and the packed
2.0.0 candidate, not mock backends. CLI/API pairs run on Windows/Linux/macOS, Node 20/22;
built dashboard pairs run once on Linux Chromium, including an actual old-tab bridge restart.
See [scope, limitations and local commands](../CONTRIBUTING.md#real-version-compatibility-gates).
This is not a claim about other minor versions or unfinished-transaction downgrades.

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
  `shared` (one initialized child for compatible stateless tools sessions in 1.3.0).
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

### Version plan
| Release | Contents | State |
|---|---|---|
| **1.1.0** | Active health probing + config hot-reload | shipped |
| **1.2.0** | Cold-start measurement, spawn gate, warm-pool correctness, health semantics, restart reporting | shipped |
| **1.3.0** | **B21** process counters, **B18** safe pooling changes, **B19** one-click controls, **B20** unified pre-warming view in UI/CLI, **B10** logs CLI, **B6** opt-in shared mode | shipped |
| **2.0.0** | Batched configuration saves and whole-batch Undo/Cancel, ordinary-account Windows saves with inherited auditing, patched TOML parser | ready for release |

The 2.0 major version identifies the incompatible pooling-save protocol and completion
semantics. Release gates include actual 1.3.0/2.0.0 client pairing, isolated upgrade and recovery,
safe downgrade after resolving transactions, ordinary-account Windows execution, and the
exact release commit passing the Linux/macOS/Windows CI matrix. Existing 1.3.0 releases and
tags remain unchanged.

`B10` and `B6` were originally slated for 1.2.0. 1.2.0 was taken by unplanned work that came out
of running the live bridge — a pool that had silently stopped refilling, and a cold start nobody
was measuring. Both were worth shipping first; neither was on the plan. Recorded here so the slip
is visible rather than quietly renumbered.

`B6` targets session churn by retaining one initialized process across compatible stateless
sessions. Pooling still launches a separate child per session. Shared-mode savings must be
measured with aligned process-counter deltas and identical workloads, not inferred from
historical session counts or assumed client/server compatibility.

### 1.3.0 delivery gates

All six items belong to this release. Local implementation checkpoints are not separate
releases or permission to publish incremental commits to `main`. Keep one unpublished release
change until the complete scope is ready; tag only after the exact final commit passes the
Linux/macOS/Windows CI matrix.

1. **B21 baseline:** count actual process launches independently of latency samples, including
   warm starts, classic SSE, recycle and resume. Identify each measurement interval. Keep real
   local server data outside the repository and compare deltas from matching intervals.
2. **B18 configuration transaction:** only pooling settings may be changed. Require the existing
   admin nonce, validate limits, back up before writing, preserve unrelated JSON, reject stale
   revisions, and make undo conflict-safe. Apply the edit even with file watching disabled.
3. **B19 one-click control:** show the requested warm count and resident-process cost before
   activation. A click is approval; a recommendation is not. Report failures in the UI.
4. **B20 consolidated view:** show all stdio candidates and already-pooled servers in both the
   dashboard and CLI. Include latency evidence, process totals, current/target warm count,
   eligibility and explicit enable/disable controls. HTTP proxies are not local spawn candidates.
5. **B10 logs:** support `--follow`, `--since`, `--server` and `--grep`, including multiline log
   records and rotation, without losing or duplicating records.
6. **B6 shared mode:** explicit opt-in, compatible initialization and isolated routing of request
   IDs, progress and cancellation. Define unsupported stateful capabilities before dispatch.
   Handle child exit and credential recycling without replaying tool calls whose outcome is
   unknown. Verify both correctness and reduced launches under identical replayed workloads.

Use focused tests at each checkpoint, demonstrate regression tests fail with the relevant fix
removed from an isolated copy, and investigate every new failure before proceeding. Never use
a throwaway bridge with the production config directory: nonce, session and log files are shared
within that directory.

`B14` socket handoff and `B9` OAuth brokerage are separate, unapproved implementation work.

## Feature backlog
| # | Item | Detail |
|---|---|---|
| **B5** | MCP SDK adoption | Replace hand-rolled JSON-RPC framing with the official SDK. |
| **B6** | `shared` sharing mode | 1.3.0 implementation: [bounded stateless-tools profile](shared-sessions.md), explicit activation and no tool replay. |
| **B9** | Bridge-side OAuth broker | For `auth: none` servers whose resource does not pre-authorize the Azure CLI, so no `audience` token can be minted. The bridge would run the OAuth flow itself and share one credential across clients. Adds a callback listener and refresh-token storage to a 24/7 daemon — needs a threat-model review first. |
| **B10** | `mcp-pacemaker logs` | 1.3.0 implementation: durable log reader, follow, filters and rotation handling. |
| **B11** | Reap orphans from a previous instance | On Windows, force-killing the bridge (Task Manager, `Stop-Process -Force`, a hard reboot) terminates it without running its `SIGTERM` shutdown, so **children it spawned can survive indefinitely** — real servers have no self-destruct, and they hold their ports and credentials. Measured directly with a heartbeat file: after `taskkill /F` on the bridge, a directly-spawned server kept running (the `cmd.exe`-wrapped one did not). The test suite hit the same thing and leaked 24 processes per run until teardown was changed to kill the tree. A Job Object with `KILL_ON_JOB_CLOSE` is the proper fix but needs native code; the pure-Node alternative is to record child pids alongside `sessions.json` and, on startup, kill any that survived — guarded by a command-line match, since Windows reuses pids. |
| **B14** | Zero-downtime restart (socket handoff) | See below. The one remaining reason a bridge restart is visible to a user. |

### B14 — zero-downtime restart via socket handoff

**Problem.** Session *state* already survives a restart: `sessions.json` plus resume means a client
that keeps using its session id is re-established on a fresh child. What does not survive is the
**connection**. The listening socket dies with the process, so every client gets `ECONNREFUSED`
for the restart window. Some clients — `rmcp`, and Copilot CLI through it — treat a single
connection failure as permanent: they never retry, never resume with `Last-Event-ID`, and never
re-initialize, so the server is dead to them for the life of the session even though the bridge
is healthy seconds later. Restarting for the 1.2.0 upgrade wedged **13 sessions across 3 agents**,
all of which needed a manual MCP reload.

Nothing in the transport spec fixes this: the only recovery path it defines is a client
re-initializing after HTTP 404, and a client that has stopped making requests never sees one.
So the bridge has to stop dropping the socket.

**Mechanism.** Hand the listening socket to the replacement process so the port never stops
accepting.

1. The old process spawns the new one with an IPC channel and sends the live handle
   (`child.send('server', server)`) — the same primitive `cluster` uses. It works on Windows too;
   Node duplicates the socket with `WSADuplicateSocket` underneath.
2. The new process finishes **all** startup first — config parsed, resumable sessions loaded,
   warm pools filled — and only then begins accepting. Accepting before it is ready just moves
   the failure rather than removing it.
3. The old process stops accepting, drains in-flight requests, closes its SSE streams cleanly,
   and exits. Exactly one process accepts at any moment; the handover point is a single explicit
   message, not a race.

**Server children do not transfer.** Their stdio pipes belong to the old process and cannot be
meaningfully passed. They die with it, and each affected session is re-established on a fresh
child by the existing resume path. That is a real cost now that it is measured — 2-7s per server
on this machine — which is why the warm pool had to be correct first: the replacement pays a warm
adoption, not a cold start.

**Prerequisites,** all shipped: session resume (1.0.0), warm-pool refill correctness and the
spawn gate (1.2.0), clean SSE close on shutdown (1.2.0).

**Open questions.** Whether the supervisor or the old bridge owns spawning the successor; how a
failed handover rolls back without leaving the port unowned; whether a client mid-SSE-stream sees
the switch at all.

**Validation.** Restart under live load and assert zero connection refusals, zero client reloads
needed, and every pre-restart session id still served afterwards.

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
| **B15** | Cold-start measurement + pooling advice | p50/p95/max spawn time per server in `/api/status` and the dashboard; `doctor` recommends `sharing`/`minWarm` sized from observed concurrency. Advice only — pooling is never enabled automatically, since a warm pool costs a resident process per slot |
| **B16** | Cold-start concurrency gate | `MCP_MAX_CONCURRENT_SPAWNS`; package-manager-backed servers share one cache and corrupted it when started together (`npm error code ECOMPROMISED` from 17 simultaneous `npx` invocations) |
| **B17** | Warm-pool correctness | Refill after an unattended child exit (a pool could drain to empty and stay there), refill toward target in one pass instead of one child per take, and stop double-counting failures for pooled servers |

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
