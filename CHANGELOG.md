# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-30

First public release. It starts at 1.0.0 rather than 0.x because the bridge, its config format
and its HTTP surface have been running a real 15-server setup daily rather than only a test
suite, and the items below are the defects that shook out of that. Treating the config schema and
the `/<name>/mcp` endpoints as a stable contract from the first tag is honest about that, and
means later changes to them have to be versioned properly.

### Added

- **Bridge** (`mcp-bridge`): a zero-dependency local HTTP endpoint that keeps MCP servers
  running independently of any editor or CLI. stdio servers are exposed over both SSE
  (`/<name>/sse`) and Streamable HTTP (`/<name>/mcp`); remote servers are reverse-proxied at
  `/<name>` with credentials injected.
- **Setup CLI** (`mcp-pacemaker`): `init` detects installed MCP hosts, imports their servers,
  wires them to the bridge, registers auto-start and starts it. `import`, `plan`, `install`,
  `emit`, `upgrade`, `status`, `doctor`, `start`, `stop` and `uninstall` cover the rest of the
  lifecycle. Every config write is backed up first, and `plan` is a dry run.
- **Host adapters**: VS Code, Cursor, Claude Desktop, Copilot CLI, Gemini CLI, Codex CLI and
  Claude Code, each written in that host's own config format and location.
- **Pluggable auth**: `command` (e.g. `az account get-access-token`), `env`, `static` and
  `none`, with a per-key token cache and configurable refresh window.
- **Auto-start and supervision**: a per-user scheduled task on Windows (logon plus workstation
  unlock, no admin required) and a supervisor that restarts the bridge if it exits. A bridge
  started against a port another pacemaker already serves adopts it and exits cleanly instead
  of thrashing.
- **Dashboards**: a web UI at `/ui` and a live terminal UI via `mcp-pacemaker top`, both
  showing sessions, warm pool, token expiry and recent events. The web dashboard streams over
  SSE and can recycle a server; its `Health` tab runs the same checks as `doctor`.
- **HTTP API**: everything the dashboards show is plain JSON on the same loopback port —
  `/status`, `/api/status`, `/api/doctor`, and the `/api/events` + `/api/logs` SSE streams.
  `POST /admin/recycle/<name>` restarts a server and is guarded by loopback plus a per-start
  nonce written next to the config.
- **Session controls**: warm pooling, `maxSessions` caps, idle reaping and per-server recycle.
  Idle reaping frees the server process without ending the client's session — a client that comes
  back is served transparently against a freshly started server.
- **Resumable sessions**: a client's session id survives the bridge restarting, a recycle, or an
  idle reap. The bridge records the client's `initialize` and replays it against a fresh server
  process, so the client keeps using the id it already holds. Disable with `MCP_RESUME=0`; the
  retention window is `MCP_RESUME_TTL_MS` (default 24h). An explicit `DELETE` is final.
- **Scheduled recycle**: per-server `recycleMinutes` (or `MCP_RECYCLE_MINUTES`) restarts servers
  that hold a credential they can only refresh interactively. Because a recycle is now invisible
  to connected clients, the bridge does this itself rather than needing an editor extension.
- **Timeouts**: `MCP_REQUEST_TIMEOUT_MS` (default 30s) for ordinary calls, and a separate
  `MCP_INIT_TIMEOUT_MS` (default 180s) for `initialize`, which also pays for spawning the server.
- **Proactive credential refresh**: a cached token is renewed shortly before it expires
  (`MCP_TOKEN_REFRESH_LEAD_MS`, default 5 minutes) instead of the expiry being discovered by a
  request. Only credentials already in use are refreshed.
- **OAuth pass-through for proxied servers**: the bridge answers
  `/.well-known/oauth-protected-resource/<name>` from the upstream, so a client authenticating
  against the bridge can discover where to log in. The `resource` field is rewritten to the
  bridge's own URL for that server, because RFC 9728 has the client check it against the URL it
  is addressing and reject a document that names anything else; a 401 challenge is rewritten the
  same way so it points at the bridge's copy. `authorization_servers` and `scopes_supported` are
  relayed untouched, and those are what determine the audience, so the token stays valid for the
  upstream behind the bridge.
- **Queue at the concurrency cap**: at `maxSessions`, a new session waits briefly
  (`MCP_QUEUE_TIMEOUT_MS`, default 10s) for a slot before being refused, so a burst is absorbed
  rather than failed outright.

### Hardening

There is nothing to fix relative to a previous release, but the following were found and fixed
by running this against a live 15-server setup before publishing. They are recorded because each
one is a trap for anyone building something similar.

- Tear down the whole process tree on Windows. Bare commands (`npx`, `uvx`, and `.cmd` shims)
  spawn under a `cmd.exe` wrapper, so `child.kill()` signalled only the wrapper and left the
  real server orphaned on every recycle, idle reap, session close and shutdown. The orphans
  also held their tokens, so a recycle could leave two servers competing.
- Hold keep-alive sockets open past Node's 5 second default. A client busy across that window
  never processes the server's `FIN`, so the socket stayed pooled and the next request failed
  with `ECONNRESET`.
- Never cache an empty auth-command result. A token tool can exit 0 while printing nothing;
  caching that served an empty credential for the full refresh window, so every upstream
  request returned 401 until it expired.
- Mint one token per key. On startup every server requested its token at once and each spawned
  its own token process, which is what made those concurrent calls return nothing.
- Run auth commands through a shell so quoted arguments survive. Constructing `cmd /c <command>`
  by hand re-escaped embedded quotes and broke any command quoting a path with spaces.
- Wire VS Code over Streamable HTTP instead of SSE, the transport behind `-32001` reconnect
  failures.
- Rewrite an existing entry in place when a host already lists a bridged server under a
  different key, instead of adding a duplicate registration of the same server.
- Report warnings in the `doctor` summary rather than printing `all good.` beneath them.
- Resolve a server's relative command and arguments against a working directory it carries in
  its own config, instead of depending on how the bridge was launched. A server defined as
  `node .vscode/mcp/<name>/index.js` failed with `MODULE_NOT_FOUND` whenever the bridge started
  without the matching `--cwd`.
- Report a server that starts and then exits non-zero, including the tail of its stderr.
  `lastError` was only set when the process failed to spawn, so a server crashing on startup
  left `/api/status` and `doctor` looking healthy while every session died.
- Give `initialize` its own timeout. Sharing the 30s call timeout meant a server whose first run
  downloads itself returned `-32001 upstream timeout` and appeared broken.
- Reap idle sessions by default (`MCP_IDLE_TIMEOUT_MS`, 30 minutes). Clients are not obliged to
  send `DELETE` and some never do; one observed client opened a session per run and left 241
  server processes running within an hour. Reaping is safe because a returning client's session
  is transparently re-established.
- Do not let a killed child's late `exit` event delete the session that replaced it. `taskkill /F
  /T` takes about a second on Windows, so a client returning inside that window was resumed onto
  a fresh server and then silently dropped when the old exit finally arrived — the failure that
  session resume exists to prevent. The mapping is now torn down only if it still points at the
  child that exited.
- Do not reap a session that has a request in flight, and measure the idle clock from when a
  request finished rather than when it started. A call slower than the idle timeout previously
  had its server killed underneath it, leaving the caller waiting for a reply that could never
  arrive.
- Report a server whose relative script path cannot resolve. `doctor` and the dashboard health
  page now flag a stdio server whose arguments name a path that does not exist from the directory
  it would run in, and warn when a relative path is used with no `cwd` at all. This failure was
  otherwise silent: the server was listed as configured and only died when a client first called
  it. Package specs passed to a runner (`npx @scope/pkg`) are not mistaken for paths.
- Strip hop-by-hop headers from proxied responses (RFC 9110 §7.6.1). A header the upstream named
  in its own `Connection` header, or a `trailer` it announced, is connection-scoped and was being
  relayed to the client, where it is meaningless or misleading.
- Do not report a teardown the bridge initiated as a crash. `taskkill /F` exits non-zero, so
  every recycle, idle reap and session close was recorded as a failure, burying real ones.

[1.0.0]: https://github.com/girishkvs/mcp-pacemaker/releases/tag/v1.0.0
