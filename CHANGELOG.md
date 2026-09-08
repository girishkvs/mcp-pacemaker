# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-09-08

### Added

- Cumulative per-server process launch, failed launch, warm adoption, new session and resume
  counters. The status snapshot identifies the bridge instance and interval start so process
  churn can be compared without mixing time windows. Latency samples remain capped separately.
- One-click pre-warming controls and conflict-safe Undo, with the requested warm count and
  resident-process cost shown before activation. Pooling policy edits preserve active children.
- A consolidated pre-warming dashboard tab and `mcp-pacemaker prewarm` CLI view, both using
  the same snapshot data. Explicit CLI actions enable, disable or undo one server's settings.
- `mcp-pacemaker logs` reads the durable log and retained rotation with `--follow`, `--since`,
  `--server` and literal `--grep`. Multiline context, partial UTF-8 writes and rotation are
  handled without treating continuation lines as independent server records.
- Opt-in shared stdio children for compatible stateless tools sessions. One real initialization
  serves virtual sessions with owner-scoped IDs, progress, cancellation and cursors, bounded
  queues, idle retention and draining. Unsupported features fail explicitly; uncertain tool
  calls are never replayed. UI and CLI distinguish shared children from uninitialized pools.

### Fixed

- Reserve session capacity before asynchronous startup, preventing queued cold starts from
  overbooking the configured cap. Concurrent resumes of one session share one handshake.
- Bind session lookup and deletion to the requested server. A stale exit or deleted resume
  cannot remove or resurrect a replacement session.
- Distinguish bridge-generated transport errors from identical numeric codes returned by an
  upstream, so a legitimate server response is not mislabeled as a bridge timeout.
- Guard shared JSON before serialization in both directions, including on Node 20, and bound
  combined response sizes. Excessive depth or output produces controlled errors rather than
  crashing the bridge or silently replaying tool calls.
- Identify changed metadata fields when a pooling write is refused by the conflict guard.
- Avoid false Windows pooling conflicts from unrelated timestamp updates while retaining
  audit, integrity-label, permission and file-identity checks. Refuse automatic writes when
  audit policy cannot be verified or preserved.
- Run configuration writes in a bounded, serialized worker so Windows permission inspection
  does not block the bridge's request processing.
- Update the UI build's `browserslist` dependency to 4.28.9 to address its published memory-growth
  and custom-stats advisories.

## [1.2.0] - 2026-09-04

### Added

- **Cold start is measured.** The bridge spawns every child, so it is the only thing positioned
  to know what starting a server actually costs — and it was throwing that away. `/api/status`
  and the dashboard now report p50/p95/max spawn time per server, timed from `spawn()` to the
  server answering `initialize`, because a process existing says nothing about the package
  manager work that follows it. On the author's machine one server measured a 20s cold start
  while the pre-warm pool sat empty and a server that starts in 200ms had a full one.

- **A gate on concurrent cold starts** (`MCP_MAX_CONCURRENT_SPAWNS`, default 2). Servers launched
  through `npx`, `uvx` or `dnx` share one package cache, and starting several at once can corrupt
  it: 17 simultaneous `npx` invocations here produced `npm error code ECOMPROMISED / Lock
  compromised` and failed every one of those sessions. No server definition can fix that — it is
  a property of the concurrency — so the bridge queues cold starts instead. The slot is held
  until the child first speaks, which is when the expensive part is over.

  Only servers that actually use a package manager are gated; a plain `node server.js` shares no
  cache and was never at risk. Detection is from the command, and per-server
  `sharedPackageCache` forces it either way for a wrapper script the heuristic cannot see.
  Waiting for a slot is bounded by `MCP_SPAWN_GATE_WAIT_MS` (15s) — past that the spawn proceeds
  ungated, because a corrupted cache is a risk while a hung client request is a certainty.

- **Pooling advice, never pooling by default.** When a server's measured cold start passes
  `MCP_POOL_ADVICE_MS` (2s), `doctor` and the dashboard name the number and print the exact
  config that would hide it, sized from observed peak concurrency. It is not applied: a warm pool
  costs a resident process per slot, and that is the user's call to make. Cold start is otherwise
  invisible to the person paying for it, who just experiences a slow tool.

- **Pools size themselves once you opt in.** `sharing: "pool"` with no `minWarm` now targets peak
  concurrent sessions over the last hour, capped by `MCP_WARM_MAX` (8). An explicit `minWarm`
  still wins. Defaulting to one warm child is how a burst of 17 sessions ended up paying 16 cold
  starts on a server that was configured to pool.

- **Restart reporting.** `/api/status` carries how long ago the bridge restarted and how many
  clients held a session before it and have not come back; `status` warns and the dashboard shows
  a banner. The bridge re-establishes those sessions correctly, but some clients treat a single
  connection failure as permanent and need an MCP reload — this says who.

- `cappedSessions` alongside `sessions`, so a server's count matches the cap actually enforced.
  The cap counts Streamable HTTP sessions while the display summed those and classic SSE, which
  is how a server showed `33/32`.

### Changed

- **A 401 or 403 only counts against health when the bridge holds the credential.** For a server
  with `auth: {type: none}` the *client* authenticates, so an opening 401 is the handshake
  working as designed. Counting it flipped a healthy server to `failing` every 60 seconds. The
  rule is now the one that matters: failing means the tool actually failed.

- **The bridge's own 503 counts as a failure.** Refusing a session at the concurrency cap is the
  most client-visible failure the bridge produces, and it was invisible to health — an operator
  saw a healthy server while the bridge was the thing saying no.

- A terminated session still answers **404**, per the transport spec, which makes re-initializing
  on 404 a client MUST. An earlier revision of this work returned 410 for sessions known to be
  gone; it reads better to a human and strands a compliant client, since 410 has no defined
  recovery behaviour. The distinction moved to the response body and the log, where a client is
  not allowed to care about it.

### Fixed

- **A warm pool never refilled after a child died on its own.** The exit handler removed the
  corpse and stopped; refill only ran on boot, on take, on recycle and on reload. A pooled server
  that went quiet drained to empty and stayed there, silently degrading to a cold spawn per
  session — the exact failure pooling exists to prevent, and invisible because an empty pool
  looks like one nobody has asked for anything yet. Seen here as one server sitting at `warm: 0`
  for three hours while another with identical config stayed full purely because it was busy.
  Refill now happens on an unattended exit, with backoff so a child that dies instantly cannot
  become a spawn loop.

- **A pooled server counted every failure twice.** A warm child adopted into a session kept the
  pool's exit handler and gained the session's, and both reported the exit — so an identical
  server lost health twice as fast for having been pooled.

- **A pool refilled one child per take,** so a burst that emptied it recovered long after the
  burst was over. Refill now runs toward the target in one pass, bounded by the spawn gate.

- A static `authorization` header did not mark a server as bridge-authenticated, so its 401 read
  as `unknown` forever and its challenge was relayed to a client that could not act on it.

- The health probe no longer calls servers the bridge does not authenticate.

- SSE streams are closed on shutdown instead of dropped. A clean close reads as "reconnect" to a
  client; a dropped TCP connection reads as a transport fault, and some clients latch on that.

- A failed request names the credential source it actually used — `audience X`, `auth.command`,
  or the configured `authorization` header — rather than a generic message.

- `staleClients` counts only clients that were active near the restart. It counted every resume
  record predating the restart, and the resume file holds a day of churn — one polling client
  left hundreds of dead ids, so a restart reported 326 stale clients where there were three.

## [1.1.0] - 2026-09-03

### Added

- **Edit `servers.json` without restarting.** Save the file and the bridge picks it up, or run
  `mcp-pacemaker reload` (also `POST /admin/reload`). The reload is a diff: servers whose
  definition is unchanged keep their processes and their live sessions, so adding one server no
  longer costs an outage on every other one. A file that does not parse, or a server with neither
  `command` nor `url`, is rejected whole — the bridge logs why and keeps serving the last good
  config, so a half-written editor save cannot take anything down. `MCP_CONFIG_WATCH=0` requires
  an explicit reload instead of watching the file.

- **Per-server health.** `/api/status`, `doctor`, `top` and the dashboard now report each server
  as `ok`, `failing` (with a count of consecutive failures), or `unknown`. Previously the only
  signal was `lastError`, which is sticky and only ever accumulates: a server that failed once
  last week looked exactly like one failing right now, and one that had recovered still showed
  the old error. A server here returned 401 on every call for hours while the dashboard showed
  nothing wrong. `unknown` is deliberately distinct from `ok` — a server nobody has called is not
  claimed to be working.

  Health is derived from traffic already being proxied, so it costs nothing. A JSON-RPC error
  *from* a server counts as healthy, because the server answered; a 401/403, a 5xx, a spawn
  failure or a non-zero exit counts as failing.

- **Optional health probing.** `MCP_HEALTH_INTERVAL_MS` (or per-server `healthIntervalMinutes`)
  periodically calls an HTTP server so an idle one gets a verdict before a client needs it —
  a credential that expires overnight is otherwise found by a failed tool call. Off by default,
  since a probe is a real request to somebody else's service. stdio servers are not probed: that
  would mean spawning a process, which costs more than the request it would pre-empt.

- **A durable log.** The bridge writes `bridge.log` alongside its config and rolls it at
  `MCP_LOG_MAX_BYTES` (default 5 MB, keeping one previous file). Set it to `0` to disable.
  Previously the only history was an in-memory buffer served by `/api/logs`, which holds a few
  hundred lines: a client that reconnects every 30 seconds fills that in about two minutes, so
  nothing that happened overnight could be explained the next morning. Redirecting stderr was
  not an alternative, because the supervisor starts the bridge without a redirect. See
  [SECURITY.md](SECURITY.md) for what the file does and does not contain.

### Fixed

Everything since 1.0.0, including two defects that combined to send a client to the browser to
sign in repeatedly, for a server it was never responsible for authenticating.

- **A credential is cached for no longer than it is actually valid.** The configured
  `refreshMinutes` was applied as a flat window, but an auth command usually returns a JWT served
  from the provider's own cache — `az account get-access-token`, for instance, hands back a token
  it minted earlier, which can already be most of the way through its life. The bridge then went
  on presenting a dead token for the rest of the window while reporting it as healthy, and every
  request to that server returned 401. A JWT's `exp` claim now bounds the cache entry, a token
  that arrives already expired is not cached at all, and an opaque (non-JWT) credential still
  falls back to `refreshMinutes`.

- **An upstream 401 is no longer turned into a login prompt for a server the bridge
  authenticates.** The challenge was relayed for every proxied server, so when the bridge's own
  credential was refused, the client was told to authenticate — a login it cannot win, because
  the bridge overwrites whatever token the client returns with its own on the next request. The
  effect was a client sent back to the browser to sign in over and over, for a server it was
  never responsible for authenticating. A 401 on a server with `audience` or `auth.command` is
  now reported as the bridge-side failure it is (`lastError`, plus a log line), the rejected
  credential is discarded rather than served for the rest of its window, and no challenge is
  passed on. Servers with `auth: none`, where the client really is the one authenticating, are
  unchanged.

- **A bare `audience` is expanded into its token command in exactly one place.** The expansion
  was duplicated, and the expanded string doubles as the token cache key, so the two copies
  drifting apart would have minted under one key and looked it up under another — silently
  disabling the cache.

- **The session retention window is now enforced while the bridge runs**, not only when
  `sessions.json` is read at startup. A bridge left running for days kept accepting session ids
  well past `MCP_RESUME_TTL_MS` and kept rewriting them to disk, so the file grew without bound
  — on a bridge up for 28 hours, records 45 hours old were still being honoured under a 24-hour
  window. Expired records are now refused at resume time and dropped as the file is written.

- **A server named after one of the bridge's own routes is now reported.** `api`, `admin`, `ui`,
  `status` and `.well-known` are answered by the bridge before it consults the server table, so a
  server with one of those names was unreachable and nothing said so — the client simply got the
  bridge's own reply. `doctor` and the dashboard Health page now flag it.

- **A crash keeps its own error message.** When a server exited and the in-flight request then
  timed out, the generic timeout overwrote the exit code and stderr tail that explained why —
  replacing the cause with the symptom. A timeout is now only recorded while the child is still
  alive.

- **A scheduled recycle added by a config edit now takes effect.** The recycle interval was
  computed once at startup from the servers that had `recycleMinutes` then, so a server given one
  later would never be recycled. The schedule is rebuilt on every reload.

### Internal

Changes that affect contributors rather than users.

- **The test suite leaked 24 processes per run.** Tests tore the bridge down with `child.kill()`,
  which on Windows is `TerminateProcess` — the bridge's `SIGTERM` handler never ran, so every
  server child it had spawned was orphaned. Running the suite a few times inside the fixture's
  120s self-destruct window loaded the machine enough that teardown elsewhere missed its
  deadline, which surfaced as an intermittent failure in the kill-tree test that looked unrelated.
  Tests now tear down the whole process tree via `test/helpers/kill-bridge.mjs`; the leak is zero
  and the suite passes 8 consecutive runs.

- **The suite checks itself.** `npm test` names its files explicitly, which is portable across
  the Node versions in CI but drifts silently — two new test files were written, passed when run
  directly, and did not run under `npm test` at all. `test/suite-integrity.test.mjs` now fails if
  a test file is missing from the list, if the list names a file that no longer exists, or if two
  files claim the same port.

- The `stubborn-mcp-server` test fixture deliberately outlives its stdin closing, and its
  self-destruct timer was scoped to the `--heartbeat` flag. Fixtures spawned without that flag
  therefore survived the run and accumulated across runs. The timer is now unconditional.
- The test port allocation, recorded at the top of `test/auth-token.test.mjs`, had drifted from
  the assignments actually in use. It has been rebuilt from real usage and now lists every file.
  A duplicated port fails only under the parallel suite and only intermittently, so the note is
  worth keeping accurate.

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

[1.2.0]: https://github.com/girishkvs/mcp-pacemaker/releases/tag/v1.2.0
[1.1.0]: https://github.com/girishkvs/mcp-pacemaker/releases/tag/v1.1.0
[1.0.0]: https://github.com/girishkvs/mcp-pacemaker/releases/tag/v1.0.0
