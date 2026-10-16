# Commands and operations

Every command, how start and stop behave, durable logs and server health. The
[README](../README.md) covers setup and everyday use.

## Command reference

| Command | What it does |
|---|---|
| `init [--from source] [--client a,b] [--yes]` | Interactive setup: import one source, wire selected hosts, auto-start, launch |
| `status` | Bridges, wired hosts, servers, and any server currently failing |
| `reload` | Re-read `servers.json` into the running bridge without restarting it |
| `doctor` | Diagnose config, bridge reachability, host wiring |
| `prewarm [--port N] [--json]` | One view of stdio candidates, pools, shared-child state and measured process starts |
| `prewarm --enable <server> [--count N]` | Explicitly enable warm slots; `--disable <server>` turns them off |
| `logs [--follow] [--since 2h] [--server name] [--grep text]` | Read and filter durable logs, including retained rotation |
| `top` / `dashboard` | Live terminal UI / web dashboard |
| `plan --client <host>` | Dry run — show exactly what `install` would change |
| `import --from <source>` | Build `~/.mcp-pacemaker/servers.json` from one supported JSON host config |
| `install --client <host> [--port N]` | Wire one host (its own `--port` gives it its own bridge) |
| `emit --client <host>` | Print the config entries without writing anything |
| `start` / `stop` | Start or stop bridges (`--port` for one, else all) |
| `upgrade --to <version> [--plan] [--yes]` | Stage and replace one managed installation, including its CLI, preserving port/config/host wiring |
| `upgrade --to <version> --sxs [--port N]` | Keep the old instance and start an isolated new one; omitted port is OS-assigned |
| `upgrade --recover` | Resume or roll back an interrupted managed replacement from its durable journal |
| `upgrade --fix-legacy-access [--plan] [--yes]` | Administrator terminal, Windows: one-time fix for a 1.3 install set up as administrator; changes only that task's run-as user entry and the owner of its `bin\cli.mjs` |
| `[--instance <directory>]` | Select one installation when discovery finds several; valid before or after the command |
| `upgrade [--self]` | Legacy host repair; `--self` still prints same-major installation guidance only |
| `update-check [--json]` | Compare the installed version with its maintained npm channel |
| `uninstall` | Stop managed bridges, remove auto-start, restore available host-file `.bak` copies; native entries are not restored |

> Package installation alone does not upgrade a running backend. Use explicit `upgrade --to`
> for managed replacement. Bare `upgrade` retains the older host-repair behavior.

> On start, pacemaker **probes the port**: it *adopts* an existing pacemaker bridge and *refuses to collide* with a foreign service (the wizard offers another port).

For a supervisor created by these patch releases, `stop --port N` verifies the matching
installation/configuration identity, waits for shutdown, and holds managed autostart until an
explicit `start --port N`. Normal OS shutdown does not create that hold. Use the matching
installation's CLI. Older or directly launched bridges have no managed stop record and are
refused rather than reported as stopped; disable their OS autostart and verify shutdown first.

On Linux/macOS the control socket lives beside the configuration, independent of `TMPDIR`.
Its complete path must fit within 103 UTF-8 bytes. `install` and `init` check this before
changing configuration or autostart; use a shorter configuration location rather than
relying on an implicit socket-location fallback.

Isolated and pooled stdio servers support HTTP+SSE (`/<name>/sse`) and Streamable HTTP
(`/<name>/mcp`). Shared mode requires Streamable HTTP.

Host-file `.bak` backups and what `uninstall` restores are described under
[Uninstall](../README.md#uninstall) in the README. Managed upgrades, `--sxs` and `--instance`
are described in [upgrades and rollback](upgrades.md).

## Reading durable logs

```sh
mcp-pacemaker logs --since 2h --server filesystem
mcp-pacemaker logs --follow --grep timeout
mcp-pacemaker logs --config /path/to/servers.json --since 2026-09-07T12:00:00Z
```

`logs` reads `bridge.log.1` then `bridge.log` beside the selected config, including when
the bridge is stopped. `--since` accepts durations in seconds/minutes/hours/days or an ISO
timestamp with timezone. `--server` matches the exact log-header server name; `--grep` is
a case-insensitive literal match, not a regular expression. Matching multiline records retain
their header and context.

`--follow` handles complete new lines, split UTF-8 writes, truncation and rollover until
interrupted. It warns if rotation has already discarded an unread generation. Only retained
history is available; it cannot recover logs the bridge has deleted. Individual lines over
1 MiB fail explicitly rather than being silently truncated.

## Server health

Every server carries a health verdict in `/api/status`, `doctor`, `top` and the dashboard:

| State | Meaning |
|---|---|
| `ok` | The last request to this server succeeded |
| `failing` | Recent requests are failing, with a count of how many in a row |
| `unknown` | Nothing has called it yet |

This is passive and free — it is derived from traffic the bridge is already proxying. A JSON-RPC
error *from* the server counts as healthy (it answered); a 401/403, a 5xx, a spawn failure or a
non-zero exit counts as failing, and the state clears the moment a request succeeds again.

A server nobody calls stays `unknown` forever, which is honest but not much help if its credential
quietly expires overnight. `MCP_HEALTH_INTERVAL_MS` adds a periodic probe for HTTP servers so they
get a verdict without waiting for a client:

```bash
MCP_HEALTH_INTERVAL_MS=300000 mcp-pacemaker start    # probe every 5 minutes
```

It is off by default because a probe is a real request to somebody else's service. Set
`"healthIntervalMinutes": 0` on a server to exclude just that one, or a number to give it its own
interval. stdio servers are not probed: a probe would mean spawning a process, which costs more
than the request it is meant to pre-empt.
