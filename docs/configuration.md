# Configuration

How to define servers in `servers.json`, how live edits are applied, and the controls for
sessions, resources and sharing.

## servers.json

Config lives at `~/.mcp-pacemaker/servers.json`. `import` fills it from your existing client
config and **carries over `audience`/`auth`/`headers`**, so HTTP servers usually need no hand-editing.
See [`examples/servers.example.json`](../examples/servers.example.json).

```jsonc
{
  "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."] },

  "my-api": {
    "type": "http",
    "url": "https://my-service.example.com/mcp",
    "auth": { "type": "command", "command": "my-cli print-token", "refreshMinutes": 50 }
  }
}
```

**Auth options** (per HTTP server):

| `auth.type` | Behavior |
|---|---|
| `command` | Runs any command that prints a token on stdout; the result is cached and auto-refreshed (`refreshMinutes`). Provider-agnostic — see below. |
| `env` | Uses `process.env[var]`. |
| `static` | Fixed `header` + `value`. |
| `none` | No header is added — the **client** authenticates, and the bridge relays OAuth discovery and challenges for it. |

`auth.type: "command"` is deliberately just "run this and use what it prints", so it works with
whatever issues tokens in your environment. Some examples — none of these are special-cased:

```jsonc
// Azure
{ "type": "command", "command": "az account get-access-token --resource api://<id> --query accessToken -o tsv" }
// Google Cloud
{ "type": "command", "command": "gcloud auth print-access-token" }
// AWS (e.g. a signed token from your own helper)
{ "type": "command", "command": "aws-token-helper --profile prod" }
// HashiCorp Vault
{ "type": "command", "command": "vault read -field=token secret/my-api" }
// 1Password / any secret manager
{ "type": "command", "command": "op read op://vault/my-api/token" }
// A plain script
{ "type": "command", "command": "./scripts/get-token.sh" }
```

By default the token is sent as `Authorization: Bearer <token>`; set `header` to send it
somewhere else (for example `{ "header": "X-Api-Key" }`).

**How long a credential is cached.** If the command returns a JWT, its `exp` claim decides —
`refreshMinutes` is only an upper bound and a fallback for opaque credentials. This matters
because token CLIs serve from their own cache: `az account get-access-token` will hand back a
token it minted earlier that may be nearly spent, and trusting a flat window would keep a dead
token in play. If the upstream rejects a credential the bridge supplied, that 401 is reported on
the server (`doctor`, `/api/status` → `lastError`) and the credential is discarded rather than
reused — the client is never asked to log in for a server the bridge authenticates.

> **Azure shorthand.** A bare `"audience": "<res>"` expands to
> `az account get-access-token --resource <res> …`. That is a convenience for Azure users only —
> every other provider uses `auth.command` above.

## Editing servers.json while it runs

Save the file and the bridge picks it up. Servers whose definition did not change are left
completely alone — same processes, same live sessions — so adding one server does not cost you the
fourteen that were already working:

```bash
$ mcp-pacemaker reload           # or just save the file; the bridge watches it
✓ reloaded /Users/you/.mcp-pacemaker/servers.json on :8850
·   added:   postgres
·   changed: github
·   2 session(s) restarted; untouched servers kept theirs
```

A file that does not parse, or a server with neither `command` nor `url`, is **rejected whole** —
the bridge logs why and keeps serving the last good config, so a half-written save cannot take your
servers down. Set `MCP_CONFIG_WATCH=0` to require an explicit `reload` instead of watching.

## Multi-agent & resource controls

Multiple hosts/agents can share one bridge — each gets its own isolated session by default,
and HTTP servers share the cached token across all of them. The dashboard, `top`, and
`mcp-pacemaker status` show **which agents are connected** to each server.

| Control | Env / config | Default | Effect |
|---|---|---|---|
| Idle reaper | `MCP_IDLE_TIMEOUT_MS` | `1800000` (30 min) | free Streamable HTTP children idle past the timeout. Safe by default because a returning client's session is transparently re-established. `0` disables |
| Concurrency cap | `MCP_MAX_SESSIONS_PER_SERVER`, or per-server `maxSessions` | `0` (unlimited) | reject new sessions past the cap (HTTP 503) |
| Queue at the cap | `MCP_QUEUE_TIMEOUT_MS` | `10000` (10s) | at the cap, wait this long for a slot before returning 503, so a burst is absorbed rather than failed. `0` rejects immediately |
| Sharing policy | per-server `sharing` (+ `minWarm`) | `isolated` | `isolated` = one child per session; `pool` pre-starts exclusive children; `shared` reuses one initialized child for compatible stateless tools sessions. Both alternatives require explicit activation |
| Cold-start gate | `MCP_MAX_CONCURRENT_SPAWNS`, `MCP_SPAWN_GATE_WAIT_MS` | `2`, `15000` | how many package-manager-backed servers may cold-start at once. `npx`, `uvx`, `dnx` and friends share one cache, and starting several together can corrupt it — this queues them. Detected from the command, or forced either way with per-server `sharedPackageCache`. Servers that use no package manager are never gated. If no slot frees within the wait, the spawn proceeds ungated rather than hold a client request. `0` disables |
| Pooling advice | `MCP_POOL_ADVICE_MS`, `MCP_WARM_MAX` | 2s, 8 | recommend pooling once a server's measured cold start passes this, and cap the suggested (and auto-sized) pool here. Advice only — the bridge never enables pooling on its own |
| Session resume | `MCP_RESUME`, `MCP_RESUME_TTL_MS` | on, 24h | re-establish a session id the bridge has not seen — after a restart, recycle or idle reap. `MCP_RESUME=0` disables |
| Scheduled recycle | per-server `recycleMinutes`, or `MCP_RECYCLE_MINUTES` | off | restart a server periodically, for servers holding a credential they can only refresh interactively |
| Request timeouts | `MCP_REQUEST_TIMEOUT_MS` / `MCP_INIT_TIMEOUT_MS` | 30s / 180s | `initialize` also pays for spawning the server, so it gets a longer budget than ordinary calls |
| Credential refresh | `MCP_TOKEN_REFRESH_LEAD_MS` | `300000` (5 min) | renew a cached token before it expires instead of discovering the expiry on a request. A JWT's own `exp` still caps how long it is cached |
| Durable log | `MCP_LOG_MAX_BYTES` | `5242880` (5 MB) | `bridge.log` next to your config, rolled to `bridge.log.1` at this size. `0` disables. The dashboard only keeps the last few hundred lines in memory, which a chatty client fills in minutes |
| Config watching | `MCP_CONFIG_WATCH` | on | reload `servers.json` when it is saved. `0` requires an explicit `mcp-pacemaker reload`. Either way, only servers whose definition changed are restarted, and an unparseable file is rejected without disturbing anything |
| Health probing | `MCP_HEALTH_INTERVAL_MS`, or per-server `healthIntervalMinutes` | off | periodically call an HTTP server so it has a health verdict before a client needs it. Passive health from real traffic is always on and costs nothing |

### Measuring process churn

For stdio servers, `/api/status` reports `spawn.total` (successful process launches),
`spawn.attempts`, `spawn.failures`, `spawn.warmAdoptions`, `spawn.sessionStarts`, and
`spawn.sessionResumes`. Launches include classic SSE, Streamable HTTP, warm-pool refill,
and replacements after recycle or resume. Adopting an existing warm child does not count
as another launch. The unit is one bridge-launched process, not all of its descendants.

These cumulative counters do not share the 50-sample latency limit. They reset when the
bridge process restarts; compare snapshots only within the same `instanceId`. `startedAt`
identifies that interval. Save the final snapshot before a planned restart for a before/after
comparison. HTTP-proxied servers have no local process counters (`spawn: null`).

`spawn.samples` and p50/p95/max still describe the latest 50 directly observed, successful
cold initializations, not all launches. Latencies are `null` until observed; a warm child's
idle lifetime is not a cold-start sample. The existing `requests` count covers routed HTTP
requests, not just `tools/call`; do not label it as a tool-call count.

### Shared mode

Set `"sharing": "shared"` on a stdio server only when its tools are stateless, operate on
explicit inputs and use one common credential context. This is an operator assertion, not
something latency or matching capabilities can prove. Leave workspace-, conversation- or
client-account-dependent servers isolated.

Compatible sessions have identical full initialization parameters, including `clientInfo`,
and empty client capabilities. One child receives one real initialization; each virtual session
gets its own IDs, progress, cancellation and tools-list cursors. Only the upstream's actual
tools capability is exposed. Roots, sampling, elicitation, tasks, resource subscriptions and
other stateful methods are not supported. Incompatible clients fail explicitly, without
silently falling back to a different mode.

Deleting one session leaves the others running. The initialized child is retained between
compatible reconnects for up to `sharedLingerMs` (30 minutes by default). Recycle drains work,
then replaces the generation on later use. A timeout or child exit never triggers automatic
replay of a potentially executed tool call.

The server keeps its existing credential provider and configured `recycleMinutes`. Shared
mode does not promise silent credential renewal. The dashboard and `prewarm` CLI show the
actual shared-child state, members, queued work and cumulative process launches.
See [the shared-session contract](shared-sessions.md) for limits and failure semantics.
