# HTTP API

Everything the dashboards show is plain HTTP on the same loopback port, so you can script it.
Read endpoints need no auth; administrative writes require a nonce.

| Endpoint | Method | Returns |
|---|---|---|
| `/status` | GET | Tiny liveness probe: `ok`, `service`, `version`, `port` and the server names. Used to tell a pacemaker bridge apart from a foreign service on the same port |
| `/api/status` | GET | Full snapshot — every server with sessions, pids, warm count, request count, `health`, `lastError`, connected clients |
| `/api/doctor` | GET | The health checks, as JSON |
| `/api/events` | GET (SSE) | The same snapshot pushed every 2s — what the dashboard consumes |
| `/api/logs` | GET (SSE) | Bridge log: replays the last 100 lines, then streams. For anything older, read `bridge.log` next to your config |
| `/admin/recycle/<name>` | POST | Restart a server's processes. Omit `<name>` to recycle everything |
| `/admin/reload` | POST | Flush a pending configuration batch, or re-read an externally edited `servers.json`. Only changed definitions are reconfigured |
| `/admin/servers/<name>/pooling` | POST | Stage enable/disable or batch cancel/undo with admin nonce, bounded input and a matching config revision |
| `/<name>/mcp` | POST/GET/DELETE | Streamable HTTP transport for that server |
| `/<name>/sse` | GET | HTTP+SSE transport for that server |
| `/.well-known/oauth-protected-resource/<name>` | GET | OAuth discovery relayed from the upstream, for HTTP servers where the client authenticates |

Pooling mutations require `x-mcp-pooling-batch: 1`. A staged change returns **HTTP 202** with
`pending: true`, a batch ID, a private cancel/undo receipt, and the public snapshot. Acceptance
is not activation. `prewarm.batches` in the snapshot reports bounded pending, applying and
completed outcomes; it does not expose receipt tokens or full configurations.
Clients without the batch header are rejected before a change is queued, rather than letting
an older client report a queued save as already enabled.
Rich snapshots carry an instance-scoped `snapshotVersion` so a delayed HTTP response or older
SSE frame cannot replace newer active settings or prematurely expire a batch receipt.

```bash
# is a server actually running, and who is using it?
curl -s http://127.0.0.1:8850/api/status | jq '.servers[] | {name, sessions, pids, clients}'

# watch the bridge log
curl -N http://127.0.0.1:8850/api/logs

# force a restart of one server (nonce is written next to servers.json)
curl -X POST http://127.0.0.1:8850/admin/recycle/filesystem \
  -H "x-mcp-nonce: $(cat ~/.mcp-pacemaker/admin.nonce)"
```

`/admin/*` is guarded twice: the request must arrive on loopback, **and** carry the nonce that the
bridge writes to `admin.nonce` next to your config at startup. The nonce is new on every start, so
only same-box tooling that can read that file — the CLI, and the dashboard the bridge itself
served — can change anything.

The [dashboards](dashboards.md) use these same endpoints. Custom clients written for 1.3.0 need
the changes in [upgrading from 1.3.0](compatibility.md#upgrading-from-130).
