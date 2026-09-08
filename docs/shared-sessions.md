# Shared stdio sessions

Status: 1.3.0 implementation contract; not a claim that every server is compatible.

## Configuration

Add `"sharing": "shared"` to a stdio definition only after confirming the profile below.
Use `/<name>/mcp`: classic SSE endpoints explicitly reject shared mode.
Pooling buttons never enable shared mode or replace an existing shared policy.

| Setting | Default | Purpose |
|---|---|---|
| `sharedLingerMs` | 1800000 | Keep the initialized child between compatible sessions. |
| `sharedDrainTimeoutMs` | 30000 | Maximum drain time before terminating unresolved work. |
| `sharedRetryDelayMs` | 1000 | Backoff after a failed generation. |
| `sharedMaxSessions` | 128 | Virtual members plus joining clients per group. |
| `sharedMaxInFlight` | 8 | Dispatched operations per child. |
| `sharedMaxQueued` | 32 | Unsent operations waiting for dispatch. |
| `sharedMaxIds` | 4096 | Retained request IDs per virtual session. |
| `sharedMaxCursors` | 256 | Retained tools-list cursors per virtual session. |
| `sharedMaxLineBytes` | 1048576 | Maximum JSON-line size, including translated fields. |
| `sharedMaxBufferBytes` | 4194304 | Maximum buffered protocol data per stream. |

All settings require bounded integers; invalid values fail explicitly. The bridge's existing
session cap and request/initialization timeouts also apply. A slot is reserved before waiting
for shared initialization or the spawn gate. Concurrent resumes of one external session ID
share one handshake.
Client and upstream JSON have a maximum depth of 64, counting the root as depth 0.
An upstream depth violation terminates its generation with explicit failure metadata,
not an uncaught serializer exception; no business call is replayed.

## Purpose and approval

`sharing: "shared"` reuses one initialized stdio child across compatible virtual HTTP sessions.
This differs from `pool`: a pooled child is uninitialized and belongs exclusively to its first
session. Both modes remain opt-in. No latency recommendation enables either mode automatically.

Shared mode is for a stateless-tools profile: tools operate on explicit inputs, the configured
credential context is common, and the server has no implicit per-client workspace, conversation,
account or subscription state. Enabling the mode asserts that profile. Matching capabilities
alone does not prove the implementation is stateless.

The default remains `isolated`. Unsupported clients receive a clear compatibility error before
their business request is dispatched. There is no silent sharing downgrade, guessed callback
recipient, or automatic replay on another process.

## Compatibility and initialization

One group per configured server and configuration generation is allowed. Its compatibility key
contains the complete, canonically ordered initialization parameters and configuration. Preserve
array order, absent properties and all client identity fields. The JSON-RPC request ID is not
part of the initialization parameters.

For the first profile:

- Support released protocol versions `2025-03-26`, `2025-06-18` and `2025-11-25`.
- Require empty client capabilities. Roots, sampling, elicitation, tasks and unknown extensions
  cannot safely be routed from an arbitrary stdio callback to an individual client.
- Support `tools/list`, `tools/call` and `ping`.
- Reject stateful protocol methods, subscriptions, logging changes and task-augmented calls.
- Do not interpret arbitrary tool argument/result fields as request IDs or state handles.
- Bind tools-list cursors to their originating virtual session and child generation.
- Retain the actual upstream protocol version, instructions and implementation metadata.
  The upstream may negotiate any of the three supported versions.
- Expose only the upstream's actual `tools` capability, without inventing flags. This
  explicitly tools-only surface does not advertise optional prompts, resources, logging,
  completions or tasks even if the upstream supports them. An empty `experimental` object
  is harmless; unknown or nonempty experimental extensions are incompatible.

Concurrent compatible arrivals share a creation promise installed before awaiting process
creation. Exactly one upstream `initialize` and one `notifications/initialized` are sent.
Each virtual session receives the result with its own request ID and must complete its own
initialized notification before dispatching tools.

An incompatible client does not replace or disturb the established group. Failed initialization
fails all waiters, removes the failed creation promise, and terminates the candidate. A later
attempt may start a new group with bounded retry behavior.

## Routing

Use distinct typed keys: integer `1` and string `"1"` are different client IDs.

| Message | Required behavior |
|---|---|
| Client request | Translate to a generation-unique upstream ID and retain owner plus original ID. |
| Child response | Deliver only to its mapped owner, restoring the original ID. |
| Client progress token | Translate only `_meta.progressToken`; restore it on the owner's progress notifications. |
| Client cancellation | Translate only that session's request ID. Never cancel another client's request. |
| Child `ping` | Answer as the bridge peer. It is not a response even if its ID matches an operation. |
| Other child requests | Reject explicitly; never select the first/recent client or broadcast callbacks. |
| Tools-list changes | Fan out to members only when the common catalog contract permits it. |
| Other notifications | Drop unowned logs and unexposed catalog changes with diagnostics. Never broadcast their data; reject unknown extensions. |

Classify messages by category (`method`, `result`, `error`) before consulting ID maps. Unknown
or late responses must not become notifications. Progress associated with a POST must be
delivered on its originating POST stream; an unrelated GET stream is not a replacement.

Bound operations, queued work, input lines, retained IDs/cursors and stream buffers. Reject
overflow explicitly instead of allocating without limit or silently truncating protocol data.

## Virtual child adapter

`bin/shared-sessions.mjs` exports `SharedSessionManager`. It takes:

```js
{
  spawn: async (name, definition) => actualChild,
  kill: (actualChild) => {},
  onFailure: (name, detail) => {},
  onInitialized: (name, elapsedMs) => {},
  onResponse: (name) => {},
  log: (name, text) => {},
  initTimeoutMs,
  requestTimeoutMs
}
```

`await manager.acquire(name, definition, initializeParams)` returns an EventEmitter-compatible
virtual child with `stdin` accepting newline-delimited JSON-RPC, readable `stdout`, the actual
group `pid`, `exitCode`, `signalCode`, `__spawnedAt`, `__sharedSession: true`, and `detach()`.
It plugs into the existing Streamable HTTP per-session response parser without spawning again.
One actual child owns one stdout parser; virtual stdout contains only that session's messages.
For already-parsed HTTP JSON, use `child.writeMessage(message)`. It applies the same input,
depth, ID and ownership guards before serialization. Calling it after detachment throws an
explicit `SHARED_DETACHED` admission error instead of leaving a request waiting indefinitely.

The bridge's process-kill helper must detect a virtual child and detach it instead of killing
its shared PID. Actual group creation goes through the existing spawn gate and B21 counter.
Virtual session attachment is not an OS spawn or a cold-initialization sample.
`onResponse` reports actual upstream responses, not locally generated rejections. Health must
not classify errors by a numeric JSON-RPC code that an upstream can also legitimately use.

Provide `recycle(name)`, `remove(name)`, `shutdown()` and `inspect(name)` methods. Inspection
exposes only lifecycle facts such as generation, state, members and unresolved operations.

## Lifetime, drain and credentials

Deleting one session forgets and tombstones only that session. Remove its unsent work and send
owner-scoped cancellation for dispatched work. Other clients and their operations remain alive.
The actual child lingers between compatible sessions, bounded by `sharedLingerMs` (default
30 minutes). Unresolved work prevents idle eviction.

Cancellation is not proof that execution stopped. Retain execution ownership until the
response arrives or a bounded failure/drain policy terminates the generation.

Recycling marks the generation draining and stops new dispatch to it. Existing work gets a
bounded opportunity to finish; once drained, terminate promptly rather than waiting for the
next full recycle interval. A drain deadline fails unresolved work explicitly as potentially
executed, terminates that generation, and permits a later fresh generation. Never replay those
business calls. Fence old exit handlers and timers so they cannot delete a replacement.

The server retains its existing credential mechanism. The bridge does not freeze a token in
the shared initialization, infer renewal from a generic cache, or substitute an auth provider.
Keep configured credential recycling. A synthetic short-expiry test must show: expired call
fails unchanged; draining/replacement creates a fresh generation; a new call succeeds; the
failed call was dispatched once. Real provider renewal still requires its own canary.

Resume reattaches only compatible stateless sessions. It is not restoration of arbitrary
application state and does not preserve TCP connections across a bridge restart; that is B14.

## Acceptance gates

1. More than fifty compatible initialize/DELETE cycles reuse one actual child and one upstream
   initialization. Two simultaneously active sessions must also share that same generation.
2. Concurrent numeric/string ID collisions, out-of-order results, progress and cancellation
   route to the correct owner. Forged or late messages cannot cross sessions.
3. Delete one client while another works, kill a child during a request, and recycle while busy.
   Pending callers fail promptly and dispatched tool calls are never replayed.
4. Incompatible initialization and unsupported callbacks/methods fail explicitly. Isolation
   defaults and existing HTTP proxy behavior remain unchanged.
5. Counter deltas for identical isolated and shared workloads show actual reduced launches,
   not merely fewer latency samples or a lower instant process count.
6. Use an isolated config directory and spare port for real-server and browser/CLI canaries.
   Do not alter another project's client or orchestration configuration.

Reference: released MCP
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[progress](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress), and
[cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation).
Draft transport changes are not applied to clients speaking released versions.
