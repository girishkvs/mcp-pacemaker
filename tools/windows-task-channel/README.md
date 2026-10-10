# Windows task channel guard

This is a separate, **query-only** boundary for one task-hosted original-account
worker. It does not stop processes, change tokens, impersonate, enable privileges,
register tasks, install accounts, elevate, repair ACLs, or enumerate processes.
The existing same-user legacy broker and modern lifetime helper are unchanged.

## Interface

`bin/windows-task-channel.mjs` verifies the packaged executable hash before **every
role**, then directly starts the helper on private inherited standard streams.
The helper derives and holds its actual parent; a request cannot select a PID.
It first emits a separate `started` event with its **own** PID/FILETIME for
exit tracking. That event is not readiness, caller authorization or worker proof.

```js
const caller = await queryTaskChannelCaller();
const trust = await inspectTrustedCodeRoot(controllerPackageRoot);
const channel = await createTaskChannel({
  operationId, targetSid, sessionId, manifestParent,
  bootstrap: { nodePath, nodeSha256, scriptPath, scriptSha256 },
  manifest: { /* public canonical operation binding and ephemeral public key */ },
});
const peer = await channel.awaitWorker();
const { peer: observed, frame } = await channel.receive();
await channel.send(response);
const authorization = await channel.authorize();
await channel.close();
```

`channel` exposes `manifestPath`, `endpoint`, `controllerIdentity`, `actorFacts`,
`guardIdentity`, `targetSession`, `workerSession`, `pid`, `awaitWorker`, `send`, `receive`, `authorize`, `closed`,
and `close`. Returned objects are detached copies, never native state.
`closed` resolves with native process exit code/signal/reason. Every pending
operation fails when the channel becomes invalid. `close` releases proof only:
it never signals either parent or worker. The caller retains responsibility
for journal-driven removal of its exact, newly-created operation directory.
Query failures include `guardIdentity`, `helperExit` when observed, and
`cleanupUnverified`. If exit cannot be verified, the error keeps that fact and
the close error; it is never silently replaced by a generic readiness timeout.

The helper exclusively creates `<manifestParent>/<operationId>/manifest.json`.
An existing operation directory is refused, never reused or repaired.
Default exact worker arguments, after the native Node executable, are:

```
<absolute scriptPath> --manifest <absolute manifestPath> --operation <UUID> --controller-root <manifestParent>
```

Optional `bootstrap.argv` must equal that sequence. Native script/executable
read handles pin the verified bytes for the operation. Only local drive-absolute
paths are supported; relative, device, network and reparse paths are refused.
`expectedCreationTime`, when supplied, further restricts the observed peer birth;
it never selects a PID or permits reconnecting.

The manifest contains `protocol:1`, `operationId`, `endpoint`, `targetSid`,
`sessionId`, `targetSession`, `bootstrap`, `controllerIdentity`, `actorFacts`, and `document`
(the supplied public `manifest`). **No private key belongs in this document.**

The worker calls:

```js
const { document, readerIdentity, protection } =
  await readProtectedManifest(manifestPath, { operationId, manifestParent });
```

The reader validates the exact operation path, OS file owner, restrictive
directory/file security and no-redirect path chain, and its **own actual parent
Node** image, argv, SID, session and FILETIME. It also freshly verifies that the
bound session still belongs to that SID and the manifest's logon generation,
returning `targetSession` separately from the protected manifest snapshot.
It does not query the elevated
controller's token or threads: an ordinary other-user reader usually lacks
those rights. Its trust anchor is the controller-owned protected manifest and
bootstrap, not a self-reported admin field. `protection.actorOwnerSid` comes from
the OS descriptor. Own-user operation explicitly reports
`same-user-not-self-tamper-proof`; it does not protect against its own user.

## Identity and authorization

The helper owns exactly one local pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
`PIPE_REJECT_REMOTE_CLIENTS` and maximum one instance. A **direct Node worker**
connects: no proxy is treated as the worker. `GetNamedPipeClientProcessId` and
`GetNamedPipeClientSessionId` supply the peer, then query/synchronize process and
query-token handles remain open. The identity contains:

- `pid`, exact decimal FILETIME `creationTime`, `ownerSid`, `sessionId`
- `imagePath`, `imageSha256`, and `argvSha256`

Generation-bound WMI queries inspect only the guard's parent link or the
selected process's argv. Parent-thread IDs come from process-scoped PSS
snapshots, not WMI. There is no name/PID sweep or generic PID RPC.
Received JSON remains under `frame`; peer-supplied identity/type fields cannot
replace the separately generated `peer` envelope. Disconnection, peer exit,
parent exit, identity ambiguity or a deadline invalidates the operation.
No reconnect or replacement peer is accepted.

Controller facts come from the actual held parent's primary token: elevation,
enabled (not deny-only) Administrators SID, restrictions, AppContainer and
SID/session. Two process-scoped `PSS_CAPTURE_THREADS` (`0x80`, context flags zero)
captures retain a complete 1–128 unique-entry set, including PSS termination
metadata. Each thread is separately held with query/synchronize rights. Live
threads require matching owner PID, birth, liveness and token checks on both
observations. A PSS-terminated entry is accepted as already ended only when
supported flags and both snapshots agree with its held owner/birth/exit, its
exit strictly predates the first observation, and its held handle is signaled.
Ended handles remain held through the second observation. At least one live
thread is required. A live thread ending during observation still refuses.
The raw count/bounds include ended entries; no missing or partial set is accepted.
The ID sets, classifications and held
generations must remain unchanged. Missing/inaccessible primary or thread facts,
churn and observed thread impersonation refuse full caller/serve/authorize roles,
including same-user calls; they cannot become partial successful authorization.
`observed-none` is a **bounded observation, not an atomic
promise about future thread impersonation**. The guard's own thread fact is
separate. No controller thread ID is guessed from Node or Task Scheduler.

Only `cli-context`, `caller` and `serve` open their actual controller parent with
`PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`
(`0x101400`), as required by the existing PSS capture. Authorization reuses that
held parent handle but repeats the complete observations, not cached facts.
Peer, manifest-reader, inspect-root and other process opens retain `0x101000`.
Denied query access refuses without fallback, privilege changes or permission
repair. The ordinary CLI and full-facts roles share ID capture, not eligibility
or administrator policy.

A different target SID requires actual elevated/enabled-admin, unrestricted,
non-AppContainer and nonimpersonating observations. Own-user query-only operation
requires no elevation. `authorize()` repeats actual parent/token/thread
observations; the task controller must call it and enforce its role immediately
before **each** permitted task mutation. It is available before the peer connects
for the preapproved bootstrap task operations, without opening a second helper.
Persisted facts and supplied booleans
never confer authority.

After the token/thread query, before acknowledging authorization, the guard
rechecks its held peer process/current SID/session, queries the **same pipe**
with `PeekNamedPipe`, and checks operation/framing/handshake deadlines. A peer
that exits or disconnects during that query cannot receive a stale successful
acknowledgement. This is still a point-in-time observation, not a promise that
the worker can never exit after the reply.

`inspectTrustedCodeRoot` checks root ancestors and all code-tree entries without
importing them. Allowed owners/writers are the actual actor, SYSTEM,
Administrators and the Windows TrustedInstaller service SID. Unknown write,
delete, ownership or permission authority is refused, even if a deny ACE might
make it harmless. Ancestor creation of an unrelated child is not deletion of an
existing protected child. Held no-delete path handles and native reparse checks
avoid following a replacement path. This is conservative admission, not a
general Windows effective-access evaluator or loaded-code attestation.
Only this read-only role omits the unused parent-thread observations and
reports `parentThreadImpersonation: "unverified"` with
`parentThreadQueryError: "NOT_OBSERVED_READ_ONLY_ROLE"`. It still queries the
held parent's primary token/SID and all root ACLs, with facts captured after
the completed walk. No caller flag selects this behavior. Caller/serve/authorize
roles retain their existing complete-observation requirement for admin authority.

## Application authentication stays outside this helper

The Node controller keeps its ephemeral private key **only in memory**. It signs
a domain-separated canonical operation digest, fresh worker challenge, this
guard's observed PID/birth/SID/session, and sequence. The worker verifies the
signature using the protected manifest key and compares its own native identity.
The same held pipe carries the exchange and later messages.

The guard does not implement these signatures or task verbs. The application
must not treat `awaitWorker()` alone as mutual authentication. Task `RunEx`
success/instance GUID/EnginePID, argv text, a nonce, or a copied JSON identity
is not loaded-code attestation. The elevated controller must remain safe even
against a lying authenticated worker: only preapproved task verbs and fixed
operation/sequence/state digests, with controller-chosen paths and definitions.

### Read state and cancellation

Peer reads decode UTF-8 and validate the outer JSON **object** in their own
bounded read task. The final authorization check observes any completed read
failure before emitting an acknowledgement. A valid object remains queued for
normal delivery exactly once; encoded/opaque values inside that object are not
interpreted as commands. Invalid UTF-8, invalid JSON and non-object frames cannot
be acknowledged merely because the peer process and pipe are still alive.

A separate continuous stdin reader keeps close/EOF/protocol failure observable
while a command is executing, including while authorization is blocked in token
or session queries. It queues at most 32 parsed commands and executes them in
order. Command IDs start at 1 and increase by one; duplicate/out-of-order IDs,
unknown commands and overflow refuse the channel. Close and EOF are latched
independently of queued authorization requests. The existing cancellation
watchdog/deadlines remain unchanged; there is no unbounded read queue or reconnect.

Owned tests compile a barrier into a private copy of `Authorize`, confirm the
peer read is faulted before release, then assert no authorization event. Separate
pre/post-peer close and EOF tests keep the parent alive and the watchdog enabled.
Queued-authorization cancellation, sequence/overflow refusal and valid opaque
FIFO delivery have their own controls. No barrier or bypass option is shipped.

## Bound interactive-session eligibility

Before creating bootstrap resources, before reporting a verified worker, and
on **every** authorization, the helper queries only the operation's fixed local
session. It uses `WTSQuerySessionInformationW` and `LookupAccountNameW`;
it does not enumerate sessions/users or call `WTSQueryUserToken`.

Full `WTSUserName`/`WTSDomainName` strings are resolved to a canonical **user SID**,
which must equal the selected SID. They are sampled twice, bracketed by
`WTSSessionInfoEx` snapshots with the same session ID, state and nonzero logon
FILETIME. The fixed-width extended-info name fields are consistency checks only;
a truncated 20-character name is **never** used for SID resolution. Permission
denial, missing/empty/unmapped identity, unsupported generation information,
changed samples, non-user SIDs and wrong ownership all cause refusal.

`active` and `disconnected` (still logged on without a connected client) are
eligible. Connected-but-not-logged-on, idle, listen, reset, down, initialization
and shadow states are not. The captured logon generation is fixed for this
operation; reauthorization cannot silently switch to a reused session.

The trusted `targetSession` shape is:

```
{ sessionId, ownerSid, state, logonTime, observedAt,
  source: "wts-account-sid-snapshot", atomicRunExBinding: false }
```

`ready.targetSession` and `document.targetSession` are initial observations.
After `awaitWorker()`, `channel.workerSession` is the separately trusted fresh
post-launch observation, not a peer frame field. `authorize().targetSession`
is fresh again. The reader also returns a fresh top-level `targetSession`.
The application must authenticate the handshake and freshly authorize before
importing target code or performing target work/stop operations.

Each session observation has a five-second bound. Other-session queries require
the existing WTS Query Information rights; refusal does not trigger permission
repair, logon, impersonation or privilege enabling.

**WTS snapshots cannot hold session ownership or bind it atomically to Task
Scheduler `RunEx`.** A logoff/reassignment can still happen after the last query
and before the task call. The application must report this snapshot/call limit,
recheck immediately before bootstrap, and require actual same-connection worker
SID/session/generation proof plus fresh session eligibility after launch and
before target work. No task result or stored session ID replaces these checks.

The runtime hash check catches packaged drift, not atomic replacement by a
same-user package writer. Updates must use immutable candidate directories;
there is no new trusted-launcher chain or on-the-fly compilation.

## Ordinary CLI effective-context observation

`queryCliCallerContext()` is a separate fixed role for ordinary **current-user**
dispatch. It does not authorize elevated/cross-user task work and does not
replace `queryTaskChannelCaller`, `serve` or `authorize`.

The native role derives the caller from its fresh private stdin pipe using
`GetNamedPipeServerProcessId`. It cross-checks the existing NT basic-process
parent-slot pattern, exact returned size/self PID, parent birth and liveness.
The JS export also requires the returned caller PID to equal `process.pid`.
The installed SDK calls that NT slot `Reserved3`: this is an explicit Windows
compatibility limit, not a portable documented PPID contract. Unsupported layout
or binding refuses the observation. The pipe query runs before its next blocking
read. No supplied PID or mode boolean provides authority.

Like the full caller/serve roles, this role opens its actual parent with
`PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`
(`0x101400`). Two bounded, process-scoped `PSS_CAPTURE_THREADS` (`0x80`) captures
with context flags zero retain raw thread identity and termination metadata.
This uses the same complete held-generation observation as full facts, including
the strict already-ended classification described above. Every live thread must
positively return `ERROR_NO_TOKEN` from `OpenThreadToken(TOKEN_QUERY)` twice;
the complete ID set, held generations and classifications must stay unchanged.
Primary SID/session and token facts must remain stable. Primary elevation,
enabled Administrators and guard-thread impersonation must be false.

No VM reads, thread-context or handle capture, global enumeration,
impersonation, privilege enabling or rights-expansion fallback are used.
Denial, token presence, churn or unknown information means explicit
noneligibility/refusal, never a primary-token-only shortcut. The failed limited
mask and successful query-information probes establish behavior on the owned
host, not a documented universal minimum-rights claim.

The result contains `proofScope: "cli-effective-context-snapshot"`,
`ordinaryEligible`, `reason`, caller `identity`, `actorFacts`, `guardIdentity`,
`helperExit`, and:

```
observation: {
  method: "pss-threads-held-token-query", processAccess: "0x101400",
  captureFlags: "0x80", threadContextFlags: 0, threadCount,
  completeStableThreadSet, primaryStable,
  atomicFutureProtection: false, observedAt
}
```

Only a complete positive result with verified helper exit supports the
non-elevated current-user path. Selected-instance JSON cannot supply that
decision. Verified noneligibility keeps strict checks; thrown errors, especially
`cleanupUnverified`, must not become fallback success. This is a **moment-in-time
complete observation**, not immunity to future thread creation/impersonation.
Consume it before importing target code; do not cache it as lasting authority.
Native-probe and role-roundtrip timings are not end-to-end CLI measurements.

## Bounds and qualification

- Peer frames: 16 KiB UTF-8 including newline, JSON objects only; strict UTF-8,
  no CR framing. A partial frame has five seconds after its first byte.
- Manifest/init/event bounds: 64 KiB; public document at most 48 KiB.
- Handshake: 2–30 seconds (default 30); total lifetime: 2–900 seconds
  (default 900). Native startup/read-only queries have a 13-second bound, below
  the unchanged 15-second JS readiness limit. A dedicated background thread
  watches parent exit, stdin cancellation and deadlines even if WMI or file ACL
  calls block the main thread. It exits **only this helper**. Root walks also
  check cancellation/liveness between entries. A close/EOF gets a short 500 ms
  grace for normal shutdown, not a longer operation deadline.
- One outstanding native peer read; JS queues at most 32 messages/requests.
  Native pipe write deadline is one second.
- Thread set: 1–128, two bounded observations. Code-root scan: at most 2,048
  directories/16,384 files. Bounds/inaccessible objects cause refusal.

Build with `tools/windows-task-channel/build.ps1`; `-Verify` checks recorded
compiler/reference/source inputs and two byte-identical clean compilations.
No downloads, installs, elevation or runtime compiler are used.

`test/windows-task-channel.test.mjs` uses only owned same-user processes/pipes,
45-second expiry and captured PID+FILETIME cleanup receipts. Pure reflection
policy tests are labeled models and never bypass shipped native authorization.
Actual elevated **two-user** pipe/security/task/session behavior is not qualified
by those tests. Run it only in a separately authorized existing two-user test
environment; this work creates no accounts, credentials, logons or tasks.
Blocked-query tests compile an isolated, explicitly marked test variant with
a 30-second stand-in for a blocked root read. One failure-injection variant
also disables its watchdog to verify the JS exit-unverified error path. Neither
behavior is exposed by a shipped argument, environment variable or auth bypass.
