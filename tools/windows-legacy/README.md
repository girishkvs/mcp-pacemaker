# Legacy process broker

This separate own-source .NET Framework 4.6.2 executable supports an explicitly
partial, restart-only legacy handoff. It does not change the modern lifetime
helper or its Job Object proof. No npm runtime dependencies, compiler, PowerShell,
downloads, privilege changes or service/task mutations run inside this broker.

## API and caller responsibilities

```js
const session = await prepareLegacyProcesses({ port, root, expected });
const plan = session.plan;
const current = await session.status(); // read-only held-handle status
const receipt = await session.stop();   // consumes this session's stop once
await session.close();                 // closes handles; does not stop targets
const recovered = await verifyLegacyProcessesGone(plan); // read-only
```

`root` is an absolute existing package directory. `port` is an integer 1..65535.
Discovery requires exactly one IPv4 127.0.0.1 listener on that port; wildcard or
ambiguous listeners refuse. It opens the bridge and its native parent, verifies
both user SIDs match the broker's user, and requires these parsed argument lists:

- `node.exe <root>/bin/mcp-bridge.mjs --port <N>`
- `pwsh.exe|powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden
  -File <root>/supervisor/supervise.ps1 -Port <N>`

Actual image paths and SHA256 values are recorded, not assumed to equal the
upgrader's Node executable. Parsed argv is hashed and not emitted. Native
creation time is an exact decimal Windows FILETIME string. WMI command-line
reads are checked against the held process generation. No cwd/PEB read, process
injection or debugging is used.

Both script arguments must be fully qualified Windows drive-absolute or ordinary
UNC paths before comparison. Relative, drive-relative (`C:script.ps1`),
root-relative (`\script.ps1`) and device-namespace spellings refuse; the broker
never resolves target arguments against its own cwd or guesses the target cwd.
Existing case-insensitive full-path comparison and native executable identity
queries are unchanged.

Process discovery uses documented `TH32CS_SNAPPROCESS` snapshots: one per capture
or revalidation phase to bind the two roots, and one per stop sweep round. At most
16,384 PID/parent pairs are retained in memory. The native entry buffer also
contains other OS fields; the broker reads only the PID/parent offsets, never
marshals names, and clears that buffer after each entry. It closes the snapshot
before opening candidates. No global pair list is returned or logged, and no
unrelated entries receive process/token/image queries. Snapshot overflow,
layout/duplicate/enumeration failure and `ERROR_BAD_LENGTH` refuse a capture or
revalidation phase without retry; during a stop they are reported, and the sweep
still stops every process it already holds and tries again in its next round.

Snapshot pairs are discovery hints, not process authority or an atomic tree.
A sweep candidate must still bind to a held process through its own native
parent, creation-time and owner checks. Unknown historical branches stay
untouched.

The argv query covers only the two held roots, in one query per phase run by a
worker that owns its connected WMI scope/searcher/cursor. Missing, extra,
duplicate or stale rows refuse the entire phase; the native watchdog remains the
hard whole-helper bound for a blocked call.

Each phase separately hashes at most 64 executable files, 256 MiB per file and
512 MiB total. Read handles deny writes/deletion until the phase finishes.
Every process image path is reopened and matched by volume/file identity before
reusing a digest; paths alone and prior-phase digests are not cache keys.

The caller must independently verify the exact known legacy package, selected
launcher/task ownership, source hashes, and config-directory nonce/revision.
Matching process arguments and captured script hashes do **not** make an arbitrary
script an approved legacy package. Cwd is not a supported config binding.

Prepare is read-only. It captures **only the two roots** and binds them to the
listener and to each other. It does not list the bridge's session processes: a
busy 1.3 bridge starts and ends them every few seconds, so a list would be stale
before the stop. It also walks its own parent chain, checking creation order at
each step, and refuses with `Run the upgrade from a terminal the 1.3 bridge did
not start` if that chain reaches the supervisor or the bridge: such an upgrade
would stop itself. Script read handles deny script modification/deletion during
this session. The plan contains:

```text
protocol: 1
kind: "legacy-observed-process-set"
roots: { supervisor, bridge }
observed: []   (2.1.0 plans listed descendants here; recovery still verifies them)
excluded: []
observedSetSha256
treeCompleteness: "unproven"
scope
planSha256
```

Root identities include PID, creation time, parent PID/creation time, owner SID,
image path/hash, argv hash and root script hash. No opaque commit token is in
`plan`. Passing a previous `plan` as `expected` binds its roots: protocol, kind,
port, root, owner and both root identities must match exactly. Descendants are
not compared, so sessions that started or ended since the plan do not refuse it.
A changed root generation still requires a new plan and confirmation.

Only after the caller's per-plan confirmation and holding and rechecking the
**exact selected** autostart registration may the caller invoke `stop()`. This
broker does not attest that the task is held. It rechecks the roots, listener and
argv/image identity, then stops through retained native handles, never by a
fresh PID lookup:

1. Terminate the supervisor and wait for it, so it cannot start another bridge.
2. Pin: take a snapshot and hold a handle to each process whose live parent PID
   (read from its own handle, not the snapshot) is a held process and which
   started no earlier than that process, walking the whole tree in one pass.
   Repeat until a snapshot shows nothing new, at most eight times. Nothing is
   stopped here.
3. Terminate the bridge and wait for it.
4. Sweep: pin again, then terminate every held process not yet stopped and wait
   for them, even if that pin found the tree still growing or could not read a
   snapshot. Repeat until a round's pin settles with nothing new and nothing is
   left to stop.

Pinning comes first because Node ends a process's direct children together with
it through a job object, and 1.3 runs each bare server command under a `cmd.exe`
wrapper. Without the pin, ending the bridge would end the wrappers at once and
leave the real servers under them with a parent nobody holds. A process that has
already exited is held too while it can still be opened, so its children stay
traceable. A wrapper the bridge starts in the few milliseconds between the last
pin snapshot and the bridge's exit is not held; if it has started its server by
then, that server is left running like any other untraceable process.

Held handles keep their PIDs from being reused, so a process that names a held
PID as its parent and started no earlier than it was started by it. A process
older than that parent got the PID from an earlier owner and is left alone; a
held root that appears under a pinned process (its creator's PID was reused) is
already held and is skipped. The broker and its own parent chain, matched by PID
and creation time, are never adopted. A live process owned by another user is
reported, not stopped.
Processes whose parent had already exited before the stop cannot be traced and
stay untouched.

Root capture ambiguities refuse. After mutation starts, failures are explicit and
may be partial; never automatically relaunch the old supervisor, replay tools, or
broaden cleanup. The caller must preserve its task hold and journal when the root
stop is uncertain.

### Failure diagnostics

The existing refusal envelope keeps its exception type, native error code,
stage, reason and `mutationStarted` flag. When available, `captureFailure`
contains fixed API/substage labels and nullable stored PID, creation, parent,
liveness and owner-match facts. An initial query-handle denial reports the
requested PID but `generationKnown: false` and `creationTime: null`. Other call
sites can report an API with unknown substage/target; unknown fields are not
inferred from a PID or exception.

`observation: "stored-observations-not-fresh-proof"` identifies these as prior
observations, not a new identity check or stop authority. No diagnostic recovery
query, retry, stronger access, argv, image path, SID or raw exception text is
added. Metadata is attached to the original exception, separately for each
operation/argv worker; collection failures leave the original refusal intact.
Success frames, plans, digests, approvals and stop behavior do not change.

## Honest receipt

```text
legacyRootStopVerified: true|false
observedDescendantsStopped: true|false   (every process the sweep found was stopped)
descendantsFound
descendantsStopped
treeCompleteness: "unproven"
observedCount
excludedCount
planSha256
errors: [...]
unattributed: "Not discovered or not provable; left untouched."
```

There is no `stopped:true` or `activeProcesses:0` field. A wrapper that exits
before the stop leaves its children with no traceable parent. Matching snapshots
do not prove no such processes exist. This broker neither counts nor kills
historical/unattributed orphans. The caller requires `legacyRootStopVerified`;
a process the sweep could not stop is reported in `errors` and left running.

`verifyLegacyProcessesGone(plan)` validates the protected plan's shape/digest,
then opens **only its captured IDs** (the roots, plus any descendants a 2.1.0 plan
listed) with query/synchronize access. A different creation time is an unrelated
reused PID and is untouched; a matching live identity keeps the receipt false;
inaccessible identities keep it unverified. It never requests terminate access or
performs discovery, so its `descendantsFound` and `descendantsStopped` are null,
and for a plan that lists no descendants `observedDescendantsStopped` is false:
the check cannot vouch for them. The journal's authentication/ownership and phase
authorization belong to the caller. A hash inside the plan is an integrity check,
not an authentication credential.

## Bounds and lifecycle

- Plans hold at most 512 identities, including both roots, so a 2.1.0 plan is
  still accepted for recovery checks. A plan written now holds only the roots.
- The stop holds at most 2048 processes and reads at most 2048 children of one
  process. Each pin takes at most eight snapshots; a tree still growing after
  that is pinned further by the next sweep round. The sweep runs at most 16
  rounds. One busy 1.3 host had 533 processes in its tree. Reaching the process,
  child or round bound is reported in `errors`; the root stop stands.
- One argv query during capture and one during revalidation.
- The native watchdog allows 15 seconds to receive the request. Capture and
  revalidation then each have 120 seconds, timed from the request rather than
  from broker start; verification is bounded by the watchdog alone. Each phase
  adds a 10-second watchdog margin, longer than one 8-second WMI query, so a
  phase refusal is reported rather than cut off. Node waits 150 seconds for a
  prepare or verification response.
- Uncommitted session: 120 seconds; expiration requires fresh prepare.
- Stop: the supervisor, the pin, the bridge and every sweep round share **one
  20-second** budget. Once it is spent, remaining exits are polled, not awaited,
  and the sweep ends. Node's whole stop exchange, including revalidation, is
  bounded to 170 seconds.
- Close/exit verification: three seconds.
- Plans: at most 240 KiB UTF-8 before emit/accept. Requests and responses: at most
  256 KiB UTF-8. No full command lines or config contents are emitted.
- Native parent watch: caller loss before commit releases handles without target
  termination. After commit the already-authorized bounded stop finishes.

  Prepare/stop responses include bounded phase timing/resource diagnostics and
  the broker's own PID/FILETIME for owned exit evidence. These values confer no
  target authority and are not part of the plan digest. A test-only outer
  cleanup job is not proof that the production stop succeeded.

Detached native launch avoids inherited console/Node child termination, but is
not an unbounded daemon. Parent loss and deadlines end the broker. Native target
handles are non-inherited. No elevation or privilege enablement is attempted.

Both native launches (prepare and verify-only) first compare actual executable
SHA256 to packaged metadata. This detects package drift, not malicious replacement
of executable plus metadata or the whole package.
It is not an atomic executable-replacement defense; supported upgrades stage
separate immutable package roots rather than replacing a running helper in place.

## Build, inventory and tests

```powershell
.\tools\windows-legacy\build.ps1
.\tools\windows-legacy\build.ps1 -Verify
node --test test/windows-legacy-process.test.mjs
```

The build reuses the installed recorded Roslyn and .NET Framework 4.6.2 reference
assemblies, including built-in `System.Management` and `System.Web.Extensions`.
It compiles twice under different owned paths and compares bytes, records source,
build script, compiler and reference hashes, and installs nothing. `-Verify`
updates no artifact. `inventory.mjs` checks the exact separate asset layout.
The immutable historical security helper and modern lifetime binaries stay
unchanged.

Dedicated tests use a synthetic argument-compatible supervisor for bounded
native identity cases. The upgrader owns the additional byte-exact known-1.3
package/launcher/config/task E2E; passing these focused tests does not replace it.
