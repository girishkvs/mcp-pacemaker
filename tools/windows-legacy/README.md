# Legacy observed-process broker

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

Child discovery uses one documented `TH32CS_SNAPPROCESS` snapshot per capture
or revalidation phase. At most 16,384 PID/parent pairs are retained in memory.
The native entry buffer also contains other OS fields; the broker reads only
the PID/parent offsets, never marshals names, and clears that buffer after each
entry. It closes the snapshot before opening candidates. No global pair list
is returned or logged, and no unrelated entries receive process/token/image
queries. Snapshot overflow, layout/duplicate/enumeration failure and
`ERROR_BAD_LENGTH` refuse the whole operation without retry.

Snapshot pairs are discovery hints, not process authority or an atomic tree.
Every candidate must still bind to an already-held live parent through native
parent/creation/owner checks. Unknown historical branches remain unproven.
Fresh revalidation refuses added or changed generations; a reused numeric PID
cannot replace an exited captured handle.

Argv queries cover only held live IDs, at most 32 per query and four concurrent
workers. Each worker owns its connected WMI scope/searcher/cursor. Missing,
extra, duplicate or stale rows refuse the entire phase. Failed waves stop new
dispatch and join before a response; the native watchdog remains the hard
whole-helper bound for blocked calls. Descendant argv is discarded after
hashing. Already-exited captured descendants remain recorded as gone rather
than being adopted by PID.

Each phase separately hashes at most 64 executable files, 256 MiB per file and
512 MiB total. Read handles deny writes/deletion until the phase finishes.
Every process image path is reopened and matched by volume/file identity before
reusing a digest; paths alone and prior-phase digests are not cache keys.

The caller must independently verify the exact known legacy package, selected
launcher/task ownership, source hashes, and config-directory nonce/revision.
Matching process arguments and captured script hashes do **not** make an arbitrary
script an approved legacy package. Cwd is not a supported config binding.

Prepare is read-only. It captures the roots and a bounded set of currently
provable descendants **before any stop**. Each ancestry edge is checked against
a held, still-live parent and child creation time. Script read handles deny
script modification/deletion during this session. The plan contains:

```text
protocol: 1
kind: "legacy-observed-process-set"
roots: { supervisor, bridge }
observed: [captured identities]
excluded: [proven older nonmembers; never termination targets]
observedSetSha256
treeCompleteness: "unproven"
scope
planSha256
```

Identities include PID, creation time, parent PID/creation time, owner SID, image
path/hash, argv hash and root script hash. No opaque commit token is in `plan`.
Passing a previous full `plan` as `expected` requires exact equality, including
all root generations, hashes and observed members. Changes require a new plan
and confirmation; no new set is silently substituted.

If a query returns a candidate whose actual creator PID equals a still-live held
parent, but whose creation time predates that parent's held generation, it is
excluded with PID/birth/parent-birth evidence and reason `predates-held-parent`.
Only query/synchronize access is opened for this check; an excluded candidate
never receives terminate access and is not traversed. This handles older
survivors whose creator's numeric PID was reused. The plan digest binds the
excluded evidence too. A dead parent, changed live edge, inaccessible query or
other ambiguous ownership still refuses. Stop rechecks any excluded candidate
still returned by the same rooted query; changed generations require replanning.

Cached identities repeat the native generation, parent, owner and liveness
checks before reuse. If a selected root predates a newer held generation of its
numeric creator PID, only that false descendant edge is ignored. The root
remains selected, its parent-birth binding is not rewritten, and it is not added
to `excluded`. Non-root or unproven cached edges still refuse. Revalidation uses
the same classification; depth eight and the combined identity limit do not
change.

Only after explicit per-plan interruption/uncertain-HTTP confirmation and holding
and rechecking the **exact selected** autostart registration may the caller invoke
`stop()`. This broker does not attest that the user has paused callers or held the
task. It rechecks roots, listener, argv/image identity and currently reachable
members. A newly observed child before commit causes refusal, not silent expansion.
Then it terminates the selected supervisor, bridge, and admitted descendants
through their retained native handles, never by a fresh PID lookup.

All root/capture ambiguities refuse. After mutation starts, failures are explicit
and may be partial; never automatically relaunch the old supervisor, replay
tools, or broaden cleanup. The caller must preserve its task hold and journal
when stop is uncertain.

### Failure diagnostics

The existing refusal envelope keeps its exception type, native error code,
stage, reason and `mutationStarted` flag. When available, `captureFailure`
contains fixed API/substage labels and nullable stored PID, creation, parent,
liveness and owner-match facts. An initial query-handle denial reports the
requested PID but `generationKnown: false` and `creationTime: null`. Existing
ancestry-refusal details are retained. Other call sites can report an API with
unknown substage/target; unknown fields are not inferred from a PID or exception.

`observation: "stored-observations-not-fresh-proof"` identifies these as prior
observations, not a new identity check or stop authority. No diagnostic recovery
query, retry, stronger access, argv, image path, SID or raw exception text is
added. Metadata is attached to the original exception, separately for each
operation/argv worker; collection failures leave the original refusal intact.
Success frames, plans, digests, approvals and stop behavior do not change.

## Honest receipt

```text
legacyRootStopVerified: true|false
observedDescendantsStopped: true|false
treeCompleteness: "unproven"
observedCount
excludedCount
planSha256
errors: [...]
unattributed: "Not discovered or not provable; left untouched."
```

There is no `stopped:true` or `activeProcesses:0` field. A wrapper that exits
before capture can leave an unprovable descendant. Matching snapshots and empty
captured sets do not prove no such processes exist. This broker neither counts
nor kills historical/unattributed orphans.

`verifyLegacyProcessesGone(plan)` validates the protected plan's shape/digest,
then opens **only its captured IDs** with query/synchronize access. A different
creation time is an unrelated reused PID and is untouched; a matching live
identity keeps the receipt false; inaccessible identities keep it unverified.
It never requests terminate access or performs discovery. The journal's
authentication/ownership and phase authorization belong to the caller. A hash
inside the plan is an integrity check, not an authentication credential.

Excluded candidates are never opened by recovery verification and are never
required to exit. Counts describe this bounded observation, not all historical
orphans or complete tree coverage.

## Bounds and lifecycle

- At most 512 **combined held and excluded identities**, including both roots,
  and eight ancestry levels. Any count/depth/byte/query failure refuses the
  whole plan; no subset is silently accepted.
- At most 48 argv queries during capture and 32 during revalidation.
- Initial capture: 15-second native watchdog, 20-second Node response bound.
- Uncommitted session: 120 seconds; expiration requires fresh prepare.
- Stop revalidation: 15 seconds; termination/waits share **one eight-second**
  budget. Node's whole stop exchange is bounded to 30 seconds.
- Close/exit verification: three seconds.
- Plans: at most 240 KiB UTF-8 before emit/accept. Complete encoded requests:
  at most 256 KiB; no full command lines or config contents emitted.
- Native parent watch: caller loss before commit releases handles without target
  termination. After commit the already-authorized bounded stop finishes.

  Prepare/stop responses include bounded phase timing/resource diagnostics and
  the broker's own PID/FILETIME for owned exit evidence. These values confer no
  target authority and are not part of the plan digest. Termination order and its
  single shared eight-second budget are unchanged. A test-only outer cleanup job
  is not proof that the production stop succeeded.

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
