# Windows process lifetime helper

The bridge awaits this packaged, own-source .NET Framework 4.6.2 program before
reading config, listening, or spawning workloads. It has no npm dependencies,
runtime compilation, PowerShell invocation, downloads, elevation, or service setup.

Before **each owner and observer launch**, the Node module hashes the actual
executable bytes and compares them with the packaged metadata's recorded SHA256.
Missing files, invalid metadata and mismatched bytes fail before native spawn.
This is a packaged-identity guard, not protection against a same-user actor
replacing both the executable and metadata, or replacing the whole package.

## Ownership

The helper opens its **actual parent** from native process information and retains
that process handle. It requires `watch-parent <caller PID>` and checks that PID
against its actual parent; it cannot select an unrelated target. Bare invocation
fails before assigning any process. This is an internal bridge launch contract,
not a standalone command to run in a shell.

Creation-time ordering rejects a reused parent PID, and an already exited parent
is refused. It creates an unnamed, non-inheritable Job Object
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, without either breakaway flag, assigns
the bridge, verifies membership, and only then writes `MCP_JOB_READY`.

The bridge is not suspended: it is awaiting that acknowledgement and cannot start
any work yet. Every later Windows child inherits the job **during process
creation**, before its first instruction. This covers isolated, pool, shared,
auth-command, and config-write helper spawns, including cmd/npx wrappers. There is
no start-then-assign race, post-crash PID sweep, process enumeration in production,
or fallback to uncontained spawning.

The owner was started before the bridge joined this job and remains outside it.
It alone holds the non-inheritable job handle. On bridge exit, the held process
handle signals and the owner closes the job, terminating surviving descendants.
Both native roles use detached Windows launches, so Node's automatic direct-child
termination does not kill the owner before it can drain. These are not unowned
daemons: each role watches its actual parent's held process handle and exits when
that parent is lost. Owner stdio/process references do not keep an otherwise
finished bridge alive.
Killing the owner also closes the job and terminates the bridge and descendants.
Normal DELETE/recycle still uses the existing per-session tree cleanup; shared
detach, counters and request replay rules are unchanged. POSIX does not launch
this helper or change its process behavior.

A bridge exit notification can precede final job teardown. This mechanism does
not adopt or clean processes abandoned by an earlier runtime.

## Verified managed stop

`ensureWindowsProcessLifetime()` returns
`{protocol:1, ownerPid, ownerCreationTime}` on Windows (`null` on POSIX).
The creation identity is a decimal **Windows FILETIME string**, not a rounded
JavaScript timestamp or .NET DateTime tick count. The identity comes from the
native owner after assignment and its PID must match the spawned child.

The supervisor calls `await observeWindowsProcessLifetime(identity)` before
declaring the bridge ready or permitting stop. It returns `{done, pid}` after a
separate native observer has opened the owner, checked its exact creation time
and same helper image, and retained that process handle. It also opens a
read-only synchronization handle to the owner's initially-unsignaled drain
event. The owner creates that event before readiness, names it from its PID and
creation time, and refuses a pre-existing event. Neither handle is inherited.
The observer is outside
the bridge job, read-only, and also watches its own parent: losing the supervisor
does not orphan the observer. Unavailable/reused identities fail closed.

After root exit the owner calls `TerminateJobObject`, then queries actual job
accounting until `ActiveProcesses == 0`, bounded to five seconds. Only successful
drain signals that held event and returns exit code zero. Kill-on-close remains
the failure backstop. The observer waits on the held owner handle, checks both
successful exit and the signaled event, emits the
drain receipt, then exits itself. Only after observer exit and complete output
does `done` resolve to `{verified:true, ownerExited:true, activeProcesses:0}`.
Forced owner death (including a forced exit code zero) or a failed drain rejects
`done`; PID disappearance or an exit code alone is never accepted as proof.
These session-local kernel events leave no files or persistent settings.

Managed startup sends the owner identity early and waits for the supervisor's
observer acknowledgement before config initialization. This avoids losing the
owner before failed-start cleanup can arm observation. Budget root exit and
`observer.done` inside one existing stop deadline, not two sequential deadlines.

Windows 10/11 and Server 2016+ with .NET Framework 4.6.2+ are required. An outer job
whose restrictions prevent nested assignment causes explicit startup failure,
not an uncontained bridge. ARM64 execution remains an outstanding platform gate.
The historical configuration security helper is separate and unchanged.

## Build and verify

Use the already installed Visual Studio Roslyn compiler and 4.6.2 targeting pack:

```powershell
.\tools\windows-process-lifetime\build.ps1
.\tools\windows-process-lifetime\build.ps1 -Verify
# Optional: select the exact recorded, installed compiler/reference directory.
.\tools\windows-process-lifetime\build.ps1 -Verify -CompilerPath C:\path\to\Roslyn\csc.exe
```

Both modes compile twice in different owned temporary directories and require
identical bytes. Verification also requires the recorded compiler, references,
normalized source/build-script hashes and packaged binary hash; it updates
nothing. Builds install no tools and clean their explicitly recorded scratch
files. Only the entry point and P/Invoke declarations are static.

`inventory.mjs` checks the exact separate asset layout and normalized build inputs
on every platform. It does not substitute for the byte-for-byte Windows rebuild.
Package/native gates require these assets for current versions starting at 2.0.2;
the immutable 1.3.1 security-helper baseline is not relabeled or modified.

## Regression

`test/windows-process-lifetime.test.mjs` uses only owned synthetic nested
`cmd -> Node stand-in -> cmd -> Node worker` processes, dynamic loopback TCP
heartbeats, MCP readiness, 45-second expiry backstops and captured
PID/creation-time/held-handle cleanup. DELETE/recycle are controls; abrupt bridge
loss must stop both heartbeats and terminate every captured descendant. Evidence
is retained outside Git; set `MCP_LIFETIME_TEST_EVIDENCE` to an existing private
evidence parent. The known historical live bridge exit trigger remains unknown.
