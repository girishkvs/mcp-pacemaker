# Windows CI native toolchain

CI restores two immutable public build dependencies into `RUNNER_TEMP`. It does
not select the runner's latest Visual Studio, install a framework, or change the
packaged native binaries, sources, build scripts or metadata.

| Dependency | Public source | SHA256 |
| --- | --- | --- |
| Microsoft.Net.Compilers.Toolset 5.9.0 | [NuGet](https://www.nuget.org/packages/Microsoft.Net.Compilers.Toolset/5.9.0) | `b0227910320c5af14d80ec32b5e1a759c1e3cc2ec12e7d9cc8862cf826bd9551` |
| Microsoft.Net.4.6.2.TargetingPack 4.6.1590.5, `cab1.cab` | [Microsoft Visual Studio package](https://download.visualstudio.microsoft.com/download/pr/3e04be02-cc29-4ce0-aea5-2ad7c040b6f9/4d4e304503ea6b2067bc916aded7bd1244e8608c57056afcd6f8e79c99448915/cab1.cab) | `4d4e304503ea6b2067bc916aded7bd1244e8608c57056afcd6f8e79c99448915` |

The NuGet package's Microsoft author signature and NuGet repository signature
were verified, as was the cabinet's Microsoft signature. The cabinet URL/hash
and file keys are from the Visual Studio targeting-pack package manifest and
the matching `netfx_462mtpack.msi` File table (MSI SHA256
`2a844b85a06034e020eb08d90249159dfe6f0ab8b57d24b15766de34f7179ccd`).

`restore-toolchain.ps1` checks both archive hashes **before extraction**. It
extracts only the compiler's `tasks/net472` subtree with path checks and the six
named reference-pack files. It checks `csc.exe`, its version, and every referenced
DLL against all three existing helper metadata files before returning tool paths.
There is no alternative-version or installed-tool fallback.

The compiler is exactly
`5.9.0-1.26357.3 (35d9211b841e7613c1d2f8f5af6d628ace696c4c)`, with SHA256
`3aafb7b9c54fa31a7092af35148971ee616965e7f9a0b80fb7fdc4bdd1d1a555`.
The reference DLLs are revision `4.6.1590.0`. The similarly named
`Microsoft.NETFramework.ReferenceAssemblies.net462` NuGet package version `1.0.3`
contains revision `4.6.1586.0`, whose hashes do **not** match. Do not substitute it.

CI passes `-CompilerPath` and `-ReferenceAssemblyPath` to each unchanged `-Verify`
command. All source/build-script/reference/compiler/binary hash checks and both
independent build passes still run. The historical `PoolingSecurityHelper` is not
rebuilt or changed. Native test fixture builders use `MCP_NATIVE_COMPILER` and
`MCP_NATIVE_REFERENCES` from the same restore; their existing hash checks remain.
With those variables absent, their installed-tool local behavior is unchanged.

## Local verification

Use a new private directory. If local network policy requires an approved package
source, acquire the exact archives through that source into a private directory,
then pass `-PackageDirectory`. Offline restore checks the same hashes and never
falls back to downloading. It does not alter machine package-source settings.

```powershell
$toolchain = .\tools\windows-ci\restore-toolchain.ps1 `
    -DestinationDirectory C:\private\native-tools -PackageDirectory C:\private\archives
.\tools\windows-ci\test-toolchain.ps1 `
    -PackageDirectory $toolchain.PackageDirectory -TestDirectory C:\private\native-checks
.\tools\windows-process-lifetime\build.ps1 -Verify `
    -CompilerPath $toolchain.CompilerPath -ReferenceAssemblyPath $toolchain.ReferenceAssemblyPath
```

The focused test hides installed tool paths, reproduces all three packaged helpers,
checks rejection of modified references and either modified archive, and compiles
all nine native fixture builders. It does not execute the fixture programs or run
the native lifetime suites. Caller-owned output directories remain available for
inspection; remove those exact directories when finished. CI uses its ephemeral
runner directory. None of these dependencies or CI tools are added to the npm
package.

## Caller-context prerequisite

Toolchain reproducibility does not prove that the Windows runner can run the
ordinary-caller upgrade tests. `ManagedUpgrader` and `LegacyUpgrader` require an
actual non-elevated, non-enabled-administrator caller at the start of both execute
and recover. The Windows task-channel tests also assert `ordinaryEligible: true`;
their only platform condition is Windows.

[GitHub documents hosted Windows runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges)
as administrator sessions with UAC disabled. The
[image configuration](https://github.com/actions/runner-images/blob/1b60920cc98c97c717d4790ffdfcb5350e21b5ad/images/windows/scripts/build/Configure-BaseImage.ps1#L28-L31)
sets `ConsentPromptBehaviorAdmin=0`; this setting alone does not establish the
running machine's `EnableLUA` value or its actual caller token.

Before the shared execution preflight, CI reads all three registry values (including
presence and denied/unavailable status) and runs the
production `queryCliCallerContext()` query. The log includes only the eligibility
reason, privilege/impersonation/observation flags and helper exit status, not
account identities, paths or credentials. RID 500 and positive-session checks use
the actual native identity, never a username. A non-ordinary controller result is logged without
skipping tests or changing the production guard. The snapshot records that
diagnostic Node caller; every upgrade still checks its own actual caller.

CI uses the [shared execution contracts](../../docs/execution-context.md) without
a demotion bootstrap. The hosted Windows lane does not need a preconfigured
identity: `ci-ordinary-user.ps1` provisions one. No runner is registered by these
tools.

## Hosted ordinary-account lane

`ci-ordinary-user.ps1` is the active CI path. A hosted runner signs in as the
built-in Administrator, and Task Scheduler ignores `RunLevel` for that account, so
nothing can demote it. The script instead creates a disposable standard account,
which is never an administrator, and runs one contract as that account with
`Start-Process -Credential`.

It refuses unless `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted` and
the caller is the built-in Administrator, so it cannot create an account on a
development machine. The password is generated in memory and never written,
logged or exported. The worker gets a private home, `AppData` and temporary tree
rather than the administrator's profile. Output is streamed while the worker runs,
because a job-level timeout would kill a final dump. The account, its profile, its
`ProfileList` key and the work tree are removed on every exit path, and the script
fails if the account still exists.

## Retained local ordinary Windows test launcher

These diagnostic tools are not called by the active CI workflow. They remain for
reproducing local lifecycle and cleanup tests on a suitable existing account;
they are not a solution for the hosted built-in Administrator account.

`ordinary-run.mjs` uses `ordinary-task.ps1` to create exactly one unique, no-trigger
Task Scheduler bootstrap for the same existing user. Its principal is the recorded
SID, `InteractiveToken` (3), `RunLevel=0`, with no restart and one fixed Exec action.
The recorded session must be positive. It does not create a user, change UAC or
registry settings, enable privileges, alter/filter tokens, impersonate, or repair
existing permissions. Unknown identity/policy, wrong SID/session and
privileged/unverified children refuse. The controller's built-in Administrator
classification is diagnostic only; it does not establish the worker's privileges.
The same limited task is attempted, and the actual worker must pass the native
ordinary-context checks before any test command starts. There is no desktop or
administrator fallback.

The tested COM calls use **create-only `0x12`**
(`TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE`) with explicit `$null` password and
SDDL, and **`RunEx($null, 0x4, sessionId, $null)`**. Empty strings and omitted
arguments are not treated as equivalent. The new resource retains its necessary
default ownership/security; no existing task ACL is changed or new user granted
access.

The retained wrapper supports `npm test`, the explicit pooling diagnostic, and
compatibility prepare/test/cleanup. Compiler restore and reproducible builds stay
in the original controller context. The task child's
production `queryCliCallerContext()` and `requireOrdinaryUpgradeCaller()` checks
must succeed before a test command starts. Each upgrade retains its own checks.

The controller records its actual `process.execPath`, explicit npm CLI and checkout
working directory. npm defaults to the CLI bundled beside that Node executable;
`MCP_CI_NPM_CLI` can name an explicit CLI when using a retained Node-only toolchain.
There is no implicit npm fallback, and the CLI entry-point hash is checked again
in the child. The task bootstrap starts that exact Node executable with
a cleared environment containing only the allowlisted Windows system/home/temp
paths, `PATH`, `CI`, the two native-toolchain paths and the pooling test flag.
The selected Node directory is first in `PATH`, retaining the controller's other
entries, so npm scripts also select the same matrix Node.
It never transfers arbitrary environment values, `NODE_OPTIONS`, registry tokens
or job credentials. Tests do not use another process's global Node/npm selection.

Each invocation owns a new `pacemaker-ordinary-*` directory beneath `RUNNER_TEMP`,
with fixed input, binding and receipt filenames. One bounded Node guardian is
launched and acknowledged **before** the controller joins its own lifetime job.
Its normal PowerShell child owns task create/run/cleanup. Directly detached
PowerShell did not execute its script reliably in local qualification; the narrow
Node guardian plus normal PowerShell child was tested. No job breakaway policy is
changed. This is one task-specific guardian, not another scheduled cleanup task or
a general privileged broker.

Before registration, the guardian records the task name, run ID, input hash and
complete expected definition hash, arms the existing native controller-owner
observation and acknowledges readiness. It refuses pre-existing collisions and
never upserts. An uncertain registration result is reconciled only against the
pre-recorded name, owned marker and complete binding. The check uses the resolved
`Task.Definition.XmlText`, including settings/defaults and explicit action
principal context; persisted task XML may omit defaults. No raw XML or whole SID
is logged. Stop/Delete always recheck the exact definition. Stop targets only the
recorded running `InstanceGuid`, never a prefix or PID sweep.

Before tests, the controller and guardian both arm native observation of the
worker's exact lifetime-owner generation; the worker arms the controller-owner
observation and performs fresh production ordinary-context/SID/session checks.
The guardian remains until success, refusal, startup failure, timeout or
controller loss has converged on the same cleanup path. Command result, native
drain, bootstrap/task-instance completion and registration deletion have separate
receipts. A missing fact fails; cleanup failure never becomes a success-shaped
receipt. Read-only task absence is independently checked.
The task action checks the original input-byte hash before starting Node. The
Node worker checks that same hash and its exact observed lifetime-owner identity
again before executing the test command.

Controller loss or uncertainty terminates the worker; its job terminates
remaining descendants. Success requires original exit/output, verified zero
active worker processes, completed bootstrap instance and task absence. Startup is
bounded to 45 seconds, the full `test` command to 60 minutes, other operations to
45 minutes, and cleanup observation to 15 seconds. The reusable controller's
validated maximum remains 60 minutes. Bootstrap waiting has a
separate finite backstop. Stdout/stderr and private receipts remain for inspection.

The guardian host arms independent timers before starting PowerShell. Synchronous
COM calls cannot block these timers. Startup and operation deadlines each have
30 seconds of cleanup grace; expiry writes cancellation, requests termination of
that exact child and allows 10 seconds to observe its exit. A separate hard exit
limits the guardian to 11 seconds after expiry even when termination is unverified.
The receipt explicitly leaves task cleanup unverified, preserves any original
command result and retains the task/input binding for exact reconciliation.
The recorded worker-observation time determines whether startup was timely, not
when the host's polling callback happens to run. A late or invalid startup receipt
cannot authorize a test command.

```powershell
node tools/windows-ci/ordinary-run.mjs test
node tools/windows-ci/ordinary-tests.mjs --output C:\private\ordinary-launcher-checks
```

The focused controls cover genuine ordinary/npm and already-privileged children,
missing/wrong-session binding, post-registration input changes, exit/error/timeout,
and deterministic controller death before
registration, after registration before RunEx, after RunEx before worker
readiness, and during a real descendant workload. They also cover registration
uncertainty, collision, definition mismatch, and stop/delete failure. No native
token facts are invented. Blocked-child startup and operation controls also check
the host watchdog, including an intentionally unavailable exit observation.
Intentional collision/mismatch fixtures are removed only
by their separately recorded test-owner binding. Injected cleanup failures remain
failures; the test controller explicitly invokes exact-binding cleanup recovery
and verifies absence. The `-Recover` path can only clean a recorded failed owned
registration, never create or run one.

**Limit:** guardian loss, simultaneous loss of its hosting process tree, or host
termination is not claimed to be orphan-free. Task execution is bounded by the
existing CI deadline plus cleanup, but registration cleanup can remain unverified.
The task name and binding receipts must be retained for explicit reconciliation;
there is no ACL repair or silent retry. These files are excluded from npm.

The full-test budget accounts for an older measured 42m16s Windows run before
additional cases were added. It changes only the CI command envelope, not any
product startup, quiesce, stop or native deadline. Budget-selection assertions
cover the full-test and other operations; the focused timeout control still uses
10 seconds. Neither those checks nor a filtered integration run qualify the full
expanded Windows suite.

Local qualification does not prove hosted account/session eligibility. A hosted
run did launch same-account, same-session tasks, but the built-in Administrator
workers remained elevated and administrator-enabled and were refused. Microsoft
[documents that task RunLevel is ignored for the built-in Administrator](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks).
An unsuitable environment must remain blocked, not skip ordinary tests or change policy.
