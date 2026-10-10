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

Immediately before `npm test`, CI reads both registry values and runs the
production `queryCliCallerContext()` query. The log includes only the eligibility
reason, privilege/impersonation/observation flags and helper exit status, not
account identities, paths or credentials. A non-ordinary result is logged without
skipping tests or changing the production guard. The snapshot records that
diagnostic Node caller; every upgrade still checks its own actual caller.

## Ordinary Windows test launcher

`ordinary-run.mjs` uses the existing desktop broker:
`Shell.Application.Windows().FindWindowSW(SWC_DESKTOP).Document.Application.ShellExecute`
with the `open` verb. This is the same desktop method used by local ordinary
qualification. It does not create a user, change UAC or registry settings, enable
privileges, alter tokens, or impersonate another process. An absent desktop,
different SID/session, privileged child or unknown caller binding is an error.
There is no administrator fallback.

The wrapper runs `npm test`, the explicit pooling diagnostic, and compatibility
prepare/test/cleanup. Compiler restore and reproducible builds stay in the original
controller context. Linux/macOS commands are unchanged. The desktop child's
production `queryCliCallerContext()` and `requireOrdinaryUpgradeCaller()` checks
must succeed before a test command starts. Each upgrade retains its own checks.

The controller records its actual `process.execPath`, explicit npm CLI and checkout
working directory. npm defaults to the CLI bundled beside that Node executable;
`MCP_CI_NPM_CLI` can name an explicit CLI when using a retained Node-only toolchain.
There is no implicit npm fallback, and the CLI entry-point hash is checked again
in the child. The desktop bootstrap starts that exact Node executable with
a cleared environment containing only the allowlisted Windows system/home/temp
paths, `PATH`, `CI`, the two native-toolchain paths and the pooling test flag.
The selected Node directory is first in `PATH`, retaining the controller's other
entries, so npm scripts also select the same matrix Node.
It never transfers arbitrary environment values, `NODE_OPTIONS`, registry tokens
or job credentials. Tests do not use the desktop's global Node/npm selection.

Each invocation owns a new `pacemaker-ordinary-*` directory beneath `RUNNER_TEMP`
(the system temp directory locally), with fixed input, context, output and exit
receipt filenames. The existing lifetime helper contains both controller and
ordinary worker jobs. Before running tests, the controller arms observation of
the worker's exact lifetime-owner generation, and the worker arms observation of
the controller's exact lifetime-owner generation. Controller loss or uncertainty
terminates the worker; its job then terminates remaining descendants. Success
requires a matching exit receipt and verified zero active processes. Startup is
bounded to 45 seconds, the full `test` command to 60 minutes, other operations to
45 minutes, and cleanup observation to 15 seconds. The reusable controller's
validated maximum remains 60 minutes. Bootstrap waiting has a
separate finite backstop. Stdout/stderr and private receipts remain for inspection.

```powershell
node tools/windows-ci/ordinary-run.mjs test
node tools/windows-ci/ordinary-tests.mjs --output C:\private\ordinary-launcher-checks
```

The small launcher checks use actual ordinary and already-privileged children,
missing expected caller binding, a specific failing exit code, stderr/exception
capture, timeout, and forced controller death with a running descendant. They do
not change or invent native token facts. The privileged control requires an
already-privileged test controller and does not elevate one. These are CI-only
files and are excluded from the npm package.

The full-test budget accounts for an older measured 42m16s Windows run before
additional cases were added. It changes only the CI command envelope, not any
product startup, quiesce, stop or native deadline. Budget-selection assertions
cover the full-test and other operations; the focused timeout control still uses
10 seconds. Neither those checks nor a filtered integration run qualify the full
expanded Windows suite.

Local qualification does not prove that a hosted runner supplies an eligible
existing desktop. Hosted behavior remains unverified until the workflow runs;
unavailable or privileged desktop launches must fail clearly rather than skip
ordinary tests or change host policy.
