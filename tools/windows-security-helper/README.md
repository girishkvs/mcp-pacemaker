# Windows security helper

`bin/windows/PoolingSecurityHelper.exe` is an own-source, AnyCPU .NET Framework
console program. It contains both the native security reader and the operation
code; there is no companion reader DLL or third-party runtime dependency.
The `bin/windows/src/` source and build metadata ship alongside the executable.

## Runtime

Requires Windows with .NET Framework 4.6.2 or later. Windows 10 1607+, Windows 11,
and Windows Server 2016+ include that version or newer. Windows PowerShell 5.1
alone on older Windows does not establish this prerequisite.
PowerShell is **not** launched by the helper.
There is no runtime compilation, download, elevation, or policy change.
AnyCPU uses the installed Framework's process architecture; native calls use
pointer-sized handles. Windows ARM64 execution has not been validated.

The Node caller must launch the package-relative executable directly (no shell)
with exactly one argument, `inspect` or `copy`, and supply:

| Environment variable | Used by | Value |
| --- | --- | --- |
| `MCP_POOL_SOURCE` | Both | Source config path |
| `MCP_POOL_SECURITY` | Copy | Previously inspected fingerprint |
| `MCP_POOL_TEMP` | Copy | Existing empty replacement file |
| `MCP_POOL_BACKUP` | Copy | Existing empty backup file |

`inspect` writes one line: `F:<base64 SHA256>` for complete security or
`P:<base64 SHA256>` when audit read is denied. These are comparison values,
not log fields. The caller must refuse automatic writes for partial (`P:`)
state. Successful `copy` writes nothing to stdout.

| Exit code | Meaning |
| --- | --- |
| 0 | Inspection or copy/verification succeeded |
| 3 | Source fingerprint changed before or after copy; caller reports conflict |
| 1 | Invalid input, I/O failure, or security cannot be preserved |

On failure, stderr contains only `MCPERR type=<exception type>` and, for native
errors, `MCPERR nativeError=<integer>`. No path, descriptor, token, config bytes,
or exception message is logged. Caller owns process timeout and error mapping.

Fingerprint framing is unchanged: canonical native descriptor (mask `0x1f7`),
separate managed audit descriptor, and integer file attributes, written with
`BinaryWriter` length prefixes before SHA256. Copy preserves owner/group/DACL
through SDDL and verifies the entire fingerprint on both staging files, then
rechecks the source. It does not copy unsupported audit/integrity/attribute
state or weaken it to force success. It never writes config contents.

## Build and verify

Prerequisites, installed by the developer or CI image:

1. Visual Studio or Build Tools with MSBuild and its Roslyn `csc.exe`, supporting
   `/deterministic` and `/pathmap`. `vswhere` discovers current releases, including
   Visual Studio 2026; an explicit compiler path is also supported.
2. The .NET Framework **4.6.2 targeting pack** (reference assemblies, not a new
   runtime). The script reports missing prerequisites; it installs nothing.
3. Windows PowerShell 5.1 or PowerShell 7 for the build script only.

From the repository root:

```powershell
# Update executable and metadata after source changes.
.\tools\windows-security-helper\build.ps1

# Read-only source/toolchain/hash check plus byte-for-byte rebuild.
.\tools\windows-security-helper\build.ps1 -Verify

# Select an already-installed compiler explicitly when reproducing recorded bytes.
.\tools\windows-security-helper\build.ps1 -Verify -CompilerPath 'C:\path\to\Roslyn\csc.exe'
```

The build uses `/noconfig /nostdlib+` with explicit `mscorlib.dll` and `System.dll`
references, fixed options, LF-normalized UTF-8 source, and mapped source paths.
It compiles twice under different temporary paths and refuses unequal bytes.
Temporary build files are removed by explicit path. No `dotnet build`, runtime
Framework compiler, NuGet restore, or external binary is involved.

`PoolingSecurityHelper.build.json` records compiler version/hash, reference
hashes, options, normalized source/build-script hashes, and executable SHA256.
`-Verify` checks all inputs and requires rebuilt bytes to match the packaged
binary. Verification never updates the binary or metadata.

Reproducibility is scoped to the **recorded compiler and references**. A newer
CI image/compiler may produce different bytes; do not treat a changed toolchain
as verification of the old binary. Use the recorded installed toolchain or
explicitly rebuild, review, and validate the updated assets. This is integrity
checking, not code signing or protection against someone replacing all assets.

The published executable must contain only the production sources above.
Audit-denial/delay test variants belong in disposable directories outside `bin/`
and must never be included in an npm tarball. Release validation must also run
the real package on supported Windows/Node versions and verify packaged file
inclusion. This build alone does not establish those platform results.
