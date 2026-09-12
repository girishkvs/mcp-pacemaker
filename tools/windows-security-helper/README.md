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
with exactly one action argument. Paths are passed in the environment, never in
arguments. No action enables privileges.

### Batch file operations

| Action | Environment | UTF-8 stdin |
| --- | --- | --- |
| `inspect-access` | `MCP_POOL_SOURCE` | Unused |
| `stage` | `MCP_POOL_SOURCE`, `MCP_POOL_TEMP` (new destination) | `{"expected":{"identity":"…","revision":"…","security":"…"},"bytes":"<base64>"}` |
| `move-no-replace` | `MCP_POOL_SOURCE`, `MCP_POOL_TEMP` (destination) | `{"expected":{"identity":"…","revision":"…","security":"…"}}` |

Each successful action writes one JSON line with exactly
`{identity, revision, security, size}`. Pass only the first three fields back in
`expected`, not the complete result. `identity` is lowercase hexadecimal
`volumeSerial:fileIndexHighAndLow` (8 digits, colon, 16 digits). `revision` is
lowercase SHA256 of the complete bytes; `size` is their integer byte count.
`security` is a lowercase SHA256 comparison value, not a descriptor to log.
Custom config paths, including spaces and Unicode, use the same environment API.

All three actions require a disk file, no final-component reparse point, exactly
one hard link, and at most 1 MiB. Only Normal/Archive file attributes are supported;
read-only, compressed, encrypted, sparse, hidden, and other attributes fail closed.
The input envelope is limited to 1,400,000 bytes, strict UTF-8 and depth 8.
Edited bytes must be canonical base64 decoding to at most 1 MiB of UTF-8.
The helper does not parse the edited configuration; complete JSON validation and
allowed field edits remain the Node coordinator's responsibility.

Native `GetSecurityInfo` queries the held handle with `READ_CONTROL` sections
`0x1f7`. The new actions never call the legacy privileged audit reader.
The security hash frames `mcp-access-v1`, native owner SID, group SID,
DACL-protection bit, raw DACL, native label ACL, and attributes with `BinaryWriter`.
Byte arrays have signed Int32 lengths (`-1` for null). The discriminator is a
BinaryWriter UTF-8 string; protection and attributes are UInt32, all little-endian.
The DACL's `SE_DACL_AUTO_INHERITED` (`0x400`) bookkeeping is not hashed: Windows can
clear it while retaining the exact grants. Defaulted/auto-inherit-request and
other unsupported descriptor control state is refused. Audit control flags are
outside this non-audit fingerprint; label ACE bytes and flags remain exact.

Supported DACLs have non-null raw ACLs containing ordinary non-callback allow/deny
ACEs. Unsupported object/callback/policy ACEs fail closed. No label, or one
low/medium label with a nonzero mask composed only of NW/NR/NX (`1` through `7`),
is supported. Only the inherited label ACE flag is allowed. Other native non-audit
policy is refused.

`stage` opens the source with actual `FILE_READ_DATA | FILE_WRITE_DATA |
READ_CONTROL` access. Parent DeleteChild authority does not bypass source write
denial. The held source handle denies other data writers/deleters during staging.
Expected identity, bytes, and security are checked before creation and again
around writing. When the source owner equals the caller's user SID or current
token default owner, that owner is retained. Retaining an already assignable
default owner avoids an unnecessary ownership change across a version roundtrip.
Otherwise the caller must already obtain source `READ_CONTROL | WRITE_DAC` through
`ReOpenFile` on the same object; only simple allow DACLs without OWNER RIGHTS or
CREATOR special SIDs qualify. The candidate owner then becomes the creator.
The source group must remain exact or creation/verification fails.

The candidate uses native `CREATE_NEW` with `SECURITY_ATTRIBUTES` containing the
accepted owner/group/DACL/protection and supported labels **before any bytes**.
It never clones audit entries or sets SACL protection. A label-bearing creation
descriptor marks the SACL defaulted (`SE_SACL_DEFAULTED`); this lets Windows inherit
folder auditing while retaining the supplied mandatory label. The label remains
part of the exact empty-file verification. Windows inherits the
destination folder's auditing, including when the source protects its audit ACL.
File-specific auditing is not detected or promised to carry forward. The UI must
provide the agreed nonblocking audit-inheritance warning without claiming
custom rules were detected.

The empty candidate's security must equal the accepted fingerprint before
`WriteFile`. Bytes are written through that owned handle, flushed using
`FlushFileBuffers`, and then hashed and security-checked again. Security mismatch
before writing can leave an empty, securely created candidate. A later failure
can leave a partially/fully written candidate; callers must validate ownership
before cleanup, never blindly delete a destination on any failure.

`move-no-replace` holds a source handle with share-read/share-delete, denies data
writers, and checks identity/content/security before `MoveFileExW(..., 0)`.
It checks the destination and held object afterward and returns the moved
descriptor. Existing destinations are never overwritten. There is no exists-check
followed by an overwriting rename.

**Limits:** the rename API is path-based. Another actor with delete/rename or
directory/security authority can still swap the source path/ancestors between
validation and the move, or change security during an operation. Postchecks
detect some races but cannot undo them. This is not CAS, an atomic two-file
transaction, a power-loss guarantee, or a complete metadata clone. A failed move
postcheck can mean the move already happened; the coordinator must inspect
transaction state before recovery. Deadline/commit gating, rollback/recovery,
watcher coordination, and the missing-active interval belong to Node.

| Exit | New-action meaning |
| --- | --- |
| `0` | One descriptor JSON line; empty stderr |
| `3` | `PoolingConflictException` for an expected/state mismatch, or `Win32Exception` with native `80`/`183` for an existing destination |
| `1` | Policy, request, I/O, access, or other failure |

Failures have empty stdout. Stderr is exactly `MCPERR type=<exception type>` and,
for a `Win32Exception`, a second line `MCPERR nativeError=<integer>`. Relevant
types are `PoolingPolicyException` (unsupported or mismatched creation security),
`PoolingConflictException`, `Win32Exception`, `ArgumentException`,
`FormatException`, `DecoderFallbackException`, and `IOException`. Native `5` is
access denied; `32` is a sharing violation; `2`/`3` are missing path components.
No exception messages, paths, token information, config bytes, or descriptors are
printed. Legacy stale-security conflicts retain their empty-stderr behavior.

### Legacy compatibility

`inspect` and `copy` remain available with their existing contract:

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

The build uses `/noconfig /nostdlib+` with explicit `mscorlib.dll`, `System.dll`,
`System.Core.dll`, and `System.Web.Extensions.dll` references. JSON serialization
uses .NET Framework's built-in `JavaScriptSerializer`, not an npm dependency.
Sources are `AssemblyInfo.cs`, `PoolingSecurityReader.cs`,
`PoolingSecurityHelper.cs`, and `PoolingNativeFiles.cs`, with fixed options,
LF-normalized UTF-8 source, and mapped source paths.
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

## Targeted tests

```powershell
npm exec --no --offline --package=node@20.20.2 -- node --test test/windows-security-helper.test.mjs test/windows-batch-security.test.mjs
npm exec --no --offline --package=node@22.23.2 -- node --test test/windows-security-helper.test.mjs test/windows-batch-security.test.mjs
```

The real-helper tests cover descriptor stability, full-byte staging, exact 1 MiB
bounds, stale identity/revision/security, malformed/bounded input, held writers,
hard links, and both collision points. There are no successful-path mocks.

The isolated `TEST-SETUP` audit fixture requires an audit-reading oracle token
and an existing Explorer window. Otherwise that one test explicitly skips.
It launches the **same Node executable** through Explorer, verifies medium
integrity and absence of SeSecurityPrivilege, then runs the packaged helper
directly. The elevated oracle separately verifies raw DACL/group/labels,
owner rules, unchanged failed sources, and the retained original's complete
audit descriptor. The mixed audit case retains one explicit plus one inherited
source rule on `previous`; its new candidate has only the parent's inherited
rule. A protected audit source also permits folder inheritance on the candidate.
An incompatible inherited label must leave the candidate empty.

`test/fixtures/windows-batch-security/FixturePolicy.cs` is compiled only by
TEST-SETUP to establish synthetic raw DACLs and labels; it is not linked into,
loaded by, or shipped as a dependency of the production helper. All fixture
policy changes are confined to a fresh owned temporary directory, removed by
the test. No live files, tasks, bridge, or token privileges are changed.
