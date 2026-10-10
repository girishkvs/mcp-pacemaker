# User-runtime execution contracts

The default runtime is an ordinary process belonging to its user. Starting the
bridge or supervisor, registering autostart, upgrading and recovering do not
silently elevate, demote, impersonate or select another account. An unavailable
or privileged context refuses before runtime work. Read-only planning and
installation with both `--no-start` and `--no-autostart` remain separate.

`bin/runtime-context.mjs` is the shared observation boundary:

| Platform | Required effective context |
| --- | --- |
| Windows | The existing native ordinary-caller proof: no elevation, enabled administrator membership or observed thread impersonation |
| Linux | Stable non-root real/effective IDs, matching saved/filesystem IDs, and zero inherited/permitted/effective/ambient capabilities |
| macOS | Stable non-root real/effective user IDs and matching real/effective group IDs |

These are snapshots, not a promise that a process can never change context.
The guard does not grant access to an arbitrary installation. Existing instance,
file-security, service-registration and account-authorization checks still apply.
Explicit original-account administration remains the separate Windows-only
capability described in [account upgrades](account-upgrades.md).

## Test contracts

`tools/ci/test-contracts.mjs` declares the execution role, command and required
capabilities. It verifies that the source contract includes every registered
source test and preserves the declared test concurrency.

| Contract | Required role and coverage |
| --- | --- |
| `source` | Ordinary runtime; complete registered source suite. Windows also needs the real caller's WTS logon because its account/session tests use that API. |
| `source-ordinary` | Windows only. Ordinary runtime without a logon session; every registered file except the four in `SESSION_REQUIRED_TESTS`. The two Windows lanes must together cover every registered file exactly once. |
| `compatibility` | Ordinary runtime; complete CLI/API compatibility command |
| `browser` | Ordinary runtime; declared browser compatibility command |
| `audit` | Verified privileged Windows fixture; the unchanged mandatory audit test, including its ordinary worker and complete result checks |
| `service-context` | Read-only capability observation; **not** test coverage |

Run the same entry point locally or in CI:

```text
npm run test:contract -- plan
npm run test:contract -- source --check
npm run test:contract -- source
npm run test:contract -- compatibility
npm run test:contract -- service-context --check
```

The service-context observation uses the current user's WTS session on Windows,
owned `/run/user/<uid>` and user `systemd` manager on Linux, or the caller's `gui`
launchd domain on macOS. A CLI-only or browser contract does not require a desktop
merely for consistency with Windows.

No adapter creates a user or session, changes UAC, edits privileges, rewrites a
token, or falls back to another identity. Setup capability and ordinary runtime
capability are not interchangeable. A missing required capability is a blocked
qualification, not a successful skip.

Windows integration fixtures also need a private checkout, home and temporary
tree whose ancestors satisfy the existing path-security checks. A shared writable
drive can correctly fail with `UNTRUSTED_PATH_WRITER` even when the process is
ordinary. Use short, trusted profile-owned test roots: the nested upgrade packages
must remain within the native .NET executable path limits, not just Node's file
API limits. Do not change drive ACLs, enable long-path policy or relax the native
checks to make an unsuitable test root pass.

## CI and release boundaries

The public workflow separates three roles rather than assuming an OS label implies a runtime.

| Lane | Runner | What it proves |
| --- | --- | --- |
| `test (ubuntu-latest\|macos-latest, 20\|22\|24)` | Stock hosted | Ordinary user-runtime source and compatibility suites |
| `windows-ordinary (20\|22\|24)` | Stock hosted Windows | Install, syntax, pinned native toolchain, three reproducible native builds, the actual refusal of an elevated built-in Administrator, then the `source-ordinary` and `compatibility` contracts run as a provisioned disposable standard account |
| Windows session lane | Ordinary interactive Windows session | The four `SESSION_REQUIRED_TESTS` files, through the local publication gate |

A stock hosted Windows runner signs in as the built-in Administrator with a full elevated token, and
Task Scheduler ignores `RunLevel` for that account, so that account cannot host the ordinary
user-runtime contract. The lane therefore does not try to demote it. It provisions a disposable
standard account, which is never an administrator, and runs the suite as that account. It also
proves the elevated refusal itself, and `tools/ci/windows-runner-role.mjs` fails loudly if a Windows
runner ever does satisfy the ordinary contract, so real coverage is promoted rather than left
unexecuted.

A provisioned account signs in with a password logon and has no interactive logon session, so the
four `SESSION_REQUIRED_TESTS` files that bind one stay in the session lane. They are still required,
not skipped: `tools/npm-publication/local-gate.mjs` runs the complete source suite for the current
release and requires `role: user-runtime` with `sessionVerified: true`. A Windows container without a
real logged-on account cannot satisfy that, and neither can a hosted job. `testContract` asserts the
two Windows lanes cover every registered file exactly once, so no file can fall out of both.

The CI provider bounds job lifetime and owns job teardown; the contract entry
point does not claim to provide VM or network isolation.

The local command forwards cancellation to its owned test child and waits for
exit/output closure, escalating termination after five seconds. Unverified
closure after another five seconds is an error, not successful cleanup. Source
tests retain a 60-minute command budget and compatibility tests a 45-minute budget;
the audit keeps its existing 210-second budget and a 16 MiB output limit.
Windows commands also use the existing native process-lifetime mechanism.
None of these command bounds changes application startup or shutdown deadlines.

No integration runner is provisioned by this change. An approved environment
must already supply the required ordinary identity and session. Do not attach a
personal workstation or unrestricted persistent runner to public pull requests.
Runner admission, trusted-source selection, disposable-machine isolation and
credential policy require independent infrastructure approval.

The existing exact-source CI and local publication requirements remain enforced.
The local source gate invokes the same read-only preflight and its verifier
requires that original command receipt. A Windows container without WTS cannot
stand in for an interactive user session. The privileged audit companion remains
required and cannot replace the source suite. No missing integration result is
relabelled as a pass.
