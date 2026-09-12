# Contributing

Thanks for taking a look. This is a small, deliberately dependency-light project, so a few
constraints matter more than they might elsewhere.

## Getting set up

```bash
git clone https://github.com/girishkvs/mcp-pacemaker
cd mcp-pacemaker
npm ci
npm test
```

Node 20 or newer. The bridge itself (`bin/mcp-bridge.mjs`) has **zero npm runtime dependencies**
and must stay that way; it runs 24/7 on a developer's machine and its dependency surface is
part of its security posture. The setup CLI and the dashboard may use dependencies.

## Lockfiles must resolve to the public registry

CI fails any lockfile containing a `resolved` URL outside `registry.npmjs.org`. If you work
behind a private mirror, re-resolve before committing:

```bash
npm install --registry https://registry.npmjs.org
```

## Tests

```bash
npm test
```

Tests are `node:test` only, no framework. Each test file that starts a bridge owns its own
ports, because files run in parallel; the current allocation is listed at the top of
`test/auth-token.test.mjs`. Pick unused ones for a new file.

Windows configuration-write coverage must exercise the normal interactive startup token,
not only a test process inheriting an elevated runner. Validate both the actual token context
and successful staging/activation. Security-oracle fixtures may use already-authorized test
authority to establish and inspect their own files; production saves must not depend on it.
Directory-inherited auditing is the default. Test ordinary access restrictions, integrity,
custom-audit behavior, contender files and crash recovery separately.

Windows automatic edits use the packaged .NET Framework 4.6.2 helper. Changes to its source
must rebuild the executable and metadata with
`tools/windows-security-helper/build.ps1`, then pass `-Verify` with the recorded compiler
and reference assemblies. See the [helper build instructions](tools/windows-security-helper/README.md).
The portable Node suite checks normalized source/build-script and binary hashes on every CI
platform; Windows also exercises the real executable. Those checks do not replace the
byte-for-byte rebuild, and a rolling CI image may not contain the recorded compiler.
No compiler or PowerShell host runs in the production config-write path.

Batch tests must cover the full five-second trailing debounce, merging complete snapshots,
Reload now, requests during a flip, stale active revisions, whole-batch Cancel/Undo and late
commit outcomes. Use controlled clocks for scheduling boundaries and real file/HTTP cases for
integration. A skipped second move is not proof of recovery after actual process termination.

**A regression test must be shown to fail without its fix.** Revert the fix, watch the test
fail, restore it, watch it pass. Several bugs in this repo were originally "covered" by tests
that passed against the broken code — a test that cannot fail is worse than no test, because
it also stops anyone else from looking. If a bug involves process lifetime or timing, prefer
observing a real signal (a heartbeat file, a recorded request) over enumerating processes or
sleeping a fixed interval.

## Real-version compatibility gates

These are separate, mandatory CI gates, not substitutes for `npm test`. The root CI job runs
CLI/API pairs on Windows, Linux and macOS with Node 20 and 22. The existing Linux/Node 22 UI
job runs one Chromium browser matrix after building the dashboard.

```bash
npm ci
npm run compat:prepare
npm run test:compat
npm run compat:clean

# Browser gate: build before packing the candidate.
npm --prefix ui ci
npm --prefix ui run build
cd ui
npx --no-install playwright install --with-deps chromium
cd ..
npm run compat:prepare
npm run test:compat:browser
npm run compat:clean
```

For an already installed local Chrome, set `MCP_COMPAT_BROWSER_CHANNEL=chrome` in your shell
instead of installing bundled Chromium. CI uses bundled Chromium, not that override.
Both standalone test commands **fail** when preparation is missing or candidate bytes have
changed. Clean and prepare again after changing package files, built assets, or Node major.

Scope is **only 1.3.0 and 2.0.0**. Preparation archives immutable published commit
`649a19908ed88461460cb264810a90a3963b009e` for 1.3.0. If a shallow checkout lacks it, the tool
fetches that exact SHA read-only into a separate temporary Git repository; it never follows
a tag or modifies checkout refs. Git, tar, Node and npm must be available. The candidate is
created by `npm pack --ignore-scripts`, extracted, and installed with the candidate's exact
source lockfile via `npm ci --omit=dev --ignore-scripts`. Legacy dependencies use its own
unchanged lockfile and the same install command. Registry URLs must remain public; npm's
normal integrity-checked cache can be reused. The prepared manifest records source/packed
file hashes, tarball hash, legacy reference and Node major.

For local restores through an approved registry, preparation honors the caller's resolved
`npm_config_registry` and `npm_config_replace_registry_host` settings (and npm cache).
For example, in a POSIX shell:

```bash
npm_config_registry=https://approved-registry.example.test/npm/ \
npm_config_replace_registry_host=npmjs npm run compat:prepare
```

Use your approved registry URL, not the example. These settings are forwarded to isolated
`npm ci` calls without changing npmrc files or recording registry settings in the manifest.
CI sets no override and uses the public registry. Both committed lockfiles and the fixture
lockfiles must retain public URLs; preparation verifies that restore leaves fixture locks
byte-identical. Registry policy or quarantine rejections fail preparation without a fallback.

Fixtures, private baseline code, configuration and fake HOME/state live in owned OS temporary
directories, never the user's active configuration. Only a manifest pointer is kept under
ignored `node_modules/.cache`. This manifest is also the prepared fixture's ownership marker:
it is created before restore, keeps its identity when preparation finishes, and is removed
only after its temporary tree is gone. A failed manifest unlink remains retryable. Other
temporary test directories use adjacent ownership markers. Ports are allocated dynamically.
Cleanup checks directory and marker identities and removes only owned files without following
links. Bridge/browser failures retain their original error and diagnostic logs in test output;
cleanup errors do not replace
the original failure. Run cleanup before another root `npm ci`, which removes the pointer.

| Pair/case | Required result |
|---|---|
| 2.0.0 CLI/API and built UI → 1.3.0 backend | Legacy HTTP 200 enable and Undo; original config bytes restored |
| 1.3.0 CLI/API and built UI → 2.0.0 backend, fresh nonce | Protocol HTTP 409, no queued write or config change |
| Already-open 1.3.0 tab through an actual bridge restart | Old nonce gets HTTP 401; refresh loads 2.0.0 and can stage/cancel |
| 2.0.0 CLI and UI → 2.0.0 backend | Queued save, Cancel, actual application and whole-batch Undo |
| Settled 1.3.0 → 2.0.0 → 1.3.0 configuration | 2.0.0 edits/Undo and both restarts preserve the expected active bytes |
| Actual 1.3.0 writes before and after that roundtrip, unchanged authority | Supported write/Undo must remain supported; known Windows audit-unavailable refusal must remain HTTP 403 with no change |

**Test-only UI asset serving:** the two mixed UI/backend cases serve exact old/new built
`ui/dist` files through Playwright, substituting only the current nonce in the HTML. All
API, admin mutation, SSE and MCP requests go to the real backend, without response mocks.
Nested JS assets are included. The old-tab upgrade case does not substitute assets: it stops
the actual 1.3.0 process and starts the packed 2.0.0 process on the same port before refresh.

No other minor-version compatibility is claimed. Writable downgrade is checked on a fresh
synthetic config with default ownership and inherited security. The test does not change
tokens, elevate, or set ACLs. It checks unchanged caller authority and, on Windows, the actual
1.3.0 helper's full/partial audit visibility. Caller-context hashes are not direct measurements
of individual bridge tokens. Only the legacy HTTP 403 audit-unavailable
condition is accepted as unsupported; unexpected errors and any new HTTP 500 fail the gate.
The Windows 2.0.0 writer retains a source owner matching the caller user or token default
owner; other owners still use checked transfer, and source write access remains required.
These gates do not test a downgrade with an unresolved transaction, installer/service
replacement, arbitrary Windows ACLs or authority changes, or all host integrations; their
separate tests and operational checks still apply.

## Changing how a host is wired

Host adapters live in `HOSTS` in `bin/cli.mjs`. Each one declares where that host's config
lives, the JSON key its servers sit under, and how a bridged entry is serialized. When you add
or change one:

- Add a case to `test/cli.test.mjs` asserting the exact entry shape.
- Never write a host config without backing it up first, and make sure `plan` reports the
  change accurately — it is what people rely on before letting the tool touch their setup.
- Re-run `mcp-pacemaker plan` against a real config afterwards. It should report no changes
  for a setup that is already correctly wired; anything else means the adapter and the
  reconciliation logic disagree.

## Pull requests

- One concern per PR.
- Explain what broke and how you proved it fixed, not just what you changed.
- Comment only what needs clarifying — why something is done a particular way, not what the
  line does.
- Update `CHANGELOG.md` under an `Unreleased` heading.
