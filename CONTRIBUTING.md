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

The complete Windows suite needs audit-read rights for successful configuration-write cases.
Security-specific fixtures modify only their own temporary files. Automatic writes deliberately
fail closed when audit policy is unreadable; the suite also exercises that restricted path.

Windows automatic edits use the packaged .NET Framework 4.6.2 helper. Changes to its source
must rebuild the executable and metadata with
`tools/windows-security-helper/build.ps1`, then pass `-Verify` with the recorded compiler
and reference assemblies. See the [helper build instructions](tools/windows-security-helper/README.md).
The portable Node suite checks normalized source/build-script and binary hashes on every CI
platform; Windows also exercises the real executable. Those checks do not replace the
byte-for-byte rebuild, and a rolling CI image may not contain the recorded compiler.
No compiler or PowerShell host runs in the production config-write path.

**A regression test must be shown to fail without its fix.** Revert the fix, watch the test
fail, restore it, watch it pass. Several bugs in this repo were originally "covered" by tests
that passed against the broken code — a test that cannot fail is worse than no test, because
it also stops anyone else from looking. If a bug involves process lifetime or timing, prefer
observing a real signal (a heartbeat file, a recorded request) over enumerating processes or
sleeping a fixed interval.

## Real-version compatibility gates

These gates run actual legacy/current CLI, API and built dashboard code, not mocked backend
responses. Scope is explicitly **1.3.0, 1.3.1, 2.0.0 and 2.0.1**. The maintained branches use
the same harness, with exact version assertions and separate historical evidence.

| Preparation | Selected legacy / current pair |
|---|---|
| Default in this 1.3.1 checkout | Packed 1.3.1 / immutable 2.0.0 |
| Default in the 2.0.1 checkout | Immutable 1.3.0 / packed 2.0.1 |
| `npm run compat:prepare:baseline` | Immutable 1.3.0 / immutable 2.0.0 |
| `npm run compat:prepare -- --peer-root <opposite-patch-checkout>` | Packed 1.3.1 / packed 2.0.1 |

```bash
npm run compat:prepare
npm run test:compat
npm run compat:clean

npm --prefix ui run build
# Install the existing Playwright Chromium browser from the ui directory for CI.
# A local run can instead set MCP_COMPAT_BROWSER_CHANNEL=chrome.
npm run compat:prepare
npm run test:compat:browser
npm run compat:clean
```

Run both gates for the explicit patch pair before publishing the complete dual-major set;
the default per-branch pairs alone do not establish that result. Run cleanup before selecting
another pair or performing `npm ci`. CI covers Windows/Linux/macOS with Node 20/22/24 and a
Linux/Node 22 Chromium lane. Node 20 is legacy runtime compatibility, not a supported secure runtime.

Publication artifact gates add `--candidate-tarball <absolute.tgz> --candidate-sha256 <digest>`.
This supplies the checkout's own candidate role without repacking it: here that is the legacy
1.3.1 role. Complete input hashes and the archive digest must match; historical mode cannot
substitute a patch. The manifest also records the exact npm CLI version.

Historical sources are pinned to `2d525f4ced01b978a5aeb83aef69145e96cced05` (1.3.0) and
`db4812a1cbfb8546c814a656397b9a48ccf0f32c` (2.0.0). Missing commits are fetched read-only by
exact SHA into an owned temporary repository. Archives honor canonical Git line endings and
committed attributes. Local candidates are packed without lifecycle scripts, compared against
their source files, and restored using their own unchanged producer locks. Caller-resolved
registry/cache settings are honored without a fallback; locks must retain public URLs.

The manifest records selection mode, exact versions and references, each archive/file hash,
candidate inputs and Node major. Editing either candidate invalidates preparation. Owned
temporary HOME/config/ports keep the user's state isolated. Identity-checked cleanup never
follows links or claims another directory. Failed cleanup remains retryable.

The selected 2.x client must preserve immediate 1.x HTTP 200 saves/Undo. The selected 1.x
client gets HTTP 409 from 2.x with a fresh nonce, or HTTP 401 after a real restart with a stale
nonce; refresh must load the selected new assets. The 2.x cases require HTTP 202 pending
receipts, actual activation, cancellation and whole-batch Undo. Settled downgrade checks
active bytes, instance changes and unchanged caller authority. Known Windows audit-unavailable
legacy HTTP 403 must remain unchanged; it is not counted as a successful legacy write.
Unresolved transactions, arbitrary ACL changes and OS-service installation are separate gates.

## npm consumer validation

`npm run consumer:check -- --tarball <absolute-file> --sha256 <digest> --version 1.3.1 --name mcp-pacemaker`
uses an owned disposable project and a separate global prefix. It does not copy the producer
lock: it records fresh dependency resolution, checks the installed command shim and exercises
the packaged bridge, CLI and UI assets with synthetic servers/private state.

Run with normal npm install-script policy and again with `--ignore-scripts`. Caller registry,
cache and offline settings are honored, but user credentials and real host configuration are
not used. Registry signatures and provenance remain separate post-publication checks.

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
