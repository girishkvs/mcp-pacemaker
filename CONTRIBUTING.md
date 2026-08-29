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

Node 20 or newer. The bridge itself (`bin/mcp-bridge.mjs`) has **zero runtime dependencies**
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

**A regression test must be shown to fail without its fix.** Revert the fix, watch the test
fail, restore it, watch it pass. Several bugs in this repo were originally "covered" by tests
that passed against the broken code — a test that cannot fail is worse than no test, because
it also stops anyone else from looking. If a bug involves process lifetime or timing, prefer
observing a real signal (a heartbeat file, a recorded request) over enumerating processes or
sleeping a fixed interval.

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
