# Install details

The [quick start](../README.md#quick-start) has the short version. This page has the full
requirements, the ordinary-user rule, npm channels and where to install.

Use a maintained **Node.js 22 or 24** release. Node 20 remains a compatibility target but is
end-of-life, not a recommended secure runtime. The bridge has no npm runtime dependencies;
the setup CLI and dashboard have their own dependencies.

**Run as an ordinary user.** From 2.1.0 the bridge, supervisor and default upgrades verify the
caller before any runtime work and refuse elevated or root callers at startup with
`User-runtime execution refused: …`. On Linux and macOS that includes `root`, which is the
default user in most container images, so run the bridge as a normal account there. The
[user-runtime contract](execution-context.md) describes what is checked and why; explicit
Windows account administration has a separate
[controller/worker path](account-upgrades.md).

Install the released package from [npm](https://www.npmjs.com/package/mcp-pacemaker).
Its repository link should point to
[`girishkvs/mcp-pacemaker`](https://github.com/girishkvs/mcp-pacemaker).
Use an exact version for a repeatable installation:

```bash
npm view mcp-pacemaker@2.1.2 version
npm install -g mcp-pacemaker@2.1.2
mcp-pacemaker --version
```

The current line uses the `latest` npm channel; the maintenance line uses `legacy` when that
channel has been published. Check the actual registry values before choosing a channel:

```bash
npm view mcp-pacemaker dist-tags --json
```

GitHub tags and npm publication are separate: a tag does not establish that the same
version or channel is available on npm, or that its package bytes are identical.
`@1` and `@2` are version ranges, not the maintained channels. They can select a version
withdrawn from a channel. `upgrade --self` resolves the installed major's channel and prints
an exact-version command; it never installs or downgrades anything.

Use a durable installation directory for a long-running service. Do not register autostart
from an `npx` cache: that cache may be removed later. Bare CLI invocation can enter the setup
wizard; use `--version` for a read-only installation check.

Windows setup also needs PowerShell 7 (`pwsh`) and Windows Script Host for its launcher.
Automatic configuration edits need .NET Framework 4.6.2 or newer. The bundled helper is
unsigned; npm provenance is not Authenticode signing or an application-control allowlist.
Windows ARM64 is not validated.

For version pairs and downgrades, see [version compatibility](compatibility.md). To replace a
running installation, see [upgrades and rollback](upgrades.md).
