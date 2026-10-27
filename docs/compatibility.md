# Version compatibility

How the 1.3.x and 2.x lines work together. For npm channels and exact-version installs, see
[install details](install.md). To replace a running installation, see
[upgrades and rollback](upgrades.md).

This documentation describes **2.1.2**. For 1.3.x immediate-save behavior, see the
[legacy documentation](https://github.com/girishkvs/mcp-pacemaker/blob/v1.3.1/README.md)
and [support policy](../SECURITY.md#supported-versions). Those documents do not establish
that a legacy version is available on npm.

The historical baselines remain **1.3.0 / 2.0.0**. The earlier **1.3.1 / 2.0.1** and
**1.3.1 / 2.0.2** patch-pair evidence is not transferable to a new release. The **2.1.2**
candidate requires fresh exact-byte compatibility and service-replacement gates.
A 2.x client handles legacy immediate saves. A 1.x client cannot write pooling settings to a
2.x bridge: update the CLI and refresh old dashboard tabs. Before downgrading, settle pending
or interrupted transactions with 2.x. See the [real-version gates](../CONTRIBUTING.md#real-version-compatibility-gates)
for exact pairs; only the exact executed pairs are covered.

## Upgrading from 1.3.0

Version 2.0.0 changes the configuration-save protocol; it does not require a new `servers.json`
format. Update the bridge and CLI together, then reload any open dashboard pages. A 1.3.0
client with a current nonce gets HTTP 409 before staging, with an instruction to update the
client. An already-open tab retains the old nonce after a bridge restart and gets HTTP 401;
refresh it to load the new dashboard and admin session.

Custom API clients must send `x-mcp-pooling-batch: 1`. Treat HTTP 202 as acceptance, not
completion, and follow the returned batch ID in `prewarm.batches` until it is applied,
cancelled or failed. CLI scripts must likewise wait for application before relying on new
settings. Undo now restores the complete batch and may affect several servers.
Updated clients still understand the immediate HTTP 200 response from a 1.3.0 bridge.

Before downgrading, cancel or apply pending changes with 2.0 and resolve any interrupted
transaction using 2.0 recovery. Stop that bridge before starting 1.3.0 with the active config.
Do not use a 1.3.0 binary to recover 2.0 transaction files or delete those files to bypass a
recovery error. Keep a protected backup of the configuration before changing versions.
If the writer worker exits, further automatic edits are refused until the bridge restarts;
existing MCP sessions continue.
