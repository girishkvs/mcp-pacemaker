# Upgrades and rollback

How to replace a running installation, run a new version beside the old one with `--sxs`,
recover an interrupted upgrade, and move a Windows 1.3.0 installation. The
[README](../README.md#upgrades) has the short version.

## What an upgrade keeps and what it ends

An upgrade restarts Pacemaker. It may end open sessions and calls in progress: clients
reconnect to the new version, and no call is retried. It never changes `servers.json` (the
server list and every server's settings stay exactly as they were) or your client setup.
Of everything clients and the dashboard do, only unfinished config work, such as a pooling
change still being saved or an unresolved config transaction, makes an upgrade refuse. A
refused upgrade puts the current version back in service; let the work finish and retry. If
that work is still settling, the upgrader keeps trying to resume the current version for up
to ten seconds. If it still cannot, the current version stays paused until
`mcp-pacemaker upgrade --recover --instance <directory> --yes` succeeds (for an
[explicit-account](account-upgrades.md) install,
`mcp-pacemaker --user <SID> --instance <directory> upgrade --recover`).

An upgrade is run by the installed version's CLI, so these rules apply from 2.1.1. A 2.1.0
bridge still refuses while any session is open, and after any client has dropped a stream.
To upgrade from 2.1.0, close your MCP clients, restart Pacemaker (`mcp-pacemaker stop`, then
`mcp-pacemaker start`) and run the upgrade before reconnecting them.

Versions before 2.1.1 also compare the session records (`sessions.json`) when they start.
Moving to one of them is refused before the download if that file is over 1 MiB, and rolls
back if the file cannot be read once the old version has stopped.

## Replacing or rolling back a running installation

These managed-upgrade commands require **2.1.0 or newer**.
Version 2.0.2 does not include them.

Run the bridge, supervisor, default upgrades and recovery as an **ordinary user**:
a normal, non-administrator terminal on Windows and a non-root session on Linux/macOS.
The [user-runtime contract](execution-context.md) rejects privileged or
unverified callers before runtime work, so a replacement does not inherit different
authority. Read-only plans remain available. Explicit Windows account administration has a separate
[controller/worker path and qualification requirements](account-upgrades.md).

For a **stable managed instance created by this implementation**:

```bash
mcp-pacemaker upgrade --to <exact-version> --plan
mcp-pacemaker upgrade --to <exact-version>
# Noninteractive confirmation of the displayed local plan:
mcp-pacemaker upgrade --to <exact-version> --yes

# Keep the existing service and host wiring:
mcp-pacemaker upgrade --to <exact-version> --sxs
mcp-pacemaker upgrade --to <exact-version> --sxs --port 9001
```

`--to` requires canonical stable SemVer, not `latest`, a range, or a Git/file spec.
Selecting another major is explicit and printed in the plan; it is not a compatibility
claim. The target must ship the managed admission/readiness protocol. Older targets
without that protocol are rejected before interruption, including for automatic SxS ports.

Normal upgrades preserve the selected port: `--port` is valid **only with `--sxs`**.
Without an SxS port, the actual new loopback listener binds port 0 and stays open;
the OS-selected port is displayed and saved for later starts. The read-only plan says
“OS-assigned,” not a guessed port. An explicitly requested busy port fails without adoption.
SxS gets separate config, nonce, logs and session files. It preserves the source working
directory for relative server commands and does not rewire any host or enable pooling.

When discovery finds multiple instances, use the exact directory printed by setup/upgrade:

```bash
mcp-pacemaker upgrade --instance <directory> --to <exact-version> --plan
mcp-pacemaker start --instance <directory>
mcp-pacemaker stop --instance <directory>
```

`--instance <directory>` and `--instance=<directory>` work before or after the
command. Selection is normalized once, including paths with spaces; conflicting
selectors or port/config overrides are rejected before an action. Text after `--`
is not interpreted as a selector. An invalid explicit selection never falls back
to the default instance.
CLI port options use canonical decimal integers from 1 to 65535; scientific notation, hex,
signs, surrounding whitespace and zero-padded spellings are rejected before requests.

Selected `start`, `stop`, `reload`, `prewarm`, `status`, `doctor`, `top`, `logs`,
`dashboard`, version/help, and upgrade commands use the same instance context.
The TUI's recycle key uses that instance's port **and nonce directory**; logs use
its config directory. Bare `mcp-pacemaker --instance <directory>` shows status
even when SxS has no host-wiring state. Host setup/removal commands (`init`,
`import`, `install`, `uninstall`) are refused with `--instance`; selection alone
does not authorize rewriting host configuration or changing autostart.
Generated prewarm Cancel/Undo commands retain the selected instance and config,
so they resolve the same CLI version and nonce directory. Windows commands use
an encoded PowerShell launcher with an explicit native argument list to preserve
spaces, quotes and shell characters; unmanaged `--config` commands remain supported.

The stable per-instance launcher selects checked version directories. Upgrades never
overwrite a running package or rewrite per-version autostart tasks. The previous selection
and package are retained. The existing command entry point dispatches to the committed
version's CLI and its own dependencies: ordinary `--version`, `status`, `update-check`
and the next `upgrade` use that version. An unfinished activation keeps the previous
CLI available for recovery; rollback restores that CLI selection. SxS does not change
the default CLI. Use `--instance <directory>` to select its CLI explicitly.

From 2.1.1 a target ships the SHA-512 dependency lock it was released and tested with
(`bin/dependency-lock.json`, declared by `dependencyLock` in `bin/upgrade-capability.json`).
The upgrader installs exactly that lock with `npm ci`, so registry metadata cannot change
the staged dependency set, and mirrors that publish only SHA-1 checksums work. Its entries
name the public registry, which npm maps to your configured registry as it does for any
lock, including through a `replace-registry-host` URL-prefix mapping. When that setting is
`never` or names only another host, the upgrader points each entry at the registry that
resolving it would have used: your configured registry, or a package scope's registry.
Older targets without that lock have their dependencies resolved into a private lock as
before. Both the lock and installed
dependency files enter the checked version inventory, and npm verifies every archive before
interruption. Target CLI startup and version are checked before quiescing.
The target archive and every CLI dependency archive require SHA-512 integrity. A resolved
lock with SHA-1-only or missing integrity is rejected before interruption and names the
package; the upgrader does not downgrade its checks to accommodate a registry.
Acquisition uses the configured npm registry, or explicit
`--registry`, with no registry fallback or global npm changes. Existing npm permissions,
TLS, release-age policy and URL-prefix mapping remain in effect; lifecycle scripts are
disabled for acquisition. For npm 12 mirrors, use your approved command-local
`replace-registry-host` full-URL-prefix mapping back through that registry—not a
hard-coded mirror URL or public-registry bypass.

Download, archive integrity, package/engine/native-binary checks and an owned packaged
startup check finish before interruption. Admission then closes, and calls in progress and
config work get up to eight seconds to finish. A call made over the older SSE transport is
answered on its stream, so it gets no grace period. Open sessions, and calls still running
after that, end with the restart. Config work still unfinished then makes the upgrade
refuse, and the upgrader resumes the current version, trying for up to ten seconds while
that work settles; let the work finish and retry. No ended tool call or failed configuration
commit is replayed. This is a **short
restart**, not socket handoff or zero downtime. Clients and dashboard tabs may need a reload.

The supervisor persists admission hold **before** forwarding quiesce. A lost reply, bridge
crash or replacement child does not release it. After a definite refusal the upgrader
resumes the current version as described above; otherwise only explicit resume/recovery or a
verified activation opens admission again. Upgrade stop is tied to the drained generation;
any replacement generation must remain held.

The activation journal blocks unattended starts after an interrupted transition.
Selection and launch intent are separate durable transitions. A selected target that
was provably never launched can recover using the exact previous stopped-generation
receipt. After launch intent, an empty port alone is not shutdown proof.
Recovery parses bounded instance/journal identities before checking executable
bytes. It fully verifies and runs the retained recovery CLI, so a damaged or
missing target file cannot prevent a safe pre-launch rollback. A damaged previous
package, stale identity or unknown journal still causes a refusal.

| Journal state | Recovery boundary |
|---|---|
| Prepared / quiescing | Explicitly resume the matching previous service |
| Stopping | Reconcile the exact drained generation |
| Stopped / selecting / selected | Require the previous completed-stop receipt; the target has no launch intent |
| Launching | Require a new held generation and verified shutdown; no empty-port inference |
| Rollback-selecting / rollback-selected | Require the durable rollback stop proof before selecting/restarting previous code |
| Rollback-launching | Require proof for the newly launched previous generation; otherwise refuse |
| Admitting / admitting-rollback | Admission may have occurred; no automatic rollback |
| Committed / rolled-back / aborted | No interrupted activation remains |

Automatic rollback is restricted to startup failure before target admission, with
unchanged configuration bytes, identity and security and verified shutdown. If admission
may have occurred, recovery refuses rather than overwriting user state.

```bash
mcp-pacemaker upgrade --recover --instance <directory> --yes
```

A crash can leave `upgrade.lock`. Recovery does not steal it based on a reusable PID.
Verify the original upgrader has exited, preserve the journal, and remove only that
instance's lock before recovery. Keep packages, configuration and transaction files.
Journal writes are file-flushed and atomically renamed; Windows directory-entry
durability across power loss is not claimed.

## One-time Windows 1.3 restart migration

The normal `upgrade --to <exact-version>` confirmation also supports the exact known
**1.3.0 Windows supervisor/launcher and per-user task shape**, with one port in the
existing install state. Invoke an upgrade-capable CLI from a separate durable package;
do not overwrite the running 1.3 package first. `--plan` remains read-only.

This transition restarts **Pacemaker, not Windows**. The 1.3 supervisor, its bridge and the
processes the bridge started are stopped, so open sessions and calls in progress end; clients
reconnect to the new version and no call is retried. The confirmation says so. `--yes`
confirms the plan shown without a prompt; without it, an unattended invocation refuses.
Run the upgrade from a terminal that the 1.3 bridge did not start. An upgrade started from
inside its tree, for example through an MCP server's shell, would stop itself, so it is
refused before anything changes. Once a 2.1.1 or newer upgrade has run against a 1.3
install, use 2.1.1 or newer for later attempts; 2.1.0 does not accept its records.

### 1.3 installs set up from an administrator terminal

When 1.3's autostart was set up from an administrator terminal, Windows makes
Administrators the owner of the task and lets your account only read it. Files the
administrator terminal created are owned by Administrators too. The upgrade must run as an
ordinary user, so it cannot change them. Planning (and `--plan`) checks the task and the
1.3 `bin\cli.mjs` first and stops before any process capture, download or change. The
message names each item.

Run this once from an administrator terminal, then run the upgrade from a normal terminal:

```bash
mcp-pacemaker upgrade --fix-legacy-access --plan   # shows the change; changes nothing
mcp-pacemaker upgrade --fix-legacy-access          # asks, then applies it
```

It accepts only the exact 1.3 task and package that the upgrade accepts. It gives the task's
own run-as user full control of that task and makes that user the owner of the 1.3
`bin\cli.mjs`, nothing else. The task XML, triggers, run-as account and run level, the other
permission entries and the file contents stay the same and are checked afterwards. The task
keeps running as you, not elevated. Before it changes anything it records the previous
permissions in `legacy-upgrade\access-<time>.json` under the configuration directory. Other
missing permissions, such as delete rights on the file, are reported but not changed. Installs
set up from a normal terminal do not need this step.

Target package, CLI dependencies, native identities and packaged startup are verified
before downtime. A separate broker holds handles to the selected supervisor and bridge and
checks their identity. It does not list the bridge's session processes in the plan, because
a busy bridge starts and ends them every few seconds. Only the verified selected task is
held. Stop ends the supervisor first. Before it ends the bridge, it holds a handle to every
process under the bridge, because Node ends a process's direct children together with it
(1.3 runs each bare server command under `cmd.exe`) and their own children would otherwise
be left with no traceable parent. It then ends the bridge and stops everything it holds,
plus anything those processes started, up to 2048 processes. Each one is checked to have
exited. The supervisor and bridge must be proven stopped before the held target starts on
the same port; a process the bridge started that cannot be stopped is reported and left
running. It does not use a name/PID kill or assume task disable stopped the running
supervisor. Configuration, host wiring and port remain unchanged; the existing CLI entry
dispatches the newly selected managed CLI.

Preparation stays outside managed discovery until the instance identity and recovery
journal are durable; the prepared directory is then published together. A pre-journal
I/O failure leaves the old installation discoverable. Failed preparation is retained,
not guessed safe to delete. A terminal rolled-back/aborted candidate is excluded only
after its bounded journal and legacy-source binding validate, so damaged target files
do not prevent retrying the still-running legacy installation.

The task's **resource owner and full security descriptor** are separate from its run-as
account. Planning and every task operation require owner/group/DACL/SACL/integrity
inspection through Task Scheduler. If the required security read is denied or unsupported,
migration refuses before touching the task; it does not enable privileges or elevate.
Existing-task updates preserve security rather than reassigning its owner: they clear
only the temporary definition's embedded descriptor, pass no replacement security
descriptor, disable automatic principal-ACE edits, and verify the complete raw resource
descriptor again afterward. Protected backups retain the original raw descriptor and XML.
Restoration requires exact equality of all non-XML registration/security fields and
Task Scheduler-normalized XML, ignoring only the exact embedded
`Task/RegistrationInfo/SecurityDescriptor` representation. Raw revision preconditions,
backups and the actual returned XML/hash are not rewritten; other metadata or XML drift refuses.
Concurrent or uncertain security changes require inspection, not permission repair.
The resource owner may be the runtime user or canonical builtin Administrators;
that does not change the run-as account. Default scope remains **current user**,
but Windows execution and recovery require a freshly verified ordinary caller
before staging or mutation; an elevated or unverified caller refuses rather than
launching a runtime with different authority. Read-only planning is unchanged.
Explicit original-account administration uses a task-only
trusted controller and an original-user worker; see
[account upgrade scope and qualification](account-upgrades.md).
`--all-users` is explicitly unsupported.

The legacy receipt reports `legacyRootStopVerified`, `observedDescendantsStopped`,
`descendantsFound`, `descendantsStopped` and `treeCompleteness: "unproven"`. This is
**not** the modern Job Object complete-descendant proof: a process whose parent had already
exited before the upgrade cannot be traced to the bridge and is left running. Recovery's
read-only check proves only that the supervisor and bridge are gone. A plan made by 2.1.1 or
newer lists no other processes, so recovery of such a plan reports
`observedDescendantsStopped: false`. The new managed runtime contains future children from
birth.

Unknown package/task shapes, changed owner/generation/configuration, a supervisor or bridge
that did not stop, or a foreign listener prevent activation. A foreign listener is never
stopped. Original code and protected configuration/task backups are retained. A verified
pre-admission target failure can restore the original CLI and scoped task and verify a
fresh legacy backend; uncertain launch, registration or admission outcomes require
explicit recovery. No configuration is deleted or replayed.

| Legacy journal phase | Recovery boundary |
|---|---|
| `legacy-prepared` / `legacy-held` | Verify the original supervisor and bridge and unchanged config; restore only the recorded task hold |
| `legacy-holding` | Task write outcome may be unknown; inspect before recovery |
| `legacy-stopping` | Read-only check that the supervisor and bridge are gone; if either still runs, recovery refuses |
| `legacy-stopped` | Revalidate partial stop and free port before safe old-version rollback |
| `legacy-launching` / `legacy-wiring` | Require modern held-target shutdown proof; a closed port alone is insufficient |
| `legacy-admitting` | Traffic may have entered; no automatic rollback |
| Legacy rollback intent phases | An interrupted task/CLI/launch outcome is reported as uncertain, not retried blindly |
| `legacy-rolled-back` / `legacy-aborted` | Original installation remains selected; the staged managed candidate stays dormant |

A killed migration can also leave the profile's `legacy-upgrade/upgrade.lock`.
Verify that exact upgrader has exited before removing its lock; never steal it by PID
guessing. Preserve the journal and backup files.

This adapter does not support direct unregistered bridges, other legacy versions,
multiple legacy ports, Linux/macOS registrations, or legacy-source SxS. Targets must
declare `legacyRestartProtocol: 1`; older published targets without it refuse before
legacy downtime.

Managed SxS keeps its own verified package copy as well as separate runtime state.
If a crash happens during port-0 startup before the port is durably recorded, recovery
reports an unknown launch outcome rather than marking it safely aborted. Preserve
that instance and its journal until readiness or shutdown can be verified.

## Manual migration for older installations

For an older installation requiring a separately verified manual migration:

Do not overwrite a package directory while its supervisor or bridge is running. Workers and
native helpers can load later, and dashboard assets are read from disk: replacement can mix
old and new code even when the original process still reports its old version.

Identify the selected port, installation directory, configuration directory and OS autostart
entry first. Settle or cancel 2.x batches, recover interrupted transactions with 2.x, and keep
a protected configuration backup. Disable the selected autostart entry and stop its supervisor
and bridge before replacing files; prove they cannot restart during replacement. Keep the
known-good installation until the new backend's version and instance identity are confirmed.
Re-register the intended autostart path, refresh dashboard tabs, and confirm host wiring.

One global npm prefix holds one package version and its shared command names. Installing the
other major there replaces it. Separate ports do not isolate credentials, nonces, logs or
session files: manual side-by-side operation needs separate durable code roots and separate
configuration directories, plus separate host/HOME state for CLI-managed setup.
`init/import --config` selects a source host configuration, not an isolated runtime profile.
There is no package `--profile` or `MCP_HOME` switch; managed SxS uses explicit instance
directories instead. Do not use an unscoped stop/uninstall
operation when another instance must remain running.
