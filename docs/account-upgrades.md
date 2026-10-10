# Explicit original-account upgrades on Windows

The default scope is **the current user**, even from an elevated terminal.
Scope does not authorize elevated runtime execution: without `--user`, Windows
upgrade and recovery require a freshly verified ordinary caller before staging
or mutation. Read-only planning remains available from an elevated terminal.
`--all-users` is not implemented. Selecting every host in `init` is not an
all-users installation, and managing one other user's instance does not convert
it into a machine service or LocalSystem service.

An explicit account operation requires a canonical numeric SID and exactly one
existing task or managed-instance selector:

```text
mcp-pacemaker --user <SID> --task <exact-task-path> upgrade --to <version> --plan
mcp-pacemaker --user <SID> --task <exact-task-path> upgrade --to <version>
mcp-pacemaker --user <SID> --instance <directory> upgrade --recover
```

### Supported option combinations

These limits apply whenever `--user` selects the task-controller path, including
an explicit selection of the current user's SID.

| Form | Explicit account behavior |
|---|---|
| `--user SID --task PATH upgrade --to VERSION [--plan]` | One existing legacy task; preserve its account and port |
| `--user SID --instance DIR upgrade --to VERSION [--plan]` | One registered managed instance |
| `--user SID --instance DIR upgrade --recover` | Recover only its recorded operation; interactive authorization remains required |
| `--sxs`, with or without `--port` | Unsupported; refuse before native/task discovery |
| `--port` without SxS | Unsupported; normal replacement preserves the selected port |
| Bare `upgrade` or `upgrade --self` | Unsupported in explicit account scope; select `--to` or `--recover` |
| Recovery with `--task`, `--to`, `--plan` or `--registry` | Unsupported; refuse rather than ignore or override an option |
| Both `--task` and `--instance`, `--config`, or `--all-users` | Refuse; no scope conversion or new registration is inferred |
| Execution with `--yes` | Refuse; it cannot replace the two interactive confirmations. With read-only `--to ... --plan`, it authorizes no write |

Selectors accept separate or equals syntax before or after `upgrade`.
Without `--user`, current-user commands include bare repair,
`--self` guidance, managed SxS with optional port, and selected-instance recovery.
No machine-wide or cross-account SxS task-creation path is added.

Another user requires an **already-elevated** administrator token, enabled
Administrators membership, and complete native authorization checks. Restricted,
AppContainer, impersonating or unverified cross-account contexts refuse.
No account label, saved administrator flag or group membership alone grants
authority. The product does not request UAC, enable privileges, impersonate,
supply passwords, create accounts or change existing permissions.

## Where code executes

Invoke the management CLI from an independently trusted installation. The
elevated controller never imports the target's CLI or recovery code and never
runs its Node/npm, dependency hooks, authentication commands or workloads.
Target records are bounded data. Elevated code roots with untrusted writers or
redirectable ancestors refuse; a hash does not turn writable code into trusted code.

Ordinary selected-CLI commands use a fresh native effective-context observation.
Only a non-elevated, non-administrator primary token plus a complete stable set
of held parent threads with no observed impersonation token can avoid the
administrator-path recursive root checks. Primary-token elevation alone is not
enough. Unknown, denied, changed or impersonating observations retain the strict
checks with a reason; unverified helper exit is fatal. Target JSON cannot select
this path. Package inventory verification still runs, and the observation does
not promise that the process can never change context afterward.

The existing task launches a bounded worker under its **unchanged original
principal, InteractiveToken logon type and run level**. That worker performs
staging, dependency acquisition, preflight, the existing same-user stop protocol,
runtime startup and rollback. Task Scheduler success is only correlation:
disabled tasks and `AllowDemandStart=false` do not prove a worker ran.
An eligible existing interactive session and actual authenticated worker are required.
Explicit account inspection also requires the selected user's profile facts from
`Win32_UserProfile`. An unavailable provider or unreadable profile stops the operation;
the adapter does not infer another user's profile from environment variables or repair WMI.
Only non-elevated (`RunLevel=0`) InteractiveToken registrations are supported;
other logon/run-level choices refuse rather than being converted.

The guard queries only the selected session. Full account-name resolution must
match the target SID; the session must be active or disconnected but still logged
on. Stable WTS snapshots bind its logon generation before bootstrap, after worker
connection and at each authorization. Missing, denied, changed or unmapped facts
refuse. The approval prompt is followed by another check before staging.
These are **point-in-time eligibility checks**, not held session ownership:
Windows does not atomically reserve that desktop across `RunEx`. Detected drift
aborts; no session is created, switched, disconnected or impersonated.

The selected task's owner may be its runtime user or canonical
`BUILTIN\Administrators` (`S-1-5-32-544`). Other accounts called “Administrator”
are not assumed privileged. Owner, group, DACL, SACL and integrity are captured,
bound and preserved independently from run-as identity. Missing, denied or
changed full security refuses; it is never repaired or relaxed.

## Controller capability and channel

The controller can only inspect/hold/repoint/restore/release the exact approved
registration. Paths, account, original XML/security and allowed variants are
sealed before worker requests. Worker data cannot select a different task,
executable, principal or privileged configuration write.

A separate query-only native guard owns one local pipe connection and retains
the actual worker PID/creation/token/session identity. It has no process-kill
interface. A protected per-operation manifest carries an ephemeral public key;
Node's built-in Ed25519 signatures bind a fresh challenge, operation digest,
guard-observed peer and monotonic request/response transcript. Private keys stay
in controller memory. There is no reconnect-by-PID or nonce-only fallback.
Signed replies also bind the checked session SID, ID and logon generation.
Peer identity is not loaded-code attestation; the fixed capability remains safe
even if an authenticated target-user worker lies.

Only new operation-directory/file/pipe security is established at creation.
The target must already be able to read the trusted bootstrap and traverse/read
the protected operation store. `--controller-root <existing-directory>` selects
an already suitable store; it does not install into Program Files or repair ACLs.
The default store parent is the controller's local application-data directory.
If its existing ancestors do not support the required target access/protection,
the operation refuses before stopping the backend.

Automatic triggers/restarts are held while deliberate demand start remains
possible. Manual/external task starts are not claimed suppressed. Conflicting
generations or revisions refuse. Because `IgnoreNew` can block a second task run
while the worker is active, verified legacy rollback launches the original
supervisor locally **inside the original-user worker**, not as the administrator.
Legacy captured roots and observed descendants are checked for the worker's
session before stop; native held-generation revalidation remains stop authority.
Excluded or unattributed historical processes are never session-query or kill targets.
The compact session request accepts at most 512 unique captured identities and
128 KiB of UTF-8. PID, FILETIME and current-account/session fields are checked
before discovery. Session queries use at most 32 exact IDs per batch and four
separate local CIM sessions, within the unchanged 15-second caller bound.
Missing, duplicate, stale or unexpected results refuse the whole operation.

## Failure and recovery

Declining the runtime-upgrade prompt after worker bootstrap restores the exact
pre-bootstrap task revision after fresh authorization. No staging or stop is
authorized by that decline. Failed authorization or restoration remains an
explicit uncertain outcome.

### Controller-only failure before instance publication

If bootstrap happened but automatic restoration failed before any managed
instance was published, **there is no automatic CLI recovery command for that
state**. `--instance <missing-directory>` cannot work, and explicit-account
`--task ... upgrade --recover` is unsupported. Do not create an instance record,
guess an operation, or edit target configuration to make either command run.

The error and `Recovery evidence:` output name the exact protected operation
directory. Keep both files:

- `manifest.json`: `document.initialTask` is the pre-bootstrap task snapshot;
  `document.binding.initialTaskRevision` binds it.
- `controller-journal.json`: `initial`, the last verified `current` revision,
  full task security, and the uncertain phase.

The supported path is **manual verified restoration of that exact task** by an
authorized operator using the existing Task Scheduler COM adapter/tooling:

1. Verify the protected evidence, task path, SID and initial revision agree.
   Missing or inconsistent evidence is a refusal, not permission to reconstruct it.
2. Re-establish the controller's required actual authority and fresh target
   SID/session/logon-generation eligibility. Saved token/session facts are not
   authorization; denied or changed checks remain blocking.
3. Read the actual task XML and complete security descriptor again. Reconcile
   it with the captured revisions before any write; do not overwrite an unknown
   intervening change.
4. Restore the saved initial definition using update-only registration while
   preserving the principal, logon type, run level and raw full descriptor.
   Re-read and verify the result. Importing XML alone or repairing permissions
   is not this procedure.

This manual path restores task registration only. It does not authorize runtime
stop/start, replay, account/session changes, or administrator writes to target
state. If those checks cannot be completed, retain the evidence and leave the
operation blocked.

Controller and worker journals share an operation ID but have separate authority.
Loss of the peer/channel ends privileged RPC; it does not authorize killing an
orphan worker. Uncertain task, stop, launch or admission outcomes remain explicit.
No unknown tool outcome is replayed.

Recovery requires the exact managed instance and its protected prior controller
record, fresh actor/task/account authorization and a new bootstrap/handshake.
The initial published legacy instance already contains that operation reference;
recovery does not depend on a later HOLD acknowledgement or administrator edits
to target state. The reference, protected manifest, controller record and target
config/port must agree. Settled committed, aborted and rolled-back transactions,
including their legacy forms, return without another worker or task mutation.
An old authorization flag is never reused. Existing stale-lock and uncertain-
admission refusals still apply; the controller does not edit target configuration
or force-remove its locks.

## Qualification boundary

Owned same-user pipe/process tests exercise the real query-only guard and worker.
The production Task Scheduler adapters are separately exercised against injected
COM objects. Neither establishes successful elevated **two-account** task/runtime
behavior. Real task security visibility does not establish mutation preservation.

`tools/account-upgrade/qualify-two-account.ps1` is a runnable qualification entry
for a separately authorized Windows environment with pre-existing accounts,
session, task, protected toolchain and operation store. It defaults to read-only
planning; `-Execute` still requires the product's interactive confirmations.
It must not be run on a live installation merely because the code is present.
