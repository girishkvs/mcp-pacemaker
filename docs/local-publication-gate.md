# Local publication regression gate

This is a local, offline gate for changes to both supported release lines. It
does not publish, authenticate, download dependencies, alter the live bridge, or
replace the genuine hosted publication evidence. A successful report always says
`releaseReady: false`.

The controller inventory also binds the native-audit/source-gate and OSV
adapter/evaluator files. The temporary
[2.0.2 CLI-runtime and UI-build risk review](npm-publishing.md#temporary-202-producer-risk-acceptance)
does not waive local qualification or authenticate it. Its raw findings and expiry
remain explicit; old controller evidence is invalid after these source changes.
The immutable 1.3.1 stage-proof contract and its original member pins are unchanged.

Published-peer `sourceProof` is a separate approved ref/run pin, not a local qualification
receipt. Its registry SLSA is verified through the pinned SDK in a fresh bounded child;
local evidence cannot stand in for that registry proof. The source/verifier/loader inputs
are included in the controller and stage-proof bindings. See the published-peer contract
in [npm publishing](npm-publishing.md).

Stage proof schema 4 has source-specific, independently selected file contracts.
New/current sources require the complete current `STAGE_PROOF_FILES` inventory,
including the registry-peer verifier. The immutable published 1.3.1 source
`688b1038f88f020312230a94ff355732c34ae185` retains its original 20-file contract.
Selection requires its exact Git commit, tree, package version and all 20 pinned
Git member identities (including the original contract and loader), not its label
or a report-supplied inventory. The actual bounded Git reader and checked-out bytes
bind that selection before replay. Unknown sources use the full current contract.

The immutable producer still runs its own unchanged proof code. Its schema-4 case
semantics match the current replay checks, so the current verifier checks all 48
cases against the original source's exact file contract without upgrading or
relabelling the receipt. Current-source proofs cannot substitute the smaller
historical inventory. Read-only compatibility replay of an old receipt is a
component preflight, never a new completed paired qualification.

## Required private verification and owner acceptance

After the complete run, invoke `publication:verify-local` (or its Node entrypoint)
with these explicit local paths:

```powershell
& 'C:\retained\nodes\node-v24.21.0-win-x64\node.exe' tools\npm-publication\verify-local.mjs `
  --report Q:\private-evidence\completed-run `
  --legacy-root Q:\checkouts\legacy `
  --current-root Q:\checkouts\current `
  --npm-root C:\retained\npm\node_modules\npm `
  --git-root 'C:\Program Files\Git' `
  --pwsh-root 'C:\Program Files\PowerShell\7' `
  --node-root C:\retained\nodes `
  --native-packages C:\retained\native-packages
```

The verifier does not run tests, npm, Docker, a signing SDK or a network request.
It reads bounded private evidence, compares original TAR/command receipts and
re-enumerates the frozen and live inputs. Missing, partial, controls-only,
changed or old-schema evidence fails, as does a run history that does not match
`run-state.json` (see [Resume an interrupted run](#resume-an-interrupted-run)). It
prints a compact `localRegression` statement only after those checks; **it never
generates owner acceptance**.

Fresh current-line inner reports use schema 5; the immutable legacy producer
retains schema 4. Both retain a private `fixture.tgz` alongside
the command receipts. The verifier recomputes its SHA256, SHA512 and SRI,
independently inspects the compressed tarball and requires its complete file
inventory to match both npm's raw output and the frozen published source bytes.
It does not guess an EOL conversion for mismatching source bytes.

Root `/LICENSE` and `/THIRD_PARTY_NOTICES.txt` use explicit `text eol=lf`
attributes so their packed bytes match the canonical LF input on every host.
The complete published-file inventory is checked across both Windows checkout
settings; explicit CRLF scripts and binary/built dashboard bytes remain unchanged.

Every producer command is required in order, with its exact executable, args,
cwd, encoding and timeout. Native identities are reconstructed from the recorded
Git tree/blob/attribute reads; extracted files and notices are compared to the
actual inventory. Retained license JSON is recomputed over the frozen physical
dependency graph and license text, including candidate coverage. A rehashed
empty or partial receipt does not qualify.

The component-only `verifyRecordedSteps` API can inspect older private diagnostic
evidence, but it does not accept a case or produce a publication statement.
`verifyRawSteps` requires schema 4/5, retained compressed bytes, a verified Git
checkout binding and the offline stage proof. Older evidence is not upgraded
or relabelled as qualification for changed source.

The stage proof records the exact bytes executed in `checkout-false`, not the
raw Windows input snapshot. Inner schemas 4 and 5 record `core.eol=crlf` explicitly
for each Git checkout, alongside its `core.autocrlf` setting. Committed `eol=lf`
attributes still force LF for MJS/JSON; `text=auto` CJS follows the explicit
Windows checkout policy. Declared binary files remain byte-exact.

Replay obtains HEAD, tree, entries, blob bodies and `check-attr --source=<HEAD>`
from the verified local Git reader. It rejects uncommitted attribute overrides,
missing text/binary declarations, custom filters, working-tree encoding and
ident expansion before requesting conversion. Git `hash-object --path` binds
the frozen raw input to its committed blob; `cat-file --filters` with the same
explicit policy and `--attr-source=<HEAD>` derives the executed bytes. Blob
object IDs, source hashes and HEAD/tree are checked and rechecked. Receipt JSON,
raw command output and the supplied proof hash list are never normalized.

The in-memory checkout binding is created by those verified Git reads, not
accepted from report JSON. Standalone proof generation/validation still hashes
the exact raw execution root. All changed verifier/producer modules were already
in `LOCAL_CONTROLLER`; their changed bytes invalidate an old controller binding.
Fresh outer reports use schema 3; nested stage proofs remain schema 4. The public
compact statement schema, contract and six-source-case coverage are unchanged. Component
replay can inspect older inner schemas 1/2/3 (including the historical Windows
native-EOL policy only when no local `core.eol` override was recorded), but cannot
produce a fresh qualifying result. New source still needs a new full run.

Publication applicability requires **both final source HEADs to be clean**.
Commit before the final local run; a later commit, amend, rebase or byte change
invalidates the statement. Input manifests retain complete Git path/blob/mode
identity, exact commit/tree and raw checkout hashes. Git's declared attributes
remain authoritative; raw Windows bytes are not blindly equated to Linux bytes.
Dirty-tree runs can still diagnose changes but cannot produce an applicable
publication statement.

The publication workflow requires the exact statement plus explicit owner review
through the existing owner dispatch/content-review mechanism described in
[npm-publishing.md](npm-publishing.md). GitHub validates the real dispatch owner,
source and existing hosted artifact chain. The trust claim is **human acceptance
of private evidence**, not independently authenticated proof that local tests ran.
Hashes bind bytes; they do not authenticate execution. No genuine local report or
review is created by adding this mechanism.

Keep full inputs, paths, reports and archives private and outside source. Only the
explicitly approved compact statement enters existing hosted manifests. There is
no GitHub local-path input, new credential/service, release-ready flag, lifecycle
hook or automatic approval. Raw Git/npm/SDK use or edited tooling remains possible
for an owner; this guards supported entrypoints, not an owner-controlled machine.

## Prepare fresh exact-byte qualification inputs

For exact hosted-source and private-policy joins, prepare the qualification
inputs in this order:

1. **Integrate and commit all final reviewed changes first**, in both release
   lines. Require clean final HEADs before materializing qualification inputs.
   Do not qualify an uncommitted mixture or reuse evidence from an earlier tree.
2. Create **new owned checkouts** of those exact commits using actual Git with
   `core.autocrlf=false` and `core.eol=lf`, under the verified committed
   attributes. This is not blanket newline replacement: explicit `eol=crlf`
   declarations still produce CRLF, and binary/`-text` files stay byte-exact.
3. Independently verify the clean commit/tree identities, exact file membership,
   Git blob IDs and modes, committed attributes, and actual rendered file bytes.
   Reject local attribute overrides, custom filters, working-tree encoding,
   `ident` expansion, unsupported conversions and arbitrary transformations.
   Record actual inventories and recompute each declared hash format; do not
   assume equal roots, filesystem modes or differently shaped inventory hashes.
4. Use **those exact raw input bytes** for a new complete local qualification
   and verifier run, and for fresh genuine private source-policy evidence.
   Preserve the existing CI, timing and separate owner-review requirements.
   Earlier reports, captures and policies for different bytes are not relabeled
   or carried forward.

The actual hosted collector must still prove that its source inventory matches
the qualified and private-policy byte subject exactly. Matching commit/tree
names or a planned checkout policy is not enough; a mismatch blocks admission.
Git byte materialization on Windows is **not** Linux runtime execution evidence.

This is input-workflow guidance, not a new public CLI flag, producer feature or
derived-byte acceptance branch. It does not change module bindings, the recorded
Windows execution-checkout policies, or the verified Git checkout checks
described above. Prepare final inputs only after the reviewed changes are stable,
integrated and committed; a later source change requires new inputs and evidence.

## Run

Use Windows with Hyper-V containers enabled, the already cached image required
by `local-windows.mjs`, physical retained dependencies in each checkout, Git for
Windows, PowerShell 7, and the retained publisher npm 12.0.2 distribution.
The Node directory must contain `node-v20.20.2-win-x64`,
`node-v22.23.2-win-x64`, and `node-v24.21.0-win-x64`.
Missing inputs fail; the launcher does not install or fetch replacements.

```powershell
node tools\npm-publication\local-windows.mjs `
  --npm-cli C:\retained\npm\node_modules\npm\bin\npm-cli.js `
  --peer-root Q:\checkouts\other-release-line `
  --output Q:\evidence\new-run-directory `
  --node-root C:\retained\nodes `
  --pwsh-root 'C:\Program Files\PowerShell\7' `
  --native-packages C:\retained\native-packages
```

`publication:local-gate` invokes this same contained launcher. Never invoke the
inner `local-gate.mjs` as a substitute. Its default entrypoint refuses a full run.
`--controls-only` exercises the isolation controls, not the source or publication
path; its report cannot stand for a complete gate.

Every full run requires one explicitly selected stable 1.x legacy source and one
stable 2.x current source, and runs their complete registered
source suites on Node 20, 22, and 24. It does not change test concurrency, shorten
the selected suite, increase application deadlines, or retry failures. UI and
publisher operations use the separately pinned Node 24.21.0 runtime.

Current-line source cases use the image's existing `ContainerUser`, with a fresh
production ordinary-caller check before execution. Each also requires a separate
privileged audit companion from the same frozen input manifest and Node executable.
Legacy cases retain their original image account and producer code. There are
three containment controls, six complete source cases and three audit companions;
no host account, image, policy or production guard is changed.

Before the current source suite, the gate invokes the same
[execution-contract preflight](execution-context.md) as CI, for the `source-ordinary`
contract. The verifier requires its exact original receipt. `ContainerUser` is an
ordinary caller but supplies no real WTS logon, so the contained suite excludes the four
`SESSION_REQUIRED_TESTS` files and records them in `sessionDeferredTests`. The host half
runs exactly those files and the verifier requires their `session-lane.json` receipt,
bound to the same commit. Neither the audit companion nor a previously passing subset
makes that source case complete.

Full qualification also takes the two already-retained, hash-pinned archives used
by [Windows CI](../tools/windows-ci/README.md): the Roslyn compiler package and
matching .NET 4.6.2 reference cabinet. They are frozen with both inputs and checked
again by the offline verifier. Before each current-line source suite, the existing
CI restorer extracts them into owned guest work storage with an explicit offline
`-PackageDirectory`. Its exact returned paths are recorded and passed to the nine
native fixture builders. No download, machine installation, compiler fallback or
legacy-producer change is made. Containment-only controls do not require these
archives.

The source-suite child receives `CI=true` and an owned temporary-directory alias
inside the guest work directory. This covers CI-dependent behavior and temporary
path aliases locally. Fixtures must resolve directories they create; external
linked inputs remain rejected. Tests for local-only operations must scope and
restore their own local environment and separately verify CI rejection. These
conditions do not supply GitHub identity, credentials, or authenticated hosted
evidence, and do not change the environment of the other gate commands.

PowerShell's module-analysis cache is explicitly placed under each owned command
home, so profile-less module loading cannot add cache files to the source checkout.

## Resume an interrupted run

A full run takes hours and stops at its first failing case. To keep the steps that
already passed, run the launcher again with the same arguments, replacing
`--output NEW_DIRECTORY` with `--resume RUN_DIRECTORY`:

```powershell
node tools\npm-publication\local-windows.mjs `
  --npm-cli C:\retained\npm\node_modules\npm\bin\npm-cli.js `
  --peer-root Q:\checkouts\other-release-line `
  --resume Q:\evidence\new-run-directory `
  --node-root C:\retained\nodes `
  --pwsh-root 'C:\Program Files\PowerShell\7' `
  --native-packages C:\retained\native-packages
```

Every run writes `run-state.json` before its first case and updates it as each step
starts and passes. It records the run binding: run ID, scope, pinned image, the Docker
engine (server version, API version, OS and kernel), the Windows build and update
revision (UBR), argument paths, Git root, the complete controller binding, the three Node
runtime hashes, and canonical hashes of the npm, PowerShell, Git and native-package trees
and of both source selections (commit, tree, checkout files and retained dependencies).
The input steps compare their frozen copies with this binding, so an input that changes
after the run starts fails the run. Each passed step adds a checkpoint with the hash of its
evidence members and of the command journal up to that point. Runs started before this
file existed cannot be resumed. The launcher resolves the run path once, so
`RUN_DIRECTORY` and `RUN_DIRECTORY\` name the same run.

The plan is fixed: the three controls, `inputs-<current>`, `inputs-<legacy>`,
`session-lane`, the current-line audit and source cases, then the legacy source cases.
Passed steps always form a prefix of it. A resume:

1. Refuses unless the live binding is identical to the recorded one. A changed controller
   file, Docker engine, Windows build or update revision, source commit, tree or byte,
   retained dependency, npm, PowerShell, Git or native-package file, Node runtime, image or
   argument path refuses, so controls proven on one engine and build never stand for cases
   run on another. It also refuses a run that already passed, a controls-only run
   (`--resume` with `--controls-only` is rejected), a run directory without
   `run-state.json`, a clock that stepped back behind the recorded history, and a second
   launcher on a run directory that a live launcher holds. Each launcher holds a named
   pipe derived from its run directory, which Windows releases when the process exits.
   A Windows cumulative update or a Docker update changes the UBR or engine version, so a
   run interrupted across one of those cannot be resumed and must start over.
2. Re-hashes every reused step against its checkpoint: each case directory and its
   storage-admission receipt, `session-lane.json`, and each input manifest with every
   copied input byte. It also checks the frozen controller and runtime trees, the empty
   Docker configuration and the checkpointed command receipts. Any difference refuses.
3. Sets aside everything after the last checkpoint into the sibling directory
   `RUN_DIRECTORY.attempts\before-invocation-N`: the failed or partial case directory, its
   storage-admission receipt, the failed `result.json`, a partial input directory and the
   command receipts written after that checkpoint. Receipts move from the highest number
   down, so a resume killed part way still leaves a contiguous journal for the next one.
   Nothing is deleted. Any other member refuses.
4. Kills and removes any container that still carries the run's ownership label, with the
   same stopped-state, zero-PID and absence checks as case cleanup. It does not stop host
   processes; make sure a killed launcher's session-lane child has exited before resuming.
5. Keeps the run ID and reruns the first step that has not passed, and every later step,
   from scratch.

A refusal changes nothing in the run directory. Because the session lane runs the live
working tree, every run re-verifies all frozen inputs right after the lane, and its receipt
is reused only after that check passed. Before a run records a pass it checks that its
evidence inventory can be built. A run cut off after recording the pass, which leaves
`evidence-manifest.json` missing or partly written, resumes: that invocation is recorded as
failed and the next one reruns nothing. Any other passed run refuses, and says so if its
evidence no longer matches its inventory. Each invocation keeps its own deadline; nothing
bounds the total time across invocations.

The final `result.json` records every invocation in `invocations`: start and end time (an
interrupted invocation has no end time), status (`failed`, `interrupted` or `passed`), binding
hash, the steps it reused and ran, and what it set aside or removed. A normal run has one
invocation. The verifier requires that history to equal `run-state.json` and rejects it
unless invocation numbers have no gap or duplicate, each invocation reused exactly the
passed prefix and ran the next steps in plan order, every planned step passed exactly once,
only the last invocation passed, and every invocation has the same binding hash. The
binding must match the report's controller, image and runtimes and both frozen input
manifests, cases must appear in plan order, and every checkpointed evidence member and
command receipt must still match its checkpoint hash. The compact `localRegression`
statement is unchanged; resume details stay in the private report.

## Isolation and evidence

The launcher creates uniquely owned Hyper-V containers with no network, host
mounts, published ports, credentials, or automatic restart. Each receives four
CPUs and 4 GiB RAM. Inputs are explicit physical source files, clean Git object
bundles, retained dependency trees, and tool distributions. Symlinks, reparse
ancestors, special files, unsafe paths, extra copied files, and changed bytes
are rejected. Host-to-guest manifests bind the actual copied bytes. Node
executables are frozen separately and their hashes checked inside the guest.
Final acceptance re-enumerates source and dependency/tool inputs and rechecks
both source HEADs; checking only the originally listed files is insufficient.
The complete npm and PowerShell roots are selected, including top-level additions
and empty directories. Frozen runtime/controller trees use the same whole-root
binding. Empty directory membership is preserved and included in copied manifests.
Both Git adapters parse bounded repository configuration with Git's own
`--no-includes` parser before repository operations. Inherited includes and
executable/worktree settings are rejected, configuration bytes are rechecked,
and each operation is bound to its intended worktree.
Guest account variables come from the guest, are checked against its Windows
token, and survive both environment sanitizers. No host identity is forwarded.
The source environment uses the validated retained npm CLI path; actual npm
operations still use the publisher runtime.

Source and tool copies have file-count and size limits. Container commands,
output, individual cases, and the whole run have deadlines. Disk protection
uses a 3 GiB host reserve and a 4 GiB per-case host free-space growth budget,
observed at most three seconds apart while waiting, with a requested 32 MiB/s
container I/O limit. Docker's requested 4 GB storage size is recorded, **not
claimed as a proven quota**: Windows reports a virtual disk size. These are
resource controls for reviewed project tests, not a general hostile-code sandbox.
Admission may wait up to 60 seconds for the required free space, recording its
samples before starting a case. This does not retry any test.
No Docker daemon settings, existing images, or unrelated containers are changed.

The contained source suite has a dedicated 60-minute harness budget on the current
release line; legacy cases keep the 25-minute budget their own line shipped, and the
verifier checks each recorded budget against the label the case used. The host session
lane is bounded separately at 40 minutes. Ordinary inner commands retain their 15-minute
default, timeout controls retain 15 seconds, and each launcher invocation is bounded by a
whole-run deadline derived from the cases it plans. A resumed run has no bound across
invocations. The source budget covers complete native-heavy suites; it does not
change application/helper deadlines, test concurrency, or test selection.
Each inner command receipt records its actual `timeoutMs`.

Before project execution, a real assertion must fail with its exact diagnostic,
and a real child/grandchild tree must remain alive until the outer timeout.
The launcher observes progressing heartbeats and all three live PIDs immediately
before cancellation. A separate early-descendant-exit control must be rejected
despite its initial heartbeat ticks. Control receipts are flushed before forced
guest termination. Cleanup verifies
the container's identity and ownership, stopped state and zero PID, then removes
only that container and confirms absence. Missing evidence or uncertain cleanup
fails the gate. Original test exits are not replaced by cleanup success.
Evidence export is a bounded 128 MiB TAR stream, not an unbounded directory copy.
Only regular files/directories with safe, unique paths are extracted; the output
volume must retain its reserve. Disposable checkouts, dependencies and temporary
files are kept outside the exported receipt directory.
Each current-line audit companion requires the existing audit test to pass without
a skip. Its privileged verifier selects a restricted worker token with the same user, medium integrity,
administrator membership disabled and no security privilege. Its suspended child
enters an owned kill-on-close job before running the original 19-case worker.
The elevated oracle verifies the actual audit, label, owner, group and DACL state
afterward. Missing privileges, worker failures or an unavailable report fail the
required case. No Explorer process or interactive desktop is needed.

The ordinary source suite retains its actual capability-skip result for this
privileged test; it is not relabeled as a pass. The separate audit is mandatory on
every current-line Node version. The offline verifier requires the original audit
command, exact test selection, successful exit, unchanged source, matching input
manifest/runtime and all 19 audit cases. Missing, swapped, skipped, failed or
changed companion evidence rejects the entire qualification.

The restricted worker has a 120-second test-only deadline within a 150-second
PowerShell test budget. These cover the measured native process startup cost in
the bounded guest, not an application deadline increase. The test emits one
structured TAP report only after every assertion passes; both the producer and
offline verifier require that report, the exact passing test and matching Node
runtime. Missing, duplicate, changed or skipped audit evidence cannot qualify.
Ordinary test runs retain the existing Explorer mode and its 20-second worker /
30-second PowerShell budgets. A capability skip there remains explicitly a skip,
not security coverage. Legacy has no equivalent audit test and is not relabeled.
The companion Node command has a 210-second envelope for that unchanged oracle,
its existing cleanup control and process overhead; the audit guest is bounded to
five minutes. Companion reports are private schema-1 `local-privileged-audit`
records, not full-source or publication-success reports.

Each run writes private command vectors, exit/error/signal details, byte hashes,
guest facts, input manifests and original results. Keep this evidence outside
the repository. A changed input invalidates the run; do not combine passing
pieces from different source snapshots into a green report. A resumed run combines
only steps bound to the identical recorded inputs.

## Publication regression coverage

| Previous repair area | Local gate boundary |
| --- | --- |
| Bootstrap, tag and approval policy | Complete registered publisher/policy/proof/peer suites, without real approval or submission |
| SDK bootstrap loading | Lane-specific pinned SDK/signature interfaces in a fresh child/home with blocked transport and subprocess APIs; no fictitious legacy owner-bootstrap modules |
| Actual staged attachment capture | Pinned npm12 OIDC/config, production stage child and parent result validation, automatic provenance, CLI/SDK serialization, same-call ID, issuer/provider/Fulcio guards, loader mutations, redirects and unknown outcomes; 48 fresh-child synthetic scenarios on publisher Node24 only |
| Checkout identity and native verification | Actual clean Git checkouts with both `core.autocrlf` settings; raw native blobs and declared build-script checkout bytes |
| Dashboard checkout bytes | Actual Vite rebuild and exact committed dashboard/notices comparison for both checkout settings |
| Canonical package inventory | Actual offline npm 12 pack, independent npm JSON/tar inspection, extraction and native/notices comparison |
| Consumer license evidence | Actual capture and finalizer over retained packages; explicitly not a fresh registry resolution |
| Windows helper and pooling deadlines | Complete original source suites in each isolated Node runtime, retaining failures and existing deadlines |

The historical repair sequence is visible in current-line commits `b77164d`,
`7d397d8`, `74a0bc2`, `bd79f00`, `3be90ab`, and `8861e7d`, with corresponding
legacy changes. Passing a new harness control is not proof that a historical
application timeout has been fixed.

`local-stage-check.mjs` is the bounded offline component used by the existing
contained inner gate. It runs only explicitly owned Node children. Before npm
modules load, each child denies real network/socket/DNS, subprocess and worker
entrypoints. A separate blocker control replaces the real underlay first, so a
broken blocker cannot make actual I/O while being tested. Only the signer and
lowest HTTP request boundary use synthetic
fixtures. No listener, owner credential or real registry/signing call is used.
The CLI positive runs the actual production `stage-child.mjs`; admission negatives
must fail before SDK/signing/HTTP. The other cases cover the saved-file/OIDC
replacement and exclusivity issue, duplicate POSTs, real 301/302/303/307/308
handling, malformed response and lost response.

The positive also passes actual npm stdout and physical capture files through
the production parent's `capturedStageOutput` boundary. Issuer redirect/invalid
URL/failure cases preserve the actual unsuccessful CLI exit and require no second
hop, exchange or stage. Real Sigstore CI-provider cases cover its separate
`sigstore` audience without invoking signing, including its 30-second body
deadline. Loader mutation controls operate on physical owned npm copies and
must reject changed main/exports/delegates/shadow packages and cached critical
modules before alternate code executes. Retained vendor originals are unchanged.

An actual npm OIDC → real Sigstore provider scenario runs both issuer audiences
in one adapter instance and checks distinct values; there is no shared one-GET
limit or reused token. Real Fulcio CA-client fixtures test the token-bearing
body, fixed HTTPS endpoint, both retry layers, CLI retry zero versus SDK defaults,
307/308, 503, malformed/oversized response and the 30-second body deadline.
These use synthetic identity/key/challenge/certificate data only and never invoke
actual attestation, signing or certificate issuance. TUF global fetch is separate.
Receipts distinguish the actual CLI's 300000 ms configured timeout from the
general SDK's 5000 ms default; both must reach the guarded outer/lower layers as
30000 ms. Missing or substituted configured-timeout metadata fails admission.

The raw parent command receipt includes every child's exact executable, argv,
cwd, 60-second deadline, exit/error/signal, stdout/stderr and digest. The verifier
requires all 48 in order, exact source/tool hashes and their independent
results. Missing, stale, partial, rehashed or wrong-runtime records reject.
The nested offline-stage proof schema is now **4**; old proof schemas 1/2/3 are not
upgraded. Expected unsuccessful issuer CLI exits remain nonzero in raw receipts
and are accepted only with all independent rejection assertions; they are not
silently converted into successful command exits.
Normal registered publisher tests also exercise capture, authenticated GitHub
reader linkage, signature rejection, unknown outcomes and proof admission.
Those compatible unit fixtures run on Nodes20/22/24; actual npm12 execution is
publisher Node24.21.0 only. `syntheticOnly: true`, `authenticated: false`,
`realRegistry: false`, `realSigning: false` and `releaseReady: false` remain
mandatory. Synthetic test request bodies and captured bundles/intents/receipts
are retained inside the raw child output and independently replayed; changed
digests alone cannot pass. No real auth headers are retained. Production capture
still retains no raw request body or response body. These tests do not replace
a genuine GHA capture or hosted approval.

## What remains hosted

Fresh registry resolution, advisories and signatures; native reproducibility
builds and cross-platform compatibility/browser/consumer runs; genuine scanned
source/history/tag identity; protected environment and owner approvals; OIDC and
Sigstore signing; actual staged provenance acquisition; submission and
publication remain separate gates. Retained package metadata is not fresh
registry evidence. Private fixture commits and tarballs are never release
candidates.

Before requesting a push or release, require a successful complete local report
for the exact candidate bytes, then the existing independent hosted gates and
fresh artifact-specific approvals. This command does not grant permission to
push, rerun CI, move tags, rewrite history, dispatch, or publish.
