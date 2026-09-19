# Local publication regression gate

This is a local, offline gate for changes to both supported release lines. It
does not publish, authenticate, download dependencies, alter the live bridge, or
replace the genuine hosted publication evidence. A successful report always says
`releaseReady: false`.

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
  --node-root C:\retained\nodes
```

The verifier does not run tests, npm, Docker, a signing SDK or a network request.
It reads bounded private evidence, compares original TAR/command receipts and
re-enumerates the frozen and live inputs. Missing, partial, controls-only,
changed or old-schema evidence fails. It prints a compact `localRegression`
statement only after those checks; **it never generates owner acceptance**.

Fresh inner reports use schema 4 and retain a private `fixture.tgz` alongside
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
`verifyRawSteps` requires schema 4, retained compressed bytes, a verified Git
checkout binding and the offline stage proof. Older evidence is not upgraded
or relabelled as qualification for changed source.

The stage proof records the exact bytes executed in `checkout-false`, not the
raw Windows input snapshot. Inner schema 4 records `core.eol=crlf` explicitly
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
Outer reports remain schema 2 and nested stage proofs remain schema 4. Component
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
  --pwsh-root 'C:\Program Files\PowerShell\7'
```

`publication:local-gate` invokes this same contained launcher. Never invoke the
inner `local-gate.mjs` as a substitute. Its default entrypoint refuses a full run.
`--controls-only` exercises the isolation controls, not the source or publication
path; its report cannot stand for a complete gate.

Every full run requires both 1.3.1 and 2.0.1 and runs their complete registered
source suites on Node 20, 22, and 24. It does not change test concurrency, shorten
the selected suite, increase application deadlines, or retry failures. UI and
publisher operations use the separately pinned Node 24.21.0 runtime.

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

The complete source suite has a dedicated 25-minute harness budget inside a
30-minute guest-case budget. Ordinary inner commands retain their 15-minute
default, timeout controls retain 15 seconds, and the whole run remains bounded
at two hours. The source budget covers complete native-heavy suites; it does not
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
The current-line source suite requires a non-skipped audit oracle in each guest.
The gate selects a restricted worker token with the same user, medium integrity,
administrator membership disabled and no security privilege. Its suspended child
enters an owned kill-on-close job before running the original 19-case worker.
The elevated oracle verifies the actual audit, label, owner, group and DACL state
afterward. Missing privileges, worker failures or an unavailable report fail the
required case. No Explorer process or interactive desktop is needed.

The restricted worker has a 120-second test-only deadline within a 150-second
PowerShell test budget. These cover the measured native process startup cost in
the bounded guest, not an application deadline increase. The test emits one
structured TAP report only after every assertion passes; both the producer and
offline verifier require that report, the exact passing test and matching Node
runtime. Missing, duplicate, changed or skipped audit evidence cannot qualify.
Ordinary test runs retain the existing Explorer mode and its 20-second worker /
30-second PowerShell budgets. A capability skip there remains explicitly a skip,
not security coverage. Legacy has no equivalent audit test and is not relabeled.

Each run writes private command vectors, exit/error/signal details, byte hashes,
guest facts, input manifests and original results. Keep this evidence outside
the repository. A changed input invalidates the run; do not combine passing
pieces from different source snapshots into a green report.

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
