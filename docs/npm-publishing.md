# Preparing and staging npm candidates

This workflow supports only the reviewed `mcp-pacemaker` **1.3.1** (`legacy`) and
**2.0.1** (`latest`) candidates. It does not establish name availability, publish
a version, approve a stage, change a dist-tag, or configure an account or trust.

Run the [local publication regression gate](local-publication-gate.md) for both
candidate checkouts before requesting a source push. Its isolated offline
results are a prerequisite, not a substitute for the hosted evidence below.

## Prerequisites

1. Commit this workflow and its tools in each candidate. Put the workflow on the
   default branch too, so GitHub permits manual dispatch. Create an approved
   annotated publication tag on the exact green source commit. For each supported
   version, only `v<version>`, `npm/v<version>`, `npm-r2/v<version>`,
   `npm-r3/v<version>`, `npm-r4/v<version>` and `npm-r5/v<version>` are accepted.
2. Required source CI is `.github/workflows/ci.yml`, an exact successful **push**
   run/attempt, including lockfiles, all Windows/Linux/macOS Node 20/22/24 test
   jobs, UI, and every additional job. Skipped or missing required jobs fail.
   This does not replace packed-consumer, native identity/execution or compatibility gates.
3. Use Node **24.21.0** and npm **12.0.2** for preparation/staging. The workflow
   installs npm only into a temporary prefix with empty local user/global
   configuration; it does not alter global npm configuration or save credentials.
   Node 24.11.0 does **not** satisfy npm 12.0.2's engines. Node 20 is legacy
   application coverage, not a supported npm 12 publishing runtime.
4. Before staging, a real 2.x package must already exist under the authorized npm
   owner. The current-line workflow provides the separately approved, one-time
   GitHub-hosted owner bootstrap for the real signed **2.0.1** tarball with
   browser 2FA. There is no dummy release, local registry publication, stored npm
   secret or 2FA bypass. This legacy workflow does not implement owner bootstrap;
   it remains preparation and OIDC-only staging. See the
   [current-line contract](https://github.com/girishkvs/mcp-pacemaker/blob/main/docs/npm-publishing.md).
5. Configure npm trust separately: repository `girishkvs/mcp-pacemaker`,
   workflow **filename** `npm-publish.yml`, environment `npm-publish`,
   `allow-stage-publish` enabled and direct publish disabled.
6. Configure the real GitHub environment `npm-publish` with owner `girishkvs` as a
   required reviewer and an explicit **tag** deployment policy for the release
   tag. This implementation uses owner proof-of-presence, so prevent-self-review
   must be off; it does not use an alternate account to bypass self-review.
   The job reads both actual environment protections and the current run's
   approval history. Merely naming an environment or bypassing it is insufficient.

The first step checks both GitHub's `runner.environment` context and the runner
environment variable, before any OIDC request. Source checks require tag object,
peeled commit/tree, checkout HEAD/tree, actual event SHA/ref, and workflow SHA/ref
to match. Never override `GITHUB_SHA`, `GITHUB_REF` or workflow identity to attest
older code from a newer workflow.

### Separate publication tags

Use `npm/v1.3.1` and `npm/v2.0.1` for the first separate publication sources.
If those tags already exist when publishing-tool repairs are needed, use the
new immutable `npm-r2/v1.3.1` and `npm-r2/v2.0.1` sources. If those also exist,
use `npm-r3/v1.3.1` and `npm-r3/v2.0.1`. Further repairs use
`npm-r4/v1.3.1` and `npm-r4/v2.0.1`. The consumer license-evidence repair uses
exactly `npm-r5/v1.3.1` and `npm-r5/v2.0.1`; r6, other versions and malformed
or substituted identities are not supported. Keep all existing
tags and GitHub releases unchanged, even when preparation failed. Each new
publication tag needs explicit approval and points to its own green commit
containing the workflow and tools that actually run. Do not reuse an approval
for a different tag object.

The complete ref, including its namespace, remains bound through source checkout, CI,
consumer artifacts, peer transfer, protected-environment tag policy and staged
provenance. A source bundle from `v<version>` cannot be relabeled as one from
`npm/v<version>`, `npm-r2/v<version>`, `npm-r3/v<version>`, `npm-r4/v<version>` or `npm-r5/v<version>`. Bundles cannot
move between these namespaces. The protected environment must explicitly allow the exact
new tags; approval for an older tag is not sufficient. Prepare fresh artifacts
for the new source; package versions
and the derived `latest`/`legacy` npm channels do not change. Existing registry
versions remain immutable, including when only the publisher tools changed.

The source HTML checkout uses CRLF to reproduce the committed dashboard bytes
on every build platform. Generated `ui/dist` files remain byte-preserved. CI
rejects rebuilt dashboard or notice changes before compatibility testing; the
publication source gate still requires the entire checkout to remain clean.

Native C# source checkout uses LF on every platform so its raw bytes match the
canonical tarball. The executable is unchanged; Windows consumer checks still
compare every native file byte-for-byte before running the helper.

## Manual inputs

There are two dispatch inputs: `action` (default **prepare**) and `approval`
(JSON). Inputs are parsed from the actual event file, not interpolated into shell
commands. Dispatch against the approved release **tag**, not `main`.

Both operational actions require `approval.localRegression`: the unchanged
compact schema-1 output of the private offline verifier. Old manifests and
approvals without it fail. This binds the exact clean final commit/tree and
path/blob/mode identity of both release lines; it is not release authorization.

For **prepare**, add `localRegressionReview`. For **stage**, add a fresh review
at `ownerPreflight.privateContentReview.localRegression`, alongside the existing
mandatory source/history/tarball review. Its exact fields are:

| Field | Required meaning |
| --- | --- |
| `reviewer` | `girishkvs`, after actual private-evidence review |
| `scope` | `private-local-regression-evidence` |
| `disposition` | `accepted`, only after explicit owner acceptance |
| `statementSha256` | SHA256 of the statement serialized by `localJson` in `local-regression.mjs` |
| `reviewedAt` | Actual review time, no more than one hour old when authorizing the action |

No tool generates this review. The hosted reader checks actual owner/run IDs and
the actual dispatch input; the trust claim is **human acceptance of private
evidence**, not independently authenticated proof of local execution. A hash,
`authenticated: true`, or a green local status cannot replace that review.
The source/final manifests retain the same statement and original prepare review;
fresh artifact-specific approvals bind their exact manifest bytes. Long-running
preparation continuation uses its original approval time. Existing hosted gates
remain mandatory, and cleanup is never conditional on the new prerequisite.

Full reports, local paths and TARs stay private. Reprepare old artifacts rather
than inserting evidence into an existing ZIP. The current-line bootstrap workflow
requires the same statement and a fresh nested owner review for signing and
publication; those actions remain unsupported by this legacy workflow.

### Exact source secret review

`collect-secrets` is a separate non-eligible action. Its approval has exactly
`schemaVersion`, `name`, `version`, `ref`, `tagObject`, `commit`, `tree`, `ciRunId`,
`ciAttempt`, `approver`, `approvedAt`, `scope` (`collect-secrets`),
`localRegression` and `localRegressionReview`. Existing fresh owner dispatch,
clean exact tag/source, successful push CI and reviewed local-regression checks
remain mandatory. Collection does not accept artifact, stage, public-package or
secret-review approval fields. It runs no npm restore, pack, stage or publication.
The only artifact is `npm-secret-collection-<runId>-1`, containing schema-2
`report.json` and exactly four canonical redacted receipts:
`execution-working-tree-gitleaks.json`, `execution-working-tree-trufflehog.json`,
`execution-history-gitleaks.json`, and `execution-history-trufflehog.json`.
It remains `eligibility: "none"`; no prepared or final candidate bundle is produced.

After inspecting that exact report and code, a **new real owner prepare dispatch**
may add `secretReview` with exactly these fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `1` |
| `scope` | `exact-source-secret-report` |
| `classification` | `synthetic-uri-userinfo-rejection-input` after actual code review |
| `reviewer` | Existing authenticated owner `girishkvs` |
| `reviewedAt` | After collection; within one hour before `approval.approvedAt` |
| `admissionRunNumber` | Exact intended next GitHub workflow run number, decimal string |
| `collection` | Exact `runId`, `jobId`, `artifactId`, `artifactDigest` (`sha256:...`) and raw report-file `reportSha256` |
| `findingIds` | Every distinct working-tree/history finding ID, each exactly once |

Read the next intended workflow run number before dispatch. An intervening
dispatch or recreated workflow fails closed; do not automatically retry or update
consent. API run/workflow IDs and attempt 1 are checked. Collection and admission
must be different runs. The source job's continuation uses the original dispatch
time, not a newly invented approval.

The original owner-only, same-source collection run must have a successful
`secret-collection` job and its complete pinned checkout/bootstrap/collection/upload
step sequence; every other job must be skipped. Its original ZIP digest,
metadata, repository/owner IDs and exact five canonical bounded members are checked through the existing authenticated artifact
readers. No raw scanner output, private policy, local triage or owner-local
evidence is uploaded. Only counts, exits, hashes and digest-only source/finding
bindings leave the collector. The trusted evidence is the reviewed collector at
the exact source plus authenticated original-artifact linkage, not independent
re-execution of raw output at admission.

The versioned proof retains original native argv digests, literal flags with
digest-only path slots, full stream byte counts/hashes, timings, completion/count
facts and pinned bootstrap provenance. Native execution and collection-step
times must follow the same exact successful source CI. Reachable history
counts/types/bytes and bundle/corpus commitments remain required.

Qualified source and fresh private source-policy inputs must use the exact
collected bytes, materialized by actual Git with `core.autocrlf=false`,
`core.eol=lf` and verified committed attributes. Explicit CRLF and binary rules
remain authoritative. Old Windows bytes or policy receipts cannot be relabeled
merely because the tree matches. The public ordered inventory-with-mode hash
and private canonical file commitment must each be reconstructed in their own
format. No root/mode equivalence or raw-stream replay is inferred from hashes.

Only the three source URI rejection inputs in
[`publication-scanners/USAGE.md`](../tools/publication-scanners/USAGE.md) are
eligible; path membership alone never approves them. Exact file/blob/line/value,
scope and source bindings and every raw finding must match. Errors, incomplete
coverage, other detectors, Gitleaks findings and payload findings remain blocking.
Matching hashes in another report are correlation only. Source/root/inventory
and finding bytes are rechecked before and after admission. The admitted original
report remains `findings`/183/count; reviewed false positives and remaining
findings are separate policy evidence in source and final gate reports.

The URI detector's pathless `Raw` and complete `RawV2` are treated as one
representation only for the three pinned fixture blob/path/line pairs and
their exact hashes/lengths. The complete uniquely quoted source literal,
URI/PLAIN record fields and `SecretParts` must all agree, without URL
normalization, percent decoding or prefix acceptance. Other disagreements
remain blocked. This correlation and eligibility check is not owner admission:
the complete original record, finding IDs, hosted collection and fresh exact
owner dispatch above remain required. A locally pinned scanner reporting
`vcs.modified=true` is not proof of official-release binary equivalence and
does not replace the hosted scanner provenance checks or full qualification.

`secret-collection` is permitted only as skipped in preparation/peer transfers;
it cannot satisfy source, consumer or finalizer jobs. Missing review preserves the
existing scan-and-deny behavior. Payload tarball scanning, private-content review,
local-regression acceptance and stage authorization are unchanged and separate.
This legacy workflow still does not add bootstrap signing or direct publication.

Preparation approval fields (without optional secret review):

```json
{
  "schemaVersion": 1,
  "name": "mcp-pacemaker",
  "version": "1.3.1",
  "ref": "refs/tags/npm-r4/v1.3.1",
  "tagObject": "<approved 40-character annotated tag object>",
  "commit": "<approved 40-character commit>",
  "tree": "<approved 40-character tree>",
  "ciRunId": "<exact completed push CI run ID>",
  "ciAttempt": 1,
  "approver": "girishkvs",
  "approvedAt": "<current UTC ISO timestamp>",
  "scope": "prepare",
  "publicPackages": ["<every explicitly approved public package name>"]
}
```

Placeholders are intentionally invalid. `publicPackages` must be a nonempty,
unique list of valid public npm names, including scoped names where needed.
Both actual producer lockfiles are checked against this disclosure approval
**before any root/UI restore or audit**. Consumer advisory queries also require
approved public coordinates; neither private names nor an ambient allowlist are
silently accepted.

### Prepare workflow and exact artifacts

Files under `bin/windows/` remain byte-identical to the immutable same-major
baseline. The PowerShell build script separately verifies its committed bytes
and its declared CRLF checkout form; code, encoding or attribute changes fail.
Preparation does not rebuild the native helper.

External gate failures expose only an allowlisted gate, fixed error code and,
for consumer/license evidence failures, a bounded reviewed diagnostic.
Missing, malformed, oversized or unowned reports produce `report-unavailable`;
raw transcripts and private review data are not printed or uploaded.

Preparation has no OIDC permission and never stages. Its jobs run in this order:

| Job | Required execution and output |
|---|---|
| `source` | Validate exact source/CI, run source gates, then pack one canonical tarball with scripts disabled. `npm-prepared-<runId>-1` contains exactly `candidate.tgz`, `source-gates.json`, `prepared.json`. |
| Six `consumer (<platform>, <npm>)` jobs | Download the same source artifact by immutable ID. Each runs both `npm-default` and `disabled` (`--ignore-scripts`) installs without copying a producer lock. Each uploads `npm-consumer-<runId>-1-<platform>-<npm>` containing exactly `report.json`. |
| `prepare` (finalizer) | Verify source and all six consumer artifacts plus the approved opposite candidate. Run exact-tarball compatibility, T32 and external gates. Copy validated bytes, **never repack**. `npm-candidate-<runId>-1` contains exactly `candidate.tgz`, `gates.json`, `manifest.json`. |

The six hosted jobs use these **12 actual install lanes**, not two local runs
plus presumed external coverage:

| Platform / hosted image | Node / npm pairs (each runs both modes) |
|---|---|
| `linux` / `ubuntu-24.04` | 22.23.2 / 11.6.1; 24.21.0 / 12.0.2 |
| `win32` / `windows-2025` | 22.23.2 / 11.6.1; 24.21.0 / 12.0.2 |
| `darwin` / `macos-15` | 22.23.2 / 11.6.1; 24.21.0 / 12.0.2 |

Windows jobs also execute the real helper tests against matching tarball helper
bytes. Finalization verifies **actual GitHub API ZIP bytes**, archive digests,
exact files, source/manifest hashes, and job/artifact/consumer receipts. Download
action warnings or caller-supplied success JSON do not replace these checks.
Source, locks and candidate bytes must remain unchanged.

Record each artifact ID, archive SHA256, run ID/attempt, manifest SHA256 and
tarball SHA256/SHA512/SRI. A source bundle is not a final candidate. Stage transfer
requires a completed successful prepare run with exactly one successful,
completed `source`, `prepare` and each of the six exact consumer job names,
all at the approved head SHA; any `stage` job must be skipped.

### T32 peer bootstrap (not npm account bootstrap)

The opposite patch is a **passive comparison input**, never this dispatch's
provenance subject. Supply this additional prepare approval field:

```json
{
  "peerArtifact": {
    "artifactId": "<opposite source artifact ID>",
    "artifactDigest": "sha256:<actual API ZIP SHA256>",
    "runId": "<opposite completed prepare dispatch ID>",
    "runAttempt": 1,
    "manifestSha256": "<opposite prepared.json SHA256>",
    "version": "<opposite patch: 1.3.1 or 2.0.1>",
    "ref": "<opposite exact approved publication tag ref>",
    "tagObject": "<opposite annotated tag object>",
    "commit": "<opposite source commit>",
    "tree": "<opposite source tree>",
    "sha256": "<opposite tarball SHA256>",
    "sha512": "<opposite tarball SHA512 hex>",
    "integrity": "sha512-<opposite tarball SHA512 base64>"
  }
}
```

1. With no peer yet, the first approved prepare can produce its canonical source
   bundle and all six real consumer artifacts. Its finalizer explicitly **fails
   for missing peer**. It creates no final candidate or stage eligibility.
2. A fresh opposite-candidate prepare can approve that first **source** artifact.
   `peer.mjs` checks the actual prior owner dispatch in the same public repository,
   completed source and all six successful consumer jobs, and no active jobs or
   stage execution (a stage job may only be skipped). The prior finalizer may
   have failed for missing peer; its success is deliberately not required.
3. Peer validation binds the annotated tag object/commit/tree, source report,
   `prepared.json`, toolchain, ZIP/file set and all tarball hashes. It never
   spoofs `GITHUB_SHA`/`GITHUB_REF` or turns that peer into a stageable artifact.
4. Then freshly prepare the first candidate with the opposite source artifact
   approved as peer. Approve the **new actual artifact hashes**, not assumed
   deterministic packing. A failed phase cannot be finalized later under a
   different dispatch SHA: a new prepare must use its actual approved
   tag/checkout/workflow identity.

This breaks the first-finalizer dependency without dummy versions or staging.

Current-line peer runs may include `sign-bootstrap` and `publish-bootstrap`
jobs only when both are completed and skipped. Executed or active bootstrap
jobs, and unknown job names, cannot supply a peer artifact.

For a later separately authorized `stage` dispatch on the **same tag**, retain the
source fields, update `scope`/`approvedAt`, and add:

```json
{
  "artifact": {
    "sha256": "<approved tarball SHA256>",
    "sha512": "<approved tarball SHA512 hex>",
    "integrity": "sha512-<approved base64 SHA512>",
    "manifestSha256": "<approved manifest SHA256>",
    "artifactId": "<immutable prepare artifact ID>",
    "artifactDigest": "sha256:<archive SHA256>",
    "runId": "<prepare run ID>",
    "runAttempt": 1
  },
  "ownerPreflight": {
    "owner": "girishkvs",
    "packageName": "mcp-pacemaker",
    "checkedAt": "<fresh owner-authenticated readback UTC timestamp>",
    "unresolvedSubmission": false,
    "privateContentReview": {
      "reviewer": "girishkvs",
      "scope": "source-and-tarball",
      "disposition": "approved",
      "historyAndAuthorsReviewed": true,
      "historicalEvidenceAccepted": true,
      "commit": "<same approved source commit>",
      "artifact": {
        "sha256": "<same approved tarball SHA256>",
        "sha512": "<same approved tarball SHA512 hex>",
        "integrity": "sha512-<same approved base64 SHA512>"
      },
      "reviewedAt": "<fresh owner review UTC timestamp>"
    },
    "expectedDistTags": { "latest": "<actual approved current 2.x version>" },
    "trust": {
      "repository": "girishkvs/mcp-pacemaker",
      "workflow": "npm-publish.yml",
      "environment": "npm-publish",
      "allowPublish": false,
      "allowStagePublish": true
    },
    "pending": { "status": "none" }
  }
}
```

Copy the **complete** actual dist-tag map, including `legacy` and any other tags.
This is owner-supplied evidence, not an OIDC-authenticated inspection of npm trust
or pending stages. Only record `none` after an owner-authenticated stage list and
the owner release ledger establish no conflicting/pending submission. Approval
and readback expire after one hour; slow runs may need a new approval.

Private-content review is a separate explicit owner attestation of source,
reachable history/authors and tarball, bound to the same source commit and all
three tarball hashes. Both review flags above must be literal `true`; a pattern
scan or fresh automation does not settle historical failures or uncertainty.
Prepared manifests leave it **pending-owner-review**; staging requires the fresh
owner attestation above. This is not a cryptographic signature or an automatic
review. Missing private scan policy remains **not-run**, with
`ownerReview: "pending"`; preparation preserves that gap rather than claiming a
scan pass. The separate owner review is mandatory before staging.

For an existing matching stage, `pending` must instead contain `status:
"matching"`, `stageId`, `version`, `tag`, `sha256`, `sha512`, `integrity`, and its
**original** `workflow` object (`ref`, `commit`, `runId`, `attempt: 1`), plus
`captureArtifactId` identifying the original GitHub `npm-stage-ledger-<runId>-1`
artifact. The reader authenticates that original run/archive and binds its
capture to the pending stage, source and tarball before recording the original
stage ID/workflow without another submission. It never creates replacement
capture evidence. Missing or invalid original capture blocks reuse.
Unknown/conflicting stages, unknown prior outcomes, wrong owners, missing trust,
registry errors or changed tags stop. A matching already-published version
produces a readback-required result, not another write; a different digest is an
immutable conflict.

The protected stage job downloads only the approved prepare artifact ID, verifies
GitHub's artifact metadata/digest/run/source and the separately approved manifest
and payload hashes, then repeats all identity/metadata/gate checks. The download
action's digest warning alone is **not** the payload guard.

The only npm mutation it implements is:

```text
npm stage publish <exact-candidate.tgz> --access=public --tag=<derived-channel>
  --registry=https://registry.npmjs.org/ --provenance --ignore-scripts --json
  --fetch-retries=0 --logs-max=0 --loglevel=silent --update-notifier=false
  --userconfig=<empty-owned-file> --globalconfig=<empty-owned-file>
```

There is no token fallback. npm runs in an empty owned directory with a restricted
environment. Supplied npm tokens/config, alternative ID tokens and Node injection
are rejected. The actual GitHub identity is forwarded unchanged. npm OIDC exchange
failure therefore cannot fall back to an old user credential.

## Gate integration contract

These are implemented **Node entrypoints**, called directly by the workflow
driver. All paths are absolute; report output must be outside the checkout:

```text
node tools/npm-publication/source-gates.mjs --context <absolute context.json> --output <absolute source-gates.json>
node tools/npm-publication/artifact-gates.mjs --tarball <absolute candidate.tgz> --source-report <absolute source-gates.json> --context <absolute context.json> --output <absolute gates.json>
node tools/npm-publication/external-gates.mjs --request <absolute request.json> --output <absolute report.json>
```

There is **no required `publication:external-gates` package script**. Missing
entrypoints, declared required scripts, failed commands or incomplete evidence
block reporting. These gate entrypoints never publish.

1. **Source:** context contains approved `publicPackages`. Check both locks'
   public coordinates, verify npm, restore/audit root and UI, run root tests and
   UI typecheck/test-if-present/build plus the full
   `tools/third-party-notices/check.mjs` rebuild check. A missing UI test script
   is `not-applicable`, not passed. Preserve external `nativeIdentity` and
   `authorIdentity`; `producer-advisories` combines real OSV evidence with both
   npm audits. There is **no source compatibility run**:
   `checks.compatibility` is `pending-exact-tarball`.
2. **Artifact:** context is generated from verified `matrix`, verified `peer`
   and approved `publicPackages`, not hand-authored success claims.
   `matrix.consumerLanes` has exactly 12 `{result: <raw consumer report>, ...}`
   entries plus artifact receipts. `peer` contains `tarball`,
   `prepared: {version, artifact: {sha256, sha512, integrity}, ...}`,
   `inspection.files` and `evidence`.
   Validate/extract candidate bytes and verify packed notices. Reject missing,
   duplicate or wrong SHA/version/toolchain/mode/bin/bridge/UI consumer lanes
   **before finalizer restores or external checks**. Never rerun consumers here.
3. **Finalizer execution:** check public coordinates before root/UI restores,
   install locked Chromium, then run exact-candidate CLI/API/browser
   compatibility. Run the real T32 command with the two approved patches:

   ```text
   node tools/service-replacement/check.mjs --legacy-tarball <absolute 1.3.1.tgz> --legacy-sha256 <hex> --current-tarball <absolute 2.0.1.tgz> --current-sha256 <hex>
   ```

   Keep the own/peer file manifests and hashes attached to the correct major.
   Recheck peer bytes with `verifyArtifact` after execution. The replacement
   receipt includes parsed stdout, the **exact captured raw stdout**, command
   evidence and both approved artifacts; the external aggregator validates it.
4. **External aggregation:** requests bind `schemaVersion: 1`, `phase`,
   `sourceRoot`, `root`, `commit`, `name`, `version`, `requiredGates` and approved
   public coordinates. Artifact requests add tarball/hashes/extracted root,
   source report, replacement receipt, the full verified matrix and only its
   two Linux/npm12 raw summaries as `consumers`. Those two are not new local
   executions or substitutes for the full 12. The external report supplies all
   gates below and all 12 `consumerLanes`, bound to the same source/payload.

`NPM_PUBLICATION_CLI` identifies the pinned npm installed in an isolated prefix.
The runner uses Node plus that CLI, explicit public registry, empty owned npm
config and private HOME/temp/cache. It records command/stdout/stderr hashes;
failed commands are not retried. Failure evidence stays in the identified private
directory; success removes owned temporary trees. Public reports must not contain
raw scanner findings, private patterns or credentials.

Exact compatibility uses
`compat:prepare -- --candidate-tarball <absolute.tgz> --candidate-sha256 <hex>`,
checks the owned fixture manifest/source pair/archive hash, runs `test:compat`
and `test:compat:browser`, then `compat:clean`. Pre-existing fixtures or a changed
candidate digest fail. No fallback packs a replacement candidate.

### Required evidence and honest pending states

`policy.mjs` defines `REQUIRED_GATES`, `validateGateStatus` and `validateGates`.
Final reports bind `schemaVersion: 1`, source `commit` and tarball
`artifact: {sha256, sha512, integrity}`. Every required gate needs nonempty
`evidence: [{description, sha256}]`. Automated gates must be `passed`.

Only **four human gates** may retain `ownerReview: "pending"` with
`status: "pending-owner-review"`: source/payload private identifiers, author
identity and historical risk disposition. The two private-identifier gates may
instead be `not-run` with that same pending owner review. These are unresolved
human obligations, **not manufactured passes**. Missing evidence, any other
pending/missing/skipped gate, and findings or execution failures block completion.
Fresh automation never erases historical uncertainty or author/private review.

The external gate sets in `gates.mjs` are:

| Phase | Required external gates |
|---|---|
| source | `source-gitleaks`, `source-trufflehog`, `source-private-identifiers`, `producer-advisories`, `author-identity`, `native-release-identity`, `historical-risk-disposition` |
| artifact | `payload-gitleaks`, `payload-trufflehog`, `payload-private-identifiers`, `consumer-advisories`, `licenses-notices`, `runtime-closure`, `consumer-npm11`, `consumer-npm12`, `consumer-platforms`, `native-windows-execution`, `service-replacement` |

Source also supplies `ui-build`; the artifact finalizer supplies `compatibility`.
`native-release-identity` replaces the old `native-rebuild` name: helper bytes,
source, metadata and build script must match the immutable same-major sanitized
release **byte for byte**. `native-windows-execution` separately checks actual
Windows helper execution against those bytes. This is **not a new compiler
build**, and it does **not prove an ordinary desktop user's token/authority
context**. Neither native gate may use a human-pending status.

`licenses-notices` verifies the actual extracted UI/runtime notice artifacts:
`THIRD_PARTY_NOTICES.txt`, `ui/dist/THIRD_PARTY_NOTICES.txt`,
`ui/dist/third-party-manifest.json`, and candidate `LICENSE`. It also requires
**consumer result and matrix report schema 2** with embedded license-evidence
schema 1, captured before each fresh local consumer install is removed. Every
dependency path/name/version/integrity is bound to its installed `package.json`
bytes and standalone license texts with SHA-256 hashes. Both script modes on
all three platforms and both pinned npm toolchains carry these bytes in the
original `report.json`; command stdout hashes and the official immutable ZIP
digest bind them through matrix validation. The finalizer rechecks metadata,
hashes, coverage, declarations and text markers. Candidate license evidence must
match the canonical tarball; the tarball `LICENSE` remains authoritative.

Producer version drift is not a license failure when the exact fresh consumer
evidence passes review. Missing, conflicting, linked, tampered or unknown
evidence still stops preparation. Repeated installed coordinates must agree in
integrity and text and are counted explicitly. The exact reviewed Yoga
supplement additionally requires the consumer integrity and reviewed source-file
hashes to match the packed and independently reviewed supplement. An unknown
Yoga version cannot reuse older text. No producer-install or producer-lock
fallback can waive missing consumer evidence.

Old schema-1 matrix artifacts, including immutable r4 runs, are not eligible
under this repair and must not be rewritten or repacked. New repair source
refs need fresh hosted runs. Local synthetic tests are not upstream license
approval; fresh hosted upstream license bytes still need actual verification.
Consumer/license failures retain only an allowlisted public coordinate/reason
or a fixed recovery hint, at most 512 characters, in `error.reviewRequired`.
`consumer-platforms` instructs the operator to verify all six immutable schema 2
reports, both modes and exact source/artifact bindings; missing or changed
evidence requires fresh consumers. `licenses-notices` preserves exact allowed
coordinate reasons, otherwise instructs review of exact versions, hashes,
declarations and canonical notices, without producer substitution or reuse of
changed evidence. Raw stderr, paths, stdout, commands and private exception
text are not replayed. The owned failure reader rechecks the gate-specific
allowlist; the external report remains schema 1.

Finalizers must retain each original `consumers[].result` unchanged, including:

```text
result.schemaVersion = 2
result.dependencies[] = { path, name, version, integrity }
result.licenseEvidence = {
  schemaVersion: 1,
  packages: [{
    path, name, version, integrity,
    packageJson: { path: "package.json", sha256, text },
    files: [{ path, sha256, text }],
    reviewedSources: [{ path, sha256 }]
  }]
}
```

`packages` matches dependency count and order, including the candidate.
`reviewedSources` is empty except for exact reviewed supplement coordinates.
`verifyMatrixReports` in `tools/npm-publication/matrix.mjs` is the shared
authenticated entry point in both release lines; pass its full return value
through the existing `matrix` request field. It verifies immutable archives,
source/job/command bindings and evidence. The lower-level
`validateConsumerLicenseEvidence` only checks evidence structure and bindings,
not archive authenticity or license approval. Do not use it alone as a gate.

`runtime-closure` separately checks extracted runtime paths and actual consumer
installed-bin/bridge/UI evidence.

### Scanner installation

Both source and finalizer jobs call `install-scanners.mjs`. It downloads official
**Gitleaks 8.30.1** and **TruffleHog 3.97.1** release archives using independently
pinned archive/checksum digests, plus the pinned upstream Gitleaks config. It
does not use `go install`. Scanner scope includes source history and the actual
payload; unavailable tools or findings fail, not skip.

The Gitleaks v8.30.1 `config/gitleaks.toml` SHA256 is
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
The scanner validates this local input and records its effective digest after
removing global path exclusions; defaults that exclude lockfiles/binary paths
are not accepted. The installer supplies the config; the scanner itself does
not download it.

Preparation forwards explicit absolute `MCP_GITLEAKS_BIN`/`MCP_GITLEAKS_SHA256`,
`MCP_GITLEAKS_CONFIG`, `MCP_TRUFFLEHOG_BIN`/`MCP_TRUFFLEHOG_SHA256` and optional
`MCP_GO_BIN`/`MCP_GIT_BIN` tool paths only. Scanner binaries must match their pins; these settings
are not forwarded to staging npm. Private policy/exemptions require explicit
reviewed inputs, never ambient configuration.

## Stage reconciliation and owner approval

The job writes an **unknown-outcome** ledger before calling npm. npm 12.0.2 emits
name-keyed JSON, with `stageId` inside the package entry on successful submission.
The fresh source-pinned child retains the automatic `.sigstore` JSON-text
attachment from the **actual serialized POST**, not a separately signed bundle.
Before loading npm, the adapter binds the physical distribution inventory
(including package manifests, exports and delegates), actual caller-specific
`require.resolve` destinations, and an empty npm module cache. Generated
`node_modules/.bin` command shims are platform-specific and excluded from the
inventory; none is an allowed loader destination. Changed distributions fail
closed and need explicit review rather than refreshed hashes at execution time.

The original `ACTIONS_ID_TOKEN_REQUEST_URL` must be HTTPS without userinfo,
fragment or an existing ambiguous audience. Both the npm audience and the real
Sigstore `CIContextProvider('sigstore')` request use the same guarded transport.
Original query/identity data and the requested audience are preserved. Issuer
requests have no redirects/retries, a 30-second total/body deadline and a 64 KiB
response cap. An issuer failure prevents another hop, token exchange or stage.
Raw issuer responses, credentials and underlying errors are never retained.

Fulcio is not credential-free: its certificate POST contains
`credentials.oidcIdentityToken` in the JSON body. The adapter binds that request
to `https://fulcio.sigstore.dev/api/v2/signingCert`, permits one certificate
attempt, disables both its outer Sigstore retry helper and lower HTTP retries,
rejects redirects, and bounds the request/response to 64 KiB/256 KiB with a
30-second total/body deadline. A certificate failure blocks later continuation.
The supported CLI already flattens `--fetch-retries=0` to zero outer retries;
the explicit adapter guard also covers the general SDK's retry defaults.
The certificate body, token and raw response are never retained in production.
TUF's credential-free global-fetch metadata reads are a separate path, unchanged
by these issuer/certificate controls.

It writes durable unknown intent before the request, forces zero retries and
redirect rejection below npm-registry-fetch, and permits at most one stage POST.
307/308 cannot replay it. The serialized body, bundle and successful response are
hash-bound to the **same call's** stage ID and exact source/workflow/tarball.
Limits are 64 MiB request, 2 MiB bundle, 64 KiB response and 30 seconds including
body consumption; the CLI child has a two-minute cap. Capture failure leaves the
outcome unknown. Request auth headers/options and raw body/response are not saved;
only the actual provenance bundle and bounded metadata/hashes are retained.

The parser checks version, size, hashes and a UUID stage ID and requires the CLI
ID to equal the captured response ID. npm 11 array output,
missing IDs, network loss or malformed responses leave the outcome unknown.
The ledger is uploaded even on failure when possible. A lost runner can lose that
artifact: absence of a ledger is not proof nothing was staged.

Do not rerun a stage job. Run attempt >1 is rejected. Before a fresh dispatch,
the owner must reconcile authenticated stage/version state and authorize the new
operation. GitHub's package-wide no-cancel concurrency group is **not** a durable
FIFO, and npm website approvals are outside it. Maintain one owner release ledger
across both majors and pending stages. Never approve out of order without a fresh
channel-state check.

OIDC supports stage submission, not stage list/view/download/approve/reject,
dist-tag changes, deprecation, access changes or unpublish. Perform owner reads
from an approved GitHub-hosted release environment with appropriate owner
authentication, not from the local development machine:

```text
npm stage list mcp-pacemaker --json
npm stage view <exact-stage-id> --json
npm stage download <exact-stage-id> --json
```

These commands are **not run by this workflow**. The view JSON's real fields
include `id`, `packageName`, `version`, `tag`, `shasum`; SHA1 alone is insufficient.
Match downloaded bytes to the approved SHA256 and SHA512/SRI.

Before owner publication approval, obtain `stage-1.json`,
`capture/provenance.sigstore` and `capture/receipt.json` from the **original**
successful stage run's `npm-stage-ledger-<runId>-1` artifact. Use its actual
GitHub artifact ID. Verification requires a read-only GitHub token for the
existing authenticated API readers and the separate owner stage/tarball readback:

```text
NPM_PUBLICATION_CLI=<isolated npm12.0.2/bin/npm-cli.js>
node tools/npm-publication/verify-staged.mjs stage-record.json stage-view.json
  downloaded.tgz provenance.sigstore current-tags.json receipt.json
  <original-github-capture-artifact-id>
```

The verifier first fetches the original run/jobs/artifact through GitHub, validates
the actual archive digest, and requires the exact capture, bundle and original
stage records from that archive. Local hashes or `authenticated: true` cannot
replace this read. A reconciled ledger points back to that original artifact;
verify the original `stage-1.json`, not a newly relabelled record.

It then uses npm 12.0.2's bundled **sigstore 5.0.0**, validates signature,
chain, certificate identity/issuer and transparency thresholds, and separately
checks package subject/digest, source/workflow and the **original staging run**.
It can read official Sigstore TUF metadata. It never creates a token or signs.
Its result does not perform or authorize npm approval.

**A genuine hosted capture remains an execution gate.** Stage download returns
only the tarball; no undocumented bundle endpoint is guessed. The authenticated
GitHub artifact establishes the source-bound observer's same-call linkage. It
does not turn a local hash into execution authentication or cryptographically
prove which attachment bytes the registry stored. Stage view/download cannot
prove that either. Missing, lost, expired or mismatched original capture blocks
owner approval, even if an unrelated bundle verifies for the same source/run.
Readback, reconciliation, rejection/removal and credential cleanup remain
independent of this acceptance prerequisite. Staging can disclose source/package
metadata through public Sigstore transparency before owner approval.

Do not substitute a pre-signed export. In npm12.0.2, successful OIDC can enable
automatic provenance even with `provenance-file`; libnpmpublish then generates a
different attachment. Explicit `--provenance=false` plus `--provenance-file`
is rejected too. The adapter preserves Trusted Publishing and captures its
actual automatic attachment after SDK generation and registry serialization.
Offline tests use explicit synthetic OIDC/signature/HTTP fixtures in fresh
children with denied external I/O. They are not real captures or owner approval.

The owner approves the exact stage separately with npm 2FA, after fresh tag
readback and proof verification. Stage tags are immutable. A wrong tag requires
separately authorized rejection/restaging, not a hidden tag write.

## After publication

Registry signatures remain **pending publication** until the version exists.
Read version metadata and the complete dist-tag map; download and compare the
registered tarball to the approved hashes. Install the exact version into a
disposable consumer project without a copied producer lock and run:

```text
npm audit signatures --json --include-attestations
```

Use the supported pinned verifier and inspect coverage for the intended candidate,
including missing/invalid registry signatures and provenance. Exit zero alone is
not acceptance. Check source/workflow/issuer/subject and real consumer smoke
results; append this separate acceptance evidence to the release ledger.
The signed bootstrap does not waive provenance or registry signatures. Block
acceptance on missing or invalid evidence; containment, rollback or deprecation
needs separate owner authorization.
Never overwrite an immutable name/version or roll a channel across majors.

## Local tests and official contracts

```text
node --test test/npm-publication*.test.mjs
```

These lightweight tests inject clients/executors/verifiers and use controlled
file/receipt fixtures. Node 24.11.0 may run these pure tests; it is **not** the
publishing toolchain. Passing them proves local guard decisions, not hosted
matrix execution, actual scans, native execution, license coverage, T32,
compatibility, npm trust, signature cryptography, protected environment
enforcement or successful staging/publication. No hosted tests, scans, installs
or npm stage command were executed by this local test/docs validation.
The publication entrypoint is not a local dry run and must not be used as one.

Implementation references (not re-fetched by local unit validation):

- [Node 24.21.0 official release index](https://nodejs.org/dist/index.json)
- [npm 12.0.2 publish/precedence/output](https://github.com/npm/cli/blob/v12.0.2/lib/commands/publish.js)
- [npm 12 pack name-keyed JSON](https://github.com/npm/cli/blob/v12.0.2/lib/utils/tar.js)
- [npm stage commands/auth/tag semantics](https://github.com/npm/cli/blob/v12.0.2/docs/lib/content/commands/npm-stage.md)
- [npm provenance construction](https://github.com/npm/cli/blob/v12.0.2/workspaces/libnpmpublish/lib/provenance.js)
- [Sigstore 5 verifier options](https://github.com/sigstore/sigstore-js/blob/7d2900eca1c22b3f87c13987c8d4b7c9a29b733a/packages/client/src/config.ts)
- Actions: checkout **6.1.0**, setup-node **6.5.0**, upload-artifact/download-artifact
  **6.0.0**. Full commit pins in the workflow were resolved from official action
  repository tags; they are not floating major tags.
