# Preparing and staging npm candidates

This workflow supports only the reviewed `mcp-pacemaker` **1.3.1** (`legacy`) and
**2.0.1** (`latest`) candidates. It does not establish name availability, publish
a version, approve a stage, change a dist-tag, or configure an account or trust.

## Prerequisites

1. Commit this workflow and its tools in each candidate. Put the workflow on the
   default branch too, so GitHub permits manual dispatch. Create an approved
   annotated publication tag on the exact green source commit. For each supported
   version, only `v<version>`, `npm/v<version>` and `npm-r2/v<version>` are accepted.
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
new immutable `npm-r2/v1.3.1` and `npm-r2/v2.0.1` sources. Keep all existing
tags and GitHub releases unchanged, even when preparation failed. Each new
publication tag needs explicit approval and points to its own green commit
containing the workflow and tools that actually run. Do not reuse an approval
for a different tag object.

The complete ref, including its namespace, remains bound through source checkout, CI,
consumer artifacts, peer transfer, protected-environment tag policy and staged
provenance. A source bundle from `v<version>` cannot be relabeled as one from
`npm/v<version>` or `npm-r2/v<version>`, nor can an `npm/` source bundle become
an `npm-r2/` bundle. The protected environment must explicitly allow the exact
new tags; approval for an older tag is not sufficient. Prepare fresh artifacts
for the new source; package versions
and the derived `latest`/`legacy` npm channels do not change. Existing registry
versions remain immutable, including when only the publisher tools changed.

## Manual inputs

There are two dispatch inputs: `action` (default **prepare**) and `approval`
(JSON). Inputs are parsed from the actual event file, not interpolated into shell
commands. Dispatch against the approved release **tag**, not `main`.

Preparation approval fields:

```json
{
  "schemaVersion": 1,
  "name": "mcp-pacemaker",
  "version": "1.3.1",
  "ref": "refs/tags/npm-r2/v1.3.1",
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

External gate failures expose only an allowlisted gate and fixed error code.
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
**original** `workflow` object (`ref`, `commit`, `runId`, `attempt: 1`).
That path records the original stage ID/workflow without another submission.
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
  --fetch-retries=0 --userconfig=<empty-owned-file> --globalconfig=<empty-owned-file>
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
actual installed producer license declarations, texts and reviewed supplements
covering **every exact name/version in all 12 independent consumer graphs**.
A fresh/platform-specific consumer version absent from that evidence fails the
gate and needs reviewed exact-version license evidence. Producer locks do not
pin consumer resolutions; packed notice presence alone is not license coverage.
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
The parser checks version, size, hashes and a UUID stage ID. npm 11 array output,
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

Before owner publication approval, obtain the **actual staged provenance bundle**
through a supported npm/Sigstore retrieval path and verify it:

```text
NPM_PUBLICATION_CLI=<isolated npm12.0.2/bin/npm-cli.js>
node tools/npm-publication/verify-staged.mjs stage-record.json stage-view.json
  downloaded.tgz bundle.sigstore current-tags.json
```

The verifier uses npm 12.0.2's bundled **sigstore 5.0.0**, validates signature,
chain, certificate identity/issuer and transparency thresholds, and separately
checks package subject/digest, source/workflow and the **original staging run**.
It can read official Sigstore TUF metadata. It never creates a token or signs.
Its result does not perform or authorize npm approval.

**Retrieval remains an execution gate:** the versioned stage download command
returns the tarball, not a documented provenance bundle. This tool deliberately
does not guess an attestation endpoint or accept a rendered provenance link as
proof. If the expected bundle cannot be obtained and verified, **stop before owner
approval**. Hashes are not signatures. Staging can already disclose source/package
metadata through public Sigstore transparency, even before npm owner approval.

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
