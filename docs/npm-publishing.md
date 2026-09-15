# Preparing, signing, publishing the bootstrap, and staging npm candidates

This workflow supports only the reviewed `mcp-pacemaker` **1.3.1** (`legacy`) and
**2.0.1** (`latest`) candidates. The separately approved `publish-bootstrap`
action performs one first-package owner-authenticated direct publication of
2.0.1/latest. It is **not staging**. No action approves a stage, changes account
or trust settings, or repairs a channel after publication.

**All npm registry, authentication, publication and session-revocation operations
run only on GitHub-hosted runners.** Do not run these operational entrypoints
against npm from a local machine. Local injected unit tests and permitted
verification of already fetched evidence are separate.

## Prerequisites

1. Commit this workflow and its tools in each candidate. Put the workflow on the
   default branch too, so GitHub permits manual dispatch. Create an approved
   annotated publication tag on the exact green source commit. For each supported
   version, only `v<version>` and `npm/v<version>` are accepted.
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
   owner. The first **2.0.1/latest** uses the protected `sign-bootstrap` job below,
   then the protected GitHub `publish-bootstrap` action with genuine owner
   browser 2FA and that exact verified CI provenance file. There is no dummy
   release, unsigned exception, persistent npm secret or first-package staging
   attempt. The short-lived owner login session exists only in runner memory.
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

Use `npm/v1.3.1` and `npm/v2.0.1` when preparing the same unpublished package
versions after publishing-tool repairs. Keep existing GitHub release tags and
releases unchanged. Each new publication tag needs explicit approval and points
to its own green commit containing the workflow and tools that actually run.
Do not move a release tag or reuse an approval for a different tag object.

The complete ref, including `npm/`, remains bound through source checkout, CI,
consumer artifacts, peer transfer, protected-environment tag policy and staged
provenance. A source bundle from `v<version>` cannot be relabeled as one from
`npm/v<version>`. Prepare fresh artifacts for the new source; package versions
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
  "ref": "refs/tags/npm/v1.3.1",
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
all at the approved head SHA; `stage`, `sign-bootstrap` and `publish-bootstrap`
jobs must be skipped.

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
    "ref": "<opposite approved refs/tags/npm/vVERSION or refs/tags/vVERSION>",
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

### Stage input, after the signed bootstrap and trust setup

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

The stage job's only npm mutation is:

```text
npm stage publish <exact-candidate.tgz> --access=public --tag=<derived-channel>
  --registry=https://registry.npmjs.org/ --provenance --ignore-scripts --json
  --fetch-retries=0 --userconfig=<empty-owned-file> --globalconfig=<empty-owned-file>
```

There is no token fallback. npm runs in an empty owned directory with a restricted
environment. Supplied npm tokens/config, alternative ID tokens and Node injection
are rejected. The actual GitHub identity is forwarded unchanged. npm OIDC exchange
failure therefore cannot fall back to an old user credential.

## Signed first publication: 2.0.1 only

`sign-bootstrap` is a separate manual action, **not an npm publish action**.
It requires the real `npm-publish` protected environment and owner approval.
Prepare still has no OIDC. Only protected signing and staging jobs have
`id-token: write`, with one package-wide no-cancel concurrency group.
Signing publishes metadata to public Sigstore services, so it needs its own
explicit disclosure approval even though it makes **no npm write**.

### Signing approval

Use `action: sign-bootstrap` on the actual approved 2.0.1 publication tag.
The approval has **exactly** these top-level fields:

```text
schemaVersion, name, version, ref, tagObject, commit, tree,
ciRunId, ciAttempt, approver, approvedAt, scope, artifact, ownerPreflight
```

Use the source fields above, `version: "2.0.1"`, `scope: "sign-bootstrap"`,
and the exact eight-field final prepare `artifact` object shown in the stage
example. Do **not** copy prepare-only `publicPackages` or `peerArtifact` into
this strict approval. Their original source/matrix/peer evidence remains bound
inside the approved final manifest and is revalidated, not replaced.

The bootstrap `ownerPreflight` is different from stage preflight:

```json
{
  "owner": "girishkvs",
  "packageName": "mcp-pacemaker",
  "registry": "https://registry.npmjs.org/",
  "checkedAt": "<fresh UTC timestamp>",
  "packageStatus": "absent",
  "nameApproved": true,
  "publicProvenanceApproved": true,
  "unresolvedSubmission": false,
  "unresolvedSigning": false,
  "priorSigning": { "status": "none" },
  "privateContentReview": {
    "reviewer": "girishkvs",
    "scope": "source-and-tarball",
    "disposition": "approved",
    "historyAndAuthorsReviewed": true,
    "historicalEvidenceAccepted": true,
    "commit": "<same approved commit>",
    "artifact": {
      "sha256": "<approved tarball SHA256>",
      "sha512": "<approved tarball SHA512 hex>",
      "integrity": "sha512-<approved tarball SHA512 base64>"
    },
    "reviewedAt": "<fresh UTC timestamp>"
  }
}
```

These placeholders fail validation. Approval, owner readback and content review
expire after one hour, including while signing runs. Name approval is an owner
decision; an anonymous registry 404 does **not** reserve a name or prove the
owner can claim it. The job independently requires a definitive, fresh package
404 from the fixed public registry. A present package/version, denied lookup,
redirect, network error or unknown outcome blocks signing.
Bootstrap deliberately does **not** require already-existing npm ownership or
trusted-publisher configuration: those cannot establish first-package access.

Browser access to the npm website, including a package-page 404, does not prove
Node can reach the npm registry or Sigstore trust/signing services. TLS handshake
failures remain blocking transport errors, not package-absence evidence.
Use the approved GitHub-hosted runner and stop on any transport failure.
Never disable TLS verification, substitute a dependency-feed
registry, or redirect publication credentials to a feed proxy to force success.
Existing dependency-feed policy is not changed by this workflow.

Before a fresh signing dispatch after any prior attempt, the owner must settle
its release ledger and use:
`"priorSigning": {"status":"reconciled","runIds":["<actual prior run ID>"]}`.
The current signing run cannot already be reconciled. A copied approval or a
missing artifact does not settle a lost signing/publication outcome.

### Signing execution and artifact contract

1. Require actual hosted Linux/x64, Node **24.21.0**, original run attempt 1,
   owner actor/triggering actor, repository IDs and actual dispatch inputs.
   Validate annotated tag object, peeled commit/tree, clean checkout, package
   metadata, lock hashes, event SHA/ref and exact workflow source.
2. Read exact successful push CI and the real protected environment/tag policy
   and current run's owner approval. Re-read the completed prepare run and its
   final/source ZIPs, all six consumer ZIPs and jobs, **12 install receipts**,
   Windows execution evidence, opposite-patch source ZIP/jobs and T32 binding.
   Require all existing automated gates and the fresh separate owner review.
   Nothing repacks, installs consumers again or substitutes a newer workflow
   identity for the prepared source.
3. Record `signing-outcome-unknown` before the single signing call. A fresh,
   restricted child loads the already installed npm **12.0.2** library
   `libnpmpublish@12.0.0`, its reviewed provenance source and bundled
   `sigstore@5.0.0`. It signs the standard npm PURL subject with the exact
   compressed tarball SHA512 using the **actual** GitHub identity. No alternate
   ID token, npm auth/config, GitHub read token or Node injection reaches it.
   Signing HTTP retries are disabled. Errors are not echoed with tokens.
4. Verify the full bundle's signature chain, GitHub issuer, exact anchored
   workflow certificate identity and transparency logs. Separately check SLSA
   v1 subject/source/ref/workflow/run and repository/owner IDs. Re-read source,
   protected approval, prepare evidence, registry absence and unchanged bytes
   before accepting the result.
5. Export `npm-bootstrap-signed-<signRunId>-1`, containing **exactly**:

   ```text
   candidate.tgz
   gates.json
   manifest.json
   provenance.sigstore
   bootstrap.json
   ```

   The first three files are byte-identical to the approved prepare artifact.
   `bootstrap.json` records `phase: "bootstrap-signed-not-published"`, exact
   source/workflow/run/repository IDs, prepare artifact approval, original
   signing approval, tarball/report hashes, bundle SHA256 and actual readbacks.
   Registry signatures remain `pending-publication`; owner publication approval
   remains `not-performed`. The original prepare manifest is **not rewritten**
   to claim it signed anything.

The separate `npm-bootstrap-ledger-<signRunId>-1` retains unknown/success records
when possible, even after job failure. A lost runner can lose that artifact.
**Never rerun the job or blindly repeat signing.** Attempt >1 is rejected.
Even a correctly signed bundle is unusable through this contract unless the
original signing run, signing step and artifact export all completed
successfully. A failed post-sign check or lost upload requires owner
reconciliation and separately approved next steps.

Stock npm provenance signs the package subject, source/workflow and run. It
does **not** cryptographically sign owner approval, gate receipts, job ID or a
stage ID. GitHub API artifact/ZIP checks authenticate those additional receipt
bindings; SHA256/SHA512 alone do not authenticate provenance.

### GitHub-hosted owner bootstrap approval

Use `action: publish-bootstrap`, `scope: "publish-bootstrap"`, the same source
and final prepare `artifact`, and a **fresh** owner preflight/content review.
Reconcile the completed signing run: `priorSigning.status` must be `reconciled`
and its `runIds` must include that run. Add these two exact top-level fields:

```json
{
  "signedArtifact": {
    "artifactId": "<immutable signing artifact ID>",
    "artifactDigest": "sha256:<actual signing API ZIP SHA256>",
    "runId": "<original successful signing run ID>",
    "runAttempt": 1,
    "receiptSha256": "<bootstrap.json SHA256>",
    "bundleSha256": "<provenance.sigstore SHA256>"
  },
  "ownerAuth": {
    "spki": "<canonical standard base64 DER RSA-4096 public SPKI>",
    "sha256": "<lowercase SHA256 of those DER bytes>",
    "transaction": "<fresh CSPRNG 16-byte nonce, lowercase 32-character hex>"
  }
}
```

RSA exponent must be 65537. Keep the corresponding private key in the owner's
approved memory-only holder, never in GitHub, approval JSON, files or logs.
The nonce is a transaction identifier, not an npm credential. It must be new
for each separately approved dispatch. Generic approval does not fill in the
separate content/history review fields.

The complete strict top-level publish approval is:

```text
schemaVersion, name, version, ref, tagObject, commit, tree, ciRunId, ciAttempt,
approver, approvedAt, scope, artifact, ownerPreflight, signedArtifact, ownerAuth
```

### Owner execution and encrypted challenge handoff

1. The job has **no OIDC permission**. Its first step rejects unsupported hosted
   context; tools also require actual Linux/x64, Node24.21.0, owner actor,
   original attempt1, event/ref/source/workflow identity and exact approval.
   The real protected environment must still have ID `21922517673`, the
   required owner review and the approved tag policy.
2. Install the pinned SDK before authentication. Download the signing artifact
   using the actual GitHub API and verify its ZIP/digest/five-file contract,
   source, CI, gates, six consumer jobs/twelve installs, peer/T32 evidence,
   signatures, claims and fresh owner review. Require registry package absence.
   `verify-bootstrap.mjs` now refuses operational execution outside this hosted
   publish job. Its GET/crypto verification is not a local or offline command.
3. A job-bounded background supervisor retains only the GitHub read credential.
   It launches a separate owner process with restricted environment, private
   HOME and no npmrc, GitHub token, OIDC token, Node injection or proxy settings.
   The runner tracking identifier remains for GitHub's end-of-job cleanup.
   Owner stdout/stderr are not exported. A correlated IPC request obtains
   fresh full verification before login and each publication authorization.
4. The owner process calls pinned **npm-profile13.0.1 `loginWeb`**, never its
   password fallback. Only the npm website challenge URL is encrypted using
   `OwnerAuthEnvelope`; no token, done URL or OTP enters files, environment,
   IPC, public logs or artifacts. The runner polls the official registry.
   Foreground workflow wait/upload steps can run while this background process
   waits for real owner browser approval.
5. Verify/decrypt the challenge in the approved owner holder, then open only
   that URL in the approved owner browser. **Encryption does not authenticate
   origin:** first verify the actual GitHub run/job/source, artifact ID/API ZIP
   digest, expected file and every AAD field. Require literal authenticated AAD,
   fresh issue/expiry, expected key fingerprint/nonce and unused sequence.
6. On login, actual npm `whoami` and profile must identify `girishkvs`; profile
   must report `tfa.mode: "auth-and-writes"`. After fresh verification, use the
   documented `libnpmpublish.publish(manifest, retainedTarBuffer, options)`.
   `pacote.manifest(localTgz, {fullMetadata:true, fullReadJson:true, ...})` reads
   the unchanged archive offline with scripts disabled. Metadata/options,
   tarball and provenance hashes are rechecked. Options explicitly select
   `defaultTag: "latest"`, public access, npm12.0.2, `provenanceFile`, public
   registry and zero retries. No `stage` or generated `provenance` option is set.
7. Fsync an immutable `submission-outcome-unknown` record **before each PUT**.
   Only npm's confirmed `EOTP`/HTTP401 for this exact package PUT, with valid
   npm auth/done URLs, permits a browser challenge and one continuation.
   Recheck source, registry absence, artifact, gates and owner freshness after
   real browser authorization. A second EOTP, transport error, lost response
   or other error never permits another PUT. No TTY spoof or bypass token.
8. Check acknowledged publication against actual registry metadata, exactly
   2.0.1/latest, SRI and freshly downloaded tarball SHA256/SHA512. This is not
   registry-signature or published-provenance acceptance. Those checks and
   the fresh registry consumer remain pending until the anonymous acceptance
   steps below pass.
9. Finally, attempt npm12's logout session DELETE for **only the new session
   token**. No other token inventory/browser session is revoked. A failed or
   lost logout response is `revocation-failed-owner-action-required`; a lost
   login response is `login-outcome-unknown`. Neither is disguised as cleanup.
   Do not rerun a failed job or reuse an approval. Reconcile the release ledger,
   npm state and any possible session/publication before new authorization.

The transport adapter matters: npm-registry-fetch does not forward its caller's
`redirect` option to make-fetch-happen. In the fresh owner child, only registry
calls use a constrained transport with official HTTPS registry destinations,
redirect rejection, normal TLS, no disk cache and zero retries. Owner auth is
host-bound. Separate Sigstore trust reads carry no npm credentials.

### Owner artifacts, receipts and process limits

| Artifact | Exact challenge file / contents |
|---|---|
| `npm-owner-auth-<runId>-1-login` | `challenge-1.json`: encrypted login URL |
| `npm-owner-auth-<runId>-1-publication-2fa` | `challenge-2.json`: encrypted publication-2FA URL; absent when no publication challenge was issued |
| `npm-owner-bootstrap-ledger-<runId>-1` | Immutable safe verification, unknown-outcome, publication/readback, cleanup and process receipts |

Challenge schema is exactly `{schemaVersion, algorithm, aad, wrappedKey, nonce,
ciphertext, tag}`, with algorithm `RSA-OAEP-256+A256GCM`. Binary fields are
canonical padded base64. RSA wraps a fresh 32-byte AES key with OAEP-SHA256
(empty label); GCM uses a fresh 12-byte nonce and 16-byte tag. Plaintext is only
`{"url":"<website challenge>"}`. Authenticate literal decoded AAD bytes. Its
ordered fields are:

```text
repository, ref, commit, runId, runAttempt, owner, name, version,
sha256, keySha256, transaction, sequence, kind, purpose, issuedAt, expiresAt
```

`runAttempt` is1, `purpose` is `mcp-pacemaker-npm-owner-auth`, expiry is exactly
ten minutes after issue. Sequence/kind is either1/`login` or2/`publish-2fa`.
These are the **publication run's** identity, not the earlier signing run.
Signing receipts keep their original identity. Envelope tampering/replay fails;
possessing the public key alone must never authorize a browser handoff.

`owner-<three-digit-record-number>.json` ledger records contain `schemaVersion`, exact binding
(the first eleven AAD fields above), `recordedAt` and a fixed `phase` with only
safe phase-specific fields. `done.json` adds `outcome`, `attempts`, `cleanup`,
`success`. This owner-process success requires `published-readback-matched`
**and** `revoked`; it is not full workflow acceptance. Verification
receipts retain the full original signing proof and add actual
`checks.publicationRun` and `checks.publicationEnvironment`.

Job timeout is40 minutes, supervisor deadline30 minutes, owner lifetime20
minutes. Waits are bounded (login10, publication challenge15, completion10
minutes); every registry request is bounded. An `always()` cleanup step requests
shutdown, allows two minutes for cleanup, then identity-checks exact job-owned
process IDs before forced termination if needed. Runner cleanup remains a final
backstop. Lost runners/forced termination can prevent revocation or artifact
upload: missing receipts are **unknown**, not proof nothing happened.

Only after the hosted registry-signature/provenance/consumer acceptance below
may stage-only trust and the separately gated 1.3.1/legacy path proceed. These
additional owner operations are not silently bundled. Never upgrade a live
service as part of publication validation.

### Anonymous post-publication acceptance

The same sole-active `publish-bootstrap` job now performs acceptance before it
can succeed. There are no further owner credentials or npm writes:

1. `post-publication.mjs prepare` runs **after** confirmed readback, session
   revocation and exit of both owner processes. It uses a GitHub read token to
   recheck actual source/CI, signed/prepared API ZIPs, all twelve prepublication
   consumer installs, peer evidence and both protected-environment approvals.
   It verifies the retained signing proof again. Historical registry absence
   in that signing receipt stays historical; it is not fabricated as current
   absence after publication. The GitHub-token-bearing process then exits.
2. `post-publication.mjs verify` runs in a separate step with **no GitHub token,
   npm token or OIDC**. It requires the verified owner state and source receipt.
   Anonymous GETs use normal TLS, reject redirects and non-registry origins,
   have 30-second timeouts and enforce response-size limits.
3. Fetch the published version metadata and complete dist-tag map, exact
   tarball, public registry signing keys and the **actual attestation URL
   returned by version metadata**. No guessed attestation endpoint is used.
   The bootstrap must still contain only2.0.1 with `latest: 2.0.1`.
4. Create a new owned, empty consumer with private HOME/config/cache. Install
   `mcp-pacemaker@2.0.1` from the public registry with scripts disabled, an exact
   dependency spec and a newly generated consumer lock. Never use the retained
   `.tgz` as the installation source or copy the producer lock. Every installed
   target file must match the approved archive; runtime notices are checked.
5. Run pinned npm12.0.2 `audit signatures --json --include-attestations`.
   Require empty `invalid`/`missing` arrays and exactly one `verified` entry for
   the intended name/version, root installation location, public registry and
   actual attached bundles. An exit code or aggregate count is not coverage.
   Independently verify the observed target's registry signatures against the
   official registry keys and its publication time.
6. Verify the actual attached SLSA bundle using Sigstore, exact subject/SHA512,
   issuer, certificate identity, transparency evidence and **original signing
   source/workflow/run**. It must match the approved signing bundle, not merely
   an unrelated valid bundle. Never substitute the publisher/verifier run.
7. Only after those checks, run the installed npm bin, an isolated real bridge
   and its packaged UI assets. Recheck installed bytes, the consumer lock and
   final registry metadata/channel state. Clean the owned consumer.

Each npm command has a six-minute limit; the anonymous workflow step has a
fourteen-minute limit within the existing forty-minute job bound.

The upload step **`Export post-publication acceptance or failure receipt`**
always attempts to retain `npm-post-publication-<publicationRunId>-1`, containing
one `post-publication.json`, bounded to64KiB. A successful receipt has:

```text
schemaVersion: 1
status: accepted
binding, checkedAt, publication, checks, evidence, consumer
registryMutation: not-performed
```

`evidence` includes registry signature/key and target audit coverage, metadata/
attestation/audit hashes, verified attached provenance and the original signing
identity. `consumer` includes the exact registry spec, fresh lock hash, toolchain,
installed-bin/bridge/UI results and `producerLockCopied: false`.

**Full acceptance requires this receipt with `status: accepted` and a successful
actual job/run**, in addition to owner `done.json` and cleanup. On failure,
`status: not-accepted` records the failing phase without raw SDK errors or URLs;
the job fails. Publication is not rolled back. There is no republish, unpublish,
tag mutation or automatic retry. Missing receipts after runner loss are unknown.

The proof and consumer functions also accept1.3.1 plus explicit original stage
expectations for reuse by a future actual GitHub-hosted read-only caller. This
bootstrap entrypoint remains2.0.1-only; no standalone legacy verification action
is added. Actual staged-bundle retrieval and verification **before** owner stage
approval remain separate mandatory gates.

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
only from separately approved GitHub-hosted execution with appropriate owner authentication:

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

Do not reuse the bootstrap export as staged proof. In npm **12.0.2**, the OIDC
publish path can set `opts.provenance=true` even when `provenance-file` was
supplied; libnpmpublish then generates another bundle instead of using that
file. `--no-provenance` plus `--provenance-file` is also mutually exclusive.
Therefore pre-signing/exporting a bundle in the stage job would not prove it
was the bundle actually attached to the stage. Stage arguments and verification
remain unchanged until a supported retrieval path supplies the **actual**
staged bundle. Inspect the real owner UI/API with separate authorization;
do not guess endpoints or weaken this acceptance gate.

The owner approves the exact stage separately with npm 2FA, after fresh tag
readback and proof verification. Stage tags are immutable. A wrong tag requires
separately authorized rejection/restaging, not a hidden tag write.

## After publication

All registry, signature and registry-consumer operations run on GitHub-hosted
runners, never on the owner's machine. The first2.0.1 bootstrap automatically
runs the anonymous acceptance path above after revocation.

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
There is **no absent-provenance bootstrap exception**. Missing or invalid
provenance and invalid registry signatures block acceptance;
containment/rollback/deprecation needs separate owner authorization.
Never overwrite an immutable name/version or roll a channel across majors.

## Local tests and official contracts

```text
node --test --test-concurrency=2 test/npm-publication*.test.mjs
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
- [npm12 documented direct SDK publication](https://github.com/npm/cli/blob/v12.0.2/workspaces/libnpmpublish/README.md)
- [npm-profile13.0.1 browser-auth protocol](https://github.com/npm/npm-profile/blob/v13.0.1/lib/index.js)
- [npm12 browser-OTP continuation](https://github.com/npm/cli/blob/v12.0.2/lib/utils/auth.js)
- [npm12 logout endpoint](https://github.com/npm/cli/blob/v12.0.2/lib/commands/logout.js)
- [npm12 signature audit and target-attestation output](https://github.com/npm/cli/blob/v12.0.2/lib/utils/verify-signatures.js)
- [Bundled pacote22 signature and attached-provenance verification](https://github.com/npm/pacote/blob/v22.0.0/lib/registry.js)
- [Sigstore 5 verifier options](https://github.com/sigstore/sigstore-js/blob/7d2900eca1c22b3f87c13987c8d4b7c9a29b733a/packages/client/src/config.ts)
- Actions: checkout **6.1.0**, setup-node **6.5.0**, upload-artifact/download-artifact
  **6.0.0**. Full commit pins in the workflow were resolved from official action
  repository tags; they are not floating major tags.
