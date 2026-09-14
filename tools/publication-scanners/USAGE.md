# Local/CI publication scanners

These tools do not install scanners, restore packages, change registry settings, authenticate,
publish, or authorize publication. Node 20+ and existing `node:test` are the only JS requirements.

## Secret scanners

Supply **reviewed executable digests**, not a digest calculated merely to bless an unknown download:

| Environment variable | Input |
|---|---|
| `MCP_GITLEAKS_BIN` | Absolute path to Gitleaks **8.30.1** |
| `MCP_GITLEAKS_SHA256` | Approved executable SHA-256 for this platform/build |
| `MCP_GITLEAKS_CONFIG` | Absolute path to that module's `config/gitleaks.toml` |
| `MCP_TRUFFLEHOG_BIN` | Absolute path to TruffleHog **3.97.1** |
| `MCP_TRUFFLEHOG_SHA256` | Approved executable SHA-256 for this platform/build |
| `MCP_GO_BIN` | Optional Go executable; default `go` |
| `MCP_GIT_BIN` | Optional Git executable; default `git` |

Equivalent CLI options are `--gitleaks-bin`, `--gitleaks-sha256`, `--gitleaks-config`,
`--trufflehog-bin`, `--trufflehog-sha256`, `--go-bin`, and `--git-bin`.

CI provisioning is separate: pin `github.com/zricethezav/gitleaks/v8@v8.30.1` and
`github.com/trufflesecurity/trufflehog/v3@v3.97.1`, or exact reviewed release assets.
Verify module/release provenance before accepting binary hashes; never use `latest`.
Gitleaks builds reporting `version is set by build process` require `go version -m` to
prove the exact module/version/checksum in `TOOL_PINS`. The upstream config has its own
pinned SHA-256. The runner removes only its global filename exclusions so lockfiles,
binaries and images are not silently skipped; both config hashes are recorded.
No local or candidate ignore config, baseline, or inline Gitleaks allow comment is accepted.

```sh
node tools/publication-scanners/cli.mjs source --root /absolute/candidate
node tools/publication-scanners/cli.mjs artifact --root /absolute/owned/extracted/package
```

`source` snapshots all working-tree files, including ignored/untracked files, except Git
metadata and generated untracked `node_modules` directories. Tracked dependencies remain
in scope. It also creates an isolated local bundle of `HEAD` and all ancestors. Gitleaks scans
that Git history; TruffleHog scans every raw object reachable from the same HEAD, including
complete historical blobs, binary/archive bytes, tree filenames and commit metadata.
Other branches, reflogs and unreachable objects are **not** the intended history.
Shallow repositories, missing objects, current submodules and filesystem links fail closed.
The runner explicitly sets `safe.bareRepository=explicit` in its isolated Git environment.
All bare-history operations use `--git-dir` or `GIT_DIR`; the safeguard is never changed to
`all` or disabled. Candidate Git configuration is not trusted by either scanner.

History export uses bounded `rev-list` and `cat-file --batch-check/--batch`, not a textual diff.
Every exported object is verified against its Git object ID over its type, size and complete
raw bytes. Metadata/framing/truncation errors block; no object can be silently omitted.
The export is bounded to 200,000 objects, 256 MiB/object and 1 GiB total raw bytes, plus framing.
Batch output is held in bounded memory while writing the owned corpus. Reports hash object
metadata and the full export inventory; the export is rehashed after scanning and removed
with the owned workspace. Original history paths are not printed.

`artifact` accepts an already owned, extracted package root; it excludes no files, writes
nothing there, and hashes all bytes before/after scanning. It does not unpack or verify the
original tarball. Optional `--artifact-sha256` is labeled a **caller binding**, not an independently
verified tarball hash. The calling pack inspector must prove extraction identity.

Both tools run serially with online verification and automatic updates disabled. Children
receive no credentials, proxy settings, scanner overrides or user Git configuration.
All output is captured with a 32 MiB cap and 10-minute deadline per scan. Scan findings use
exit 183 internally, distinct from failures. Invalid/missing completion output, warnings,
errors, truncation diagnostics and changed inputs block the gate. Public reports contain
counts and hashes, never raw findings, paths, matching text, stderr or native error strings.

The pinned TruffleHog native Git parser has a Windows cancellation race: it closes its diff
channel before `cmd.Wait()`. Source completion can cancel the still-unreaped Git command,
producing `Error waiting for git command to complete.` with
`exec: canceling Cmd: TerminateProcess: Access is denied.` A matching diagnostic remains
`trufflehog-git-cancellation-race`, never success. Raw-object filesystem history scanning
avoids that upstream Git subprocess entirely; it does not suppress diagnostics, alter the
binary, lower log visibility, add sleeps/retries, or change timeouts. Explicit bare Git and
normal-clone controls distinguish this process-lifetime issue from a bare-repository denial.

Archive traversal is enabled to depth 20, decoding to depth 5, with supported-format limits
in each report. Pattern detection is not proof that every binary/archive format is understood.
Gitleaks history uses its Git parser; TruffleHog history uses the verified raw-object corpus.
Neither scans unreachable objects or external submodule repositories. No generic secret scan
certifies private identifier review.

## Local-only finding locations

Use the same pinned tool environment for private working-tree triage:

```sh
node tools/publication-scanners/diagnose.mjs --local-only \
  --root /absolute/candidate --output /private/new-triage-report.json
```

The destination must be new, absolute, outside the candidate and outside every Git checkout.
Keep it in private local storage; never upload it as a CI artifact. CI is rejected, as is
omitting the explicit local opt-in. Stdout contains only status/counts and the report hash.
The local report additionally contains detector/rule names, inventory-checked repository-relative
paths and scanner-reported line numbers. Missing line numbers remain `null`; malformed or
unowned locations fail. Matches, snippets, raw tokens, absolute paths and raw stderr are never
serialized. Synthetic classification starts as `not-assessed`; location in a test is not proof.

This command scans an owned snapshot of all current source bytes under the normal source
inventory rules and checks both snapshot and source stability. Owned snapshots are removed
automatically. **History is not scanned by this diagnostic command**, and its result cannot
replace the full source/publication gate or separate owner review. Default publication reports
remain counts/hashes only. The direct API is `diagnoseSource({root, tools?, localOnly: true})`
from `secrets.mjs`, with the same CI rejection; keep returned locations local.

## OSV exact-lock advisory gate

Only explicit approved **public package names and exact versions** leave the process.
Keep a local input file `{ "schemaVersion": 1, "packages": ["public-package-name"] }`
containing all names approved for OSV queries. Missing names fail before any request.
No private names, code, lock paths, registry credentials or resolution URLs are sent.

```sh
node tools/publication-scanners/cli.mjs advisories \
  --producer-root-lock /candidate/package-lock.json \
  --producer-ui-lock /candidate/ui/package-lock.json \
  --public-packages /private/public-package-approval.json
node tools/publication-scanners/cli.mjs advisories \
  --consumer-lock /owned/consumer/package-lock.json \
  --public-packages /private/public-package-approval.json
```

Lock v2/v3 is supported. Both producer locks are mandatory together. A separate consumer lock
is explicitly `fresh-consumer`, never relabeled producer evidence. For a local tarball entry,
also supply `--local-artifact` with `{ "name": "...", "version": "...", "sha256": "...",
"integrity": "sha512-..." }`; its lock SRI must be present and match. That binding must come from
the caller's actual tarball inspector. The exact bound local artifact is validated and
**excluded from OSV queries**, not added to the public-package allowlist. Same-name wrong-version,
missing/null/wrong-SRI or non-local-resolution entries fail instead of being silently excluded.
Remote dependency entries must retain public npm resolution URLs;
there is no registry or mirror fallback.

The read-only OSV batch query uses at most 100 coordinates/request, a 30-second request deadline,
an 8 MiB response cap, schema validation, no redirects/credentials, and rejects incomplete
pagination. Duplicate coordinates are cached **within one run only**. Each invocation queries
again and records time, per-lock/graph hashes and response hashes. There is no lifetime cache
or offline-success fallback.

The API also accepts `consumers: [...]` **instead of** `locks`, for actual resolved graph
summaries retained after consumer-project cleanup. Each summary must bind the candidate
name/version/tarball SHA-256 and record exact Node/npm/platform/script mode, successful
installed-bin and bridge/UI checks, `producerLockCopied: false`, and its actual
`dependencies: [{ name, version, integrity }]`. The local candidate's SRI is mandatory, non-null
and must match the inspected artifact, as must the summary name/version/SHA-256. Only that
validated local candidate is excluded from public queries. Null integrity on other dependencies
is retained as unavailable evidence; it is not invented.
Each report hashes the original summary, records its lane and resolved coordinate graph,
and labels it `fresh-consumer` / `resolved-consumer-summary`. No producer lock is substituted,
no lock is reconstructed, and no synthetic lock digest is emitted. The caller must establish
summary authenticity and restore provenance; this advisory check does not certify them.
Each scope retains the validated `localArtifact` binding and its exclusion status; graph hashes
and package counts describe external advisory coordinates, while the original lock/summary hash
binds the full supplied graph. Every other dependency still requires explicit public-name
approval before any request. Missing approval input fails; an explicitly empty list can only
pass a validated local-only graph and produces no OSV request.

Findings block unless a separately reviewed local `--exemptions` input contains exact
`{ "schemaVersion": 1, "exemptions": [{ "id": "...", "package": "...", "version": "...",
"reviewedBy": "...", "reason": "...", "expiresAt": "<ISO date>" }] }`.
No exemptions are supplied by this tool. Review metadata is not echoed; input hash and exact
public finding coordinates are recorded. This gate does not prove safe manifest ranges,
consumer behavior, licenses, notices, cryptographic provenance or registry signatures.

## Separate private-content policy and owner review

```sh
node tools/publication-scanners/cli.mjs private --source --root /candidate \
  --commit <exact-commit> --policy /private/content-policy.json
node tools/publication-scanners/cli.mjs private --root /owned/extracted/package \
  --commit <exact-commit> --artifact-sha256 <exact-tarball-sha256> \
  --policy /private/content-policy.json
```

Local policy schema: `{ "schemaVersion": 1, "literals": [{ "value": "<local-only-text>",
"ignoreCase": true }] }`. Empty policies fail. Do not commit private patterns, account/email/
path lists or review evidence, or put those lists in GitHub secrets. The optional gate returns
`not-run` without a policy, never `passed`. With a policy it checks filenames and UTF-8/UTF-16LE
content, returns only policy/input/evidence hashes and counts, and **always** leaves
`ownerReview: "pending"`. It does not expand archives or review history. A real publication
must require separate owner private-content-review evidence bound to the exact commit and
tarball, including formats/history this literal gate cannot certify.

## JS and exit contracts

`index.mjs` exports async:

- `scanSource({ root, tools? })`
- `scanArtifact({ root, tools?, artifactSha256? })`
- `scanAdvisories({ locks?: [{ path, scope }], consumers?: [...], publicPackages?, publicPackagesPath?,
  exemptionsPath?, localArtifact? })`, scopes `producer-root`, `producer-ui`, `fresh-consumer`
- `scanPrivateContent({ root, policyPath?, binding: { commit, artifactSha256? }, source? })`
- `scanPublicationRequest({ request, tools?, policyPath?, publicPackages?, publicPackagesPath?,
  exemptionsPath? })`
- `toolsFromEnvironment()` and `TOOL_PINS`

`tools` contains `{ gitleaks: { path, sha256, configPath }, trufflehog: { path, sha256 }, go?, git? }`.
Results use `schemaVersion: 1`, `status`, `kind`, timestamps, scope and evidence. CLI prints only
that safe JSON: `passed` = exit 0, `findings` = 1, `error` = 2, `not-run` = 3. A successful
individual scanner is not publication approval. Callers must require each needed gate and
separate owner evidence.

## Publication request/report adapter

```sh
node tools/publication-scanners/cli.mjs \
  --request /absolute/owned/request.json --output /absolute/owned/scanner-report.json
```

This accepts the publication runner's schema-1 source/artifact request and emits its
`{ schemaVersion, phase, commit, artifact?, gates }` wrapper, with scanner-specific reports
under `scannerDetails`. The output must be new and outside both scan roots; existing files
are never overwritten. Evidence SHA-256 values hash the actual serialized, redacted scanner
reports/executions. Secret evidence includes pinned tool version, approved binary digest and
the hash of the actual argument vector, without exposing local paths.

The adapter emits only requested scanner-supported gates:

- Source: `source-gitleaks`, `source-trufflehog`, `source-private-identifiers`,
  optional `producer-advisories`.
- Artifact: `payload-gitleaks`, `payload-trufflehog`, `payload-private-identifiers`,
  `consumer-advisories`.

Add `producer-advisories` to `requiredGates` when the combining adapter wants source OSV
in addition to the publication runner's independent npm audits. Artifact OSV uses both
provided npm12 summaries, one for each script mode, and never reads a producer lock.
This is **not** a complete `publication:external-gates` implementation: the parent adapter
must combine it with real native/platform/license/history checks, not fabricate their status.

Gate statuses are `passed`, `failed`, or `not-run`. Missing private policy stays `not-run`.
A real clean literal check passes its private-identifiers **scanner gate**, but always leaves
`ownerReview: "pending"` and the report's private-content owner review pending. The publication
runner must enforce its separate stage-only owner approval bound to the exact commit/tarball.
No boolean, empty policy, request field, or owner approval overrides a missing/failing scanner;
no scanner success supplies owner approval.

The adapter checks checkout HEAD and package name/version before and after gates, and verifies
all supplied tarball SHA-256/SHA-512/SRI values. Extraction identity is still the calling
extractor's responsibility; HEAD binding is not proof the working tree is clean.

The existing tool inputs apply. Input files may be supplied as CLI `--policy`,
`--public-packages`, `--exemptions`, or, in request mode only, local environment variables
`MCP_PUBLICATION_PRIVATE_POLICY`, `MCP_PUBLICATION_PUBLIC_PACKAGES`,
`MCP_PUBLICATION_ADVISORY_EXEMPTIONS`. The parent must forward these **paths**, not private
policy contents. Missing public-package approval fails the advisory gate before any query.

```sh
node --test --test-concurrency=1 test/publication-scanners*.test.mjs
```

Default tests use local fixtures and controlled OSV responses, with no real scans or API calls.
Set `MCP_PUBLICATION_SCANNER_FIXTURES=1` plus the five required tool inputs to run tiny owned
real-scanner fixtures: clean source/history/artifact and synthetic ignored/untracked,
deleted-history and archive-only findings. These never scan candidate repositories, verify
synthetic credentials, or commit to candidate branches. Fixture directories are removed by
identity after each test.
