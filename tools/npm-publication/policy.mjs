import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const POLICY = Object.freeze({
  name: 'mcp-pacemaker',
  repository: 'girishkvs/mcp-pacemaker',
  owner: 'girishkvs',
  workflow: '.github/workflows/npm-publish.yml',
  environment: 'npm-publish',
  registry: 'https://registry.npmjs.org/',
  node: '24.21.0',
  npm: '12.0.2',
});

export const REQUIRED_GATES = Object.freeze([
  'source-gitleaks', 'source-trufflehog', 'source-private-identifiers',
  'payload-gitleaks', 'payload-trufflehog', 'payload-private-identifiers',
  'author-identity', 'producer-advisories', 'consumer-advisories',
  'licenses-notices', 'runtime-closure', 'native-release-identity', 'native-windows-execution', 'ui-build',
  'consumer-npm11', 'consumer-npm12', 'consumer-platforms',
  'compatibility', 'service-replacement', 'historical-risk-disposition',
]);

export function validateGateStatus(name, gate) {
  const human = ['source-private-identifiers', 'payload-private-identifiers',
    'author-identity', 'historical-risk-disposition'].includes(name);
  assert.ok(gate?.status === 'passed' ||
    human &&
    gate?.ownerReview === 'pending' &&
    (gate.status === 'pending-owner-review' ||
      name.endsWith('-private-identifiers') &&
      gate.status === 'not-run'), `Required gate not passed: ${name}`);
}

export function digest(bytes) {
  return {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sha512: createHash('sha512').update(bytes).digest('hex'),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
  };
}

export function sameDigests(actual, expected) {
  for (const key of ['sha256', 'sha512', 'integrity']) {
    assert.equal(actual[key], expected[key], `Artifact ${key} mismatch`);
  }
}

export function channelFor(version) {
  assert.ok(['1.3.1', '2.0.1'].includes(version), 'Only approved 1.3.1/2.0.1 candidates are supported');
  return version.startsWith('1.') ? 'legacy' : 'latest';
}

export function publicationTagName(ref, version) {
  channelFor(version);
  const tag = `v${version}`;
  assert.ok([`refs/tags/${tag}`, `refs/tags/npm/${tag}`,
    `refs/tags/npm-r2/${tag}`, `refs/tags/npm-r3/${tag}`, `refs/tags/npm-r4/${tag}`].includes(ref),
    'Publication requires the exact approved release or npm tag');
  return ref.slice('refs/tags/'.length);
}

export function fresh(value, now = Date.now()) {
  const age = now - Date.parse(value);
  assert.ok(Number.isFinite(age) &&
    age >= 0 &&
    age <= 60 * 60 * 1000, 'Approval/owner readback is missing, future dated, or older than one hour');
}

export function validateApproval(approval, action, now = Date.now()) {
  assert.ok(['prepare', 'stage', 'sign-bootstrap', 'verify-bootstrap', 'publish-bootstrap'].includes(action),
    'Unsupported publication scope');
  assert.equal(approval.schemaVersion, 1);
  assert.equal(approval.name, POLICY.name);
  const channel = channelFor(approval.version);
  publicationTagName(approval.ref, approval.version);
  for (const key of ['tagObject', 'commit', 'tree']) {
    assert.match(approval[key] ?? '', /^[a-f0-9]{40}$/, `Invalid approved ${key}`);
  }
  for (const key of ['ciRunId', 'ciAttempt']) {
    assert.match(String(approval[key] ?? ''), /^[1-9][0-9]*$/, `Invalid ${key}`);
  }
  assert.equal(approval.approver, POLICY.owner);
  assert.equal(approval.scope, action, 'Approval does not authorize this action');
  fresh(approval.approvedAt, now);
  if (action === 'prepare') {
    assert.ok(Array.isArray(approval.publicPackages) &&
      approval.publicPackages.length > 0, 'Explicit public-package disclosure approval is required');
    assert.equal(new Set(approval.publicPackages).size, approval.publicPackages.length);
    for (const name of approval.publicPackages) {
      assert.match(name, /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/);
    }
  }
  if (action !== 'prepare') {
    const artifact = approval.artifact;
    assert.match(artifact?.sha256 ?? '', /^[a-f0-9]{64}$/);
    assert.match(artifact.sha512 ?? '', /^[a-f0-9]{128}$/);
    assert.equal(artifact.integrity, `sha512-${Buffer.from(artifact.sha512, 'hex').toString('base64')}`);
    assert.match(artifact.manifestSha256 ?? '', /^[a-f0-9]{64}$/);
    assert.match(artifact.artifactDigest ?? '', /^sha256:[a-f0-9]{64}$/);
    for (const key of ['artifactId', 'runId']) {
      assert.match(String(artifact[key] ?? ''), /^[1-9][0-9]*$/);
    }
    assert.equal(artifact.runAttempt, 1, 'Prepare reruns need a fresh dispatch, not reused artifacts');
    if (action === 'stage') validateOwnerPreflight(approval, now);
    else validateBootstrapApproval(approval, action, now);
  }
  return channel;
}

export function validateOwnerPreflight(approval, now = Date.now()) {
  const owner = approval.ownerPreflight;
  assert.equal(owner?.owner, POLICY.owner, 'Owner-authenticated preflight is required; OIDC cannot list stages');
  fresh(owner.checkedAt, now);
  assert.equal(owner.packageName, POLICY.name);
  validateOwnerContentReview(approval, now);
  assert.equal(owner.unresolvedSubmission, false, 'Unknown previous outcome: owner reconciliation required');
  assert.deepEqual(owner.trust, {
    repository: POLICY.repository, workflow: 'npm-publish.yml', environment: POLICY.environment,
    allowPublish: false, allowStagePublish: true,
  }, 'Missing or wrong stage-only trust; bootstrap/trust setup is a separate owner operation');
  assert.ok(owner.expectedDistTags &&
    typeof owner.expectedDistTags === 'object' &&
    !Array.isArray(owner.expectedDistTags), 'Expected current dist-tags are required');
  assert.match(owner.expectedDistTags.latest ?? '', /^2\.\d+\.\d+$/, 'Bootstrap real 2.x first');
  if (owner.expectedDistTags.legacy !== undefined) {
    assert.match(owner.expectedDistTags.legacy, /^1\.\d+\.\d+$/);
  }
  const pending = owner.pending;
  assert.ok(['none', 'matching'].includes(pending?.status),
    'Conflicting/unknown pending stage: owner disposition required, no retry');
  if (pending.status === 'matching') {
    assert.match(pending.stageId ?? '', /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
    assert.equal(pending.version, approval.version);
    assert.equal(pending.tag, channelFor(approval.version));
    sameDigests(pending, approval.artifact);
    assert.equal(pending.workflow?.ref, `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`);
    assert.equal(pending.workflow.commit, approval.commit);
    assert.match(String(pending.workflow.runId ?? ''), /^[1-9][0-9]*$/);
    assert.equal(pending.workflow.attempt, 1);
  }
}

export function validateOwnerContentReview(approval, now = Date.now()) {
  const review = approval.ownerPreflight?.privateContentReview;
  assert.equal(review?.reviewer, POLICY.owner, 'Separate owner private-content review is required');
  assert.equal(review.scope, 'source-and-tarball', 'A pattern scan is not owner content review');
  assert.equal(review.disposition, 'approved');
  assert.equal(review.historyAndAuthorsReviewed, true, 'Owner must review reachable history and identities');
  assert.equal(review.historicalEvidenceAccepted, true, 'Fresh gates do not settle historical uncertainty');
  assert.equal(review.commit, approval.commit, 'Owner content review covers different source');
  sameDigests(review.artifact, approval.artifact);
  fresh(review.reviewedAt, now);
}

export function exactKeys(value, keys, description) {
  assert.ok(value &&
    typeof value === 'object' &&
    !Array.isArray(value), `Missing ${description}`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `Unexpected ${description} fields`);
}

function validateBootstrapApproval(approval, action, now) {
  assert.equal(approval.version, '2.0.1', 'Only the first 2.0.1 latest publication may bootstrap');
  exactKeys(approval, ['schemaVersion', 'name', 'version', 'ref', 'tagObject', 'commit', 'tree',
    'ciRunId', 'ciAttempt', 'approver', 'approvedAt', 'scope', 'artifact', 'ownerPreflight',
    ...(['verify-bootstrap', 'publish-bootstrap'].includes(action) ? ['signedArtifact'] : []),
    ...(action === 'publish-bootstrap' ? ['ownerAuth'] : [])], 'bootstrap approval');
  if (action === 'publish-bootstrap') {
    exactKeys(approval.ownerAuth, ['spki', 'sha256', 'transaction'], 'owner auth envelope');
    assert.match(approval.ownerAuth.spki, /^[A-Za-z0-9+/]+={0,2}$/);
    assert.ok(approval.ownerAuth.spki.length <= 1368);
    assert.match(approval.ownerAuth.sha256, /^[a-f0-9]{64}$/);
    assert.match(approval.ownerAuth.transaction, /^[a-f0-9]{32}$/);
    assert.equal(approval.ownerAuth.sha256.length, 64);
    assert.equal(approval.ownerAuth.transaction.length, 32);
  }
  exactKeys(approval.artifact, ['sha256', 'sha512', 'integrity', 'manifestSha256', 'artifactId',
    'artifactDigest', 'runId', 'runAttempt'], 'prepare artifact approval');
  const owner = approval.ownerPreflight;
  exactKeys(owner, ['owner', 'checkedAt', 'packageName', 'privateContentReview', 'unresolvedSubmission',
    'unresolvedSigning', 'registry', 'packageStatus', 'nameApproved', 'publicProvenanceApproved',
    'priorSigning'], 'bootstrap owner preflight');
  assert.equal(owner.owner, POLICY.owner);
  assert.equal(owner.packageName, POLICY.name);
  fresh(owner.checkedAt, now);
  assert.equal(owner.registry, POLICY.registry);
  assert.equal(owner.packageStatus, 'absent', 'Bootstrap requires an absent package, not just an absent version');
  assert.equal(owner.nameApproved, true, 'Fresh owner name-availability approval is required');
  assert.equal(owner.publicProvenanceApproved, true, 'Signing publicly discloses metadata');
  assert.equal(owner.unresolvedSubmission, false, 'Unknown publication outcome requires owner reconciliation');
  assert.equal(owner.unresolvedSigning, false, 'Unknown signing outcome requires owner reconciliation');
  const prior = owner.priorSigning;
  assert.ok(['none', 'reconciled'].includes(prior?.status), 'Owner signing ledger reconciliation is required');
  exactKeys(prior, prior.status === 'none' ? ['status'] : ['status', 'runIds'], 'prior signing disposition');
  if (prior.status === 'reconciled') {
    assert.ok(Array.isArray(prior.runIds) &&
      prior.runIds.length > 0);
    assert.equal(new Set(prior.runIds.map(String)).size, prior.runIds.length);
    for (const id of prior.runIds) assert.match(String(id), /^[1-9][0-9]*$/);
  }
  exactKeys(owner.privateContentReview, ['reviewer', 'scope', 'disposition', 'historyAndAuthorsReviewed',
    'historicalEvidenceAccepted', 'commit', 'artifact', 'reviewedAt'], 'owner content attestation');
  exactKeys(owner.privateContentReview.artifact, ['sha256', 'sha512', 'integrity'], 'reviewed tarball');
  validateOwnerContentReview(approval, now);
  if (['verify-bootstrap', 'publish-bootstrap'].includes(action)) {
    const signed = approval.signedArtifact;
    exactKeys(signed, ['artifactId', 'artifactDigest', 'runId', 'runAttempt', 'receiptSha256', 'bundleSha256'],
      'signed artifact approval');
    for (const key of ['artifactId', 'runId']) assert.match(String(signed[key]), /^[1-9][0-9]*$/);
    for (const key of ['receiptSha256', 'bundleSha256']) assert.match(signed[key], /^[a-f0-9]{64}$/);
    assert.match(signed.artifactDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(signed.runAttempt, 1, 'Signing reruns are not accepted');
    assert.notEqual(String(signed.runId), String(approval.artifact.runId));
    assert.equal(prior.status, 'reconciled', 'Owner must reconcile the actual completed signing run');
    assert.ok(prior.runIds.map(String).includes(String(signed.runId)));
  }
}

export function validateContext(env, event, approval) {
  assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted', 'Unsupported runner: reject before OIDC');
  assert.equal(env.RUNNER_OS, 'Linux');
  assert.equal(env.RUNNER_ARCH, 'X64');
  assert.equal(env.GITHUB_ACTIONS, 'true');
  assert.equal(env.GITHUB_SERVER_URL, 'https://github.com');
  assert.equal(env.GITHUB_API_URL, 'https://api.github.com');
  assert.equal(env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(env.GITHUB_REPOSITORY, POLICY.repository);
  assert.equal(env.GITHUB_REPOSITORY_OWNER, POLICY.owner);
  assert.equal(env.GITHUB_ACTOR, POLICY.owner);
  assert.equal(env.GITHUB_TRIGGERING_ACTOR, POLICY.owner);
  assert.equal(env.GITHUB_RUN_ATTEMPT, '1', 'Never rerun a possibly spent stage approval; dispatch after reconciliation');
  assert.equal(event.repository?.full_name, POLICY.repository);
  assert.equal(event.repository?.private, false);
  assert.equal(event.repository?.fork, false);
  assert.equal(event.sender?.login, POLICY.owner);
  assert.equal(env.GITHUB_REF, approval.ref, 'Dispatch must use the approved release tag');
  assert.equal(env.GITHUB_SHA, approval.commit, 'Event SHA must identify the actual packaged source');
  assert.equal(env.GITHUB_WORKFLOW_SHA, approval.commit);
  assert.equal(env.GITHUB_WORKFLOW_REF, `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`);
}

export function validateSource(source, approval) {
  assert.equal(source.tagType, 'tag', 'An approved annotated release tag is required');
  assert.equal(source.tagObject, approval.tagObject);
  assert.equal(source.tagCommit, approval.commit);
  assert.equal(source.tagTree, approval.tree);
  assert.equal(source.head, approval.commit);
  assert.equal(source.tree, approval.tree);
  assert.equal(source.status, '', 'Source tree is not clean');
  assert.equal(source.workflowMatches, true, 'Working workflow differs from the approved source');
}

export function validatePackage(pkg, approval) {
  assert.equal(pkg.name, POLICY.name);
  assert.equal(pkg.version, approval.version);
  assert.ok(pkg.private === undefined ||
    pkg.private === false, 'Private package cannot be staged');
  assert.equal(pkg.repository?.url, `git+https://github.com/${POLICY.repository}.git`);
  for (const key of ['tag', 'packageExtensions', 'workspaces', 'bundledDependencies', 'bundleDependencies']) {
    assert.equal(pkg[key], undefined, `Unreviewed package option: ${key}`);
  }
  for (const hook of ['prepublish', 'prepare', 'prepack', 'postpack', 'prepublishOnly', 'publish', 'postpublish',
    'preinstall', 'install', 'postinstall']) {
    assert.equal(pkg.scripts?.[hook], undefined, `Unreviewed lifecycle hook: ${hook}`);
  }
  const allowed = { registry: POLICY.registry, access: 'public', tag: channelFor(pkg.version) };
  for (const [key, value] of Object.entries(pkg.publishConfig ?? {})) {
    assert.ok(Object.hasOwn(allowed, key), `Unreviewed publishConfig: ${key}`);
    assert.equal(value, allowed[key], `Conflicting publishConfig.${key}`);
  }
  assert.equal(pkg.dependencies?.['smol-toml'], '^1.8.0', 'Reviewed safe direct TOML floor is required');
  if (pkg.gitHead !== undefined) {
    assert.equal(pkg.gitHead, approval.commit);
  }
}

export function npm12Contents(output, approval, bytes, requireStageId = false) {
  const parsed = JSON.parse(output);
  assert.deepEqual(Object.keys(parsed), [POLICY.name], 'Expected npm12 name-keyed JSON, not npm11 array output');
  const item = parsed[POLICY.name];
  assert.equal(item.name, POLICY.name);
  assert.equal(item.version, approval.version);
  assert.equal(item.id, `${POLICY.name}@${approval.version}`);
  assert.equal(item.integrity, digest(bytes).integrity);
  assert.equal(item.shasum, createHash('sha1').update(bytes).digest('hex'));
  assert.equal(item.size, bytes.length);
  assert.equal(item.filename, `${POLICY.name}-${approval.version}.tgz`);
  assert.ok(Array.isArray(item.files) &&
    item.files.length > 0);
  assert.equal(item.entryCount, item.files.length);
  assert.deepEqual(item.bundled, []);
  if (requireStageId) {
    assert.match(item.stageId ?? '', /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i,
      'Stage response missing valid stageId; outcome unknown, do not retry');
  }
  return item;
}

export function validateRegistry(packument, approval) {
  assert.equal(packument?.name, POLICY.name, 'Package absent/lookup failed: manual real-version bootstrap required');
  assert.ok(packument.maintainers?.some(item => item.name === POLICY.owner),
    'Package ownership is missing or conflicts; stop rather than claiming the name');
  assert.deepEqual(packument['dist-tags'], approval.ownerPreflight.expectedDistTags,
    'Channel state changed; obtain fresh owner approval');
  const existing = packument.versions?.[approval.version];
  if (existing) {
    assert.equal(existing.dist?.integrity, approval.artifact.integrity,
      'Immutable published-version conflict; never overwrite or unpublish-and-reuse');
    return 'published-matching';
  }
  assert.ok(packument.versions &&
    typeof packument.versions === 'object', 'Incomplete registry version readback');
  return 'absent';
}

export function validateGates(report, approval, artifact) {
  assert.equal(report?.schemaVersion, 1, 'Missing real artifact-gate report');
  assert.equal(report.commit, approval.commit);
  sameDigests(report.artifact, artifact);
  for (const name of REQUIRED_GATES) {
    const gate = report.gates?.[name];
    validateGateStatus(name, gate);
    assert.ok(Array.isArray(gate.evidence) &&
      gate.evidence.length > 0, `Missing concrete evidence: ${name}`);
    for (const evidence of gate.evidence) {
      assert.match(evidence.sha256 ?? '', /^[a-f0-9]{64}$/, `Missing evidence digest: ${name}`);
      assert.ok(typeof evidence.description === 'string' &&
        evidence.description.length > 0, `Missing evidence description: ${name}`);
    }
  }
}

export function validateCi(run, jobs, approval) {
  assert.equal(String(run.id), String(approval.ciRunId));
  assert.equal(run.run_attempt, Number(approval.ciAttempt));
  assert.equal(run.head_sha, approval.commit);
  assert.equal(run.head_repository?.full_name, POLICY.repository);
  assert.equal(run.repository?.full_name, POLICY.repository);
  assert.equal(run.path, '.github/workflows/ci.yml');
  assert.equal(run.event, 'push', 'Require exact post-merge push CI, not a PR merge simulation');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  const required = ['Lockfiles resolve to the public registry', 'ui'];
  for (const os of ['ubuntu-latest', 'windows-latest', 'macos-latest']) {
    for (const node of [20, 22, 24]) required.push(`test (${os}, ${node})`);
  }
  for (const name of required) {
    const matches = jobs.filter(job => job.name === name);
    assert.equal(matches.length, 1, `CI job missing or ambiguous: ${name}`);
  }
  assert.ok(jobs.length >= required.length);
  for (const job of jobs) {
    assert.equal(job.head_sha, approval.commit);
    assert.equal(job.status, 'completed');
    assert.equal(job.conclusion, 'success', `CI job failed or skipped: ${job.name}`);
  }
}

export function validateEnvironment(environment, policies, reviews, approval) {
  assert.equal(environment.name, POLICY.environment, 'Real protected environment is required');
  const rule = environment.protection_rules?.find(item => item.type === 'required_reviewers');
  assert.ok(rule?.reviewers?.some(item => item.reviewer?.login === POLICY.owner),
    'Owner proof-of-presence environment reviewer is required');
  assert.equal(rule.prevent_self_review, false, 'Sole-owner proof-of-presence must not create a self-review deadlock');
  assert.equal(environment.deployment_branch_policy?.custom_branch_policies, true);
  assert.equal(environment.deployment_branch_policy?.protected_branches, false);
  assert.ok(policies.some(item => item.type === 'tag' &&
    item.name === approval.ref.slice('refs/tags/'.length)), 'Environment must explicitly allow the exact release tag');
  assert.ok(reviews.some(item => item.state === 'approved' &&
    item.user?.login === POLICY.owner &&
    item.environments?.some(value => value.id === environment.id &&
      value.name === POLICY.environment)), 'Missing actual owner environment approval for this run');
}

export function validateTransfer(runInfo, jobs, metadata, approval) {
  const artifact = approval.artifact;
  assert.equal(String(runInfo.id), String(artifact.runId));
  assert.equal(runInfo.head_sha, approval.commit);
  assert.equal(runInfo.repository?.full_name, POLICY.repository);
  assert.equal(runInfo.head_repository?.full_name, POLICY.repository);
  assert.equal(runInfo.path, POLICY.workflow);
  assert.equal(runInfo.event, 'workflow_dispatch');
  assert.equal(runInfo.run_attempt, 1);
  assert.equal(runInfo.status, 'completed');
  assert.equal(runInfo.conclusion, 'success');
  const required = ['source', 'prepare'];
  for (const platform of ['linux', 'win32', 'darwin']) {
    for (const npm of ['11.6.1', POLICY.npm]) required.push(`consumer (${platform}, ${npm})`);
  }
  for (const name of required) {
    const matches = jobs.filter(job => job.name === name);
    assert.equal(matches.length, 1, `Missing or ambiguous prepare job: ${name}`);
    assert.equal(matches[0].status, 'completed');
    assert.equal(matches[0].conclusion, 'success');
    assert.equal(matches[0].head_sha, approval.commit);
  }
  assert.ok(!jobs.some(job => ['stage', 'sign-bootstrap', 'publish-bootstrap'].includes(job.name) &&
    job.conclusion !== 'skipped'), 'Artifacts must come from a prepare-only run');
  assert.equal(String(metadata.id), String(artifact.artifactId));
  assert.equal(metadata.expired, false);
  assert.equal(metadata.name, `npm-candidate-${artifact.runId}-1`);
  assert.equal(metadata.digest, artifact.artifactDigest, 'Artifact archive digest mismatch');
  assert.equal(String(metadata.workflow_run?.id), String(artifact.runId));
  assert.equal(metadata.workflow_run?.head_sha, approval.commit);
}

export function stageArguments(tarball, channel, config) {
  assert.ok(['latest', 'legacy'].includes(channel));
  assert.ok(tarball.endsWith('.tgz'), 'Only the approved tarball may be staged');
  return ['stage', 'publish', tarball, '--access=public', `--tag=${channel}`,
    `--registry=${POLICY.registry}`, '--provenance', '--ignore-scripts', '--json',
    '--fetch-retries=0', `--userconfig=${config.user}`, `--globalconfig=${config.global}`];
}

export async function submitOnce({ approval, bytes, readRegistry, execute, record, config, tarball }) {
  validateApproval(approval, 'stage');
  sameDigests(digest(bytes), approval.artifact);
  const state = validateRegistry(await readRegistry(), approval);
  if (state === 'published-matching') {
    await record({ status: state, stageId: null, publicationAcceptance: 'pending-registry-verification' });
    return;
  }
  const pending = approval.ownerPreflight.pending;
  if (pending.status === 'matching') {
    await record({ status: 'owner-reconciled-existing-stage', stageId: pending.stageId,
      workflow: pending.workflow,
      provenance: 'pending-owner-cryptographic-verification' });
    return;
  }
  await record({ status: 'submission-outcome-unknown', stageId: null,
    instruction: 'Owner-authenticated stage/version reconciliation required before another dispatch' });
  // One call only. The pinned CLI disables HTTP retries; failure never authorizes a second write.
  const output = await execute(stageArguments(tarball, channelFor(approval.version), config));
  const item = npm12Contents(output, approval, bytes, true);
  await record({ status: 'submitted-awaiting-owner-verification', stageId: item.stageId,
    provenance: 'pending-owner-cryptographic-verification',
    registrySignatures: 'pending-publication', ownerPublicationApproval: 'pending' });
}
