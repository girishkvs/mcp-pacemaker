import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { validateLocalApproval, validateLocalRegression } from './local-regression.mjs';
import {
  assertCollectionJobSkipped, secretHash, secretId, secretKeys as exactKeys,
  validateSecretCollection, validateSecretReview, sourceCiAttempt,
} from './secret-report.mjs';

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
  if (gate?.admission !== undefined) {
    assert.equal(name, 'source-trufflehog');
    const value = gate.admission;
    exactKeys(value, ['kind', 'commit', 'tree', 'collection', 'reviewSha256', 'admissionRunId',
      'admissionRunNumber', 'rawStatus', 'rawFindings', 'reviewedFalsePositives', 'remainingFindings'],
    'secret admission receipt');
    assert.equal(value.kind, 'exact-reviewed-source-secret-admission');
    assert.equal(value.rawStatus, 'findings');
    assert.ok(Number.isSafeInteger(value.rawFindings) && value.rawFindings > 0 && value.rawFindings <= 128);
    assert.equal(value.reviewedFalsePositives, value.rawFindings);
    assert.equal(value.remainingFindings, 0);
    for (const key of ['commit', 'tree']) assert.match(value[key], /^[a-f0-9]{40}$/);
    assert.match(value.reviewSha256, /^[a-f0-9]{64}$/);
    for (const key of ['admissionRunId', 'admissionRunNumber']) secretId(value[key]);
    exactKeys(value.collection, ['runId', 'jobId', 'artifactId', 'artifactDigest', 'reportSha256'],
      'admitted collection link');
    for (const key of ['runId', 'jobId', 'artifactId']) secretId(value.collection[key]);
    assert.match(value.collection.artifactDigest, /^sha256:[a-f0-9]{64}$/);
    assert.match(value.collection.reportSha256, /^[a-f0-9]{64}$/);
  }
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

export function publicationRef(ref) {
  const match = typeof ref === 'string' &&
    /^refs\/tags\/(?:npm(?:-r([1-9][0-9]{0,15}))?\/)?v(1\.3\.1|2\.0\.1)$/.exec(ref);
  const generation = match?.[1] === undefined ? undefined : Number(match[1]);
  assert.ok(match &&
    match[0] === ref &&
    (generation === undefined ||
      Number.isSafeInteger(generation) &&
      generation >= 2), 'Publication requires the exact approved release or npm tag');
  return { tag: ref.slice('refs/tags/'.length), version: match[2] };
}

export function publicationTagName(ref, version) {
  channelFor(version);
  const parsed = publicationRef(ref);
  assert.equal(parsed.version, version, 'Publication requires the exact approved release version');
  return parsed.tag;
}

export function assertCandidateEvidence(value) {
  assert.notEqual(value?.kind, 'npm-registry-published', 'Published peer is comparison-only, not candidate evidence');
  assert.notEqual(value?.origin, 'npm-registry-published', 'Published peer is comparison-only, not candidate evidence');
  assert.notEqual(value?.purpose, 'service-comparison-only', 'Peer is comparison-only, not candidate evidence');
  assert.notEqual(value?.stageEligible, false, 'Comparison-only evidence cannot authorize stage');
}

export function fresh(value, now = Date.now()) {
  const age = now - Date.parse(value);
  assert.ok(Number.isFinite(age) &&
    age >= 0 &&
    age <= 60 * 60 * 1000, 'Approval/owner readback is missing, future dated, or older than one hour');
}

export function validateApproval(approval, action, now = Date.now()) {
  assertCandidateEvidence(approval);
  assert.ok(['collect-secrets', 'prepare', 'stage'].includes(action), 'Unsupported publication action');
  assert.equal(approval.schemaVersion, 1);
  assert.equal(approval.name, POLICY.name);
  const channel = channelFor(approval.version);
  publicationTagName(approval.ref, approval.version);
  for (const key of ['tagObject', 'commit', 'tree']) {
    assert.match(approval[key] ?? '', /^[a-f0-9]{40}$/, `Invalid approved ${key}`);
  }
  secretId(approval.ciRunId);
  sourceCiAttempt(approval.ciAttempt);
  assert.equal(approval.approver, POLICY.owner);
  assert.equal(approval.scope, action, 'Approval does not authorize this action');
  fresh(approval.approvedAt, now);
  if (approval.secretReview !== undefined) validateSecretReview(approval.secretReview, approval, now);
  if (action === 'collect-secrets') {
    exactKeys(approval, ['schemaVersion', 'name', 'version', 'ref', 'tagObject', 'commit', 'tree',
      'ciRunId', 'ciAttempt', 'approver', 'approvedAt', 'scope', 'localRegression', 'localRegressionReview'],
    'collection-only approval');
  }
  if (action === 'prepare') {
    assert.ok(Array.isArray(approval.publicPackages) &&
      approval.publicPackages.length > 0, 'Explicit public-package disclosure approval is required');
    assert.equal(new Set(approval.publicPackages).size, approval.publicPackages.length);
    for (const name of approval.publicPackages) {
      assert.match(name, /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/);
    }
  }
  if (action === 'stage') {
    const artifact = approval.artifact;
    assertCandidateEvidence(artifact);
    assert.match(artifact?.sha256 ?? '', /^[a-f0-9]{64}$/);
    assert.match(artifact.sha512 ?? '', /^[a-f0-9]{128}$/);
    assert.equal(artifact.integrity, `sha512-${Buffer.from(artifact.sha512, 'hex').toString('base64')}`);
    assert.match(artifact.manifestSha256 ?? '', /^[a-f0-9]{64}$/);
    assert.match(artifact.artifactDigest ?? '', /^sha256:[a-f0-9]{64}$/);
    for (const key of ['artifactId', 'runId']) {
      assert.match(String(artifact[key] ?? ''), /^[1-9][0-9]*$/);
    }
    assert.equal(artifact.runAttempt, 1, 'Prepare reruns need a fresh dispatch, not reused artifacts');
    validateOwnerPreflight(approval, now);
  }
  return channel;
}

export function validateOwnerPreflight(approval, now = Date.now()) {
  const owner = approval.ownerPreflight;
  assert.equal(owner?.owner, POLICY.owner, 'Owner-authenticated preflight is required; OIDC cannot list stages');
  fresh(owner.checkedAt, now);
  assert.equal(owner.packageName, POLICY.name);
  const review = owner.privateContentReview;
  assert.equal(review?.reviewer, POLICY.owner, 'Separate owner private-content review is required');
  assert.equal(review.scope, 'source-and-tarball', 'A pattern scan is not owner content review');
  assert.equal(review.disposition, 'approved');
  assert.equal(review.historyAndAuthorsReviewed, true, 'Owner must review reachable history and identities');
  assert.equal(review.historicalEvidenceAccepted, true, 'Fresh gates do not settle historical uncertainty');
  assert.equal(review.commit, approval.commit, 'Owner content review covers different source');
  sameDigests(review.artifact, approval.artifact);
  fresh(review.reviewedAt, now);
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
    assert.match(String(pending.captureArtifactId ?? ''), /^[1-9][0-9]*$/,
      'Original capture artifact ID required for stage reuse');
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
  validateLocalRegression(report.localRegression);
  const subject = report.localRegression.subjects.find(item => item.commit === approval.commit);
  assert.ok(subject, 'Artifact gates do not cover a tested local source');
  if (approval.localRegression) assert.deepEqual(report.localRegression, approval.localRegression);
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
  const admission = report.gates['source-trufflehog'].admission;
  if (admission) {
    const collection = validateSecretCollection(report.sourceSecretEvidence?.collection);
    assert.equal(collection.source.commit, approval.commit);
    assert.equal(admission.commit, approval.commit);
    assert.equal(admission.tree, collection.source.tree);
    assert.equal(admission.collection.reportSha256, secretHash(`${JSON.stringify(collection, null, 2)}\n`));
    assert.equal(secretId(admission.collection.runId), secretId(collection.workflow.runId));
    const raw = collection.raw.executions.reduce((total, item) => total + item.findings, 0);
    assert.equal(admission.rawFindings, raw);
    assert.equal(report.sourceSecretEvidence.status, collection.raw.status);
    assert.deepEqual(report.sourceSecretEvidence.executions, collection.raw.executions);
  }
}

export function validateCi(run, jobs, approval) {
  sourceCiAttempt(approval.ciAttempt);
  assert.equal(String(run.id), String(approval.ciRunId));
  assert.equal(run.run_attempt, approval.ciAttempt);
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
  for (const value of [approval, approval.artifact, runInfo, metadata]) assertCandidateEvidence(value);
  assertCollectionJobSkipped(jobs);
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
  assert.ok(!jobs.some(job => job.name === 'stage' &&
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
    '--fetch-retries=0', '--logs-max=0', '--loglevel=silent', '--update-notifier=false',
    `--userconfig=${config.user}`, `--globalconfig=${config.global}`];
}

export async function submitOnce({ approval, bytes, readRegistry, execute, reconcile, record, config, tarball }) {
  validateLocalApproval(approval);
  validateApproval(approval, 'stage');
  sameDigests(digest(bytes), approval.artifact);
  const state = validateRegistry(await readRegistry(), approval);
  if (state === 'published-matching') {
    await record({ status: state, stageId: null, publicationAcceptance: 'pending-registry-verification' });
    return;
  }
  const pending = approval.ownerPreflight.pending;
  if (pending.status === 'matching') {
    assert.equal(typeof reconcile, 'function', 'Original authenticated stage capture reader required');
    const original = await reconcile();
    assert.equal(original.stageId, pending.stageId);
    assert.deepEqual(original.workflow, pending.workflow);
    assert.equal(String(original.capture.artifactId), String(pending.captureArtifactId));
    await record({ status: 'owner-reconciled-existing-stage', stageId: original.stageId,
      workflow: original.workflow, originalCapture: original.capture,
      provenance: 'pending-owner-cryptographic-verification' });
    return;
  }
  await record({ status: 'submission-outcome-unknown', stageId: null,
    instruction: 'Owner-authenticated stage/version reconciliation required before another dispatch' });
  // One call only. The pinned CLI disables HTTP retries; failure never authorizes a second write.
  const result = await execute(stageArguments(tarball, channelFor(approval.version), config));
  assert.equal(typeof result?.stdout, 'string', 'Actual captured stage child output required');
  const item = npm12Contents(result.stdout, approval, bytes, true);
  const capture = result.capture;
  assert.ok(capture &&
    typeof capture === 'object', 'Actual stage capture required');
  assert.deepEqual(Object.keys(capture).sort(), ['bundleSha256', 'receiptSha256', 'stageId']);
  assert.equal(capture.stageId, item.stageId, 'CLI stage ID differs from the actual POST response');
  for (const key of ['receiptSha256', 'bundleSha256']) assert.match(capture[key], /^[a-f0-9]{64}$/);
  await record({ status: 'submitted-awaiting-owner-verification', stageId: item.stageId,
    capture,
    provenance: 'pending-owner-cryptographic-verification',
    registrySignatures: 'pending-publication', ownerPublicationApproval: 'pending' });
}
