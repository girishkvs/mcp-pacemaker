import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const LOCAL_CONTRACT = 'mcp-pacemaker-private-local-regression-v1';
export const LOCAL_VERSIONS = Object.freeze(['1.3.1', '2.0.1']);
export const LOCAL_NODES = Object.freeze(['20.20.2', '22.23.2', '24.21.0']);
export const LOCAL_CONTROLS = Object.freeze([
  ['failure-control', 'fail'], ['timeout-control', 'timeout'],
  ['early-descendant-exit-control', 'timeout-early-exit'],
]);
export const LOCAL_CASES = Object.freeze([
  ...LOCAL_CONTROLS.map(([name, mode]) => ({ name, mode })),
  ...LOCAL_VERSIONS.flatMap(version => LOCAL_NODES.map(node => ({
    name: `v${version}-node${node}`, mode: 'gate', version, node,
  }))),
]);
export const LOCAL_CONTROLLER = Object.freeze([
  'local-windows.mjs', 'local-windows-entry.mjs', 'local-gate.mjs', 'local-inputs.mjs',
  'local-git.mjs', 'local-environment.mjs', 'local-sdk-check.mjs', 'local-source.mjs',
  'local-regression.mjs', 'local-evidence.mjs', 'local-case-evidence.mjs', 'verify-local.mjs',
  'local-stage-check.mjs', 'stage-proof-contract.mjs', 'stage-capture.mjs',
  'stage-sdk.mjs', 'stage-sdk-pins.json', 'stage-child.mjs',
  'offline-stage/deny.cjs', 'offline-stage/fixture.cjs', 'offline-stage/npm.cjs', 'offline-stage/oidc.cjs',
  'offline-stage/control.cjs',
  'offline-stage/loader.cjs', 'stage-issuer.mjs', 'stage-loader.mjs', 'stage-sdk-loader.json',
  'offline-stage/services.cjs', 'stage-fulcio.mjs',
  'local-audit-report.mjs',
].map(name => `tools/npm-publication/${name}`).concat(['test/helpers/local-regression-fixture.mjs']));

export function exactLocalKeys(value, keys) {
  assert.ok(value &&
    typeof value === 'object' &&
    !Array.isArray(value), 'Missing local regression object');
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), 'Unexpected local regression fields');
}

export function localHash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function localJson(value) {
  if (Array.isArray(value)) return `[${value.map(localJson).join(',')}]`;
  if (value !== null &&
      typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${localJson(value[key])}`).join(',')}}`;
  }
  assert.notEqual(value, undefined);
  return JSON.stringify(value);
}

export function localCommitment(value) {
  return localHash(localJson(value));
}

export function localSha(value) {
  assert.match(value ?? '', /^[a-f0-9]{64}$/, 'Invalid local regression digest');
}

export function validateLocalRegression(value, source, now = Date.now()) {
  exactLocalKeys(value, ['schemaVersion', 'kind', 'contract', 'scope', 'runId', 'completedAt',
    'reportSha256', 'evidenceSha256', 'controllerSha256', 'image', 'runtimes', 'subjects',
    'coverage', 'releaseReady', 'executionProof']);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, 'local-regression-integrity-checked');
  assert.equal(value.contract, LOCAL_CONTRACT);
  assert.equal(value.scope, 'both-release-lines-local-only');
  assert.equal(value.releaseReady, false);
  assert.equal(value.executionProof, 'not-authenticated');
  assert.match(value.runId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.ok(Number.isFinite(Date.parse(value.completedAt)) &&
    Date.parse(value.completedAt) <= now, 'Invalid local regression completion time');
  for (const key of ['reportSha256', 'evidenceSha256', 'controllerSha256']) localSha(value[key]);
  assert.match(value.image, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(value.coverage, { controls: 3, sourceCases: 6 });
  assert.deepEqual(value.runtimes?.map(item => item.version), LOCAL_NODES);
  for (const runtime of value.runtimes) {
    exactLocalKeys(runtime, ['version', 'sha256']);
    localSha(runtime.sha256);
  }
  assert.deepEqual(value.subjects?.map(item => item.version), LOCAL_VERSIONS);
  for (const subject of value.subjects) {
    exactLocalKeys(subject, ['version', 'commit', 'tree', 'treeEntriesSha256',
      'checkoutFilesSha256', 'inputManifestSha256']);
    for (const key of ['commit', 'tree']) assert.match(subject[key], /^[a-f0-9]{40}$/);
    for (const key of ['treeEntriesSha256', 'checkoutFilesSha256', 'inputManifestSha256']) localSha(subject[key]);
  }
  if (source) {
    const own = value.subjects.find(item => item.version === source.version);
    assert.ok(own, 'Local regression does not cover this release line');
    assert.equal(own.commit, source.commit, 'Local regression covers a different commit');
    assert.equal(own.tree, source.tree, 'Local regression covers a different tree');
  }
  return value;
}

export function validateLocalReview(review, statement, now = Date.now()) {
  exactLocalKeys(review, ['reviewer', 'scope', 'disposition', 'statementSha256', 'reviewedAt']);
  assert.equal(review.reviewer, 'girishkvs');
  assert.equal(review.scope, 'private-local-regression-evidence');
  assert.equal(review.disposition, 'accepted');
  assert.equal(review.statementSha256, localCommitment(statement), 'Owner accepted different local evidence');
  const age = now - Date.parse(review.reviewedAt);
  assert.ok(Number.isFinite(age) &&
    age >= 0 &&
    age <= 3_600_000, 'Local evidence owner review is missing, future dated or expired');
  assert.ok(Date.parse(review.reviewedAt) >= Date.parse(statement.completedAt));
}

// This validates an owner's statement. It does not authenticate the owner or prove execution.
export function validateLocalApproval(approval, { continuing = false, now = Date.now() } = {}) {
  const at = continuing ? Date.parse(approval.approvedAt) : now;
  assert.ok(Number.isFinite(at) &&
    at <= now);
  validateLocalRegression(approval.localRegression, approval, at);
  const review = ['prepare', 'collect-secrets'].includes(approval.scope)
    ? approval.localRegressionReview : approval.ownerPreflight?.privateContentReview?.localRegression;
  validateLocalReview(review, approval.localRegression, at);
  return approval.localRegression;
}

export function validatePreparedLocal(prepared, approval, source = approval) {
  validateLocalRegression(prepared.localRegression, source);
  assert.deepEqual(prepared.localRegression, approval.localRegression, 'Prepared local evidence differs');
  assert.equal(prepared.preparationApproval?.approver, 'girishkvs');
  assert.equal(prepared.preparationApproval.scope, 'prepare');
  const at = Date.parse(prepared.preparationApproval.approvedAt);
  assert.ok(Number.isFinite(at) &&
    at <= Date.now());
  validateLocalReview(prepared.localRegressionReview, prepared.localRegression, at);
}

export function validateLocalManifest(bytes, approval, gates) {
  assert.ok(Buffer.isBuffer(bytes));
  assert.equal(localHash(bytes), approval.artifact.manifestSha256);
  const manifest = JSON.parse(bytes.toString('utf8'));
  validateLocalApproval(approval);
  validatePreparedLocal(manifest, approval);
  assert.deepEqual(manifest.source, Object.fromEntries(
    ['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]])));
  if (gates) assert.deepEqual(gates.localRegression, manifest.localRegression);
  return manifest;
}
