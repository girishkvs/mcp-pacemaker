import assert from 'node:assert/strict';
import { validateLocalApproval, validateLocalManifest } from './local-regression.mjs';
import {
  POLICY, digest, sameDigests, validateApproval, validateContext, validateGates, exactKeys, fresh,
} from './policy.mjs';
import { inspectTarball } from './tarball.mjs';
import { zipFiles } from './matrix.mjs';
import { verifyProvenance } from './provenance.mjs';

export const CANDIDATE_FILES = Object.freeze(['candidate.tgz', 'gates.json', 'manifest.json']);
export const BOOTSTRAP_FILES = Object.freeze([...CANDIDATE_FILES, 'provenance.sigstore', 'bootstrap.json'].sort());
export const sourceBinding = approval => Object.fromEntries(
  ['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]]));
export const parse = bytes => JSON.parse(bytes.toString('utf8'));

export function exactFiles(files, names) {
  assert.ok(files instanceof Map);
  assert.deepEqual([...files.keys()].sort(), [...names].sort(), 'Unexpected publication artifact files');
  for (const bytes of files.values()) {
    assert.ok(Buffer.isBuffer(bytes) &&
      bytes.length > 0, 'Empty/non-byte publication artifact member');
  }
}

export function exactArchive(bytes, names) {
  const files = zipFiles(bytes);
  exactFiles(files, names);
  let end = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65_557) &&
      bytes.readUInt32LE(end) !== 0x06054b50) end--;
  assert.ok(end >= 0);
  assert.equal(bytes.readUInt16LE(end + 10), names.length, 'Unexpected ZIP directory/member');
  return files;
}

export function bootstrapWorkflow(env) {
  return {
    ref: env.GITHUB_WORKFLOW_REF, commit: env.GITHUB_WORKFLOW_SHA,
    runId: env.GITHUB_RUN_ID, attempt: 1,
    repositoryId: env.GITHUB_REPOSITORY_ID, ownerId: env.GITHUB_REPOSITORY_OWNER_ID,
  };
}

export function validateBootstrapContext({ env, event, approval, runtime = process }) {
  validateLocalApproval(approval);
  validateApproval(approval, 'sign-bootstrap');
  validateContext(env, event, approval);
  assert.equal(runtime.platform, 'linux', 'Bootstrap signing requires actual hosted Linux');
  assert.equal(runtime.arch, 'x64');
  assert.equal(runtime.versions.node, POLICY.node);
  assert.equal(env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.CI, 'true');
  assert.equal(env.GITHUB_JOB, 'sign-bootstrap');
  assert.equal(event.inputs?.action, 'sign-bootstrap');
  assert.deepEqual(JSON.parse(event.inputs.approval), approval);
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID']) {
    assert.match(env[key] ?? '', /^[1-9][0-9]*$/);
  }
  assert.equal(String(event.repository.id), env.GITHUB_REPOSITORY_ID);
  assert.equal(String(event.repository.owner?.id), env.GITHUB_REPOSITORY_OWNER_ID);
  assert.equal(event.repository.owner?.login, POLICY.owner);
  assert.notEqual(env.GITHUB_RUN_ID, String(approval.artifact.runId));
  assert.ok(!approval.ownerPreflight.priorSigning.runIds?.map(String).includes(env.GITHUB_RUN_ID),
    'Current signing run cannot already be reconciled');
}

export function validateCandidate(files, approval, locks) {
  exactFiles(files, CANDIDATE_FILES);
  validateLocalManifest(files.get('manifest.json'), approval, parse(files.get('gates.json')));
  assert.equal(digest(files.get('manifest.json')).sha256, approval.artifact.manifestSha256);
  const manifest = parse(files.get('manifest.json'));
  const gates = parse(files.get('gates.json'));
  const bytes = files.get('candidate.tgz');
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.phase, 'prepared-not-staged');
  assert.equal(manifest.name, POLICY.name);
  assert.equal(manifest.version, approval.version);
  assert.equal(manifest.major, 2);
  assert.equal(manifest.channel, 'latest');
  assert.deepEqual(manifest.source, sourceBinding(approval));
  assert.deepEqual(manifest.workflow, {
    ref: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`, commit: approval.commit,
    runId: String(approval.artifact.runId), attempt: 1,
  });
  assert.equal(String(manifest.ci.runId), String(approval.ciRunId));
  assert.equal(manifest.ci.attempt, Number(approval.ciAttempt));
  assert.equal(manifest.ci.headSha, approval.commit);
  assert.equal(manifest.ci.conclusion, 'success');
  assert.deepEqual(manifest.toolchain, { node: POLICY.node, npm: POLICY.npm });
  exactKeys(locks, ['root', 'ui'], 'actual source lock hashes');
  for (const hash of Object.values(locks)) assert.match(hash, /^[a-f0-9]{64}$/);
  assert.deepEqual(manifest.producerLocks, locks);
  assert.equal(manifest.artifact.filename, 'candidate.tgz');
  sameDigests(digest(bytes), approval.artifact);
  sameDigests(manifest.artifact, approval.artifact);
  const inspection = inspectTarball(bytes, approval);
  assert.deepEqual(inspection.files, manifest.artifact.files);
  assert.equal(manifest.gateReportSha256, digest(files.get('gates.json')).sha256);
  assert.equal(gates.sourceReportSha256, manifest.sourceReportSha256);
  validateGates(gates, approval, manifest.artifact);
  assert.deepEqual(manifest.stage, { status: 'not-submitted', stageId: null });
  assert.deepEqual(manifest.publicationApproval, { status: 'not-authorized' });
  assert.deepEqual(manifest.registrySignatures, { status: 'pending-publication' });
  assert.deepEqual(manifest.privateContentReview, {
    status: 'pending-owner-review', commit: approval.commit, artifact: digest(bytes),
  });
  assert.ok(manifest.sourceArtifact &&
    manifest.peerArtifact &&
    Array.isArray(manifest.matrixArtifacts) &&
    manifest.matrixArtifacts.length === 6, 'Complete source, peer and six consumer receipts are required');
  return { manifest, gates, bytes, inspection };
}

export function validateAbsentRegistry(readback, now = Date.now()) {
  exactKeys(readback, ['registry', 'name', 'status', 'checkedAt'], 'registry absence readback');
  assert.equal(readback.registry, POLICY.registry);
  assert.equal(readback.name, POLICY.name);
  assert.equal(readback.status, 404, 'Bootstrap blocked: package exists or registry outcome is unknown');
  fresh(readback.checkedAt, now);
}

export async function signBootstrapOnce({
  approval, files, locks, workflow, revalidate, sign, verifyBundle, record, cache,
}) {
  validateApproval(approval, 'sign-bootstrap');
  const candidate = validateCandidate(files, approval, locks);
  assert.equal(workflow.ref, `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`);
  assert.equal(workflow.commit, approval.commit);
  assert.equal(workflow.attempt, 1);
  for (const key of ['runId', 'repositoryId', 'ownerId']) assert.match(workflow[key], /^[1-9][0-9]*$/);
  const base = {
    schemaVersion: 1, name: POLICY.name, version: '2.0.1', channel: 'latest',
    source: sourceBinding(approval), artifact: digest(candidate.bytes), workflow,
    prepareArtifact: approval.artifact, signApproval: approval,
    gateReportSha256: candidate.manifest.gateReportSha256,
    sourceReportSha256: candidate.manifest.sourceReportSha256,
  };
  const before = await revalidate();
  validateAbsentRegistry(before.registry);
  validateApproval(approval, 'sign-bootstrap');
  await record({ ...base, phase: 'signing-outcome-unknown',
    recordedAt: new Date().toISOString(),
    instruction: 'No retry. Owner must reconcile the release ledger and any public signing outcome.' });
  // Only this call may sign. A missing result never authorizes a second call.
  const bundleBytes = await sign();
  assert.ok(Buffer.isBuffer(bundleBytes) &&
    bundleBytes.length <= 2 * 1024 * 1024, 'Invalid signed bundle output');
  await verifyProvenance({ record: base, bundle: parse(bundleBytes), verifyBundle, cache });
  validateCandidate(files, approval, locks);
  const checks = await revalidate();
  validateAbsentRegistry(checks.registry);
  validateApproval(approval, 'sign-bootstrap');
  const receipt = {
    ...base, phase: 'bootstrap-signed-not-published', recordedAt: new Date().toISOString(), checks,
    provenance: { filename: 'provenance.sigstore', sha256: digest(bundleBytes).sha256,
      verification: 'verified', verifier: 'sigstore@5.0.0 (npm@12.0.2)' },
    registrySignatures: 'pending-publication', ownerPublicationApproval: 'not-performed',
  };
  await record(receipt);
  return { bundleBytes, receipt };
}

export async function verifyBootstrapProof({
  approval, files, locks, workflow, verifyBundle, cache,
}) {
  const scope = approval.scope === 'publish-bootstrap' ? 'publish-bootstrap' : 'verify-bootstrap';
  validateApproval(approval, scope);
  exactFiles(files, BOOTSTRAP_FILES);
  const signed = approval.signedArtifact;
  assert.equal(digest(files.get('bootstrap.json')).sha256, signed.receiptSha256);
  assert.equal(digest(files.get('provenance.sigstore')).sha256, signed.bundleSha256);
  const receipt = parse(files.get('bootstrap.json'));
  exactKeys(receipt, ['schemaVersion', 'name', 'version', 'channel', 'source', 'artifact', 'workflow',
    'prepareArtifact', 'signApproval', 'gateReportSha256', 'sourceReportSha256', 'phase', 'recordedAt',
    'checks', 'provenance', 'registrySignatures', 'ownerPublicationApproval'], 'bootstrap receipt');
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.phase, 'bootstrap-signed-not-published', 'Unknown or incomplete signing outcome');
  assert.equal(receipt.name, POLICY.name);
  assert.equal(receipt.version, '2.0.1');
  assert.equal(receipt.channel, 'latest');
  assert.deepEqual(receipt.source, sourceBinding(approval));
  assert.deepEqual(receipt.workflow, workflow);
  assert.equal(workflow.runId, String(signed.runId));
  assert.equal(workflow.attempt, 1);
  assert.deepEqual(receipt.prepareArtifact, approval.artifact);
  sameDigests(receipt.artifact, approval.artifact);
  assert.ok(Number.isFinite(Date.parse(receipt.recordedAt)) &&
    Date.parse(receipt.recordedAt) <= Date.now(), 'Invalid signing receipt time');
  validateApproval(receipt.signApproval, 'sign-bootstrap', Date.parse(receipt.recordedAt));
  validateLocalApproval(receipt.signApproval, { now: Date.parse(receipt.recordedAt) });
  assert.deepEqual(receipt.signApproval.localRegression, approval.localRegression);
  for (const key of ['ref', 'tagObject', 'commit', 'tree', 'ciRunId', 'ciAttempt']) {
    assert.equal(String(receipt.signApproval[key]), String(approval[key]));
  }
  assert.deepEqual(receipt.signApproval.artifact, approval.artifact);
  assert.deepEqual(receipt.provenance, {
    filename: 'provenance.sigstore', sha256: signed.bundleSha256,
    verification: 'verified', verifier: 'sigstore@5.0.0 (npm@12.0.2)',
  });
  assert.equal(receipt.registrySignatures, 'pending-publication');
  assert.equal(receipt.ownerPublicationApproval, 'not-performed');
  validateAbsentRegistry(receipt.checks.registry, Date.parse(receipt.recordedAt));
  const candidate = validateCandidate(new Map(CANDIDATE_FILES.map(name => [name, files.get(name)])), approval, locks);
  assert.equal(receipt.gateReportSha256, candidate.manifest.gateReportSha256);
  assert.equal(receipt.sourceReportSha256, candidate.manifest.sourceReportSha256);
  await verifyProvenance({ record: receipt, bundle: parse(files.get('provenance.sigstore')), verifyBundle, cache });
  return { source: receipt.source, workflow, artifact: digest(candidate.bytes), signedArtifact: signed };
}

export async function verifyBootstrap(options) {
  const { approval, revalidate } = options;
  const scope = approval.scope === 'publish-bootstrap' ? 'publish-bootstrap' : 'verify-bootstrap';
  const proof = await verifyBootstrapProof(options);
  const checks = await revalidate();
  validateAbsentRegistry(checks.registry);
  validateApproval(approval, scope);
  return {
    schemaVersion: 1, status: 'bootstrap-proof-verified-not-published',
    ...proof, checks, verifiedAt: new Date().toISOString(),
    provenance: 'cryptographically-verified', registrySignatures: 'pending-publication',
    ownerPublicationApproval: 'not-performed', npmWrite: 'not-performed',
  };
}
