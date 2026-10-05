import { LOCAL_CONTRACT, LOCAL_NODES, localCommitment, localHash, releaseRole, releaseVersions } from '../../tools/npm-publication/local-regression.mjs';
const FIXTURE_TIME = new Date().toISOString();

// Synthetic unit-test inputs only. These are not local reports, real owner reviews or release evidence.
export function syntheticLocalReview(statement, reviewedAt = new Date().toISOString()) {
  return { reviewer: 'girishkvs', scope: 'private-local-regression-evidence', disposition: 'accepted',
    statementSha256: localCommitment(statement), reviewedAt };
}

export function syntheticLocalApproval(approval) {
  approval.approvedAt ??= FIXTURE_TIME;
  const at = Date.parse(approval.approvedAt);
  const peerVersion = approval.peerArtifact?.version ??
    (releaseRole(approval.version) === 'legacy' ? '2.0.1' : '1.3.1');
  const subjects = releaseVersions([approval.version, peerVersion]).map((version, index) => {
    const source = approval.version === version ? approval : approval.peerArtifact?.version === version
      ? approval.peerArtifact : { commit: String(index + 1).repeat(40), tree: String(index + 3).repeat(40) };
    return { version, commit: source.commit, tree: source.tree, treeEntriesSha256: 'a'.repeat(64),
      checkoutFilesSha256: 'b'.repeat(64), inputManifestSha256: 'c'.repeat(64) };
  });
  approval.localRegression = { schemaVersion: 1, kind: 'local-regression-integrity-checked',
    contract: LOCAL_CONTRACT, scope: 'both-release-lines-local-only',
    runId: '11111111-1111-4111-8111-111111111111', completedAt: new Date(at - 60_000).toISOString(),
    reportSha256: 'a'.repeat(64), evidenceSha256: 'b'.repeat(64), controllerSha256: 'c'.repeat(64),
    image: 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9',
    runtimes: LOCAL_NODES.map(version => ({ version, sha256: 'd'.repeat(64) })),
    subjects, coverage: { controls: 3, sourceCases: 6 }, releaseReady: false, executionProof: 'not-authenticated' };
  const review = syntheticLocalReview(approval.localRegression, approval.approvedAt);
  if (['prepare', 'collect-secrets'].includes(approval.scope)) approval.localRegressionReview = review;
  else approval.ownerPreflight.privateContentReview.localRegression = review;
  return approval;
}

export function syntheticPreparedLocal(prepared, approval) {
  prepared.localRegression = approval.localRegression;
  prepared.preparationApproval = { scope: 'prepare', approver: 'girishkvs', approvedAt: approval.approvedAt };
  prepared.localRegressionReview = syntheticLocalReview(approval.localRegression, approval.approvedAt);
  return prepared;
}

export function syntheticCleanProducerEvidence(source) {
  const scopes = ['producer-root', 'producer-ui'];
  const audits = scopes.map(scope => ({ scope, disposition: 'advisory-free', rawExitCode: 0,
    rawFindingCount: 0, rawCounts: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } }));
  const osv = { status: 'passed', findings: [], rawFindingCount: 0, remainingFindings: 0,
    distinctCoordinates: 2, scope: scopes.map((scope, index) => ({ scope,
      lockSha256: [source.rootLockSha256, source.uiLockSha256][index], graphSha256: '3'.repeat(64), packages: 1 })),
    evidence: [{ querySha256: '4'.repeat(64), responseSha256: '5'.repeat(64),
      rawResponseSha256: '6'.repeat(64), responseBytes: 2, queries: 2 }] };
  const gate = { status: 'passed', disposition: 'advisory-free', advisoryFree: true,
    rawFindingCount: 0, remainingFindings: 0, nativeAudits: audits, osv,
    evidence: [{ description: 'Synthetic zero-finding producer report; no queries executed', sha256: localHash(JSON.stringify(osv)) }] };
  return { source, checks: { audits }, gate };
}
