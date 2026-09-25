import { LOCAL_CONTRACT, LOCAL_NODES, localCommitment } from '../../tools/npm-publication/local-regression.mjs';
const FIXTURE_TIME = new Date().toISOString();

// Synthetic unit-test inputs only. These are not local reports, real owner reviews or release evidence.
export function syntheticLocalReview(statement, reviewedAt = new Date().toISOString()) {
  return { reviewer: 'girishkvs', scope: 'private-local-regression-evidence', disposition: 'accepted',
    statementSha256: localCommitment(statement), reviewedAt };
}

export function syntheticLocalApproval(approval) {
  approval.approvedAt ??= FIXTURE_TIME;
  const at = Date.parse(approval.approvedAt);
  const subjects = ['1.3.1', '2.0.1'].map((version, index) => {
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
  if (approval.scope === 'prepare') approval.localRegressionReview = review;
  else approval.ownerPreflight.privateContentReview.localRegression = review;
  return approval;
}

export function syntheticPreparedLocal(prepared, approval) {
  prepared.localRegression = approval.localRegression;
  prepared.preparationApproval = { scope: 'prepare', approver: 'girishkvs', approvedAt: approval.approvedAt };
  prepared.localRegressionReview = syntheticLocalReview(approval.localRegression, approval.approvedAt);
  return prepared;
}
