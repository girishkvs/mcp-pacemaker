import assert from 'node:assert/strict';
import { POLICY, sameDigests } from './policy.mjs';
import { githubReaders, zipFiles } from './matrix.mjs';
import { sha256, validateCapture } from './stage-capture.mjs';

export async function reconcileStageCapture(approval, readers = githubReaders(process.env)) {
  const pending = approval.ownerPreflight.pending;
  assert.equal(pending.status, 'matching');
  assert.match(String(pending.captureArtifactId ?? ''), /^[1-9][0-9]*$/,
    'Original capture artifact ID required for stage reuse');
  const archive = await readers.readArtifactArchive(pending.captureArtifactId);
  const files = zipFiles(archive);
  const record = JSON.parse(files.get('stage-1.json').toString('utf8'));
  assert.equal(record.stageId, pending.stageId);
  assert.equal(record.name, approval.name);
  assert.equal(record.version, approval.version);
  assert.deepEqual(record.source, Object.fromEntries(['ref', 'tagObject', 'commit', 'tree']
    .map(key => [key, approval[key]])));
  assert.deepEqual(record.workflow, pending.workflow);
  sameDigests(record.artifact, approval.artifact);
  const capture = await readAuthenticatedStageCapture({
    record, artifactId: pending.captureArtifactId, receiptBytes: files.get('capture/receipt.json'),
    bundleBytes: files.get('capture/provenance.sigstore'),
    readers: { ...readers, readArtifactArchive: async id => {
      assert.equal(String(id), String(pending.captureArtifactId));
      return archive;
    } },
  });
  return { stageId: record.stageId, workflow: record.workflow, capture };
}

export async function readAuthenticatedStageCapture({
  record, artifactId, receiptBytes, bundleBytes, readers = githubReaders(process.env),
}) {
  assert.match(String(artifactId ?? ''), /^[1-9][0-9]*$/, 'Original GitHub capture artifact ID required');
  assert.equal(record.status, 'submitted-awaiting-owner-verification',
    'Verify the original submitted record, not a relabelled reconciled record');
  const runId = record.workflow.runId;
  assert.match(runId, /^[1-9][0-9]*$/);
  assert.equal(record.workflow.attempt, 1);
  const run = await readers.readJson(`actions/runs/${runId}/attempts/1`);
  assert.equal(String(run.id), runId);
  assert.equal(run.run_attempt, 1);
  assert.equal(run.path, POLICY.workflow);
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  assert.equal(run.head_sha, record.source.commit);
  assert.equal(run.head_branch, record.source.ref.slice('refs/tags/'.length));
  assert.equal(run.repository?.full_name, POLICY.repository);
  assert.equal(run.head_repository?.full_name, POLICY.repository);
  assert.equal(run.actor?.login, POLICY.owner);
  assert.equal(run.triggering_actor?.login, POLICY.owner);
  const jobs = await readers.readJobs(runId, 1);
  // The source job is prepare-only. Stage performs source/CI admission in its
  // own transfer and submission steps; requiring the skipped source job is wrong.
  for (const name of ['stage']) {
    const matches = jobs.filter(job => job.name === name);
    assert.equal(matches.length, 1, 'Missing or ambiguous actual stage run job');
    const job = matches[0];
    assert.equal(job.status, 'completed');
    assert.equal(job.conclusion, 'success');
    assert.equal(job.head_sha, record.source.commit);
    assert.equal(String(job.run_id), runId);
    assert.ok(job.labels.includes('ubuntu-24.04'));
    assert.ok(!job.labels.includes('self-hosted'));
  }
  const metadata = await readers.readArtifactMetadata(artifactId);
  assert.equal(String(metadata.id), String(artifactId));
  assert.equal(metadata.name, `npm-stage-ledger-${runId}-1`);
  assert.equal(metadata.expired, false);
  assert.equal(String(metadata.workflow_run?.id), runId);
  assert.equal(metadata.workflow_run.head_sha, record.source.commit);
  for (const key of ['repository_id', 'head_repository_id']) {
    assert.equal(String(metadata.workflow_run[key]), String(run.repository.id));
  }
  const archive = await readers.readArtifactArchive(artifactId);
  assert.equal(`sha256:${sha256(archive)}`, metadata.digest, 'Actual GitHub archive digest mismatch');
  const files = zipFiles(archive);
  assert.deepEqual([...files.keys()].sort(), ['capture/intent.json', 'capture/provenance.sigstore',
    'capture/receipt.json', 'stage-0.json', 'stage-1.json']);
  assert.deepEqual(JSON.parse(files.get('stage-1.json')), record, 'Record is not from the original hosted run');
  assert.deepEqual(files.get('capture/receipt.json'), receiptBytes);
  assert.deepEqual(files.get('capture/provenance.sigstore'), bundleBytes);
  const capture = validateCapture({ record, receiptBytes, bundleBytes });
  assert.deepEqual(record.capture, capture);
  const intent = JSON.parse(files.get('capture/intent.json'));
  const receipt = JSON.parse(receiptBytes);
  const { response, elapsedMs, ...base } = receipt;
  assert.deepEqual(intent, { ...base, status: 'submission-outcome-unknown' });
  const unknown = JSON.parse(files.get('stage-0.json'));
  assert.equal(unknown.status, 'submission-outcome-unknown');
  assert.equal(unknown.stageId, null);
  for (const key of ['source', 'artifact', 'workflow', 'name', 'version', 'channel',
    'authorization', 'ownerPreflight']) assert.deepEqual(unknown[key], record[key]);
  return { ...capture, artifactId: String(artifactId), artifactDigest: metadata.digest,
    runId, runAttempt: 1, authentication: 'original-github-api-artifact' };
}
