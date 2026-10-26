import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { POLICY } from '../../tools/npm-publication/policy.mjs';
import { captureSubject, sha256, CAPTURE_LIMITS } from '../../tools/npm-publication/stage-capture.mjs';
const { zip } = createRequire(import.meta.url)('../../tools/npm-publication/offline-stage/fixture.cjs');

// Synthetic original GitHub archive/API replies, never authenticated release evidence.
// Each reader checks its requested identity. Invalid bundles can still be placed
// in this fixture archive so tests exercise the real later signature/claim checks.
export function stageCaptureFixture(record, bundle) {
  const saved = structuredClone(record);
  const bundleBytes = Buffer.from(JSON.stringify(bundle));
  const subject = captureSubject(saved);
  const receipt = {
    schemaVersion: 1, kind: 'npm12-actual-stage-post-observation',
    authentication: 'requires-original-github-artifact', subject,
    request: { method: 'POST', url: `${POLICY.registry}-/stage/package/${POLICY.name}`,
      sha256: sha256('synthetic serialized request fixture'), bytes: bundleBytes.length + 1024 },
    bundle: { sha256: sha256(bundleBytes), bytes: bundleBytes.length },
    timeoutMs: CAPTURE_LIMITS.timeoutMs, status: 'observed-successful-stage-response',
    response: { status: 201, sha256: sha256(JSON.stringify({ stageId: saved.stageId })),
      bytes: Buffer.byteLength(JSON.stringify({ stageId: saved.stageId })), stageId: saved.stageId },
    elapsedMs: 1,
  };
  const receiptBytes = Buffer.from(JSON.stringify(receipt));
  saved.capture = { stageId: saved.stageId, receiptSha256: sha256(receiptBytes),
    bundleSha256: sha256(bundleBytes) };
  const { response, elapsedMs, ...base } = receipt;
  const files = new Map([
    ['capture/intent.json', Buffer.from(JSON.stringify({ ...base, status: 'submission-outcome-unknown' }))],
    ['capture/receipt.json', receiptBytes], ['capture/provenance.sigstore', bundleBytes],
    ['stage-0.json', Buffer.from(JSON.stringify({ ...saved, capture: undefined,
      status: 'submission-outcome-unknown', stageId: null }))],
    ['stage-1.json', Buffer.from(JSON.stringify(saved))],
  ]);
  const archive = zip(files);
  const runId = saved.workflow.runId;
  const artifactId = '456';
  const run = { id: Number(runId), run_attempt: 1, path: POLICY.workflow,
    event: 'workflow_dispatch', status: 'completed', conclusion: 'success',
    head_sha: saved.source.commit, head_branch: saved.source.ref.slice('refs/tags/'.length),
    repository: { id: 789, full_name: POLICY.repository },
    head_repository: { id: 789, full_name: POLICY.repository },
    actor: { login: POLICY.owner }, triggering_actor: { login: POLICY.owner } };
  const jobs = [{ name: 'stage', status: 'completed', conclusion: 'success',
    head_sha: saved.source.commit, run_id: Number(runId), labels: ['ubuntu-24.04'] }];
  const metadata = { id: Number(artifactId), name: `npm-stage-ledger-${runId}-1`, expired: false,
    digest: `sha256:${sha256(archive)}`, workflow_run: { id: Number(runId), head_sha: saved.source.commit,
      repository_id: 789, head_repository_id: 789 } };
  const calls = [];
  const readers = {
    readJson: async path => {
      calls.push(['run', path]);
      assert.equal(path, `actions/runs/${runId}/attempts/1`);
      return structuredClone(run);
    },
    readJobs: async (id, attempt) => {
      calls.push(['jobs', id, attempt]);
      assert.equal(String(id), runId);
      assert.equal(attempt, 1);
      return structuredClone(jobs);
    },
    readArtifactMetadata: async id => {
      calls.push(['metadata', id]);
      assert.equal(String(id), artifactId);
      return structuredClone(metadata);
    },
    readArtifactArchive: async id => {
      calls.push(['archive', id]);
      assert.equal(String(id), artifactId);
      return Buffer.from(archive);
    },
  };
  return { record: saved, bundleBytes, receiptBytes, artifactId, readers,
    fixtureOnly: { run, jobs, metadata, files, archive, calls } };
}
