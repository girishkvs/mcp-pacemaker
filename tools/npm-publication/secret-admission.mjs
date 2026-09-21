import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isolatedEnvironment, workspace } from '../publication-scanners/core.mjs';
import { findingSourceBinding, readReviewSource } from '../publication-scanners/review-source.mjs';
import { githubReaders, MATRIX, zipFiles } from './matrix.mjs';
import { readOwnerLocalAcceptance } from './local-regression-hosted.mjs';
import { POLICY, fresh } from './policy.mjs';
import {
  SECRET_COLLECTION_JOB, SECRET_COLLECTION_STEPS, secretHash, secretId,
  reviewedFindings, validateSecretCollectionFiles, validateSecretReview,
} from './secret-report.mjs';

const admissions = new WeakMap();

export async function verifyCollectionSource(report, root, tools = {}, readSource = readReviewSource) {
  return workspace(async temp => {
    const context = { cwd: temp, env: isolatedEnvironment(temp) };
    const source = await readSource(root, { tools, context });
    assert.deepEqual(source.binding, report.source, 'Collection covers different source/root/checkout bytes');
    assert.deepEqual(await source.producerEvidence(), report.producerEvidence.source,
      'Collected full source inventory or declared checkout changed');
    for (const execution of report.raw.executions) {
      for (const finding of execution.identities) {
        const matches = source.entries.filter(entry => secretHash(entry.path) === finding.binding.pathSha256);
        assert.equal(matches.length, 1, 'Finding source path is missing or ambiguous');
        assert.deepEqual(await findingSourceBinding(source, matches[0], finding.binding.line, execution.scope),
          finding.binding, 'Finding file/blob/attributes or history mapping changed');
      }
    }
    assert.deepEqual((await readSource(root, { tools, context })).binding, source.binding,
      'Source changed during admission');
  });
}

export function validateCollectionJobs(jobs, approval, report) {
  assert.ok(Array.isArray(jobs) && jobs.length > 0 && jobs.length <= 16);
  const inactive = ['source', 'prepare', 'stage',
    ...(approval.version === '2.0.1' ? ['sign-bootstrap', 'publish-bootstrap'] : [])];
  const names = jobs.map(job => job.name).sort();
  assert.ok(JSON.stringify(names) === JSON.stringify([...inactive, 'consumers', SECRET_COLLECTION_JOB].sort()) ||
    JSON.stringify(names) === JSON.stringify([...inactive, ...MATRIX.map(item => item.jobName), SECRET_COLLECTION_JOB].sort()),
  'Incomplete original collection topology');
  const allowed = new Set(['source', 'prepare', 'consumers', 'stage', 'sign-bootstrap', 'publish-bootstrap',
    SECRET_COLLECTION_JOB, ...MATRIX.map(item => item.jobName)]);
  const seen = new Set();
  const ids = new Set();
  let collection;
  for (const job of jobs) {
    assert.ok(allowed.has(job.name) && !seen.has(job.name), 'Unexpected or duplicate collection-run job');
    seen.add(job.name);
    assert.ok(!ids.has(secretId(job.id)), 'Reused collection job ID');
    ids.add(secretId(job.id));
    assert.equal(secretId(job.run_id), secretId(report.workflow.runId));
    assert.equal(job.run_attempt, 1);
    assert.equal(job.head_sha, approval.commit);
    assert.equal(job.status, 'completed');
    assert.equal(job.conclusion, job.name === SECRET_COLLECTION_JOB ? 'success' : 'skipped',
      'Collection must not execute preparation, consumers, signing or staging');
    if (job.name === SECRET_COLLECTION_JOB) collection = job;
    else assert.deepEqual(job.steps, []);
  }
  assert.ok(collection, 'Missing collection job');
  assert.equal(secretId(collection.id), secretId(approval.secretReview.collection.jobId));
  secretId(collection.runner_id);
  const labels = collection.labels;
  assert.ok(Array.isArray(labels) &&
    labels.every(label => typeof label === 'string' &&
      label.length > 0 &&
      label.trim() === label), 'Original collection runner labels are malformed');
  assert.ok(collection.runner_name &&
    labels.includes('ubuntu-24.04') &&
    !labels.some(label => /^self-hosted$/i.test(label)), 'Original collection must use GitHub-hosted ubuntu-24.04');
  const stepNames = ['Set up job', 'Require supported hosted runner before any credentials can be requested',
    'Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
    'Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    'Install pinned publication scanners', ...SECRET_COLLECTION_STEPS,
    'Post Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    'Post Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'Complete job'];
  assert.deepEqual(collection.steps.map(step => step.name), stepNames);
  for (const [index, step] of collection.steps.entries()) {
    assert.ok(Number.isSafeInteger(step.number) && step.number > 0 &&
      (index === 0 || step.number > collection.steps[index - 1].number));
    assert.equal(step.status, 'completed'); assert.equal(step.conclusion, 'success');
  }
  const collect = collection.steps.find(step => step.name === SECRET_COLLECTION_STEPS[0]);
  const install = collection.steps.find(step => step.name === 'Install pinned publication scanners');
  const start = Date.parse(collect.started_at); const end = Date.parse(collect.completed_at);
  assert.ok(Date.parse(collection.started_at) <= Date.parse(install.completed_at) &&
    Date.parse(install.completed_at) <= start && start <= end &&
    end <= Date.parse(collection.completed_at));
  assert.ok(Date.parse(report.producerEvidence.ci.completedAt) <= Date.parse(collection.started_at) &&
    Date.parse(report.completedAt) >= start && Date.parse(report.completedAt) <= end);
  assert.equal(secretId(report.producerEvidence.ci.runId), secretId(approval.ciRunId));
  assert.equal(report.producerEvidence.ci.attempt, approval.ciAttempt);
  for (const { record } of report.producerEvidence.receipts) {
    assert.ok(Date.parse(record.native.startedAt) >= start && Date.parse(record.native.completedAt) <= end);
  }
  for (const name of SECRET_COLLECTION_STEPS) {
    const steps = collection.steps?.filter(step => step.name === name);
    assert.equal(steps?.length, 1, 'Missing or duplicate collection step');
    assert.equal(steps[0].status, 'completed');
    assert.equal(steps[0].conclusion, 'success', 'Collection step did not complete');
  }
}

// Only a real existing-owner dispatch plus original GitHub artifact readback creates a capability.
// Readers/source inspection may be injected by local unit tests, never by request JSON.
export async function readSecretAdmission(options) {
  try { return await readOriginalSecretAdmission(options); }
  catch { throw new Error('Exact source secret admission rejected'); }
}

async function readOriginalSecretAdmission({
  approval, env = process.env,
  event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8')),
  readers = githubReaders(env), inspectSource = verifyCollectionSource,
}) {
  validateSecretReview(approval.secretReview, approval);
  await readOwnerLocalAcceptance({ approval, env, event, readers, continuing: true });
  assert.equal(env.GITHUB_JOB, 'source', 'Only the source preparation job consumes secret review');
  const current = await readers.readJson(`actions/runs/${secretId(env.GITHUB_RUN_ID)}`);
  assert.equal(secretId(current.run_number), secretId(env.GITHUB_RUN_NUMBER));
  assert.equal(secretId(current.run_number), secretId(approval.secretReview.admissionRunNumber),
    'Consent is for a different dispatch; it cannot be replayed');
  const dispatchedAt = Date.parse(current.created_at);
  assert.ok(Number.isFinite(dispatchedAt) && dispatchedAt <= Date.now());
  fresh(approval.approvedAt, dispatchedAt);
  const expected = approval.secretReview.collection;
  assert.notEqual(secretId(expected.runId), secretId(env.GITHUB_RUN_ID));
  const original = await readers.readJson(`actions/runs/${secretId(expected.runId)}`);
  assert.equal(secretId(original.id), secretId(expected.runId));
  assert.equal(original.head_sha, approval.commit);
  assert.equal(original.path, POLICY.workflow);
  assert.equal(original.event, 'workflow_dispatch');
  assert.equal(original.run_attempt, 1);
  assert.equal(original.status, 'completed');
  assert.equal(original.conclusion, 'success');
  for (const repository of [original.repository, original.head_repository]) {
    assert.equal(repository.full_name, POLICY.repository);
    assert.equal(repository.private, false);
    assert.equal(repository.fork, false);
    assert.equal(secretId(repository.id), env.GITHUB_REPOSITORY_ID);
    assert.equal(repository.owner.login, POLICY.owner);
    assert.equal(secretId(repository.owner.id), env.GITHUB_REPOSITORY_OWNER_ID);
  }
  for (const actor of [original.actor, original.triggering_actor]) {
    assert.equal(actor.login, POLICY.owner);
    assert.equal(secretId(actor.id), env.GITHUB_REPOSITORY_OWNER_ID);
  }
  assert.equal(secretId(current.workflow_id), secretId(original.workflow_id),
    'Consent cannot move between recreated workflows');
  assert.equal(secretId(original.repository.id), env.GITHUB_REPOSITORY_ID);
  assert.equal(secretId(original.repository.owner.id), env.GITHUB_REPOSITORY_OWNER_ID);
  assert.ok(BigInt(secretId(original.run_number)) < BigInt(secretId(current.run_number)));
  const artifacts = await readers.readArtifacts(expected.runId);
  assert.equal(artifacts.length, 1, 'Collection must contain only its redacted report artifact');
  assert.equal(secretId(artifacts[0].id), secretId(expected.artifactId));
  const metadata = await readers.readArtifactMetadata(expected.artifactId);
  assert.equal(secretId(metadata.id), secretId(expected.artifactId));
  assert.equal(metadata.name, `npm-secret-collection-${expected.runId}-1`);
  assert.equal(metadata.expired, false);
  assert.equal(metadata.digest, expected.artifactDigest);
  assert.equal(artifacts[0].digest, metadata.digest);
  assert.equal(secretId(metadata.workflow_run.id), secretId(expected.runId));
  assert.equal(metadata.workflow_run.head_sha, approval.commit);
  for (const key of ['repository_id', 'head_repository_id']) {
    assert.equal(secretId(metadata.workflow_run[key]), env.GITHUB_REPOSITORY_ID);
  }
  const archive = await readers.readArtifactArchive(expected.artifactId);
  assert.ok(Buffer.isBuffer(archive) && archive.length <= 2 * 1024 * 1024, 'Oversized collection archive');
  assert.equal(`sha256:${secretHash(archive)}`, expected.artifactDigest);
  const files = zipFiles(archive);
  const report = validateSecretCollectionFiles(files);
  const bytes = files.get('report.json');
  assert.ok(bytes.length <= 512 * 1024);
  assert.equal(secretHash(bytes), expected.reportSha256);
  assert.ok(bytes.equals(Buffer.from(`${JSON.stringify(report, null, 2)}\n`)),
    'Collection must retain the exact canonical producer serialization');
  assert.equal(report.source.commit, approval.commit);
  assert.equal(report.source.tree, approval.tree);
  assert.deepEqual(report.workflow, { runId: secretId(original.id), runNumber: secretId(original.run_number),
    attempt: 1, repositoryId: env.GITHUB_REPOSITORY_ID, ownerId: env.GITHUB_REPOSITORY_OWNER_ID, ref: approval.ref });
  assert.ok(Date.parse(report.completedAt) <= Date.parse(approval.secretReview.reviewedAt) &&
    Date.parse(report.completedAt) >= Date.parse(original.created_at), 'Review predates collection');
  validateCollectionJobs(await readers.readJobs(expected.runId, 1), approval, report);
  reviewedFindings(report, approval.secretReview);
  const capability = Object.freeze({});
  admissions.set(capability, {
    report: structuredClone(report), inspectSource,
    receipt: { kind: 'exact-reviewed-source-secret-admission', commit: approval.commit, tree: approval.tree,
      collection: structuredClone(expected), reviewSha256: secretHash(JSON.stringify(approval.secretReview)),
      admissionRunId: env.GITHUB_RUN_ID, admissionRunNumber: env.GITHUB_RUN_NUMBER },
  });
  return capability;
}

export async function consumeSecretAdmission(capability, request, tools) {
  const entry = admissions.get(capability);
  assert.ok(entry, 'Missing authenticated exact-report admission; flags cannot authorize findings');
  admissions.delete(capability);
  assert.equal(request.phase, 'source', 'Artifact findings cannot use source dispositions');
  assert.equal(request.commit, entry.report.source.commit);
  await entry.inspectSource(entry.report, request.root, tools);
  const rawFindings = entry.report.raw.executions.reduce((total, item) => total + item.findings, 0);
  assert.ok(rawFindings > 0);
  return {
    secrets: { schemaVersion: 1, kind: 'admitted-original-source-secret-evidence',
      status: entry.report.raw.status, executions: entry.report.raw.executions,
      collection: entry.report, onlineVerification: 'disabled', automaticUpdates: 'disabled' },
    admission: { ...entry.receipt, rawStatus: entry.report.raw.status,
      rawFindings, reviewedFalsePositives: rawFindings, remainingFindings: 0 },
    revalidate: () => entry.inspectSource(entry.report, request.root, tools),
  };
}
