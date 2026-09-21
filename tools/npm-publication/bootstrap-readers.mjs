import assert from 'node:assert/strict';
import { validatePreparedLocal } from './local-regression.mjs';
import { SECRET_COLLECTION_JOB } from './secret-report.mjs';
import {
  POLICY, digest, sameDigests, validateTransfer, validateCi, validateEnvironment, publicationTagName,
} from './policy.mjs';
import { MATRIX, validateConsumerJob, validateConsumerReport } from './matrix.mjs';
import { validatePeerJobs } from './peer.mjs';
import { inspectTarball } from './tarball.mjs';
import {
  BOOTSTRAP_FILES, CANDIDATE_FILES, exactArchive, parse, validateCandidate, validateAbsentRegistry,
} from './bootstrap.mjs';

const id = value => {
  assert.match(String(value ?? ''), /^[1-9][0-9]*$/);
  return String(value);
};

function repositoryBinding(repository) {
  assert.equal(repository.full_name, POLICY.repository);
  assert.equal(repository.private, false);
  assert.equal(repository.fork, false);
  assert.equal(repository.owner.login, POLICY.owner);
  id(repository.id);
  id(repository.owner.id);
}

export function workflowRun(run, approval, runId, completed) {
  assert.equal(id(run.id), id(runId));
  assert.equal(run.head_sha, approval.commit);
  assert.equal(run.path, POLICY.workflow);
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.run_attempt, 1);
  assert.equal(run.status, completed ? 'completed' : 'in_progress');
  assert.equal(run.conclusion, completed ? 'success' : null);
  repositoryBinding(run.repository);
  repositoryBinding(run.head_repository);
  assert.equal(id(run.head_repository.id), id(run.repository.id));
  for (const actor of [run.actor, run.triggering_actor]) {
    assert.equal(actor?.login, POLICY.owner);
    assert.equal(id(actor.id), id(run.repository.owner.id));
  }
}

export async function readRemoteSource(approval, readers) {
  const ref = await readers.readJson(`git/ref/tags/${publicationTagName(approval.ref, approval.version)}`);
  assert.equal(ref.ref, approval.ref);
  assert.equal(ref.object?.type, 'tag');
  assert.equal(ref.object.sha, approval.tagObject);
  const tag = await readers.readJson(`git/tags/${approval.tagObject}`);
  assert.equal(tag.sha, approval.tagObject);
  assert.equal(tag.tag, publicationTagName(approval.ref, approval.version));
  assert.equal(tag.object?.type, 'commit');
  assert.equal(tag.object.sha, approval.commit);
  const commit = await readers.readJson(`git/commits/${approval.commit}`);
  assert.equal(commit.sha, approval.commit);
  assert.equal(commit.tree?.sha, approval.tree);
  const run = await readers.readJson(`actions/runs/${id(approval.ciRunId)}/attempts/${id(approval.ciAttempt)}`);
  validateCi(run, await readers.readJobs(approval.ciRunId, approval.ciAttempt), approval);
  repositoryBinding(run.repository);
  return { repositoryId: id(run.repository.id), ownerId: id(run.repository.owner.id),
    ciRunId: id(run.id), ciAttempt: run.run_attempt, commit: approval.commit };
}

export async function readProtectedEnvironment(approval, runId, readers) {
  const environment = await readers.readJson(`environments/${POLICY.environment}`);
  const policies = await readers.readJson(`environments/${POLICY.environment}/deployment-branch-policies?per_page=100`);
  assert.equal(policies.total_count, policies.branch_policies.length, 'Incomplete protected tag policies');
  const reviews = await readers.readJson(`actions/runs/${id(runId)}/approvals`);
  validateEnvironment(environment, policies.branch_policies, reviews, approval);
  return { id: environment.id, name: environment.name, reviewer: POLICY.owner, runId: id(runId) };
}

async function artifactFiles(readers, expected, names) {
  const metadata = await readers.readArtifactMetadata(id(expected.id));
  assert.equal(id(metadata.id), id(expected.id));
  assert.equal(metadata.name, expected.name);
  assert.equal(metadata.expired, false);
  assert.match(expected.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(metadata.digest, expected.digest);
  assert.equal(id(metadata.workflow_run?.id), id(expected.runId));
  assert.equal(metadata.workflow_run.head_sha, expected.commit);
  for (const key of ['repository_id', 'head_repository_id']) {
    assert.equal(id(metadata.workflow_run[key]), id(expected.repositoryId));
  }
  const archive = await readers.readArtifactArchive(metadata.id);
  assert.equal(`sha256:${digest(archive).sha256}`, expected.digest, 'Actual GitHub ZIP digest mismatch');
  return { metadata, files: exactArchive(archive, names) };
}

export async function readCandidateEvidence(approval, locks, readers) {
  const approved = approval.artifact;
  const run = await readers.readJson(`actions/runs/${id(approved.runId)}`);
  workflowRun(run, approval, approved.runId, true);
  const jobs = await readers.readJobs(approved.runId, 1);
  const binding = { runId: approved.runId, commit: approval.commit, repositoryId: run.repository.id };
  const { files, metadata } = await artifactFiles(readers, { ...binding,
    id: approved.artifactId, digest: approved.artifactDigest, name: `npm-candidate-${approved.runId}-1`,
  }, CANDIDATE_FILES);
  validateTransfer(run, jobs, metadata, approval);
  const candidate = validateCandidate(files, approval, locks);
  const { manifest, inspection } = candidate;
  const source = manifest.sourceArtifact;
  const preparedFiles = (await artifactFiles(readers, { ...binding,
    id: source.id, digest: source.digest, name: `npm-prepared-${approved.runId}-1`,
  }, ['candidate.tgz', 'prepared.json', 'source-gates.json'])).files;
  assert.equal(digest(preparedFiles.get('prepared.json')).sha256, source.preparedSha256);
  assert.equal(digest(preparedFiles.get('source-gates.json')).sha256, source.sourceReportSha256);
  assert.equal(source.sourceReportSha256, manifest.sourceReportSha256);
  sameDigests(digest(preparedFiles.get('candidate.tgz')), approved);
  const prepared = parse(preparedFiles.get('prepared.json'));
  validatePreparedLocal(prepared, approval);
  assert.equal(prepared.schemaVersion, 1);
  assert.equal(prepared.status, 'prepared-awaiting-platform-gates');
  for (const key of ['name', 'version', 'source', 'workflow', 'ci', 'toolchain', 'producerLocks',
    'artifact', 'publicPackages', 'sourceReportSha256', 'privateContentReview',
    'localRegression', 'localRegressionReview']) {
    assert.deepEqual(prepared[key], manifest[key], `Prepared/finalized ${key} differs`);
  }
  const ids = new Set([id(metadata.id), id(source.id)]);
  const names = new Set();
  let lanes = 0;
  for (const lane of MATRIX) {
    const expectedName = `npm-consumer-${approved.runId}-1-${lane.platform}-${lane.npm}`;
    const matches = manifest.matrixArtifacts.filter(item => item.name === expectedName);
    assert.equal(matches.length, 1, 'Missing/duplicate consumer artifact receipt');
    const receipt = matches[0];
    assert.ok(!ids.has(id(receipt.id)));
    ids.add(id(receipt.id));
    names.add(receipt.name);
    assert.equal(id(receipt.runId), id(approved.runId));
    assert.equal(receipt.attempt, 1);
    const matchingJobs = jobs.filter(job => job.name === lane.jobName);
    assert.equal(matchingJobs.length, 1);
    const job = validateConsumerJob(matchingJobs[0], lane, { runId: approved.runId, commit: approval.commit });
    assert.equal(id(job.id), id(receipt.jobId));
    assert.equal(receipt.jobName, lane.jobName);
    const reportFiles = (await artifactFiles(readers, {
      ...binding, id: receipt.id, digest: receipt.digest, name: expectedName,
    }, ['report.json'])).files;
    assert.equal(digest(reportFiles.get('report.json')).sha256, receipt.reportSha256);
    const checked = validateConsumerReport(parse(reportFiles.get('report.json')), {
      approval, prepared, sourceArtifact: source,
      workflow: { repository: POLICY.repository, path: POLICY.workflow, ...prepared.workflow },
      lane, job, inspection, artifactId: receipt.id,
    });
    lanes += checked.consumerLanes.length;
  }
  assert.equal(names.size, 6);
  assert.equal(lanes, 12);
  await readPeerEvidence(manifest.peerArtifact, run.repository.id, readers, approval);
  return { ...candidate, files, repository: run.repository,
    evidence: { prepareRunId: id(approved.runId), candidateArtifactId: id(metadata.id),
      sourceArtifactId: id(source.id), consumerArtifacts: 6, consumerInstalls: lanes,
      peerArtifactId: id(manifest.peerArtifact.artifactId), checkedAt: new Date().toISOString() } };
}

async function readPeerEvidence(peer, repositoryId, readers, approval) {
  assert.equal(peer.schemaVersion, 1);
  assert.equal(peer.purpose, 'service-comparison-only');
  assert.equal(peer.name, POLICY.name);
  assert.equal(peer.version, '1.3.1', 'Bootstrap T32 must retain the approved opposite legacy patch');
  assert.equal(peer.repository, POLICY.repository);
  assert.equal(id(peer.repositoryId), id(repositoryId));
  assert.equal(peer.stageEligible, false);
  assert.equal(peer.runAttempt, 1);
  assert.equal(peer.sourcePassed, true);
  assert.equal(peer.matrixPassed, true);
  assert.equal(peer.finalizerNotRequired, true);
  assert.equal(peer.privateScans, 'pending');
  assert.equal(peer.humanApproval, 'pending');
  const run = await readers.readJson(`actions/runs/${id(peer.runId)}`);
  assert.equal(run.head_sha, peer.source.commit);
  assert.equal(run.path, POLICY.workflow);
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.run_attempt, 1);
  assert.equal(run.status, 'completed');
  assert.ok(['success', 'failure'].includes(run.conclusion));
  repositoryBinding(run.repository);
  repositoryBinding(run.head_repository);
  assert.equal(id(run.repository.id), id(repositoryId));
  assert.equal(id(run.head_repository.id), id(repositoryId));
  for (const actor of [run.actor, run.triggering_actor]) {
    assert.equal(actor?.login, POLICY.owner);
    assert.equal(id(actor.id), id(run.repository.owner.id));
  }
  const ref = await readers.readJson(`git/ref/tags/${publicationTagName(peer.source.ref, peer.version)}`);
  assert.equal(ref.ref, peer.source.ref);
  assert.equal(ref.object?.type, 'tag');
  assert.equal(ref.object.sha, peer.source.tagObject);
  const tag = await readers.readJson(`git/tags/${peer.source.tagObject}`);
  assert.equal(tag.object?.type, 'commit');
  assert.equal(tag.object.sha, peer.source.commit);
  const commit = await readers.readJson(`git/commits/${peer.source.commit}`);
  assert.equal(commit.tree?.sha, peer.source.tree);
  const jobs = await readers.readJobs(peer.runId, 1);
  const jobsEvidence = validatePeerJobs({ peer: { ...peer, ...peer.source }, jobs });
  assert.deepEqual(peer.sourceJob, jobsEvidence.sourceJob);
  assert.deepEqual(peer.consumerJobs, jobsEvidence.consumerJobs);
  const files = (await artifactFiles(readers, {
    id: peer.artifactId, digest: peer.artifactDigest, runId: peer.runId, commit: peer.source.commit,
    repositoryId, name: `npm-prepared-${peer.runId}-1`,
  }, ['candidate.tgz', 'prepared.json', 'source-gates.json'])).files;
  assert.equal(digest(files.get('prepared.json')).sha256, peer.manifestSha256);
  assert.equal(digest(files.get('source-gates.json')).sha256, peer.sourceReportSha256);
  sameDigests(digest(files.get('candidate.tgz')), peer);
  const prepared = parse(files.get('prepared.json'));
  validatePreparedLocal(prepared, approval, { ...peer, ...peer.source });
  assert.deepEqual(prepared.source, peer.source);
  assert.equal(prepared.version, peer.version);
  assert.equal(prepared.name, POLICY.name);
  assert.equal(prepared.schemaVersion, 1);
  assert.equal(prepared.status, 'prepared-awaiting-platform-gates');
  assert.deepEqual(prepared.toolchain, { node: POLICY.node, npm: POLICY.npm });
  assert.equal(prepared.artifact.filename, 'candidate.tgz');
  sameDigests(prepared.artifact, peer);
  assert.equal(prepared.sourceReportSha256, peer.sourceReportSha256);
  assert.deepEqual(inspectTarball(files.get('candidate.tgz'), { ...peer, ...peer.source }).files, prepared.artifact.files);
}

export async function readSigningRun(approval, runId, readers, completed) {
  const run = await readers.readJson(`actions/runs/${id(runId)}`);
  workflowRun(run, approval, runId, completed);
  const jobs = await readers.readJobs(runId, 1);
  const matches = jobs.filter(job => job.name === 'sign-bootstrap');
  assert.equal(matches.length, 1, 'Missing or ambiguous protected signing job');
  const job = matches[0];
  assert.equal(job.head_sha, approval.commit);
  assert.equal(id(job.run_id), id(runId));
  assert.equal(job.run_attempt, 1);
  assert.equal(job.status, completed ? 'completed' : 'in_progress');
  assert.equal(job.conclusion, completed ? 'success' : null);
  assert.ok(job.labels?.includes('ubuntu-24.04'));
  assert.ok(job.runner_name);
  const allowed = new Set(['source', 'prepare', 'consumers', 'stage', 'sign-bootstrap', 'publish-bootstrap', SECRET_COLLECTION_JOB,
    ...MATRIX.map(lane => lane.jobName)]);
  const seen = new Set();
  for (const item of jobs) {
    assert.ok(allowed.has(item.name) &&
      !seen.has(item.name), 'Unexpected/duplicate signing-run job');
    seen.add(item.name);
    if (item.name !== 'sign-bootstrap') {
      assert.equal(item.status, 'completed');
      assert.equal(item.conclusion, 'skipped', 'Signing must not run preparation or npm staging');
    }
  }
  if (completed) {
    for (const name of ['Sign and verify exact bootstrap bytes once', 'Export verified bootstrap bundle']) {
      const steps = job.steps?.filter(step => step.name === name);
      assert.equal(steps?.length, 1);
      assert.equal(steps[0].status, 'completed');
      assert.equal(steps[0].conclusion, 'success');
    }
  }
  return {
    ref: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`, commit: approval.commit,
    runId: id(run.id), attempt: 1, repositoryId: id(run.repository.id), ownerId: id(run.repository.owner.id),
  };
}

export async function readSignedArtifact(approval, readers) {
  const signed = approval.signedArtifact;
  const workflow = await readSigningRun(approval, signed.runId, readers, true);
  const { files } = await artifactFiles(readers, {
    id: signed.artifactId, digest: signed.artifactDigest, runId: signed.runId, commit: approval.commit,
    repositoryId: workflow.repositoryId, name: `npm-bootstrap-signed-${signed.runId}-1`,
  }, BOOTSTRAP_FILES);
  return { files, workflow };
}

export async function readOwnerRun(approval, runId, readers) {
  const run = await readers.readJson(`actions/runs/${id(runId)}`);
  workflowRun(run, approval, runId, false);
  const jobs = await readers.readJobs(runId, 1);
  const matches = jobs.filter(job => job.name === 'publish-bootstrap');
  assert.equal(matches.length, 1);
  const job = matches[0];
  assert.equal(job.head_sha, approval.commit);
  assert.equal(id(job.run_id), id(runId));
  assert.equal(job.run_attempt, 1);
  assert.equal(job.status, 'in_progress');
  assert.equal(job.conclusion, null);
  assert.ok(job.labels?.includes('ubuntu-24.04'));
  assert.ok(job.runner_name);
  const allowed = new Set(['source', 'prepare', 'consumers', 'stage', 'sign-bootstrap', 'publish-bootstrap', SECRET_COLLECTION_JOB,
    ...MATRIX.map(lane => lane.jobName)]);
  const seen = new Set();
  for (const item of jobs) {
    assert.ok(allowed.has(item.name) &&
      !seen.has(item.name));
    seen.add(item.name);
    if (item.name !== 'publish-bootstrap') {
      assert.equal(item.status, 'completed');
      assert.equal(item.conclusion, 'skipped', 'Owner bootstrap cannot execute another publication action');
    }
  }
  return { runId: id(run.id), jobId: id(job.id), attempt: 1,
    repositoryId: id(run.repository.id), ownerId: id(run.repository.owner.id) };
}

export async function readAbsentRegistry({ fetcher = fetch } = {}) {
  const response = await fetcher(`${POLICY.registry}${POLICY.name}`, {
    method: 'GET', redirect: 'error', cache: 'no-store',
    headers: { accept: 'application/json', 'cache-control': 'no-cache' }, signal: AbortSignal.timeout(30_000),
  });
  const result = { registry: POLICY.registry, name: POLICY.name, status: response.status,
    checkedAt: new Date().toISOString() };
  validateAbsentRegistry(result);
  return result;
}
