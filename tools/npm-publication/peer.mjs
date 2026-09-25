import assert from 'node:assert/strict';
import { exactLocalKeys, validateLocalApproval, validatePreparedLocal, validateLocalRegression } from './local-regression.mjs';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, publicationTagName, sameDigests } from './policy.mjs';
import { MATRIX, githubReaders, zipFiles } from './matrix.mjs';
import { inspectTarball } from './tarball.mjs';
import { SECRET_COLLECTION_JOB, assertCollectionJobSkipped, sourceCiAttempt } from './secret-report.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SOURCE_STEPS = [
  'Validate source, run required gates, and pack exactly once',
  'Retain canonical source bundle without repacking',
];
const CONSUMER_STEPS = [
  'Require supported hosted runner', 'Verify source transfer and run real consumers', 'Upload one consumer report',
];
const sourceTuple = value => Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, value[key]]));
const hash = bytes => digest(bytes).sha256;
const PUBLISHED = 'npm-registry-published';
export const PUBLISHED_PEER_LIMITS = Object.freeze({
  metadataBytes: 2 * 1024 * 1024, tarballBytes: 32 * 1024 * 1024, timeoutMs: 30_000,
});

function id(value) {
  assert.ok(typeof value === 'string' ||
    (typeof value === 'number' &&
      Number.isSafeInteger(value)), 'Invalid GitHub ID');
  assert.match(String(value), /^[1-9][0-9]*$/, 'Invalid GitHub ID');
  return String(value);
}

function gitSource(value) {
  assert.ok(['1.3.1', '2.0.1'].includes(value.version), 'Only opposite PATCH candidates are supported');
  publicationTagName(value.ref, value.version);
  for (const key of ['tagObject', 'commit', 'tree']) {
    assert.match(value[key] ?? '', /^[a-f0-9]{40}$/, `Invalid ${key}`);
  }
}

export function validatePeerApproval(approval, env) {
  validateLocalApproval(approval, { continuing: true });
  assert.ok(approval?.peerArtifact,
    'Missing approved peerArtifact. First prepare source+matrix bundle remains available; ' +
    'approve the opposite source artifact in a fresh prepare. Never create final/stage eligibility without T32.');
  assert.equal(approval.schemaVersion, 1);
  assert.equal(approval.scope, 'prepare', 'Peer download is only for a real prepare approval');
  assert.equal(approval.approver, POLICY.owner);
  assert.equal(approval.name, POLICY.name);
  gitSource(approval);
  // The source job already checked approval freshness. Do not spend it again after long-running gates.
  if (Object.hasOwn(approval, 'ciRunId')) id(approval.ciRunId);
  if (Object.hasOwn(approval, 'ciAttempt')) sourceCiAttempt(approval.ciAttempt);
  for (const [key, expected] of Object.entries({
    GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
    GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner,
    GITHUB_RUN_ATTEMPT: '1', GITHUB_REF: approval.ref, GITHUB_SHA: approval.commit,
    GITHUB_WORKFLOW_SHA: approval.commit, GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`,
  })) assert.equal(env[key], expected, `Wrong current prepare ${key}`);
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID']) id(env[key]);
  const peer = approval.peerArtifact;
  if (peer.kind === PUBLISHED) return validatePublishedApproval(peer, approval);
  assert.equal(peer.kind, undefined, 'Unknown peer kind');
  gitSource(peer);
  assert.equal(peer.version, approval.version === '1.3.1' ? '2.0.1' : '1.3.1', 'Peer must be the opposite PATCH');
  for (const key of ['artifactId', 'runId']) id(peer[key]);
  assert.notEqual(id(peer.runId), id(env.GITHUB_RUN_ID), 'Peer must come from a different completed run');
  assert.equal(peer.runAttempt, 1, 'Peer reruns are not accepted');
  for (const key of ['manifestSha256', 'sha256']) assert.match(peer[key] ?? '', /^[a-f0-9]{64}$/, `Invalid ${key}`);
  assert.match(peer.sha512 ?? '', /^[a-f0-9]{128}$/, 'Invalid SHA512');
  assert.equal(peer.integrity, `sha512-${Buffer.from(peer.sha512, 'hex').toString('base64')}`);
  assert.match(peer.artifactDigest ?? '', /^sha256:[a-f0-9]{64}$/, 'Invalid approved artifact digest');
  return { ...peer };
}

function validatePublishedApproval(peer, approval) {
  exactLocalKeys(peer, ['kind', 'version', 'commit', 'tree', 'sha256', 'sha512', 'integrity']);
  assert.equal(approval.version, '1.3.1', 'Published peer currently supports the legacy release only');
  assert.equal(peer.version, '2.0.1', 'Published peer must be the approved opposite patch');
  validateLocalRegression(approval.localRegression, peer, Date.parse(approval.approvedAt));
  assert.match(peer.sha256 ?? '', /^[a-f0-9]{64}$/);
  assert.match(peer.sha512 ?? '', /^[a-f0-9]{128}$/);
  assert.equal(peer.integrity, `sha512-${Buffer.from(peer.sha512, 'hex').toString('base64')}`);
  return { ...peer };
}

function ownerBinding(owner, env) {
  assert.equal(owner?.login, POLICY.owner);
  assert.equal(id(owner.id), id(env.GITHUB_REPOSITORY_OWNER_ID));
}

function repositoryBinding(repository, env) {
  assert.equal(repository?.full_name, POLICY.repository);
  assert.equal(id(repository.id), id(env.GITHUB_REPOSITORY_ID));
  assert.equal(repository.private, false);
  assert.equal(repository.fork, false);
  ownerBinding(repository.owner, env);
}

function successfulJob(jobs, name, image, steps) {
  const matches = jobs.filter(job => job.name === name);
  assert.equal(matches.length, 1, `Missing/duplicate peer job: ${name}`);
  const job = matches[0];
  assert.equal(job.conclusion, 'success', `Peer job did not succeed: ${name}`);
  id(job.runner_id);
  assert.ok(typeof job.runner_name === 'string' &&
    job.runner_name.length > 0);
  assert.ok(job.labels?.includes(image), `Wrong peer runner image: ${name}`);
  for (const stepName of steps) {
    const found = job.steps?.filter(step => step.name === stepName);
    assert.equal(found?.length, 1, `Missing/duplicate peer step: ${stepName}`);
    assert.equal(found[0].status, 'completed');
    assert.equal(found[0].conclusion, 'success', `Peer step did not succeed: ${stepName}`);
  }
  return { id: id(job.id), name: job.name };
}

export function validatePeerRun({ approval, env, run, jobs }) {
  const peer = validatePeerApproval(approval, env);
  assert.equal(peer.kind, undefined, 'Published peer has no hosted run evidence');
  assert.equal(id(run.id), id(peer.runId));
  assert.equal(run.head_sha, peer.commit);
  assert.equal(run.path, POLICY.workflow);
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.run_attempt, 1);
  assert.equal(run.status, 'completed', 'Peer run must be completed, never active');
  assert.ok(['success', 'failure'].includes(run.conclusion), 'Peer run was cancelled or has no final outcome');
  repositoryBinding(run.repository, env);
  repositoryBinding(run.head_repository, env);
  ownerBinding(run.actor, env);
  ownerBinding(run.triggering_actor, env);
  assert.ok(Array.isArray(jobs), 'Actual peer jobs required');
  assertCollectionJobSkipped(jobs);
  const names = new Set(['source', 'prepare', 'stage', 'sign-bootstrap', 'publish-bootstrap',
    SECRET_COLLECTION_JOB, ...MATRIX.map(lane => lane.jobName)]);
  const seenIds = new Set();
  const seenNames = new Set();
  for (const job of jobs) {
    const jobId = id(job.id);
    assert.ok(!seenIds.has(jobId) &&
      !seenNames.has(job.name), 'Duplicate peer job');
    seenIds.add(jobId);
    seenNames.add(job.name);
    assert.ok(names.has(job.name), 'Unexpected peer workflow job');
    assert.equal(id(job.run_id), id(peer.runId));
    assert.equal(job.run_attempt, 1);
    assert.equal(job.head_sha, peer.commit);
    assert.equal(job.status, 'completed', 'Peer job is still active');
    if (['stage', 'sign-bootstrap', 'publish-bootstrap'].includes(job.name)) {
      assert.equal(job.conclusion, 'skipped', 'A stage/signing run cannot supply a peer');
    }
  }
  const sourceJob = successfulJob(jobs, 'source', 'ubuntu-24.04', SOURCE_STEPS);
  const consumerJobs = MATRIX.map(lane => successfulJob(jobs, lane.jobName, lane.image, CONSUMER_STEPS));
  // The finalizer is deliberately not a prerequisite: the first run has no peer for T32.
  return { sourceJob, consumerJobs, sourcePassed: true, matrixPassed: true, finalizerNotRequired: true };
}

function gitBinding(peer, tagRef, tag, commit) {
  assert.equal(tagRef?.ref, peer.ref);
  assert.equal(tagRef.object?.type, 'tag', 'Peer release ref must be an annotated tag');
  assert.equal(tagRef.object.sha, peer.tagObject, 'Peer release tag moved');
  assert.equal(tag?.sha, peer.tagObject);
  assert.equal(tag.tag, publicationTagName(peer.ref, peer.version));
  assert.equal(tag.object?.type, 'commit', 'Peer tag must peel directly to a commit');
  assert.equal(tag.object.sha, peer.commit);
  assert.equal(commit?.sha, peer.commit);
  assert.equal(commit.tree?.sha, peer.tree, 'Peer commit tree mismatch');
}

function metadataBinding(peer, env, metadata) {
  assert.equal(id(metadata.id), id(peer.artifactId));
  assert.equal(metadata.name, `npm-prepared-${peer.runId}-1`, 'Peer must be the original source artifact');
  assert.equal(metadata.expired, false);
  assert.equal(metadata.digest, peer.artifactDigest, 'Peer metadata digest differs from approval');
  assert.equal(id(metadata.workflow_run?.id), id(peer.runId));
  assert.equal(metadata.workflow_run.head_sha, peer.commit);
  for (const key of ['repository_id', 'head_repository_id']) {
    assert.equal(id(metadata.workflow_run[key]), id(env.GITHUB_REPOSITORY_ID));
  }
}

function optionalBindings(prepared, report, peer) {
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.phase, 'source');
  assert.equal(report.source?.commit, peer.commit, 'Peer source report commit mismatch');
  assert.equal(report.source.version, peer.version, 'Peer source report version mismatch');
  for (const [key, value] of Object.entries({ ...sourceTuple(peer), name: POLICY.name, version: peer.version })) {
    if (Object.hasOwn(report.source, key)) assert.equal(report.source[key], value);
    if (Object.hasOwn(report, key)) assert.equal(report[key], value);
  }
  for (const [key, lock] of [['root', 'rootLockSha256'], ['ui', 'uiLockSha256']]) {
    if (Object.hasOwn(report.source, lock)) assert.match(report.source[lock], /^[a-f0-9]{64}$/);
    if (Object.hasOwn(prepared, 'producerLocks')) {
      assert.match(prepared.producerLocks?.[key] ?? '', /^[a-f0-9]{64}$/);
      assert.equal(report.source[lock], prepared.producerLocks[key], 'Peer producer lock mismatch');
    }
  }
  if (Object.hasOwn(report, 'toolchain')) assert.deepEqual(report.toolchain, prepared.toolchain);
  if (Object.hasOwn(prepared, 'workflow')) {
    const workflow = prepared.workflow;
    assert.equal(id(workflow?.runId), id(peer.runId));
    assert.equal(workflow.attempt, 1);
    assert.equal(workflow.ref, `${POLICY.repository}/${POLICY.workflow}@${peer.ref}`);
    assert.equal(workflow.commit, peer.commit);
    if (Object.hasOwn(workflow, 'repository')) assert.equal(workflow.repository, POLICY.repository);
    if (Object.hasOwn(workflow, 'path')) assert.equal(workflow.path, POLICY.workflow);
  }
  if (Object.hasOwn(prepared, 'ci')) {
    id(prepared.ci?.runId);
    id(prepared.ci.attempt);
    assert.equal(prepared.ci.headSha, peer.commit);
    assert.equal(prepared.ci.conclusion, 'success');
  }
  if (Object.hasOwn(prepared, 'preparationApproval')) {
    assert.equal(prepared.preparationApproval?.scope, 'prepare');
    assert.equal(prepared.preparationApproval.approver, POLICY.owner);
    assert.ok(Number.isFinite(Date.parse(prepared.preparationApproval.approvedAt)));
  }
  if (Object.hasOwn(prepared, 'privateContentReview')) {
    assert.equal(prepared.privateContentReview?.status, 'pending-owner-review');
    assert.equal(prepared.privateContentReview.commit, peer.commit);
    sameDigests(prepared.privateContentReview.artifact, peer);
  }
  if (Object.hasOwn(prepared, 'publicationApproval')) {
    assert.equal(prepared.publicationApproval?.status, 'not-authorized');
  }
  if (Object.hasOwn(prepared, 'stage')) {
    assert.equal(prepared.stage?.status, 'not-submitted');
    assert.equal(prepared.stage.stageId, null);
  }
  if (Object.hasOwn(prepared, 'registrySignatures')) {
    assert.equal(prepared.registrySignatures?.status, 'pending-publication');
  }
  if (Object.hasOwn(prepared, 'provenance')) {
    assert.equal(prepared.provenance?.status, 'pending-stage');
    assert.equal(prepared.provenance.verification, 'pending-owner-cryptographic-verification');
  }
}

export function validatePeerBundle({ approval, env, metadata, archive, tagRef, tag, commit }) {
  const peer = validatePeerApproval(approval, env);
  assert.equal(peer.kind, undefined, 'Published peer has no prepared bundle');
  gitBinding(peer, tagRef, tag, commit);
  metadataBinding(peer, env, metadata);
  assert.ok(Buffer.isBuffer(archive), 'Actual API ZIP bytes required');
  assert.equal(`sha256:${hash(archive)}`, peer.artifactDigest, 'Peer API ZIP digest mismatch');
  const files = zipFiles(archive);
  assert.deepEqual([...files.keys()].sort(), ['candidate.tgz', 'prepared.json', 'source-gates.json'],
    'Unexpected peer ZIP file set');
  // zipFiles omits directory entries. Reject those too, rather than accepting unreviewed members.
  let end = archive.length - 22;
  while (archive.readUInt32LE(end) !== 0x06054b50) end--;
  assert.equal(archive.readUInt16LE(end + 10), 3, 'Unexpected peer ZIP directory/member');
  assert.equal(hash(files.get('prepared.json')), peer.manifestSha256, 'Peer manifest hash mismatch');
  const prepared = JSON.parse(files.get('prepared.json').toString('utf8'));
  validatePreparedLocal(prepared, approval, peer);
  assert.equal(prepared.schemaVersion, 1);
  assert.equal(prepared.status, 'prepared-awaiting-platform-gates');
  assert.equal(prepared.name, POLICY.name);
  assert.equal(prepared.version, peer.version);
  assert.deepEqual(prepared.source, sourceTuple(peer));
  assert.deepEqual(prepared.toolchain, { node: POLICY.node, npm: POLICY.npm });
  assert.equal(prepared.artifact?.filename, 'candidate.tgz');
  const bytes = files.get('candidate.tgz');
  const hashes = digest(bytes);
  sameDigests(hashes, peer);
  sameDigests(hashes, prepared.artifact);
  assert.equal(hash(files.get('source-gates.json')), prepared.sourceReportSha256, 'Peer source report hash mismatch');
  const report = JSON.parse(files.get('source-gates.json').toString('utf8'));
  optionalBindings(prepared, report, peer);
  const inspection = inspectTarball(bytes, peer);
  assert.deepEqual(inspection.files, prepared.artifact.files, 'Peer tarball file manifest mismatch');
  return { bytes, inspection, prepared, evidence: {
    schemaVersion: 1, purpose: 'service-comparison-only', name: POLICY.name, version: peer.version,
    source: sourceTuple(peer), repository: POLICY.repository, repositoryId: id(env.GITHUB_REPOSITORY_ID),
    artifactId: id(peer.artifactId), artifactDigest: peer.artifactDigest,
    runId: id(peer.runId), runAttempt: 1, manifestSha256: peer.manifestSha256,
    sourceReportSha256: prepared.sourceReportSha256, ...hashes,
    stageEligible: false, privateScans: 'pending', humanApproval: 'pending',
  } };
}

function outside(path, checkout) {
  const part = relative(checkout, path);
  return part === '..' ||
    part.startsWith(`..${sep}`) ||
    isAbsolute(part);
}

function destination(directory, env) {
  assert.ok(typeof directory === 'string' &&
    isAbsolute(directory), 'Peer directory must be absolute and outside the checkout');
  const target = resolve(directory);
  assert.ok(!lstatSync(target, { throwIfNoEntry: false }), 'Peer directory must not already exist');
  let parent = dirname(target);
  while (true) {
    const stat = lstatSync(parent);
    assert.ok(stat.isDirectory() &&
      !stat.isSymbolicLink(), 'Peer directory ancestors must be real directories, not links');
    if (dirname(parent) === parent) break;
    parent = dirname(parent);
  }
  const physical = join(realpathSync(dirname(target)), basename(target));
  for (const checkout of [ROOT, ...(env.GITHUB_WORKSPACE ? [env.GITHUB_WORKSPACE] : [])]) {
    assert.ok(isAbsolute(checkout), 'Checkout path must be absolute');
    assert.ok(outside(target, resolve(checkout)) &&
      outside(physical, realpathSync(checkout)), 'Peer directory must be outside the checkout');
  }
  return target;
}

function gitReaders(env) {
  const get = async path => {
    assert.ok(env.GITHUB_TOKEN, 'Read-only GitHub token required');
    const response = await fetch(`https://api.github.com/repos/${POLICY.repository}/${path}`, {
      headers: { authorization: `Bearer ${env.GITHUB_TOKEN}`, accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28' },
      redirect: 'error', signal: AbortSignal.timeout(30_000),
    });
    assert.equal(response.status, 200, 'Peer GitHub read failed; no fallback');
    return response.json();
  };
  return {
    readRun: runId => get(`actions/runs/${id(runId)}`),
    // Resolve the complete approved ref before reading its independently approved tag object.
    readTag: refOrObject => get(refOrObject.startsWith('refs/tags/')
      ? `git/ref/tags/${refOrObject.slice('refs/tags/'.length)}` : `git/tags/${refOrObject}`),
    readCommit: commit => get(`git/commits/${commit}`),
  };
}

export async function downloadPeer({
  approval, env, directory, readRun, readJobs, readArtifactMetadata, readArtifactArchive, readTag, readCommit,
  fetcher, timeoutMs,
}) {
  // Snapshot current inputs without changing SHA/ref or impersonating the peer's source job.
  approval = structuredClone(approval);
  env = { ...env };
  const peer = validatePeerApproval(approval, env);
  const target = destination(directory, env);
  if (peer.kind === PUBLISHED) {
    return downloadPublishedPeer({ approval, env, target, fetcher, timeoutMs });
  }
  const readers = { ...githubReaders(env), ...gitReaders(env),
    ...Object.fromEntries(Object.entries({
      readRun, readJobs, readArtifactMetadata, readArtifactArchive, readTag, readCommit,
    }).filter(([, value]) => value !== undefined)) };
  const run = await readers.readRun(id(peer.runId));
  const jobs = await readers.readJobs(id(peer.runId), 1);
  const runEvidence = validatePeerRun({ approval, env, run, jobs });
  const tagRef = await readers.readTag(peer.ref);
  const tag = await readers.readTag(peer.tagObject);
  const commit = await readers.readCommit(peer.commit);
  gitBinding(peer, tagRef, tag, commit);
  const metadata = await readers.readArtifactMetadata(id(peer.artifactId));
  metadataBinding(peer, env, metadata);
  const archive = await readers.readArtifactArchive(id(peer.artifactId));
  const { bytes, inspection, prepared, evidence } = validatePeerBundle({
    approval, env, metadata, archive, tagRef, tag, commit,
  });
  destination(target, env);
  mkdirSync(target, { mode: 0o700 });
  const tarball = join(target, 'peer.tgz');
  writeFileSync(tarball, bytes, { flag: 'wx', mode: 0o600 });
  return { tarball, inspection, prepared,
    comparison: { version: prepared.version, artifact: digest(bytes) },
    evidence: { ...evidence, ...runEvidence } };
}

function publishedRegistryBinding(packument, approval) {
  const peer = approval.peerArtifact;
  assert.equal(packument?.name, POLICY.name, 'Published peer package missing');
  assert.ok(packument.maintainers?.some(item => item.name === POLICY.owner), 'Published peer owner mismatch');
  assert.deepEqual(packument['dist-tags'], { latest: '2.0.1' }, 'Published peer channel state changed');
  assert.ok(packument.versions &&
    typeof packument.versions === 'object' &&
    !Array.isArray(packument.versions), 'Published peer versions missing');
  assert.equal(Object.hasOwn(packument.versions, approval.version), false, 'Candidate version already published');
  const version = packument.versions[peer.version];
  assert.equal(version?.name, POLICY.name);
  assert.equal(version.version, peer.version);
  assert.equal(version.gitHead, peer.commit, 'Published peer registry source mismatch');
  assert.ok(!Object.hasOwn(packument, 'deprecated') &&
    !Object.hasOwn(version, 'deprecated'), 'Deprecated published peer');
  assert.equal(version.dist?.integrity, peer.integrity, 'Published peer registry integrity mismatch');
  assert.match(version.dist.shasum ?? '', /^[a-f0-9]{40}$/);
  assert.equal(version.dist.tarball, `${POLICY.registry}${POLICY.name}/-/${POLICY.name}-${peer.version}.tgz`,
    'Published peer requires canonical registry tarball URL');
  return version;
}

export function validatePublishedPeer({ approval, env, packument, commit, bytes }) {
  const peer = validatePeerApproval(approval, env);
  assert.equal(peer.kind, PUBLISHED);
  const version = publishedRegistryBinding(packument, approval);
  assert.equal(commit?.sha, peer.commit, 'Published peer GitHub commit mismatch');
  assert.equal(commit.tree?.sha, peer.tree, 'Published peer GitHub tree mismatch');
  assert.ok(Buffer.isBuffer(bytes) &&
    bytes.length > 0 &&
    bytes.length <= PUBLISHED_PEER_LIMITS.tarballBytes, 'Actual bounded published tarball bytes required');
  const artifact = digest(bytes);
  sameDigests(artifact, peer);
  assert.equal(createHash('sha1').update(bytes).digest('hex'), version.dist.shasum,
    'Published peer registry shasum mismatch');
  const inspection = inspectTarball(bytes, peer);
  return { bytes, inspection, comparison: { version: peer.version, artifact }, evidence: {
    schemaVersion: 1, origin: PUBLISHED, purpose: 'service-comparison-only', stageEligible: false,
    name: POLICY.name, version: peer.version, source: { commit: peer.commit, tree: peer.tree },
    ...artifact, registry: POLICY.registry, distTags: { ...packument['dist-tags'] },
    provenance: { status: version.dist.attestations?.provenance ? 'present' : 'absent', verification: 'not-performed' },
    registrySignatures: 'not-verified-by-this-read',
  } };
}

async function anonymousBytes(url, limit, fetcher, timeoutMs) {
  const controller = new AbortController();
  let timer;
  let response;
  const operation = async () => {
    response = await fetcher(url, {
      method: 'GET', headers: { accept: 'application/json, application/octet-stream' },
      credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
    });
    controller.signal.throwIfAborted();
    assert.equal(response.status, 200, 'Published peer read failed; no fallback');
    assert.notEqual(response.redirected, true, 'Published peer redirect forbidden');
    if (response.url) assert.equal(response.url, url, 'Published peer response URL changed');
    const length = response.headers.get('content-length');
    if (length !== null) {
      assert.match(length, /^(?:0|[1-9][0-9]{0,8})$/);
      assert.ok(Number(length) <= limit, 'Published peer response exceeds limit');
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      controller.signal.throwIfAborted();
      size += chunk.length;
      assert.ok(size <= limit, 'Published peer response exceeds limit');
      chunks.push(Buffer.from(chunk));
    }
    controller.signal.throwIfAborted();
    return Buffer.concat(chunks);
  };
  try {
    return await Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error('Published peer read deadline exceeded'));
      }, timeoutMs);
    })]);
  } catch (error) {
    controller.abort();
    if (!response?.body?.locked) response?.body?.cancel?.().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function downloadPublishedPeer({
  approval, env, target, fetcher = (...args) => globalThis.fetch(...args),
  timeoutMs = PUBLISHED_PEER_LIMITS.timeoutMs,
}) {
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= PUBLISHED_PEER_LIMITS.timeoutMs, 'Invalid published peer deadline');
  const readJson = async url => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(
    await anonymousBytes(url, PUBLISHED_PEER_LIMITS.metadataBytes, fetcher, timeoutMs)));
  const packument = await readJson(`${POLICY.registry}${POLICY.name}`);
  const version = publishedRegistryBinding(packument, approval);
  const peer = approval.peerArtifact;
  const commit = await readJson(`https://api.github.com/repos/${POLICY.repository}/git/commits/${peer.commit}`);
  assert.equal(commit?.sha, peer.commit);
  assert.equal(commit.tree?.sha, peer.tree);
  const bytes = await anonymousBytes(version.dist.tarball, PUBLISHED_PEER_LIMITS.tarballBytes, fetcher, timeoutMs);
  const result = validatePublishedPeer({ approval, env, packument, commit, bytes });
  destination(target, env);
  mkdirSync(target, { mode: 0o700 });
  const tarball = join(target, 'peer.tgz');
  writeFileSync(tarball, bytes, { flag: 'wx', mode: 0o600 });
  return { tarball, inspection: result.inspection, comparison: result.comparison, evidence: result.evidence };
}
