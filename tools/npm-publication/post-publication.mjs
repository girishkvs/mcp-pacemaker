import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, exactKeys, fresh, sameDigests } from './policy.mjs';
import { validateOwnerContext } from './owner-bootstrap.mjs';
import { ownerState, atomicJson, readJsonFile } from './owner-state.mjs';
import { readBootstrapDirectory } from './verify-bootstrap.mjs';
import { CANDIDATE_FILES, verifyBootstrapProof } from './bootstrap.mjs';
import { githubReaders } from './matrix.mjs';
import { sourceAndCi, sourceLocks } from './run.mjs';
import { readSignedArtifact, readCandidateEvidence, readRemoteSource, readProtectedEnvironment,
  readOwnerRun } from './bootstrap-readers.mjs';
import { npmProvenance } from './provenance.mjs';
import { anonymousBytes, JSON_LIMIT, TARBALL_LIMIT, publishedMetadata, verifyPublishedEvidence } from './published-proof.mjs';
import { requireAnonymousHosted, withPublishedConsumer, smokePublishedConsumer } from './published-consumer.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../compatibility/fixtures.mjs';

export function completedOwner(state, processExists = pid => fs.existsSync(`/proc/${pid}`)) {
  state.check();
  const done = readJsonFile(join(state.directory, 'ledger', 'done.json'));
  const supervisor = readJsonFile(join(state.directory, 'ledger', 'supervisor.json'));
  for (const value of [done, supervisor]) assert.deepEqual(value.binding, state.binding);
  assert.equal(done.success, true);
  assert.equal(done.outcome, 'published-readback-matched');
  assert.equal(done.cleanup, 'revoked', 'Anonymous acceptance requires confirmed owner-session revocation');
  assert.ok([1, 2].includes(done.attempts));
  assert.equal(supervisor.status, 'completed');
  assert.equal(supervisor.childExitCode, 0);
  for (const name of ['process.json', 'owner-process.json']) {
    const marker = readJsonFile(join(state.directory, name));
    exactKeys(marker, ['pid', 'binding'], 'completed owner process marker');
    assert.deepEqual(marker.binding, state.binding);
    assert.ok(Number.isInteger(marker.pid) &&
      marker.pid > 1);
    assert.equal(processExists(marker.pid), false, 'Owner processes must exit before anonymous acceptance');
  }
  return { outcome: done.outcome, cleanup: done.cleanup, attempts: done.attempts };
}

async function prepare(state, approval) {
  const publication = completedOwner(state);
  state.write('ledger', 'post-publication-starting.json', {
    schemaVersion: 1, binding: state.binding, status: 'pending', publication,
  });
  const readers = githubReaders(process.env);
  const local = readBootstrapDirectory(join(state.directory, 'signed'));
  const signed = await readSignedArtifact(approval, readers);
  assert.deepEqual(local, signed.files);
  await sourceAndCi(approval);
  const locks = sourceLocks();
  const source = await readRemoteSource(approval, readers);
  assert.equal(source.repositoryId, signed.workflow.repositoryId);
  assert.equal(source.ownerId, signed.workflow.ownerId);
  const signingEnvironment = await readProtectedEnvironment(approval, signed.workflow.runId, readers);
  const publicationRun = await readOwnerRun(approval, process.env.GITHUB_RUN_ID, readers);
  assert.equal(publicationRun.repositoryId, process.env.GITHUB_REPOSITORY_ID);
  assert.equal(publicationRun.ownerId, process.env.GITHUB_REPOSITORY_OWNER_ID);
  const publicationEnvironment = await readProtectedEnvironment(approval, process.env.GITHUB_RUN_ID, readers);
  assert.equal(publicationEnvironment.id, 21922517673);
  const candidate = await readCandidateEvidence(approval, locks, readers);
  for (const name of CANDIDATE_FILES) assert.deepEqual(candidate.files.get(name), local.get(name));
  const cache = ownedDirectory();
  let proof;
  try {
    proof = await verifyBootstrapProof({ approval, files: local, locks, workflow: signed.workflow,
      verifyBundle: npmProvenance(process.env.NPM_PUBLICATION_CLI).verifyBundle, cache: join(cache.dir, 'tuf') });
  } finally {
    removeOwnedDirectory(cache);
  }
  assert.deepEqual(sourceLocks(), locks);
  assert.deepEqual(readBootstrapDirectory(join(state.directory, 'signed')), local);
  state.check();
  const input = {
    schemaVersion: 1, binding: state.binding, checkedAt: new Date().toISOString(), publication,
    record: { name: POLICY.name, version: '2.0.1', source: proof.source, workflow: proof.workflow, artifact: proof.artifact },
    checks: { source, signingEnvironment, publicationRun, publicationEnvironment, preparation: candidate.evidence },
  };
  atomicJson(state.directory, 'post-publication-input.json', input);
  state.write('ledger', 'post-publication-source.json', {
    schemaVersion: 1, binding: state.binding, checkedAt: input.checkedAt,
    inputSha256: digest(Buffer.from(JSON.stringify(input))).sha256, checks: input.checks,
  });
}

export async function readPublished(record, fetcher = fetch) {
  assert.equal(record.name, POLICY.name);
  assert.equal(record.version, '2.0.1', 'This operational acceptance path is only for the first bootstrap');
  const packumentBytes = await anonymousBytes(`${POLICY.registry}${record.name}`, JSON_LIMIT, fetcher);
  const packument = JSON.parse(packumentBytes);
  const version = packument.versions?.[record.version];
  const urls = publishedMetadata(packument, version, record, { latest: '2.0.1' });
  assert.deepEqual(Object.keys(packument.versions).sort(), ['2.0.1'], 'Bootstrap registry state changed');
  return { packument, version, urls };
}

export async function acceptPublished({
  record, expectedBundle, cli, env, verifyBundle, fetcher = fetch, consumer = withPublishedConsumer,
  onPhase = () => {},
}) {
  if (fetcher === fetch) requireAnonymousHosted(env ?? process.env);
  onPhase('registry-readback');
  const before = await readPublished(record, fetcher);
  const tarball = await anonymousBytes(before.urls.tarball, TARBALL_LIMIT, fetcher);
  sameDigests(digest(tarball), record.artifact);
  const attestations = JSON.parse(await anonymousBytes(before.urls.attestations, JSON_LIMIT, fetcher));
  const keys = JSON.parse(await anonymousBytes(`${POLICY.registry}-/npm/v1/keys`, JSON_LIMIT, fetcher));
  onPhase('fresh-registry-install');
  const result = await consumer({
    record, tarball, cli, env,
    verifyAudit: async (audit, cache) => {
      onPhase('signatures-and-provenance');
      return verifyPublishedEvidence({ record, ...before, tarball, attestations, audit, keys,
        expectedTags: { latest: '2.0.1' }, expectedBundle, verifyBundle, cache });
    },
    smoke: async options => {
      onPhase('installed-bin-bridge-ui');
      return smokePublishedConsumer(options);
    },
  });
  onPhase('final-registry-readback');
  const after = await readPublished(record, fetcher);
  assert.deepEqual(after.version, before.version, 'Published version metadata changed during acceptance');
  assert.deepEqual(after.packument['dist-tags'], before.packument['dist-tags']);
  return result;
}

export function validateAcceptanceInput({ input, source, approval, binding, publication, runId }) {
  exactKeys(input, ['schemaVersion', 'binding', 'checkedAt', 'publication', 'record', 'checks'],
    'post-publication input');
  assert.equal(input.schemaVersion, 1);
  assert.deepEqual(input.binding, binding);
  assert.deepEqual(input.publication, publication);
  fresh(input.checkedAt);
  assert.deepEqual(source.binding, binding);
  assert.equal(source.inputSha256, digest(Buffer.from(JSON.stringify(input))).sha256);
  assert.deepEqual(input.record.artifact, {
    sha256: approval.artifact.sha256, sha512: approval.artifact.sha512, integrity: approval.artifact.integrity,
  });
  assert.equal(input.record.workflow.runId, String(approval.signedArtifact.runId));
  assert.notEqual(input.record.workflow.runId, String(runId));
}

async function verify(state, approval, onPhase) {
  requireAnonymousHosted(process.env);
  const publication = completedOwner(state);
  const input = readJsonFile(join(state.directory, 'post-publication-input.json'));
  const source = readJsonFile(join(state.directory, 'ledger', 'post-publication-source.json'));
  validateAcceptanceInput({ input, source, approval, binding: state.binding, publication, runId: process.env.GITHUB_RUN_ID });
  const files = readBootstrapDirectory(join(state.directory, 'signed'));
  assert.equal(digest(files.get('provenance.sigstore')).sha256, approval.signedArtifact.bundleSha256);
  const result = await acceptPublished({
    record: input.record, expectedBundle: JSON.parse(files.get('provenance.sigstore')),
    cli: process.env.NPM_PUBLICATION_CLI, env: process.env,
    verifyBundle: npmProvenance(process.env.NPM_PUBLICATION_CLI).verifyBundle, onPhase,
  });
  state.check();
  assert.deepEqual(readBootstrapDirectory(join(state.directory, 'signed')), files);
  const receipt = {
    schemaVersion: 1, status: 'accepted', binding: state.binding, checkedAt: new Date().toISOString(),
    publication, checks: input.checks, ...result, registryMutation: 'not-performed',
  };
  assert.ok(Buffer.byteLength(JSON.stringify(receipt)) <= 64 * 1024, 'Acceptance receipt is too large');
  state.write('ledger', 'post-publication.json', receipt);
}

export async function main(args) {
  let state;
  let phase = 'source-evidence';
  try {
    assert.equal(args.length, 1);
    assert.ok(['prepare', 'verify'].includes(args[0]));
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    const approval = JSON.parse(event.inputs.approval);
    validateOwnerContext({ env: process.env, event, approval });
    state = ownerState(process.env, approval);
    assert.equal(fs.existsSync(join(state.directory, 'ledger', 'post-publication.json')), false,
      'Acceptance already has a terminal receipt; no implicit rerun');
    if (args[0] === 'prepare') await prepare(state, approval);
    else await verify(state, approval, value => { phase = value; });
  } catch {
    if (state &&
        !fs.existsSync(join(state.directory, 'ledger', 'post-publication.json'))) {
      state.write('ledger', 'post-publication.json', {
        schemaVersion: 1, status: 'not-accepted', binding: state.binding, checkedAt: new Date().toISOString(),
        failureStage: phase, registryMutation: 'not-performed',
        instruction: 'Publication is not rolled back. Reconcile evidence; do not republish or unpublish.',
      });
    }
    throw new Error('Post-publication acceptance failed. No registry mutation or rollback was attempted.');
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => {
    console.error('Post-publication acceptance failed. Inspect the bounded receipt; the release is not rolled back.');
    process.exitCode = 1;
  });
}
