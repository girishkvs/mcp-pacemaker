import assert from 'node:assert/strict';
import { syntheticLocalApproval, syntheticPreparedLocal } from './helpers/local-regression-fixture.mjs';
import { beforeEach, test } from 'node:test';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { syntheticRegistrySourceProof } from './helpers/npm-publication-candidate-fixture.mjs';
import { PeerTufTransport, PEER_PROOF_LIMITS, peerTufUrl, verifyRegistrySource } from '../tools/npm-publication/provenance.mjs';
import { POLICY, digest } from '../tools/npm-publication/policy.mjs';
import { MATRIX } from '../tools/npm-publication/matrix.mjs';
import { inspectTarball } from '../tools/npm-publication/tarball.mjs';
import { downloadPeer, validatePeerApproval, validatePeerRun, validatePeerBundle,
  validatePublishedPeer, PUBLISHED_PEER_LIMITS } from '../tools/npm-publication/peer.mjs';

// Fixtures only: even an accidentally uninjected reader cannot reach GitHub.
beforeEach(t => t.mock.method(globalThis, 'fetch', async () => {
  throw new Error('Unexpected network request');
}));
const hash = bytes => digest(bytes).sha256;
const gitHash = character => character.repeat(40);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

class Fixture {
  constructor(t, version = '2.0.1', temporaryParent = tmpdir(), namespaces = {}) {
    this.home = mkdtempSync(join(realpathSync.native(temporaryParent), 'pacemaker-peer-unit-'));
    t.after(() => rmSync(this.home, { recursive: true, force: true }));
    assert.equal(realpathSync.native(this.home), this.home, 'Owned peer fixture must use the native canonical path');
    this.directory = join(this.home, 'peer');
    this.approval = {
      schemaVersion: 1, scope: 'prepare', approver: POLICY.owner, name: POLICY.name, version,
      ref: `refs/tags/${namespaces.current ?? ''}v${version}`,
      tagObject: gitHash('a'), commit: gitHash('b'), tree: gitHash('c'),
      ciRunId: '90', ciAttempt: 1,
    };
    this.env = Object.freeze({
      GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
      GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_REPOSITORY_ID: '100', GITHUB_REPOSITORY_OWNER_ID: '10',
      GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner, GITHUB_RUN_ATTEMPT: '1',
      GITHUB_RUN_ID: '300', GITHUB_REF: this.approval.ref, GITHUB_SHA: this.approval.commit,
      GITHUB_WORKFLOW_SHA: this.approval.commit,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${this.approval.ref}`,
      GITHUB_WORKSPACE: root, GITHUB_TOKEN: 'fixture-token-never-forward',
    });
    this.peer = this.approval.peerArtifact = {
      artifactId: '400', runId: '200', runAttempt: 1,
      version: version.startsWith('2.') ? '1.3.1' : '2.0.1',
      tagObject: gitHash('d'), commit: gitHash('e'), tree: gitHash('f'),
    };
    this.peer.ref = `refs/tags/${namespaces.peer ?? ''}v${this.peer.version}`;
    syntheticLocalApproval(this.approval);
    this.bytes = this.tarball();
    Object.assign(this.peer, digest(this.bytes));
    const owner = { login: POLICY.owner, id: 10 };
    const repository = { id: 100, full_name: POLICY.repository, private: false, fork: false, owner };
    this.run = { id: 200, head_sha: this.peer.commit, path: POLICY.workflow,
      event: 'workflow_dispatch', run_attempt: 1, status: 'completed', conclusion: 'failure',
      repository, head_repository: structuredClone(repository), actor: owner, triggering_actor: owner };
    this.jobs = [
      this.job('source', 501, 'ubuntu-24.04', [
        'Validate source, run required gates, and pack exactly once',
        'Retain canonical source bundle without repacking',
      ]),
      ...MATRIX.map((lane, index) => this.job(lane.jobName, 502 + index, lane.image, [
        'Require supported hosted runner', 'Verify source transfer and run real consumers',
        'Upload one consumer report',
      ])),
      { ...this.job('prepare', 508), conclusion: 'failure' },
      { ...this.job('stage', 509), conclusion: 'skipped' },
    ];
    this.tagRef = { ref: this.peer.ref, object: { type: 'tag', sha: this.peer.tagObject } };
    this.tag = { sha: this.peer.tagObject, tag: `${namespaces.peer ?? ''}v${this.peer.version}`,
      object: { type: 'commit', sha: this.peer.commit } };
    this.commit = { sha: this.peer.commit, tree: { sha: this.peer.tree } };
    this.sourceReport = {
      schemaVersion: 1, phase: 'source',
      source: { name: POLICY.name, version: this.peer.version, commit: this.peer.commit, tree: this.peer.tree,
        rootLockSha256: '1'.repeat(64), uiLockSha256: '2'.repeat(64) },
      toolchain: { node: POLICY.node, npm: POLICY.npm },
    };
    this.prepared = {
      schemaVersion: 1, status: 'prepared-awaiting-platform-gates', name: POLICY.name, version: this.peer.version,
      source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, this.peer[key]])),
      toolchain: { node: POLICY.node, npm: POLICY.npm }, producerLocks: { root: '1'.repeat(64), ui: '2'.repeat(64) },
      workflow: { ref: `${POLICY.repository}/${POLICY.workflow}@${this.peer.ref}`,
        commit: this.peer.commit, runId: '200', attempt: 1 },
      ci: { runId: '80', attempt: 1, headSha: this.peer.commit, conclusion: 'success' },
      preparationApproval: { approver: POLICY.owner, scope: 'prepare', approvedAt: '2026-09-13T00:00:00Z' },
      publicPackages: [],
      artifact: { filename: 'candidate.tgz', ...digest(this.bytes),
        files: inspectTarball(this.bytes, this.peer).files },
      privateContentReview: { status: 'pending-owner-review', commit: this.peer.commit, artifact: digest(this.bytes) },
      publicationApproval: { status: 'not-authorized' },
    };
    syntheticPreparedLocal(this.prepared, this.approval);
    this.rebundle();
    this.calls = [];
    this.readers = Object.fromEntries([
      ['readRun', () => this.run], ['readJobs', () => this.jobs],
      ['readArtifactMetadata', () => this.metadata], ['readArtifactArchive', () => this.archive],
      ['readTag', value => value === this.peer.ref ? this.tagRef : this.tag], ['readCommit', () => this.commit],
    ].map(([name, result]) => [name, async (...args) => {
      this.calls.push([name, ...args]);
      return result(...args);
    }]));
  }

  job(name, id, image, steps = []) {
    return { name, id, run_id: 200, run_attempt: 1, head_sha: this.peer.commit,
      status: 'completed', conclusion: 'success', runner_id: id + 1000, runner_name: `fixture-${id}`,
      labels: image ? [image] : [],
      steps: steps.map(name => ({ name, status: 'completed', conclusion: 'success' })) };
  }

  tarball(change = () => {}) {
    const pkg = { name: POLICY.name, version: this.peer.version,
      repository: { url: `git+https://github.com/${POLICY.repository}.git` },
      dependencies: { 'smol-toml': '^1.8.0' }, files: ['bin/', 'ui/', 'THIRD_PARTY_NOTICES.txt'] };
    change(pkg);
    const files = { 'package.json': JSON.stringify(pkg), LICENSE: 'MIT', 'README.md': 'fixture',
      'bin/cli.mjs': 'never executed', 'bin/mcp-bridge.mjs': 'never executed', 'ui/dist/index.html': 'fixture',
      'THIRD_PARTY_NOTICES.txt': 'fixture', 'ui/dist/THIRD_PARTY_NOTICES.txt': 'fixture',
      'ui/dist/third-party-manifest.json': '{}', 'bin/windows/PoolingSecurityHelper.exe': 'never executed' };
    const chunks = [];
    for (const [name, value] of Object.entries(files)) {
      const data = Buffer.from(value);
      const header = Buffer.alloc(512);
      header.write(`package/${name}`);
      header.write('0000644\0', 100);
      header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
      header.fill(32, 148, 156);
      header.write('0', 156);
      const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
      header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
      chunks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
    }
    return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
  }

  zip(entries) {
    const local = [];
    const central = [];
    let offset = 0;
    for (const [name, value] of Object.entries(entries)) {
      const data = Buffer.from(value);
      const encoded = Buffer.from(name);
      const header = Buffer.alloc(30);
      header.writeUInt32LE(0x04034b50);
      header.writeUInt32LE(data.length, 18);
      header.writeUInt32LE(data.length, 22);
      header.writeUInt16LE(encoded.length, 26);
      const index = Buffer.alloc(46);
      index.writeUInt32LE(0x02014b50);
      index.writeUInt32LE(data.length, 20);
      index.writeUInt32LE(data.length, 24);
      index.writeUInt16LE(encoded.length, 28);
      index.writeUInt32LE(offset, 42);
      local.push(header, encoded, data);
      central.push(index, encoded);
      offset += header.length + encoded.length + data.length;
    }
    const directory = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50);
    end.writeUInt16LE(central.length / 2, 8);
    end.writeUInt16LE(central.length / 2, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...local, directory, end]);
  }

  rebundle(edit = () => {}) {
    const source = Buffer.from(JSON.stringify(this.sourceReport));
    this.prepared.sourceReportSha256 = hash(source);
    const files = { 'candidate.tgz': this.bytes, 'source-gates.json': source,
      'prepared.json': Buffer.from(JSON.stringify(this.prepared)) };
    edit(files);
    this.peer.manifestSha256 = hash(files['prepared.json']);
    this.archive = this.zip(files);
    this.peer.artifactDigest = `sha256:${hash(this.archive)}`;
    this.metadata = { id: 400, name: 'npm-prepared-200-1', expired: false, digest: this.peer.artifactDigest,
      workflow_run: { id: 200, head_sha: this.peer.commit, repository_id: 100, head_repository_id: 100 } };
  }

  options() {
    return { approval: this.approval, env: this.env, directory: this.directory, ...this.readers };
  }

  bundle() {
    return { ...this.options(), metadata: this.metadata, archive: this.archive,
      tagRef: this.tagRef, tag: this.tag, commit: this.commit };
  }
}

for (const version of ['1.3.1', '2.0.1']) {
  test(`downloads only unchanged opposite PATCH bytes from a failed prior finalizer: ${version}`, async t => {
    const f = new Fixture(t, version);
    assert.deepEqual(validatePeerApproval(f.approval, f.env), f.peer);
    assert.equal(validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }).finalizerNotRequired, true);
    assert.deepEqual(validatePeerBundle(f.bundle()).inspection.files, f.prepared.artifact.files);
    assert.equal(existsSync(f.directory), false, 'Pure helpers must not write');
    const result = await downloadPeer(f.options());
    assert.deepEqual(readFileSync(result.tarball), f.bytes);
    assert.deepEqual(readdirSync(f.directory), ['peer.tgz']);
    assert.deepEqual(result.prepared, f.prepared);
    assert.equal(result.evidence.sourcePassed, true);
    assert.equal(result.evidence.matrixPassed, true);
    assert.equal(result.evidence.finalizerNotRequired, true);
    assert.equal(result.evidence.stageEligible, false);
    assert.equal(result.evidence.privateScans, 'pending');
    assert.equal(result.evidence.humanApproval, 'pending');
    assert.equal(result.evidence.sha256, hash(f.bytes));
    assert.deepEqual(result.evidence.source, f.prepared.source);
    assert.equal(result.evidence.consumerJobs.length, 6);
    assert.equal(f.env.GITHUB_SHA, f.approval.commit);
    assert.notEqual(f.env.GITHUB_SHA, f.peer.commit);
    assert.doesNotMatch(JSON.stringify(result.evidence), /fixture-token|https:|finalizerPassed/);
    assert.deepEqual(f.calls, [
      ['readRun', '200'], ['readJobs', '200', 1], ['readTag', f.peer.ref],
      ['readTag', f.peer.tagObject], ['readCommit', f.peer.commit],
      ['readArtifactMetadata', '400'], ['readArtifactArchive', '400'],
    ]);
  });
}

for (const version of ['1.3.1', '2.0.1']) {
  for (const namespaces of ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/'].flatMap(current =>
    ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/'].map(peer => ({ current, peer })))) {
    test(`peer transfer preserves exact refs: ${version} ${JSON.stringify(namespaces)}`, async t => {
      const f = new Fixture(t, version, tmpdir(), namespaces);
      assert.deepEqual(validatePeerApproval(f.approval, f.env), f.peer);
      const result = await downloadPeer(f.options());
      assert.deepEqual(readFileSync(result.tarball), f.bytes);
      assert.equal(result.evidence.source.ref, f.peer.ref);
      assert.equal(result.prepared.workflow.ref, `${POLICY.repository}/${POLICY.workflow}@${f.peer.ref}`);
      assert.ok(f.calls.some(([name, value]) => name === 'readTag' && value === f.peer.ref));
      f.tag.tag = `${namespaces.peer ? '' : 'npm/'}v${f.peer.version}`;
      assert.throws(() => validatePeerBundle(f.bundle()));
    });
  }
}

test('peer approval cannot relabel an existing source artifact into another publication namespace', t => {
  for (const namespace of ['npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/']) {
    const f = new Fixture(t);
    f.peer.ref = `refs/tags/${namespace}v${f.peer.version}`;
    assert.throws(() => validatePeerBundle(f.bundle()));
    f.tagRef.ref = f.peer.ref;
    f.tag.tag = `${namespace}v${f.peer.version}`;
    assert.throws(() => validatePeerBundle(f.bundle()));
  }
});

test('missing peer explains the non-circular next prepare and writes nothing', async t => {
  const f = new Fixture(t);
  delete f.approval.peerArtifact;
  await assert.rejects(downloadPeer(f.options()), /First prepare source\+matrix bundle remains available.*fresh prepare.*T32/s);
  assert.deepEqual(f.calls, []);
  assert.equal(existsSync(f.directory), false);
});

const approvalFailures = [
  ['same version', f => { f.peer.version = f.approval.version; }],
  ['historical version', f => { f.peer.version = '1.3.0'; }],
  ['wrong ref', f => { f.peer.ref = 'refs/heads/main'; }],
  ['same run', f => { f.peer.runId = f.env.GITHUB_RUN_ID; }],
  ['rerun', f => { f.peer.runAttempt = 2; }],
  ...['artifactId', 'runId'].flatMap(key => ['', '../1', '1?x=2', '001', 0, 1.5, Number.MAX_SAFE_INTEGER + 1]
    .map(value => [`invalid ${key} ${value}`, f => { f.peer[key] = value; }])),
  ...['tagObject', 'commit', 'tree', 'sha256', 'sha512', 'manifestSha256', 'artifactDigest', 'integrity']
    .map(key => [`invalid ${key}`, f => { f.peer[key] = '../invalid'; }]),
  ['stage approval', f => { f.approval.scope = 'stage'; }],
  ['current source spoof', f => { f.env = { ...f.env, GITHUB_SHA: f.peer.commit }; }],
  ['current ref spoof', f => { f.env = { ...f.env, GITHUB_REF: f.peer.ref }; }],
  ['invalid repository ID', f => { f.env = { ...f.env, GITHUB_REPOSITORY_ID: '../100' }; }],
];
for (const [name, corrupt] of approvalFailures) {
  test(`rejects before any reader: ${name}`, async t => {
    const f = new Fixture(t);
    corrupt(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.deepEqual(f.calls, []);
    assert.equal(existsSync(f.directory), false);
  });
}

const bindingFailures = [
  ['run id', f => { f.run.id++; }],
  ['active run', f => { f.run.status = 'in_progress'; }],
  ['workflow', f => { f.run.path = '.github/workflows/ci.yml'; }],
  ['event', f => { f.run.event = 'push'; }],
  ['run SHA', f => { f.run.head_sha = f.approval.commit; }],
  ['run attempt', f => { f.run.run_attempt = 2; }],
  ['private repository', f => { f.run.repository.private = true; }],
  ['fork', f => { f.run.head_repository.fork = true; }],
  ['repository name', f => { f.run.repository.full_name = 'other/mcp-pacemaker'; }],
  ['repository ID', f => { f.run.repository.id++; }],
  ['head repository ID', f => { f.run.head_repository.id++; }],
  ['actor', f => { f.run.actor = { login: 'other', id: 10 }; }],
  ['triggering actor', f => { f.run.triggering_actor = { login: POLICY.owner, id: 11 }; }],
  ['stage used', f => { f.jobs.at(-1).conclusion = 'success'; }],
  ['stage running', f => { f.jobs.at(-1).status = 'in_progress'; }],
  ['source failed', f => { f.jobs[0].conclusion = 'failure'; }],
  ['source upload skipped', f => { f.jobs[0].steps.at(-1).conclusion = 'skipped'; }],
  ['missing matrix', f => { f.jobs.splice(2, 1); }],
  ['duplicate matrix', f => { f.jobs.push(structuredClone(f.jobs[1])); }],
  ['consumer failed', f => { f.jobs[1].conclusion = 'failure'; }],
  ['consumer wrong SHA', f => { f.jobs[1].head_sha = f.approval.commit; }],
  ['consumer wrong run', f => { f.jobs[1].run_id++; }],
  ['consumer step skipped', f => { f.jobs[1].steps[1].conclusion = 'skipped'; }],
  ['consumer image', f => { f.jobs[1].labels = ['self-hosted']; }],
  ['moved tag ref', f => { f.tagRef.object.sha = f.approval.tagObject; }],
  ['lightweight tag', f => { f.tagRef.object.type = 'commit'; }],
  ['wrong tag object', f => { f.tag.sha = f.approval.tagObject; }],
  ['nested tag', f => { f.tag.object.type = 'tag'; }],
  ['wrong peeled commit', f => { f.tag.object.sha = f.approval.commit; }],
  ['wrong commit', f => { f.commit.sha = f.approval.commit; }],
  ['wrong tree', f => { f.commit.tree.sha = f.approval.tree; }],
  ['artifact ID', f => { f.metadata.id++; }],
  ['final artifact', f => { f.metadata.name = 'npm-candidate-200-1'; }],
  ['expired artifact', f => { f.metadata.expired = true; }],
  ['artifact run', f => { f.metadata.workflow_run.id++; }],
  ['artifact head', f => { f.metadata.workflow_run.head_sha = f.approval.commit; }],
  ['artifact repository', f => { f.metadata.workflow_run.repository_id++; }],
  ['artifact head repository', f => { f.metadata.workflow_run.head_repository_id++; }],
  ['metadata digest', f => { f.metadata.digest = `sha256:${'0'.repeat(64)}`; }],
  ['ZIP digest', f => {
    const length = f.archive.length;
    const comment = Buffer.from('unapproved ZIP bytes, unchanged valid members');
    f.archive = Buffer.concat([f.archive, comment]);
    f.archive.writeUInt16LE(comment.length, length - 2);
  }],
  ['manifest digest', f => { f.peer.manifestSha256 = '0'.repeat(64); }],
  ['candidate digest', f => { f.rebundle(files => { files['candidate.tgz'] = Buffer.from('tampered'); }); }],
  ['extra ZIP file', f => { f.rebundle(files => { files['baseline.json'] = '{}'; }); }],
  ['ZIP directory', f => { f.rebundle(files => { files['extra/'] = ''; }); }],
  ['missing ZIP file', f => { f.rebundle(files => { delete files['source-gates.json']; }); }],
  ['unsafe ZIP path', f => { f.rebundle(files => { files['../escape'] = 'bad'; }); }],
  ['case collision', f => { f.rebundle(files => { files['CANDIDATE.tgz'] = f.bytes; }); }],
];
for (const [name, corrupt] of bindingFailures) {
  test(`rejects binding without writing: ${name}`, async t => {
    const f = new Fixture(t);
    corrupt(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(existsSync(f.directory), false);
  });
}

const manifestFailures = [
  ['schema', f => { f.prepared.schemaVersion = 2; }],
  ['status', f => { f.prepared.status = 'prepared-not-staged'; }],
  ['name', f => { f.prepared.name = 'other'; }],
  ['version', f => { f.prepared.version = f.approval.version; }],
  ['source', f => { f.prepared.source.commit = f.approval.commit; }],
  ['Node', f => { f.prepared.toolchain.node = '24.11.0'; }],
  ['npm', f => { f.prepared.toolchain.npm = '11.6.1'; }],
  ['filename', f => { f.prepared.artifact.filename = '../candidate.tgz'; }],
  ['files', f => { f.prepared.artifact.files[0].sha256 = '0'.repeat(64); }],
  ['prepared digest', f => { f.prepared.artifact.sha512 = '0'.repeat(128); }],
  ['report phase', f => { f.sourceReport.phase = 'artifact'; }],
  ['report commit', f => { f.sourceReport.source.commit = f.approval.commit; }],
  ['report version', f => { f.sourceReport.source.version = f.approval.version; }],
  ['report tree', f => { f.sourceReport.source.tree = f.approval.tree; }],
  ['report lock', f => { f.sourceReport.source.rootLockSha256 = '0'.repeat(64); }],
  ['producer lock', f => { f.prepared.producerLocks.ui = '0'.repeat(64); }],
  ['workflow run', f => { f.prepared.workflow.runId = f.env.GITHUB_RUN_ID; }],
  ['workflow attempt', f => { f.prepared.workflow.attempt = 2; }],
  ['workflow ref', f => { f.prepared.workflow.ref = f.env.GITHUB_WORKFLOW_REF; }],
  ['workflow commit', f => { f.prepared.workflow.commit = f.approval.commit; }],
  ['missing workflow field', f => { delete f.prepared.workflow.runId; }],
  ['CI source', f => { f.prepared.ci.headSha = f.approval.commit; }],
  ['human approval claim', f => { f.prepared.privateContentReview.status = 'approved'; }],
  ['publication claim', f => { f.prepared.publicationApproval.status = 'authorized'; }],
];
for (const [name, corrupt] of manifestFailures) {
  test(`rejects rehashed but inconsistent manifest: ${name}`, async t => {
    const f = new Fixture(t);
    corrupt(f);
    f.rebundle();
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(existsSync(f.directory), false);
  });
}

test('requires the exact source report hash even with independently approved ZIP bytes', async t => {
  const f = new Fixture(t);
  f.rebundle(files => { files['source-gates.json'] = Buffer.from(`${files['source-gates.json']}\n`); });
  await assert.rejects(downloadPeer(f.options()), /source report/i);
  assert.equal(existsSync(f.directory), false);
});

test('inspects the actual packed version even when all approved hashes and files match', async t => {
  const f = new Fixture(t);
  const version = f.peer.version;
  f.peer.version = f.approval.version;
  f.bytes = f.tarball();
  const files = inspectTarball(f.bytes, f.peer).files;
  f.peer.version = version;
  Object.assign(f.peer, digest(f.bytes));
  f.prepared.artifact = { filename: 'candidate.tgz', ...digest(f.bytes), files };
  f.prepared.privateContentReview.artifact = digest(f.bytes);
  f.rebundle();
  await assert.rejects(downloadPeer(f.options()));
  assert.equal(existsSync(f.directory), false);
});

test('a reapproved ZIP with a symbolic-link member still fails before writing', async t => {
  const f = new Fixture(t);
  const central = f.archive.readUInt32LE(f.archive.length - 22 + 16);
  f.archive.writeUInt32LE(0o120777 * 65536, central + 38);
  f.peer.artifactDigest = f.metadata.digest = `sha256:${hash(f.archive)}`;
  await assert.rejects(downloadPeer(f.options()), /links/);
  assert.equal(existsSync(f.directory), false);
});

test('does not require or invent a successful finalizer', async t => {
  const f = new Fixture(t);
  f.jobs = f.jobs.filter(job => job.name !== 'prepare');
  const result = await downloadPeer(f.options());
  assert.equal(result.evidence.finalizerNotRequired, true);
  assert.equal(Object.hasOwn(result.evidence, 'finalizerPassed'), false);
});

test('optional workflow fields are not fabricated when absent', async t => {
  const f = new Fixture(t);
  delete f.prepared.workflow;
  delete f.prepared.ci;
  delete f.prepared.producerLocks;
  f.rebundle();
  const result = await downloadPeer(f.options());
  assert.equal(Object.hasOwn(result.prepared, 'workflow'), false);
  assert.equal(Object.hasOwn(result.prepared, 'ci'), false);
});

test('requires a new absolute directory outside the checkout, without following links', async t => {
  const f = new Fixture(t);
  const occupied = join(f.home, 'occupied');
  mkdirSync(occupied);
  writeFileSync(join(occupied, 'peer.tgz'), 'existing');
  const link = join(f.home, 'link');
  symlinkSync(occupied, link, process.platform === 'win32' ? 'junction' : 'dir');
  for (const directory of ['relative-peer', root, join(root, 'never-created-peer'),
    occupied, link, join(link, 'child'), join(f.home, 'missing-parent', 'child')]) {
    await assert.rejects(downloadPeer({ ...f.options(), directory }));
  }
  assert.deepEqual(f.calls, []);
  assert.equal(readFileSync(join(occupied, 'peer.tgz'), 'utf8'), 'existing');
  await downloadPeer(f.options());
  await assert.rejects(downloadPeer(f.options()), /exist/i);
  assert.deepEqual(readFileSync(join(f.directory, 'peer.tgz')), f.bytes);
});

test('owned peer fixtures canonicalize real aliased temp parents', async t => {
  const parent = mkdtempSync(join(realpathSync.native(tmpdir()), 'publication-peer-alias-'));
  t.after(() => rmSync(parent, { recursive: true }));
  const physical = join(parent, 'physical');
  const alias = join(parent, 'alias');
  mkdirSync(physical);
  symlinkSync(physical, alias, process.platform === 'win32' ? 'junction' : 'dir');
  assert.notEqual(realpathSync(alias), resolve(alias));

  await t.test('canonical fixture downloads exact approved bytes', async child => {
    const f = new Fixture(child, '2.0.1', alias);
    assert.equal(dirname(f.home), physical);
    assert.equal(realpathSync.native(f.home), f.home);
    await downloadPeer(f.options());
    assert.deepEqual(readFileSync(join(f.directory, 'peer.tgz')), f.bytes);
  });

  await t.test('external alias still rejects before readers; existing bytes survive', async child => {
    const f = new Fixture(child, '2.0.1', alias);
    const directory = join(alias, basename(f.home), 'peer');
    await assert.rejects(downloadPeer({ ...f.options(), directory }), /ancestors must be real directories/);
    assert.deepEqual(f.calls, []);
    assert.equal(existsSync(f.directory), false);
    await downloadPeer(f.options());
    await assert.rejects(downloadPeer(f.options()), /exist/i);
    assert.deepEqual(readFileSync(join(f.directory, 'peer.tgz')), f.bytes);
  });
});

test('rechecks the exclusive destination after remote reads', async t => {
  const f = new Fixture(t);
  f.readers.readArtifactArchive = async () => {
    mkdirSync(f.directory);
    writeFileSync(join(f.directory, 'peer.tgz'), 'contender');
    return f.archive;
  };
  await assert.rejects(downloadPeer(f.options()), /exist/i);
  assert.equal(readFileSync(join(f.directory, 'peer.tgz'), 'utf8'), 'contender');
});

test('default readers use authenticated GitHub reads but never forward auth to ZIP storage', async t => {
  const f = new Fixture(t);
  const calls = [];
  const base = `https://api.github.com/repos/${POLICY.repository}/`;
  const responses = new Map([
    [`actions/runs/${f.peer.runId}`, f.run],
    [`actions/runs/${f.peer.runId}/attempts/1/jobs?per_page=100&page=1`, { total_count: f.jobs.length, jobs: f.jobs }],
    [`git/ref/tags/v${f.peer.version}`, f.tagRef], [`git/tags/${f.peer.tagObject}`, f.tag],
    [`git/commits/${f.peer.commit}`, f.commit], [`actions/artifacts/${f.peer.artifactId}`, f.metadata],
  ]);
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push(String(url));
    if (String(url) === 'https://signed.invalid/fixture.zip?signature=secret') {
      assert.equal(options.headers, undefined);
      assert.equal(options.redirect, 'error');
      return new Response(f.archive);
    }
    assert.ok(String(url).startsWith(base));
    assert.equal(options.headers.authorization, `Bearer ${f.env.GITHUB_TOKEN}`);
    assert.ok(['error', 'manual'].includes(options.redirect));
    const path = String(url).slice(base.length);
    if (path === `actions/artifacts/${f.peer.artifactId}/zip`) {
      return new Response(null, { status: 302,
        headers: { location: 'https://signed.invalid/fixture.zip?signature=secret' } });
    }
    assert.ok(responses.has(path), `Unexpected API path: ${path}`);
    return new Response(JSON.stringify(responses.get(path)));
  });
  const result = await downloadPeer({ approval: f.approval, env: f.env, directory: f.directory });
  assert.equal(calls.length, 8);
  assert.doesNotMatch(JSON.stringify(result.evidence), /secret|signed.invalid|fixture-token/);
});

class PublishedFixture extends Fixture {
  constructor(t, version = '2.0.2') {
    super(t, version);
    this.peer = this.approval.peerArtifact = {
      kind: 'npm-registry-published', version: this.peer.version,
      commit: this.peer.commit, tree: this.peer.tree, ...digest(this.bytes),
    };
    this.approval.expectedDistTags = { latest: '2.0.1', legacy: '1.3.1' };
    this.published = { name: POLICY.name, version: this.peer.version, gitHead: this.peer.commit,
      dist: { tarball: `${POLICY.registry}${POLICY.name}/-/${POLICY.name}-${this.peer.version}.tgz`,
        integrity: this.peer.integrity, shasum: createHash('sha1').update(this.bytes).digest('hex') } };
    this.registry = { name: POLICY.name, maintainers: [{ name: POLICY.owner }],
      'dist-tags': { ...this.approval.expectedDistTags }, versions: { [this.peer.version]: this.published } };
    this.responses = new Map([
      [`${POLICY.registry}${POLICY.name}`, () => JSON.stringify(this.registry)],
      [`https://api.github.com/repos/${POLICY.repository}/git/commits/${this.peer.commit}`, () => JSON.stringify(this.commit)],
      [this.published.dist.tarball, () => this.bytes],
    ]);
    this.requests = [];
    this.fetcher = async (url, options) => {
      this.requests.push({ url, options });
      assert.ok(this.responses.has(url), `Unexpected synthetic URL: ${url}`);
      return new Response(this.responses.get(url)());
    };
  }
  options() { return { ...super.options(), fetcher: this.fetcher }; }

  declareSourceProof() {
    this.peer.sourceProof = { kind: 'registry-slsa-v1',
      ref: `refs/tags/npm-r27/v${this.peer.version}`, runId: '777', runAttempt: 1 };
    this.published.dist.attestations = {
      url: `${POLICY.registry}-/npm/v1/attestations/${POLICY.name}@${this.peer.version}`,
      provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
    };
    this.attestations = syntheticRegistrySourceProof(this.peer, this.env);
    this.responses.set(this.published.dist.attestations.url, () => JSON.stringify(this.attestations));
  }
}

test('Declared sourceProof admits absent registry gitHead only after exact cryptographic verification', async t => {
  const f = new PublishedFixture(t);
  f.declareSourceProof();
  delete f.published.gitHead;
  let verified = 0;
  const result = await downloadPeer({ ...f.options(), verifyBundle: async (bundle, options) => {
    verified++;
    assert.deepEqual(bundle, f.attestations.attestations[0].bundle);
    assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
    assert.equal(options.ctLogThreshold, 1);
    assert.equal(options.tlogThreshold, 1);
    const identity = `https://github.com/${POLICY.repository}/${POLICY.workflow}@${f.peer.sourceProof.ref}`;
    assert.ok(new RegExp(options.certificateIdentityURI).test(identity));
    assert.ok(!new RegExp(options.certificateIdentityURI).test(`${identity}-other`));
  } });
  assert.equal(verified, 1);
  assert.equal(result.evidence.provenance.verification, 'cryptographically-verified');
  assert.equal(result.evidence.stageEligible, false);
  assert.equal(result.evidence.registrySignatures, 'not-verified-by-this-read');
});

for (const version of ['2.0.2', '2.7.13', '1.3.2']) {
  test(`SYNTHETIC published peer for ${version} is immutable comparison-only input`, async t => {
    const f = new PublishedFixture(t, version);
    const result = await downloadPeer(f.options());
    assert.deepEqual(readFileSync(result.tarball), f.bytes);
    assert.deepEqual(result.comparison, { version: f.peer.version, artifact: digest(f.bytes) });
    assert.equal(result.evidence.origin, 'npm-registry-published');
    assert.equal(result.evidence.stageEligible, false);
    assert.equal(result.evidence.purpose, 'service-comparison-only');
    assert.deepEqual(result.evidence.provenance, { status: 'absent', verification: 'not-performed' });
    assert.equal(result.evidence.registrySignatures, 'not-verified-by-this-read');
    for (const key of ['prepared', 'workflow', 'runId', 'artifactId', 'consumerJobs', 'stageId']) {
      assert.equal(result[key], undefined);
      assert.equal(result.evidence[key], undefined);
    }
    assert.deepEqual(f.calls, []);
    assert.equal(f.requests.length, 3);
    for (const { options } of f.requests) {
      assert.equal(options.credentials, 'omit');
      assert.equal(options.redirect, 'error');
      assert.equal(options.cache, 'no-store');
      assert.deepEqual(Object.keys(options.headers), ['accept']);
    }
    assert.throws(() => validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }), /no hosted run/);
    assert.throws(() => validatePeerBundle(f.bundle()), /no prepared bundle/);
    f.published.dist.attestations = { provenance: {} };
    assert.deepEqual((await validatePublishedPeer({ ...f.options(), packument: f.registry, commit: f.commit,
      bytes: f.bytes })).evidence.provenance, { status: 'present', verification: 'not-performed' });
  });
}

test('Published peer rejects conflicting approvals before I/O', async t => {
  for (const mutate of [
    f => { f.peer.kind = 'unknown'; }, f => { f.peer.version = '2.0.3'; },
    f => { f.peer.version = '3.0.1'; }, f => { f.peer.version = '1.3.2'; },
    f => { f.peer.commit = '0'.repeat(40); }, f => { f.peer.tree = '0'.repeat(40); },
    f => { f.peer.sha512 = '0'.repeat(128); }, f => { f.peer.sha256 = 'invalid'; },
    f => { f.peer.runId = '123'; }, f => { delete f.approval.expectedDistTags; },
    f => { f.approval.ciAttempt = '2'; }, f => { f.env = { ...f.env, GITHUB_RUN_ATTEMPT: '2' }; },
    f => { f.approval.localRegressionReview.reviewedAt = new Date(0).toISOString(); },
  ]) {
    const f = new PublishedFixture(t);
    mutate(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.deepEqual(f.requests, []);
    assert.equal(existsSync(f.directory), false);
  }
});

test('Published peer fails exact registry, source, byte and payload conflicts without fallback', async t => {
  for (const mutate of [
    f => { f.registry.name = 'other'; }, f => { f.registry.maintainers = []; },
    f => { f.registry.versions[f.approval.version] = {}; }, f => { f.registry['dist-tags'].latest = '2.0.3'; },
    f => { f.registry.deprecated = ''; }, f => { f.published.deprecated = ''; },
    ...['name', 'version', 'gitHead'].map(key => f => { f.published[key] = 'wrong'; }),
    f => { f.published.dist.integrity = 'wrong'; }, f => { f.published.dist.shasum = '0'.repeat(40); },
    f => { f.commit.sha = '0'.repeat(40); }, f => { f.commit.tree.sha = '0'.repeat(40); },
    f => { f.bytes = Buffer.from('corrupted'); },
    ...['http:', 'https://user@', 'https://registry.npmjs.org.evil.invalid/', '?query', '#fragment']
      .map(suffix => f => { f.published.dist.tarball += suffix; }),
    ...[pkg => { pkg.version = '1.3.9'; }, pkg => { pkg.scripts = { preinstall: 'forbidden' }; }]
      .map(change => f => {
        f.bytes = f.tarball(change);
        Object.assign(f.peer, digest(f.bytes));
        Object.assign(f.published.dist, { integrity: f.peer.integrity,
          shasum: createHash('sha1').update(f.bytes).digest('hex') });
      }),
  ]) {
    const f = new PublishedFixture(t);
    mutate(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(existsSync(f.directory), false);
  }
});

test('All published reads enforce status, size, encoding, redirect and deadlines', async t => {
  for (const target of [0, 1, 2]) {
    for (const mode of ['status', 'declared-size', 'streamed-size', 'redirected', 'url', 'deadline',
      ...(target < 2 ? ['json', 'utf8'] : [])]) {
      const f = new PublishedFixture(t);
      let calls = 0;
      const limit = target === 2 ? PUBLISHED_PEER_LIMITS.tarballBytes : PUBLISHED_PEER_LIMITS.metadataBytes;
      const fetcher = async (url, options) => {
        if (calls++ !== target) return f.fetcher(url, options);
        if (mode === 'status') return new Response(null, { status: 302 });
        if (mode === 'declared-size') return new Response('', { headers: { 'content-length': String(limit + 1) } });
        if (mode === 'streamed-size') return new Response(new Uint8Array(limit + 1));
        if (mode === 'json') return new Response('{');
        if (mode === 'utf8') return new Response(new Uint8Array([255]));
        if (mode === 'deadline') return new Response(new ReadableStream({
          start(controller) { options.signal.addEventListener('abort', () => controller.error(new Error('Synthetic abort'))); },
        }));
        const response = await f.fetcher(url, options);
        Object.defineProperty(response, mode, { value: mode === 'redirected' ? true : 'https://other.invalid/' });
        return response;
      };
      await assert.rejects(downloadPeer({ ...f.options(), fetcher, timeoutMs: 50 }), `${target}/${mode}`);
      assert.equal(calls, target + 1);
      assert.equal(existsSync(f.directory), false);
    }
  }
});

test('Peer import has no external I/O or module-load fetch access', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { createRequire } from 'node:module';
    const attempts = createRequire(import.meta.url)('./tools/npm-publication/offline-stage/deny.cjs');
    Object.defineProperty(globalThis, 'fetch', { configurable: true, get() { throw new Error('Module-load fetch'); } });
    await import('./tools/npm-publication/peer.mjs');
    assert.deepEqual(attempts, []);
  `], { cwd: root, encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
});

test('Source proof is explicit and cannot select its own trust, source, workflow or run', async t => {
  for (const change of [
    proof => { proof.kind = 'verified'; }, proof => { proof.ref = 'refs/tags/v2.0.2'; },
    proof => { proof.ref = 'refs/tags/npm-r01/v1.3.1'; },
    proof => { proof.runId = 777; }, proof => { proof.runId = '0777'; },
    proof => { proof.runId = '7'.repeat(21); }, proof => { proof.runAttempt = 2; },
    proof => { proof.runAttempt = '1'; },
    ...['issuer', 'repository', 'workflow', 'commit', 'verified', 'rootPath', 'keySelector', 'result']
      .map(key => proof => { proof[key] = 'not-approval'; }),
    proof => { delete proof.ref; },
  ]) {
    const f = new PublishedFixture(t);
    f.declareSourceProof();
    change(f.peer.sourceProof);
    await assert.rejects(downloadPeer(f.options()));
    assert.deepEqual(f.requests, []);
  }
  for (const proof of [undefined, null, false, 'verified', {}]) {
    const f = new PublishedFixture(t);
    f.peer.sourceProof = proof;
    await assert.rejects(downloadPeer(f.options()));
    assert.deepEqual(f.requests, []);
  }
});

test('Registry and tarball gitHead contradictions never use the provenance fallback', async t => {
  for (const target of ['registry', 'tarball']) {
    for (const value of [null, '', false, 123, {}, '0'.repeat(40), 'A'.repeat(40), 'abc', 'e'.repeat(40) + '\n']) {
      const f = new PublishedFixture(t);
      f.declareSourceProof();
      if (target === 'registry') f.published.gitHead = value;
      else {
        f.bytes = f.tarball(pkg => { pkg.gitHead = value; });
        Object.assign(f.peer, digest(f.bytes));
        Object.assign(f.published.dist, { integrity: f.peer.integrity,
          shasum: createHash('sha1').update(f.bytes).digest('hex') });
        f.attestations = syntheticRegistrySourceProof(f.peer, f.env);
      }
      let calls = 0;
      await assert.rejects(downloadPeer({ ...f.options(), verifyBundle: async () => { calls++; } }));
      assert.equal(calls, 0);
      assert.equal(existsSync(f.directory), false);
    }
  }
});

test('Declared source proof is mandatory even with matching gitHead; missing head cannot use metadata alone', async t => {
  const old = new PublishedFixture(t, '1.3.2');
  const metadataOnly = await downloadPeer({ ...old.options(), verifyBundle: async () => { assert.fail('Not requested'); } });
  assert.equal(metadataOnly.evidence.version, '2.0.1');
  assert.equal(metadataOnly.evidence.provenance.verification, 'not-performed');
  const missing = new PublishedFixture(t);
  delete missing.published.gitHead;
  await assert.rejects(downloadPeer(missing.options()), /sourceProof/);
  assert.equal(missing.requests.length, 1);
  for (const message of ['Invalid signature', 'Untrusted certificate', 'Wrong issuer', 'Wrong SAN', 'Missing CT log', 'Missing tlog']) {
    const f = new PublishedFixture(t);
    f.declareSourceProof();
    let calls = 0;
    await assert.rejects(downloadPeer({ ...f.options(), verifyBundle: async () => {
      calls++;
      throw new Error(message);
    } }), new RegExp(message));
    assert.equal(calls, 1);
    assert.equal(existsSync(f.directory), false);
  }
});

test('Registry SLSA must bind every approved subject/source/ref/run claim before cryptographic acceptance', async t => {
  for (const change of [
    value => { value.subject[0].name = 'pkg:npm/mcp-pacemaker@1.3.2'; },
    value => { value.subject[0].digest.sha512 = '0'.repeat(128); },
    value => { value.subject.push(value.subject[0]); },
    value => { value.predicateType = 'other'; },
    value => { value.predicate.buildDefinition.buildType = 'other'; },
    value => { value.predicate.buildDefinition.externalParameters.workflow.ref = 'refs/tags/v1.3.1'; },
    value => { value.predicate.buildDefinition.externalParameters.workflow.path = '.github/workflows/other.yml'; },
    value => { value.predicate.buildDefinition.externalParameters.workflow.repository = 'https://github.com/other/repo'; },
    value => { value.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = '0'.repeat(40); },
    value => { value.predicate.buildDefinition.resolvedDependencies[0].uri = 'other'; },
    value => { value.predicate.buildDefinition.internalParameters.github.event_name = 'push'; },
    value => { value.predicate.buildDefinition.internalParameters.github.repository_id = '1'; },
    value => { value.predicate.buildDefinition.internalParameters.github.repository_owner_id = '1'; },
    value => { value.predicate.runDetails.builder.id = 'self-hosted'; },
    value => { value.predicate.runDetails.metadata.invocationId = 'https://github.com/girishkvs/mcp-pacemaker/actions/runs/778/attempts/1'; },
  ]) {
    const f = new PublishedFixture(t);
    f.declareSourceProof();
    const envelope = f.attestations.attestations[0].bundle.dsseEnvelope;
    const value = JSON.parse(Buffer.from(envelope.payload, 'base64'));
    change(value);
    envelope.payload = Buffer.from(JSON.stringify(value)).toString('base64');
    let calls = 0;
    await assert.rejects(downloadPeer({ ...f.options(), verifyBundle: async () => { calls++; } }));
    assert.equal(calls, 0);
    assert.equal(existsSync(f.directory), false);
  }
});

test('Missing, duplicate, malformed and substituted registry attestations are not source proof', async t => {
  for (const change of [
    f => { f.attestations = { attestations: [] }; },
    f => { f.attestations.attestations.push(f.attestations.attestations[0]); },
    f => { f.attestations = { verified: true, commit: f.peer.commit }; },
    f => { f.attestations.attestations[0].bundle.dsseEnvelope.payload += '\n'; },
    f => { f.attestations.attestations[0].bundle.dsseEnvelope.payloadType = 'other'; },
    f => { f.published.dist.attestations.url += '?override=true'; },
    f => { f.published.dist.attestations.provenance.predicateType = 'other'; },
  ]) {
    const f = new PublishedFixture(t);
    f.declareSourceProof();
    change(f);
    await assert.rejects(downloadPeer({ ...f.options(), verifyBundle: async () => { assert.fail('Must reject first'); } }));
    assert.equal(existsSync(f.directory), false);
  }
});

test('Declared proof verifies the registry bundle as returned and snapshots caller-owned inputs', async t => {
  const f = new PublishedFixture(t);
  f.declareSourceProof();
  const original = structuredClone(f.peer.sourceProof);
  const result = await downloadPeer({ ...f.options(), verifyBundle: async () => {
    f.peer.sourceProof.runId = '888';
    f.registry['dist-tags'].latest = '2.9.9';
  } });
  assert.deepEqual(result.evidence.provenance.sourceProof, original);
  assert.deepEqual(result.evidence.distTags, { latest: '2.0.1', legacy: '1.3.1' });
  const changed = new PublishedFixture(t);
  changed.declareSourceProof();
  await assert.rejects(downloadPeer({ ...changed.options(), verifyBundle: async bundle => {
    delete bundle.dsseEnvelope.signatures[0].keyid;
  } }), /changed the registry bundle/);
  assert.equal(existsSync(changed.directory), false);
});

test('Pinned peer verifier child has a closed environment, bounded lifetime, bound result and owned cleanup', () => {
  if (process.versions.node !== POLICY.node) {
    assert.throws(() => verifyRegistrySource({}), /pinned publisher Node/);
    return;
  }
  const cli = resolve('synthetic-npm-cli.js');
  let home;
  const execute = (_node, args, options) => {
    assert.equal(args[1], '--registry-peer');
    assert.equal(args[2], cli);
    assert.equal(options.timeout, PEER_PROOF_LIMITS.verificationMs);
    assert.equal(options.shell, false);
    assert.equal(options.maxBuffer, 1024 * 1024);
    home = options.cwd;
    assert.equal(options.env.HOME, home);
    for (const key of ['GITHUB_TOKEN', 'NODE_OPTIONS', 'npm_config_registry', 'NPM_TOKEN']) {
      assert.equal(options.env[key], undefined);
    }
    assert.deepEqual(readdirSync(home), []);
    return { status: 0, signal: null, stdout: JSON.stringify({
      status: 'cryptographically-verified', inputSha256: hash(options.input), node: POLICY.node, npm: POLICY.npm,
      requests: ['https://tuf-repo-cdn.sigstore.dev/timestamp.json'],
    }), stderr: '' };
  };
  const options = { record: { synthetic: true }, bundle: { synthetic: true }, cli,
    env: { GITHUB_TOKEN: 'synthetic', NODE_OPTIONS: 'synthetic', npm_config_registry: 'https://invalid/' } };
  verifyRegistrySource({ ...options, execute });
  assert.equal(existsSync(home), false);
  assert.equal(existsSync(`${home}.compat-owner`), false);
  for (const mutate of [
    result => { result.error = { code: 'ETIMEDOUT' }; },
    result => { result.signal = 'SIGKILL'; },
    result => { result.status = 1; },
    result => { result.stdout = '{'; },
    result => {
      const value = JSON.parse(result.stdout);
      value.inputSha256 = '0'.repeat(64);
      result.stdout = JSON.stringify(value);
    },
  ]) {
    assert.throws(() => verifyRegistrySource({ ...options, execute: (...args) => {
      const result = execute(...args);
      mutate(result);
      return result;
    } }));
    assert.equal(existsSync(home), false);
    assert.equal(existsSync(`${home}.compat-owner`), false);
  }
});

test('TUF transport denies other endpoints, redirects, retries, oversized/stalled responses and request floods', async () => {
  class HttpError extends Error {
    constructor(message, statusCode) { super(message); this.statusCode = statusCode; }
  }
  const url = 'https://tuf-repo-cdn.sigstore.dev/timestamp.json';
  for (const invalid of [
    url.replace('https:', 'http:'), url.replace('sigstore.dev', 'sigstore.dev.evil.invalid'),
    url.replace('https://', 'https://user@'), url.replace('.dev/', '.dev:443/'),
    `${url}?query`, `${url}#fragment`, `${url}\n`,
    'https://tuf-repo-cdn.sigstore.dev/targets/registry.npmjs.org/keys.json',
    'https://tuf-repo-cdn.sigstore.dev/../timestamp.json',
    'https://tuf-repo-cdn.sigstore.dev/01.root.json',
  ]) {
    const transport = new PeerTufTransport(HttpError, async () => { assert.fail('Unexpected network'); });
    await assert.rejects(transport.fetch(invalid));
    assert.equal(transport.requests.length, 0);
  }
  for (const status of [301, 302, 303, 307, 308, 403, 429, 500]) {
    let calls = 0;
    const transport = new PeerTufTransport(HttpError, async (_url, options) => {
      calls++;
      assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'omit');
      assert.deepEqual(Object.keys(options.headers), ['accept']);
      return new Response(null, { status });
    });

    await assert.rejects(transport.fetch(url));
    assert.equal(calls, 1);
  }
  const absent = new PeerTufTransport(HttpError, async () => new Response(null, { status: 404 }));
  await assert.rejects(absent.fetch('https://tuf-repo-cdn.sigstore.dev/15.root.json'),
    error => error.statusCode === 404);
  for (const mode of ['length', 'stream', 'deadline']) {
    const transport = new PeerTufTransport(HttpError, async (_url, options) => {
      if (mode === 'length') return new Response('', { headers: { 'content-length': String(PEER_PROOF_LIMITS.bytes + 1) } });
      if (mode === 'stream') return new Response(new Uint8Array(PEER_PROOF_LIMITS.bytes + 1));
      return new Response(new ReadableStream({
        start(controller) { options.signal.addEventListener('abort', () => controller.error(new Error('Synthetic abort'))); },
      }));
    }, 50);
    await assert.rejects(transport.fetch(url));
  }
  const bounded = new PeerTufTransport(HttpError, async () => new Response('{}'));
  for (let index = 0; index < PEER_PROOF_LIMITS.requests; index++) await bounded.fetch(url);
  await assert.rejects(bounded.fetch(url), /budget/);
  assert.equal(bounded.requests.length, PEER_PROOF_LIMITS.requests);
  assert.equal(peerTufUrl('https://tuf-repo-cdn.sigstore.dev/targets/' + 'a'.repeat(64) + '.trusted_root.json'),
    'https://tuf-repo-cdn.sigstore.dev/targets/' + 'a'.repeat(64) + '.trusted_root.json');
});
