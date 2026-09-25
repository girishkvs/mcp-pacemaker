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
import { POLICY, REQUIRED_GATES, digest, validateApproval, validateTransfer } from '../tools/npm-publication/policy.mjs';
import { MATRIX } from '../tools/npm-publication/matrix.mjs';
import { inspectTarball } from '../tools/npm-publication/tarball.mjs';
import {
  downloadPeer, validatePeerApproval, validatePeerRun, validatePeerBundle,
  validatePublishedPeer, PUBLISHED_PEER_LIMITS,
} from '../tools/npm-publication/peer.mjs';
import { validatePreparedLocal, validateLocalManifest } from '../tools/npm-publication/local-regression.mjs';
import { StageFixture } from './helpers/npm-publication-candidate-fixture.mjs';

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
      version: version === '2.0.1' ? '1.3.1' : '2.0.1',
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

  tarball(changePackage = () => {}) {
    const pkg = { name: POLICY.name, version: this.peer.version,
      repository: { url: `git+https://github.com/${POLICY.repository}.git` },
      dependencies: { 'smol-toml': '^1.8.0' }, files: ['bin/', 'ui/', 'THIRD_PARTY_NOTICES.txt'] };
    changePackage(pkg);
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

class PublishedFixture extends Fixture {
  constructor(t) {
    super(t, '1.3.1');
    this.peer = this.approval.peerArtifact = {
      kind: 'npm-registry-published', version: this.peer.version,
      commit: this.peer.commit, tree: this.peer.tree, ...digest(this.bytes),
    };
    this.registry = {
      name: POLICY.name, maintainers: [{ name: POLICY.owner }], 'dist-tags': { latest: '2.0.1' },
      versions: { '2.0.1': { name: POLICY.name, version: '2.0.1', gitHead: this.peer.commit,
        dist: { tarball: `${POLICY.registry}${POLICY.name}/-/${POLICY.name}-2.0.1.tgz`,
          integrity: this.peer.integrity, shasum: createHash('sha1').update(this.bytes).digest('hex') } } },
    };
    this.responses = new Map([
      [`${POLICY.registry}${POLICY.name}`, () => JSON.stringify(this.registry)],
      [`https://api.github.com/repos/${POLICY.repository}/git/commits/${this.peer.commit}`,
        () => JSON.stringify(this.commit)],
      [this.registry.versions['2.0.1'].dist.tarball, () => this.bytes],
    ]);
    this.requests = [];
    this.fetcher = async (url, options) => {
      this.requests.push({ url, options });
      assert.ok(this.responses.has(url), `Unexpected anonymous URL: ${url}`);
      return new Response(this.responses.get(url)());
    };
  }

  options() {
    return { ...super.options(), fetcher: this.fetcher };
  }

  stageControl() {
    const bytes = this.tarball(pkg => { pkg.version = this.approval.version; });
    const gates = { schemaVersion: 1, commit: this.approval.commit, artifact: digest(bytes),
      localRegression: this.approval.localRegression,
      gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, { status: 'passed',
        evidence: [{ description: 'SYNTHETIC independent gate response', sha256: hash('synthetic') }] }])) };
    const manifest = syntheticPreparedLocal({
      schemaVersion: 1, phase: 'prepared-not-staged', name: POLICY.name, version: this.approval.version, channel: 'legacy',
      source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, this.approval[key]])),
      workflow: { ref: this.env.GITHUB_WORKFLOW_REF, commit: this.approval.commit,
        runId: this.env.GITHUB_RUN_ID, attempt: 1 },
      ci: { runId: this.approval.ciRunId, attempt: this.approval.ciAttempt },
      artifact: { ...digest(bytes), files: inspectTarball(bytes, this.approval).files },
      gateReportSha256: hash(`${JSON.stringify(gates, null, 2)}\n`),
    }, this.approval);
    const jobs = MATRIX.map(lane => ({ name: lane.jobName, status: 'completed',
      conclusion: 'success', head_sha: this.approval.commit }));
    return new StageFixture(this.approval, bytes, manifest, gates, files => this.zip(files), jobs);
  }
}

test('Already-published 2.0.1 resolves directly as T32-only peer without a hosted seed', async t => {
  const f = new PublishedFixture(t);
  const result = await downloadPeer(f.options());
  assert.deepEqual(readFileSync(result.tarball), f.bytes);
  assert.equal(result.prepared, undefined);
  assert.deepEqual(result.comparison, { version: f.peer.version, artifact: digest(f.bytes) });
  assert.equal(result.evidence.origin, 'npm-registry-published');
  assert.equal(result.evidence.purpose, 'service-comparison-only');
  assert.equal(result.evidence.stageEligible, false);
  assert.deepEqual(f.calls, [], 'Published bytes must not impersonate hosted artifact readers');
  assert.equal(f.requests.length, 3);
});

test('Published peer uses late-bound anonymous bounded readers and reports absent provenance honestly', async t => {
  const f = new PublishedFixture(t);
  t.mock.method(globalThis, 'fetch', f.fetcher);
  const result = await downloadPeer({ approval: f.approval, env: f.env, directory: f.directory });
  for (const { options } of f.requests) {
    assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    assert.equal(options.cache, 'no-store');
    assert.ok(options.signal instanceof AbortSignal);
    assert.deepEqual(Object.keys(options.headers), ['accept']);
  }
  assert.deepEqual(result.evidence.provenance, { status: 'absent', verification: 'not-performed' });
  assert.equal(result.evidence.registrySignatures, 'not-verified-by-this-read');
  for (const key of ['prepared', 'workflow', 'runId', 'artifactId', 'sourcePassed', 'matrixPassed',
    'consumerJobs', 'finalizerNotRequired', 'stageId']) {
    assert.equal(result[key], undefined);
    assert.equal(result.evidence[key], undefined);
  }
  assert.deepEqual(readdirSync(f.directory), ['peer.tgz']);
  assert.doesNotMatch(JSON.stringify(result), /fixture-token/);
});

test('Present registry provenance is recorded, not claimed as verified', t => {
  const f = new PublishedFixture(t);
  f.registry.versions['2.0.1'].dist.attestations = { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } };
  const result = validatePublishedPeer({ ...f.options(), packument: f.registry, commit: f.commit, bytes: f.bytes });
  assert.deepEqual(result.evidence.provenance, { status: 'present', verification: 'not-performed' });
});

const publishedApprovalFailures = [
  ['kind missing', f => { delete f.peer.kind; }],
  ['unknown kind', f => { f.peer.kind = 'prepared'; }],
  ['same line', f => { f.peer.version = '1.3.1'; }],
  ['future version', f => { f.peer.version = '2.0.2'; }],
  ['historical version', f => { f.peer.version = '2.0.0'; }],
  ...['commit', 'tree', 'sha256', 'sha512', 'integrity'].map(key =>
    [`missing ${key}`, f => { delete f.peer[key]; }]),
  ['wrong qualified commit', f => { f.peer.commit = '1'.repeat(40); }],
  ['wrong qualified tree', f => { f.peer.tree = '2'.repeat(40); }],
  ['inconsistent SRI', f => { f.peer.sha512 = 'a'.repeat(128); }],
  ['expired local review', f => { f.approval.localRegressionReview.reviewedAt = new Date(0).toISOString(); }],
  ['unreviewed statement', f => { f.approval.localRegression.reportSha256 = 'f'.repeat(64); }],
  ['wrong own source', f => { f.approval.commit = '0'.repeat(40); }],
  ['stage scope', f => { f.approval.scope = 'stage'; }],
  ['source CI string', f => { f.approval.ciAttempt = '2'; }],
  ['collection rerun', f => { f.env = { ...f.env, GITHUB_RUN_ATTEMPT: '2' }; }],
  ...['artifactId', 'runId', 'runAttempt', 'manifestSha256', 'artifactDigest', 'ref', 'tagObject',
    'prepared', 'stageEligible', 'purpose', 'provenance', 'unexpected'].map(key =>
    [`extra ${key}`, f => { f.peer[key] = 'unapproved'; }]),
];
for (const [name, corrupt] of publishedApprovalFailures) {
  test(`published approval rejects before I/O: ${name}`, async t => {
    const f = new PublishedFixture(t);
    corrupt(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.deepEqual(f.calls, []);
    assert.deepEqual(f.requests, []);
    assert.equal(existsSync(f.directory), false);
  });
}

const publishedRegistryFailures = [
  ['package name', f => { f.registry.name = 'other'; }],
  ['missing owner', f => { f.registry.maintainers = []; }],
  ['missing versions', f => { delete f.registry.versions; }],
  ['missing peer version', f => { delete f.registry.versions['2.0.1']; }],
  ['already published candidate', f => { f.registry.versions['1.3.1'] = {}; }],
  ['changed latest', f => { f.registry['dist-tags'].latest = '2.0.2'; }],
  ['extra tag', f => { f.registry['dist-tags'].legacy = '1.3.0'; }],
  ['missing tag', f => { f.registry['dist-tags'] = {}; }],
  ['deprecated package', f => { f.registry.deprecated = ''; }],
  ['deprecated version', f => { f.registry.versions['2.0.1'].deprecated = 'no longer supported'; }],
  ...['name', 'version', 'gitHead'].map(key => [key, f => { f.registry.versions['2.0.1'][key] = 'different'; }]),
  ['integrity', f => { f.registry.versions['2.0.1'].dist.integrity = 'sha512-wrong'; }],
  ...['http://registry.npmjs.org/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz',
    'https://registry.npmjs.org.evil.invalid/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz',
    'https://registry.npmjs.org/mcp-pacemaker/-/other.tgz',
    'https://registry.npmjs.org:443/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz',
    'https://registry.npmjs.org/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz?token=synthetic',
    'https://registry.npmjs.org/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz#fragment',
    'https://user@registry.npmjs.org/mcp-pacemaker/-/mcp-pacemaker-2.0.1.tgz',
    'https://registry.npmjs.org/mcp-pacemaker/-/../-/mcp-pacemaker-2.0.1.tgz'].map((url, index) =>
    [`noncanonical tarball ${index}`, f => { f.registry.versions['2.0.1'].dist.tarball = url; }]),
];
for (const [name, corrupt] of publishedRegistryFailures) {
  test(`published registry rejects before tarball download: ${name}`, async t => {
    const f = new PublishedFixture(t);
    corrupt(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(f.requests.length, 1);
    assert.equal(existsSync(f.directory), false);
  });
}

for (const key of ['sha', 'tree']) {
  test(`published GitHub ${key} mismatch rejects before tarball download`, async t => {
    const f = new PublishedFixture(t);
    f.commit[key] = key === 'sha' ? '1'.repeat(40) : { sha: '1'.repeat(40) };
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(f.requests.length, 2);
    assert.equal(existsSync(f.directory), false);
  });
}

test('Actual published digest, shasum and archive inspection cannot be replaced by approval metadata', async t => {
  for (const corrupt of [
    f => { f.bytes = Buffer.from('tampered'); },
    f => { f.registry.versions['2.0.1'].dist.shasum = 'f'.repeat(40); },
    f => {
      f.bytes = Buffer.from('digest-approved but not a tarball');
      Object.assign(f.peer, digest(f.bytes));
      Object.assign(f.registry.versions['2.0.1'].dist, {
        integrity: f.peer.integrity, shasum: createHash('sha1').update(f.bytes).digest('hex'),
      });
    },
  ]) {
    const f = new PublishedFixture(t);
    corrupt(f);
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(existsSync(f.directory), false);
  }
});

test('Published tarball package identity, source and lifecycle policy remain mandatory after digest matching', async t => {
  for (const change of [
    pkg => { pkg.name = 'other'; },
    pkg => { pkg.version = '2.0.2'; },
    pkg => { pkg.repository.url = 'git+https://github.com/other/other.git'; },
    pkg => { pkg.gitHead = '0'.repeat(40); },
    pkg => { pkg.scripts = { preinstall: 'unreviewed' }; },
    pkg => { pkg.files = ['bin/']; },
  ]) {
    const f = new PublishedFixture(t);
    f.bytes = f.tarball(change);
    Object.assign(f.peer, digest(f.bytes));
    Object.assign(f.registry.versions['2.0.1'].dist, {
      integrity: f.peer.integrity, shasum: createHash('sha1').update(f.bytes).digest('hex'),
    });
    await assert.rejects(downloadPeer(f.options()));
    assert.equal(existsSync(f.directory), false);
  }
});

for (const status of [301, 302, 303, 307, 308, 404, 429, 500]) {
  test(`published peer refuses HTTP ${status} without retry or redirect`, async t => {
    const f = new PublishedFixture(t);
    let calls = 0;
    await assert.rejects(downloadPeer({ ...f.options(), fetcher: async () => {
      calls++;
      return new Response(null, { status, headers: { location: 'https://other.invalid/' } });
    } }));
    assert.equal(calls, 1);
    assert.equal(existsSync(f.directory), false);
  });
}

test('Every published read enforces declared and streamed size, JSON encoding and final URL', async t => {
  for (const target of [0, 1, 2]) {
    for (const failure of ['declared-size', 'streamed-size', 'redirected', 'url', 'body-error',
      ...(target < 2 ? ['malformed-json', 'invalid-utf8'] : [])]) {
      const f = new PublishedFixture(t);
      let calls = 0;
      const limit = target === 2 ? PUBLISHED_PEER_LIMITS.tarballBytes : PUBLISHED_PEER_LIMITS.metadataBytes;
      const fetcher = async (url, options) => {
        if (calls++ !== target) return f.fetcher(url, options);
        if (failure === 'declared-size') return new Response('', { headers: { 'content-length': String(limit + 1) } });
        if (failure === 'streamed-size') return new Response(new Uint8Array(limit + 1));
        if (failure === 'malformed-json') return new Response('{');
        if (failure === 'invalid-utf8') return new Response(new Uint8Array([255]));
        if (failure === 'body-error') return new Response(new ReadableStream({
          start(controller) { controller.error(new Error('Synthetic broken stream')); },
        }));
        const response = await f.fetcher(url, options);
        Object.defineProperty(response, failure === 'redirected' ? 'redirected' : 'url',
          { value: failure === 'redirected' ? true : 'https://other.invalid/' });
        return response;
      };
      await assert.rejects(downloadPeer({ ...f.options(), fetcher }), `${target}/${failure}`);
      assert.equal(calls, target + 1);
      assert.equal(existsSync(f.directory), false);
    }
  }
});

test('Published response deadlines cover both pending headers and stalled body reads', async t => {
  for (const body of [false, true]) {
    const f = new PublishedFixture(t);
    let signal;
    const fetcher = async (_url, options) => {
      signal = options.signal;
      if (!body) return new Promise((_, reject) =>
        signal.addEventListener('abort', () => reject(new Error('Synthetic aborted headers')), { once: true }));
      return new Response(new ReadableStream({
        start(controller) {
          signal.addEventListener('abort', () => controller.error(new Error('Synthetic aborted stream')), { once: true });
        },
      }));
    };
    await assert.rejects(downloadPeer({ ...f.options(), fetcher, timeoutMs: 10 }), /deadline|aborted/);
    assert.equal(signal.aborted, true);
    assert.equal(existsSync(f.directory), false);
  }
});

test('Published response deadline override can only tighten the production bound', async t => {
  const f = new PublishedFixture(t);
  for (const timeoutMs of [0, -1, '1', 1.5, Infinity, PUBLISHED_PEER_LIMITS.timeoutMs + 1]) {
    await assert.rejects(downloadPeer({ ...f.options(), timeoutMs }), /deadline/);
  }
  assert.deepEqual(f.requests, []);
  assert.equal(existsSync(f.directory), false);
});

test('Published reads snapshot approval and recheck exclusive destination before writing', async t => {
  const f = new PublishedFixture(t);
  const approvedDigest = f.peer.sha256;
  const fetcher = async (url, options) => {
    f.peer.sha256 = '0'.repeat(64);
    return f.fetcher(url, options);
  };
  const result = await downloadPeer({ ...f.options(), fetcher });
  assert.equal(result.evidence.sha256, approvedDigest);
  await assert.rejects(downloadPeer(f.options()), /exist|digest|mismatch/i);
  assert.deepEqual(readFileSync(result.tarball), f.bytes);
  const contender = new PublishedFixture(t);
  await assert.rejects(downloadPeer({ ...contender.options(), fetcher: async (url, options) => {
    const response = await contender.fetcher(url, options);
    if (url.endsWith('.tgz')) {
      mkdirSync(contender.directory);
      writeFileSync(join(contender.directory, 'peer.tgz'), 'contender');
    }
    return response;
  } }), /exist/i);
  assert.equal(readFileSync(join(contender.directory, 'peer.tgz'), 'utf8'), 'contender');
});

test('Candidate manifest positive control distinguishes valid stage approval from peer rejection', t => {
  const f = new PublishedFixture(t);
  const control = f.stageControl();
  assert.doesNotThrow(() => control.validate());
  const brokenApproval = structuredClone(control.approval);
  delete brokenApproval.ownerPreflight.privateContentReview.localRegression;
  assert.throws(() => validateLocalManifest(Buffer.from(control.files['manifest.json']), brokenApproval),
    error => /Missing local regression object/.test(error.message) &&
      error.stack.includes('validateLocalReview'));
  const peerBytes = Buffer.from(JSON.stringify(f.peer));
  assert.throws(() => validateLocalManifest(peerBytes, { ...brokenApproval,
    artifact: { ...brokenApproval.artifact, manifestSha256: hash(peerBytes) } }),
  error => /Missing local regression object/.test(error.message) &&
    error.stack.includes('validateLocalReview'));
});

test('Published comparison cannot supply hosted peer, candidate transfer, manifest or stage authorization', async t => {
  const f = new PublishedFixture(t);
  const result = await downloadPeer(f.options());
  const control = f.stageControl();
  control.validate();
  assert.throws(() => validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }), /no hosted run/);
  assert.throws(() => validatePeerBundle(f.bundle()), /no prepared bundle/);
  for (const value of [f.peer, result.evidence, result.comparison, result]) {
    validatePreparedLocal(control.manifest, control.approval);
    assert.throws(() => validatePreparedLocal(value, control.approval), /local regression/);
    const bytes = Buffer.from(JSON.stringify(value));
    const stage = { ...control.approval, artifact: { ...control.approval.artifact, manifestSha256: hash(bytes) } };
    assert.throws(() => validateLocalManifest(bytes, stage),
      error => /Missing local regression object/.test(error.message) &&
        error.stack.includes('validatePreparedLocal') &&
        !error.stack.includes('validateLocalReview'));
  }
  for (const marker of [f.peer, result.evidence]) {
    const stage = { ...control.approval, artifact: { ...control.approval.artifact, ...marker } };
    assert.throws(() => validateApproval(stage, 'stage'), /comparison-only/);
    assert.throws(() => validateTransfer(control.run, control.jobs, control.metadata, stage), /comparison-only/);
  }
  control.validate();
});

test('Peer module imports with all external I/O denied and without reading global fetch at load', () => {
  const script = `
    import assert from 'node:assert/strict';
    import { createRequire } from 'node:module';
    const require = createRequire(import.meta.url);
    const attempts = require('./tools/npm-publication/offline-stage/deny.cjs');
    Object.defineProperty(globalThis, 'fetch', { configurable: true, get() {
      throw new Error('Global fetch read at module load');
    } });
    await import('./tools/npm-publication/peer.mjs');
    assert.deepEqual(attempts, []);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script],
    { cwd: root, encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
});

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
  for (const namespaces of ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/', 'npm-r6/', 'npm-r12/'].flatMap(current =>
    ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/', 'npm-r6/', 'npm-r12/'].map(peer => ({ current, peer })))) {
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
  for (const namespace of ['npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/', 'npm-r6/', 'npm-r12/']) {
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

test('peer preparation accepts only skipped current-line bootstrap jobs', t => {
  const f = new Fixture(t);
  f.jobs.push(
    { ...f.job('sign-bootstrap', 510), conclusion: 'skipped' },
    { ...f.job('publish-bootstrap', 511), conclusion: 'skipped' },
  );
  assert.equal(validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }).matrixPassed, true);
});

for (const name of ['sign-bootstrap', 'publish-bootstrap']) {
  for (const outcome of ['success', 'failure', 'cancelled', 'running']) {
    test(`peer preparation rejects ${name} ${outcome}`, t => {
      const f = new Fixture(t);
      f.jobs.push({ ...f.job(name, 510),
        status: outcome === 'running' ? 'in_progress' : 'completed',
        conclusion: outcome === 'running' ? 'skipped' : outcome });
      assert.throws(() => validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }));
    });
  }
}

test('peer preparation still rejects an unknown skipped job', t => {
  const f = new Fixture(t);
  f.jobs.push({ ...f.job('unknown-bootstrap', 510), conclusion: 'skipped' });
  assert.throws(() => validatePeerRun({ ...f.options(), run: f.run, jobs: f.jobs }));
});

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
