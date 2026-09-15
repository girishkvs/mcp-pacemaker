import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { digest, POLICY, REQUIRED_GATES } from '../tools/npm-publication/policy.mjs';
import { readCandidateEvidence, readSigningRun, readOwnerRun } from '../tools/npm-publication/bootstrap-readers.mjs';
import { exactArchive } from '../tools/npm-publication/bootstrap.mjs';
import { inspectTarball } from '../tools/npm-publication/tarball.mjs';
import { verifyWindowsExecution } from '../tools/npm-publication/external-gates.mjs';
import { CURRENT_REF, LEGACY_REF } from '../tools/compatibility/fixtures.mjs';
import {
  MATRIX, githubReaders, matrixLane, runMatrix, selectMatrixArtifacts, validateMatrixContext,
  verifyMatrixReports, verifyPreparedBundle, zipFiles,
} from '../tools/npm-publication/matrix.mjs';
import {
  bootstrapNpmCli, installConsumerToolchain,
} from '../tools/npm-publication/install-consumer-toolchain.mjs';

// Every subprocess and API boundary is injected. These tests never install or start a consumer.
const hash = data => digest(data).sha256;
const hex = value => value.repeat(40);
const approval = {
  schemaVersion: 1, scope: 'prepare', approver: POLICY.owner, name: POLICY.name, version: '2.0.1',
  ref: 'refs/tags/v2.0.1', tagObject: hex('a'), commit: hex('b'), tree: hex('c'),
};
const nativeNames = [
  'real helper inspection emits only one fingerprint and does not change file contents',
  'real helper prepares both files with matching security without writing config data',
  'real helper refuses a stale fingerprint without writing config data',
  ...Array.from({ length: 6 }, (_, index) => `other native fixture ${index}`),
];
const tap = `TAP version 13\n${nativeNames.map((name, index) => `ok ${index + 1} - ${name}\n`).join('')}` +
  '1..9\n# tests 9\n# pass 9\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';

function save(path, bytes) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
}

function zip(entries) {
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

function packageFixture(version = approval.version, nativeFiles) {
  const pkg = {
    name: POLICY.name, version, repository: { url: `git+https://github.com/${POLICY.repository}.git` },
    dependencies: { 'smol-toml': '^1.8.0' }, scripts: { 'consumer:check': 'node tools/npm-consumer/check.mjs' },
    files: ['bin/', 'ui/', 'THIRD_PARTY_NOTICES.txt'],
  };
  const files = {
    'package.json': JSON.stringify(pkg), 'README.md': 'readme', LICENSE: 'MIT', 'CHANGELOG.md': 'changes',
    'bin/cli.mjs': 'cli', 'bin/mcp-bridge.mjs': 'bridge', 'ui/dist/index.html': 'ui',
    'THIRD_PARTY_NOTICES.txt': 'notices', 'ui/dist/THIRD_PARTY_NOTICES.txt': 'notices',
    'ui/dist/third-party-manifest.json': '{}',
    'bin/windows/PoolingSecurityHelper.exe': 'fake bytes; never executed',
    'bin/windows/PoolingSecurityHelper.build.json': '{}',
    ...Object.fromEntries(['AssemblyInfo', 'PoolingNativeFiles', 'PoolingSecurityHelper', 'PoolingSecurityReader']
      .filter(name => version === '2.0.1' || name !== 'PoolingNativeFiles')
      .map(name => [`bin/windows/src/${name}.cs`, 'fixture source'])),
  };
  if (nativeFiles) {
    for (const path of Object.keys(files).filter(path => path.startsWith('bin/windows/'))) delete files[path];
    Object.assign(files, nativeFiles);
  }
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
  return { pkg, files, tarball: gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)])) };
}

class Fixture {
  constructor(t, version = approval.version, nativeFiles) {
    this.approval = { ...approval, version, ref: `refs/tags/v${version}` };
    const approved = this.approval;
    this.dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'pacemaker-matrix-unit-')));
    t.after(() => rmSync(this.dir, { recursive: true, force: true }));
    this.env = {
      ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_ENVIRONMENT: 'github-hosted',
      RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64', RUNNER_NAME: 'fixture-runner',
      RUNNER_TEMP: join(this.dir, 'final'), GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_API_URL: 'https://api.github.com', GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_REPOSITORY: POLICY.repository, GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_REPOSITORY_ID: '100',
      GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner, GITHUB_RUN_ATTEMPT: '1',
      GITHUB_RUN_ID: '200', GITHUB_REF: approval.ref, GITHUB_SHA: approval.commit,
      GITHUB_WORKFLOW_SHA: approval.commit, GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`,
      GITHUB_JOB: 'consumers', GITHUB_TOKEN: 'must-not-reach-child', NODE_AUTH_TOKEN: 'must-not-reach-child',
      NPM_TOKEN: 'must-not-reach-child', NODE_OPTIONS: '--bad-injection',
      npm_config_registry: 'https://unapproved.invalid/', npm_config_ignore_scripts: 'true',
    };
    this.event = { inputs: { action: 'prepare', approval: JSON.stringify(approval) },
      repository: { full_name: POLICY.repository, fork: false, private: false }, sender: { login: POLICY.owner } };
    this.package = packageFixture(version, nativeFiles);
    Object.assign(this.env, { GITHUB_REF: approved.ref,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${approved.ref}` });
    this.event.inputs.approval = JSON.stringify(approved);
    const sourceReport = Buffer.from('{"schemaVersion":1}\n');
    this.prepared = {
      schemaVersion: 1, status: 'prepared-awaiting-platform-gates', name: POLICY.name, version,
      source: { ref: approved.ref, tagObject: approved.tagObject, commit: approved.commit, tree: approved.tree },
      toolchain: { node: POLICY.node, npm: POLICY.npm }, sourceReportSha256: hash(sourceReport),
      artifact: { filename: 'candidate.tgz', ...digest(this.package.tarball),
        files: inspectTarball(this.package.tarball, approved).files },
    };
    this.sourceFiles = {
      'prepared.json': JSON.stringify(this.prepared), 'candidate.tgz': this.package.tarball,
      'source-gates.json': sourceReport, 'baseline.json': '{}',
    };
    this.archives = new Map();
    this.metadata = [];
    this.jobs = [];
    this.calls = [];
    const source = this.addArtifact(300, 'npm-prepared-200-1', this.sourceFiles);
    Object.assign(this.env, {
      PREPARED_MANIFEST_SHA256: hash(this.sourceFiles['prepared.json']),
      PREPARED_ARTIFACT_ID: '300', PREPARED_ARTIFACT_DIGEST: source.digest.slice(7),
      PREPARED_TARBALL_SHA256: this.prepared.artifact.sha256,
      PREPARED_TARBALL_SHA512: this.prepared.artifact.sha512,
      PREPARED_TARBALL_INTEGRITY: this.prepared.artifact.integrity,
    });
    this.writeSource(this.env.RUNNER_TEMP);
    this.reports = join(this.dir, 'reports');
    mkdirSync(this.reports);
    this.readers = {
      readArtifactMetadata: async id => structuredClone(this.metadata.find(item => String(item.id) === String(id))),
      readArtifactArchive: async id => this.archives.get(String(id)),
      readArtifacts: async () => structuredClone(this.metadata),
      readJobs: async () => structuredClone(this.jobs),
    };
  }

  async checkBootstrapReaders() {
    const f = this;
    const workflow = { ref: f.env.GITHUB_WORKFLOW_REF, commit: approval.commit, runId: '200', attempt: 1 };
    const locks = { root: 'd'.repeat(64), ui: 'e'.repeat(64) };
    Object.assign(f.prepared, {
      major: 2, channel: 'latest', workflow, producerLocks: locks,
      ci: { runId: '199', attempt: 1, headSha: approval.commit, conclusion: 'success' },
      stage: { status: 'not-submitted', stageId: null }, publicationApproval: { status: 'not-authorized' },
      registrySignatures: { status: 'pending-publication' },
      privateContentReview: { status: 'pending-owner-review', commit: approval.commit,
        artifact: digest(f.package.tarball) },
    });
    delete f.sourceFiles['baseline.json'];
    rmSync(join(f.env.RUNNER_TEMP, 'npm-prepared/baseline.json'));
    f.sourceFiles['prepared.json'] = JSON.stringify(f.prepared);
    f.archives.set('300', zip(f.sourceFiles));
    f.metadata[0].digest = `sha256:${hash(f.archives.get('300'))}`;
    f.env.PREPARED_ARTIFACT_DIGEST = f.metadata[0].digest;
    f.env.PREPARED_MANIFEST_SHA256 = hash(f.sourceFiles['prepared.json']);
    f.writeSource(f.env.RUNNER_TEMP);
    await f.complete();
    const matrix = await f.verify();
    const actor = { login: POLICY.owner, id: 101 };
    const repository = { id: 100, full_name: POLICY.repository, fork: false, private: false, owner: actor };
    const run = { id: 200, head_sha: approval.commit, path: POLICY.workflow, event: 'workflow_dispatch',
      run_attempt: 1, status: 'completed', conclusion: 'success',
      repository, head_repository: repository, actor, triggering_actor: actor };
    const peerSource = { ref: 'refs/tags/npm/v1.3.1', tagObject: hex('d'), commit: hex('e'), tree: hex('f') };
    const peerPackage = packageFixture('1.3.1');
    const peerPrepared = { schemaVersion: 1, name: POLICY.name, version: '1.3.1',
      status: 'prepared-awaiting-platform-gates', source: peerSource,
      toolchain: { node: POLICY.node, npm: POLICY.npm }, sourceReportSha256: hash('{}'),
      artifact: { filename: 'candidate.tgz', ...digest(peerPackage.tarball),
        files: inspectTarball(peerPackage.tarball, { version: '1.3.1' }).files } };
    const peerMetadata = f.addArtifact(700, 'npm-prepared-198-1', {
      'candidate.tgz': peerPackage.tarball, 'prepared.json': JSON.stringify(peerPrepared), 'source-gates.json': '{}',
    });
    Object.assign(peerMetadata.workflow_run, { id: 198, head_sha: peerSource.commit });
    const peerJobs = f.jobs.map(job => ({ ...structuredClone(job), id: job.id + 1000,
      run_id: 198, head_sha: peerSource.commit }));
    peerJobs.push({ id: 1600, name: 'source', run_id: 198, run_attempt: 1, head_sha: peerSource.commit,
      status: 'completed', conclusion: 'success', runner_id: 600, runner_name: 'unit-source', labels: ['ubuntu-24.04'],
      steps: ['Validate source, run required gates, and pack exactly once',
        'Retain canonical source bundle without repacking'].map(name => ({ name, status: 'completed', conclusion: 'success' })) });
    const peerArtifact = { schemaVersion: 1, purpose: 'service-comparison-only', name: POLICY.name,
      version: '1.3.1', source: peerSource, repository: POLICY.repository, repositoryId: '100',
      artifactId: '700', artifactDigest: peerMetadata.digest, runId: '198', runAttempt: 1,
      manifestSha256: hash(JSON.stringify(peerPrepared)), sourceReportSha256: hash('{}'),
      ...digest(peerPackage.tarball), stageEligible: false, privateScans: 'pending', humanApproval: 'pending',
      sourceJob: { id: '1600', name: 'source' },
      consumerJobs: peerJobs.slice(0, 6).map(job => ({ id: String(job.id), name: job.name })),
      sourcePassed: true, matrixPassed: true, finalizerNotRequired: true };
    const gates = { schemaVersion: 1, commit: approval.commit, artifact: digest(f.package.tarball),
      sourceReportSha256: f.prepared.sourceReportSha256, gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, {
        status: 'passed', evidence: [{ description: 'unit-only injected gate evidence', sha256: hash(name) }],
      }])) };
    const { status, ...prepared } = f.prepared;
    const manifest = { ...prepared, phase: 'prepared-not-staged', gateReportSha256: hash(JSON.stringify(gates)),
      sourceArtifact: { id: '300', digest: f.metadata[0].digest,
        preparedSha256: hash(f.sourceFiles['prepared.json']), sourceReportSha256: f.prepared.sourceReportSha256 },
      matrixArtifacts: matrix.artifactEvidence, peerArtifact };
    const metadata = f.addArtifact(800, 'npm-candidate-200-1', {
      'candidate.tgz': f.package.tarball, 'manifest.json': JSON.stringify(manifest), 'gates.json': JSON.stringify(gates),
    });
    const a = { ...approval, ciRunId: '199', ciAttempt: 1,
      artifact: { ...digest(f.package.tarball), manifestSha256: hash(JSON.stringify(manifest)),
        artifactId: '800', artifactDigest: metadata.digest, runId: '200', runAttempt: 1 } };
    f.jobs.push(...['source', 'prepare'].map(name => ({ name, head_sha: approval.commit, status: 'completed', conclusion: 'success' })));
    const readers = { ...f.readers, readJobs: async runId => runId === '198' ? peerJobs : f.jobs,
      readJson: async path => {
        if (path === 'actions/runs/200') return run;
        if (path === 'actions/runs/198') return { ...run, id: 198, head_sha: peerSource.commit, conclusion: 'failure' };
        if (path === 'git/ref/tags/npm/v1.3.1') return { ref: peerSource.ref, object: { type: 'tag', sha: peerSource.tagObject } };
        if (path === `git/tags/${peerSource.tagObject}`) return { object: { type: 'commit', sha: peerSource.commit } };
        if (path === `git/commits/${peerSource.commit}`) return { tree: { sha: peerSource.tree } };
        throw new Error(`Unexpected unit-only read ${path}`);
      } };
    const evidence = await readCandidateEvidence(a, locks, readers);
    assert.equal(evidence.evidence.consumerInstalls, 12);
    assert.equal(evidence.evidence.consumerArtifacts, 6);
    assert.equal(evidence.evidence.peerArtifactId, '700');
    const original = f.archives.get('400');
    f.archives.set('400', Buffer.from('substituted API archive'));
    await assert.rejects(() => readCandidateEvidence(a, locks, readers), /ZIP digest/);
    f.archives.set('400', original);
    f.jobs[0].conclusion = 'skipped';
    await assert.rejects(() => readCandidateEvidence(a, locks, readers));
    f.jobs[0].conclusion = 'success';
    peerJobs[0].steps[0].conclusion = 'skipped';
    await assert.rejects(() => readCandidateEvidence(a, locks, readers), /Peer step/);
    assert.throws(() => exactArchive(zip({ 'candidate.tgz': 'x', 'extra/': '' }), ['candidate.tgz']), /directory/);
  }

  async checkBootstrapSigningRun() {
    const actor = { login: POLICY.owner, id: 101 };
    const repository = { id: 100, full_name: POLICY.repository, fork: false, private: false, owner: actor };
    const run = { id: 42, head_sha: approval.commit, path: POLICY.workflow, event: 'workflow_dispatch',
      run_attempt: 1, status: 'completed', conclusion: 'success',
      repository, head_repository: repository, actor, triggering_actor: actor };
    const job = { id: 55, name: 'sign-bootstrap', run_id: 42, run_attempt: 1, head_sha: approval.commit,
      status: 'completed', conclusion: 'success', labels: ['ubuntu-24.04'], runner_name: 'unit-only',
      steps: ['Sign and verify exact bootstrap bytes once', 'Export verified bootstrap bundle']
        .map(name => ({ name, status: 'completed', conclusion: 'success' })) };
    const readers = { readJson: async () => run, readJobs: async () => [job] };
    assert.equal((await readSigningRun(approval, '42', readers, true)).repositoryId, '100');
    job.steps[1].conclusion = 'failure';
    await assert.rejects(() => readSigningRun(approval, '42', readers, true));
    job.steps[1].conclusion = 'success';
    await assert.rejects(() => readSigningRun(approval, '42', { ...readers, readJobs: async () => [
      job, { name: 'stage', status: 'completed', conclusion: 'success' },
    ] }, true));
    run.run_attempt = 2;
    await assert.rejects(() => readSigningRun(approval, '42', readers, true));
  }

  writeSource(temp) {
    for (const [name, bytes] of Object.entries(this.sourceFiles)) save(join(temp, 'npm-prepared', name), bytes);
  }

  addArtifact(id, name, files) {
    const archive = zip(files);
    this.archives.set(String(id), archive);
    const metadata = { id, name, expired: false, digest: `sha256:${hash(archive)}`,
      workflow_run: { id: 200, head_sha: approval.commit, repository_id: 100, head_repository_id: 100 } };
    this.metadata.push(metadata);
    return metadata;
  }

  lane(index) {
    const approval = this.approval;
    const lane = MATRIX[index];
    const temp = join(this.dir, `lane${index}`);
    this.writeSource(temp);
    const root = join(temp, 'checkout');
    for (const [name, data] of Object.entries(this.package.files)) save(join(root, name), data);
    save(join(root, 'package-lock.json'), '{}');
    const cli = join(temp, 'npm-consumer-toolchain-fixture/prefix/node_modules/npm/bin/npm-cli.js');
    save(cli, 'not executed');
    save(join(dirname(cli), '../package.json'), JSON.stringify({ name: 'npm', version: lane.npm }));
    const env = { ...this.env, RUNNER_TEMP: temp, RUNNER_OS: lane.os, RUNNER_NAME: `runner-${index}`,
      MATRIX_PLATFORM: lane.platform, MATRIX_NODE: lane.node, MATRIX_NPM: lane.npm, NPM_CONSUMER_CLI: cli };
    const runtime = { platform: lane.platform, versions: { node: lane.node }, arch: 'x64',
      execPath: join(temp, lane.platform === 'win32' ? 'node.exe' : 'node') };
    const executor = (file, args, options) => {
      this.calls.push({ file, args, options });
      assert.equal(options.env.GITHUB_TOKEN, undefined);
      assert.equal(options.env.NODE_AUTH_TOKEN, undefined);
      assert.equal(options.env.NPM_TOKEN, undefined);
      assert.equal(options.env.NODE_OPTIONS, undefined);
      assert.equal(options.env.npm_config_ignore_scripts, undefined);
      assert.equal(options.env.npm_config_registry, POLICY.registry);
      assert.equal(readFileSync(options.env.npm_config_userconfig, 'utf8'), '');
      if (file === 'git') {
        const request = args.slice(2);
        let stdout = '';
        if (request[0] === 'cat-file') stdout = 'tag';
        else if (request[0] === 'hash-object') stdout = hex('d');
        else if (request[0] === 'rev-parse') {
          const ref = request[1];
          stdout = ref === approval.ref ? approval.tagObject
            : ref.includes('^{tree}') ? approval.tree
              : ref.includes(POLICY.workflow) ? hex('d') : approval.commit;
        }
        return { stdout, stderr: '' };
      }
      if (args.at(-1) === '--version') return { stdout: lane.npm, stderr: '' };
      if (args.includes('ci')) return { stdout: 'injected root restore', stderr: '' };
      if (args.includes('--test')) return { stdout: tap, stderr: '' };
      assert.ok(args.includes('consumer:check'));
      return { stdout: JSON.stringify({
        name: POLICY.name, version: approval.version, sha256: this.prepared.artifact.sha256,
        node: `v${lane.node}`, npm: lane.npm, platform: lane.platform,
        installScripts: args.includes('--ignore-scripts') ? 'disabled' : 'npm-default',
        producerLockCopied: false, installedBin: true, bridgeAndUi: true,
        dependencies: [{ name: POLICY.name, version: approval.version, integrity: this.prepared.artifact.integrity }],
        registrySignature: 'pending-publication', provenance: 'not-verified-by-consumer-smoke',
      }), stderr: '' };
    };
    return { approval, env, event: this.event, root, runtime, executor, ...this.readers };
  }

  async complete() {
    for (let index = 0; index < MATRIX.length; index++) {
      const options = this.lane(index);
      await runMatrix(options);
      const name = `npm-consumer-200-1-${MATRIX[index].platform}-${MATRIX[index].npm}`;
      const report = readFileSync(join(options.env.RUNNER_TEMP, 'npm-consumer-report/report.json'));
      this.addArtifact(400 + index, name, { 'report.json': report });
      save(join(this.reports, name, 'report.json'), report);
      this.jobs.push({ id: 500 + index, name: MATRIX[index].jobName, run_id: 200, run_attempt: 1,
        head_sha: approval.commit, status: 'completed', conclusion: 'success',
        runner_id: 600 + index, runner_name: options.env.RUNNER_NAME, labels: [MATRIX[index].image],
        steps: ['Require supported hosted runner', 'Verify source transfer and run real consumers',
          'Upload one consumer report'].map(name => ({ name, status: 'completed', conclusion: 'success' })) });
    }
  }

  verify(extra = {}) {
    return verifyMatrixReports({ directory: this.reports, approval: this.approval, prepared: this.prepared,
      env: this.env, ...this.readers, ...extra });
  }

  rewriteReport(index, change) {
    const metadata = this.metadata[index + 1];
    const path = join(this.reports, metadata.name, 'report.json');
    const report = JSON.parse(readFileSync(path));
    change(report);
    const data = JSON.stringify(report);
    save(path, data);
    const archive = zip({ 'report.json': data });
    this.archives.set(String(metadata.id), archive);
    metadata.digest = `sha256:${hash(archive)}`;
  }
}

for (const version of ['1.3.1', '2.0.1']) {
  test(`Native inventory producer rejects missing, extra, renamed and changed ${version} helper files`, async t => {
    const native = Object.fromEntries(Object.entries(packageFixture(version).files)
      .filter(([path]) => path.startsWith('bin/windows/')));
    const removed = 'bin/windows/src/PoolingSecurityReader.cs';
    const missing = Object.fromEntries(Object.entries(native).filter(([path]) => path !== removed));
    for (const files of [missing, { ...native, 'bin/windows/extra.cs': 'extra' },
      { ...missing, 'bin/windows/src/UnapprovedReader.cs': native[removed] }]) {
      const f = new Fixture(t, version, files);
      await assert.rejects(runMatrix(f.lane(2)));
      assert.equal(f.calls.filter(call => call.args.includes('--test')).length, 0);
    }
    const f = new Fixture(t, version);
    const options = f.lane(2);
    save(join(options.root, 'bin/windows/PoolingSecurityHelper.exe'), 'changed checkout binary');
    await assert.rejects(runMatrix(options), /Checkout helper bytes differ from the tarball/);
    assert.equal(f.calls.filter(call => call.args.includes('--test')).length, 0);
  });

  test(`Native inventory roundtrip carries exact ${version} paths through Windows producer and both finalizers`, async t => {
    const f = new Fixture(t, version);
    const expected = Object.entries(f.package.files).filter(([path]) => path.startsWith('bin/windows/'))
      .map(([path, bytes]) => ({ path, sha256: hash(bytes) })).sort((a, b) => a.path.localeCompare(b.path));
    assert.equal(expected.length, version === '1.3.1' ? 5 : 6);
    assert.equal(expected.some(file => file.path.endsWith('/PoolingNativeFiles.cs')), version === '2.0.1');
    await f.complete();
    const matrix = await f.verify();
    const identity = { baselineCommit: version === '1.3.1' ? LEGACY_REF : CURRENT_REF,
      files: [...expected, { path: 'tools/windows-security-helper/build.ps1', sha256: hash('unit script') }],
      reproducibilityBuild: 'not-executed-in-this-run' };
    const request = { version, matrix, extractedRoot: join(f.dir, 'lane2/checkout') };
    assert.equal(verifyWindowsExecution(request, identity).length, 2);
    for (const report of matrix.nativeWindowsEvidence) assert.deepEqual(
      report.files.toSorted((a, b) => a.path.localeCompare(b.path)), expected);
    const original = structuredClone(JSON.parse(readFileSync(join(f.reports, f.metadata[3].name, 'report.json'))).nativeWindows.files);
    for (const files of [original.slice(1), [...original, { path: 'bin/windows/unapproved.cs', sha256: hash('extra') }],
      original.map((file, index) => index ? file : { ...file, sha256: hash('changed bytes') })]) {
      f.rewriteReport(2, report => { report.nativeWindows.files = files; });
      await assert.rejects(f.verify());
      f.rewriteReport(2, report => { report.nativeWindows.files = original; });
    }
    await f.verify();
  });
}

test('bootstrap unit: reader chain rechecks nine ZIPs, twelve reports and opposite T32 bytes', async t => {
  await new Fixture(t).checkBootstrapReaders();
});

test('bootstrap unit: signing-run API requires original signing job and successful export', async t => {
  await new Fixture(t).checkBootstrapSigningRun();
});

test('owner unit: actual current API run/job must be owner-only hosted original source, not signing or preparation', async () => {
  const approval = { commit: 'a'.repeat(40) };
  const owner = { login: POLICY.owner, id: 100 };
  const repository = { full_name: POLICY.repository, id: 101, owner, private: false, fork: false };
  const run = { id: 70, head_sha: approval.commit, path: POLICY.workflow, event: 'workflow_dispatch',
    run_attempt: 1, status: 'in_progress', conclusion: null, repository, head_repository: repository,
    actor: owner, triggering_actor: owner };
  const job = { id: 71, name: 'publish-bootstrap', run_id: 70, run_attempt: 1, head_sha: approval.commit,
    status: 'in_progress', conclusion: null, labels: ['ubuntu-24.04'], runner_name: 'unit-only-hosted' };
  const readers = { readJson: async () => run, readJobs: async () => [job] };
  assert.deepEqual(await readOwnerRun(approval, '70', readers), {
    runId: '70', jobId: '71', attempt: 1, repositoryId: '101', ownerId: '100',
  });
  for (const mutate of [
    () => { job.head_sha = 'b'.repeat(40); },
    () => { job.run_attempt = 2; },
    () => { job.name = 'sign-bootstrap'; },
    () => { run.actor = { login: 'another-owner', id: 100 }; },
    () => { run.event = 'push'; },
  ]) {
    const savedJob = structuredClone(job);
    const savedRun = structuredClone(run);
    mutate();
    await assert.rejects(() => readOwnerRun(approval, '70', readers));
    Object.assign(job, savedJob);
    Object.assign(run, savedRun);
  }
  await assert.rejects(() => readOwnerRun(approval, '70', { ...readers,
    readJobs: async () => [job, { ...job, id: 72, name: 'stage' }] }));
  await assert.rejects(() => readOwnerRun(approval, '70', { ...readers,
    readJobs: async () => [job, { ...job, id: 72 }] }));
});

test('consumer contexts bind npm-only refs without accepting a different tag namespace', t => {
  const f = new Fixture(t);
  for (const { version, namespace } of ['1.3.1', '2.0.1'].flatMap(version =>
    ['npm/', 'npm-r2/', 'npm-r3/'].map(namespace => ({ version, namespace })))) {
    const a = { ...approval, version, ref: `refs/tags/${namespace}v${version}` };
    const env = { ...f.env, GITHUB_REF: a.ref,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${a.ref}` };
    const event = { ...f.event, inputs: { action: 'prepare', approval: JSON.stringify(a) } };
    validateMatrixContext(env, a, event);
    assert.throws(() => validateMatrixContext({ ...env, GITHUB_REF: `refs/tags/v${version}` }, a, event));
    assert.throws(() => validateMatrixContext({ ...env,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@refs/tags/v${version}`,
    }, a, event));
    for (const ref of ['refs/heads/main', `refs/tags/${namespace}v${version}-other`,
      `refs/tags/other/v${version}`, `refs/tags/npm-r4/v${version}`]) {
      const invalid = { ...a, ref };
      const invalidEnv = { ...env, GITHUB_REF: ref,
        GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${ref}` };
      assert.throws(() => validateMatrixContext(invalidEnv, invalid), /exact approved/);
    }
  }
});

test('all six lanes execute both modes; finalizer binds actual archives and successful jobs', async t => {
  const fixture = new Fixture(t);
  await fixture.complete();
  const verified = await fixture.verify();
  assert.equal(verified.consumerLanes.length, 12);
  assert.equal(verified.nativeWindowsEvidence.length, 2);
  assert.equal(verified.artifactEvidence.length, 6);
  assert.equal(fixture.calls.filter(call => call.args.includes('consumer:check')).length, 12);
  assert.equal(fixture.calls.filter(call => call.args.includes('--test')).length, 2);
  assert.ok(verified.nativeWindowsEvidence.every(item => item.rebuild === 'not-performed' &&
    item.ordinaryDesktopToken === 'not-proven'));
});

for (const [name, mutate] of [
  ['self-hosted context', options => { options.env.ACTUAL_RUNNER_ENVIRONMENT = 'self-hosted'; }],
  ['wrong runtime', options => { options.runtime.versions.node = '24.0.0'; }],
  ['different dispatch approval', options => { options.event.inputs.approval = '{}'; }],
  ['rerun', options => { options.env.GITHUB_RUN_ATTEMPT = '2'; }],
  ['source manifest digest', options => { options.env.PREPARED_MANIFEST_SHA256 = '0'.repeat(64); }],
  ['source archive digest', options => { options.env.PREPARED_ARTIFACT_DIGEST = '0'.repeat(64); }],
  ['missing source archive digest', options => { delete options.env.PREPARED_ARTIFACT_DIGEST; }],
  ['expected tarball digest', options => { options.env.PREPARED_TARBALL_SHA256 = '0'.repeat(64); }],
]) {
  test(`runner rejects ${name} before any command`, async t => {
    const fixture = new Fixture(t);
    const options = fixture.lane(0);
    mutate(options);
    await assert.rejects(runMatrix(options));
    assert.equal(fixture.calls.length, 0);
    assert.equal(existsSync(join(options.env.RUNNER_TEMP, 'npm-consumer-report')), false);
  });
}

test('local source tampering and API source/run/repository changes fail independently', async t => {
  const fixture = new Fixture(t);
  const verify = () => verifyPreparedBundle({ directory: join(fixture.env.RUNNER_TEMP, 'npm-prepared'),
    approval, env: fixture.env, ...fixture.readers });
  save(join(fixture.env.RUNNER_TEMP, 'npm-prepared/candidate.tgz'), 'tampered');
  await assert.rejects(verify(), /bytes differ/);
  fixture.writeSource(fixture.env.RUNNER_TEMP);
  for (const key of ['id', 'head_sha', 'repository_id', 'head_repository_id']) {
    const original = fixture.metadata[0].workflow_run[key];
    fixture.metadata[0].workflow_run[key] = key === 'head_sha' ? hex('e') : 999;
    await assert.rejects(verify());
    fixture.metadata[0].workflow_run[key] = original;
  }
  fixture.archives.set('300', zip({ 'prepared.json': '{}' }));
  await assert.rejects(verify(), /archive digest mismatch/);
});

test('failed command never emits a report', async t => {
  const fixture = new Fixture(t);
  const options = fixture.lane(0);
  const execute = options.executor;
  options.executor = (file, args, context) => {
    if (args.includes('consumer:check')) throw new Error('injected consumer failure');
    return execute(file, args, context);
  };
  await assert.rejects(runMatrix(options), /injected consumer failure/);
  assert.equal(existsSync(join(options.env.RUNNER_TEMP, 'npm-consumer-report')), false);
});

test('prepared hashes and manifest are checked even when the archive and prepared-byte hashes match', async t => {
  for (const change of [
    prepared => { prepared.sourceReportSha256 = '0'.repeat(64); },
    prepared => { prepared.artifact.sha512 = '0'.repeat(128); },
    prepared => { prepared.artifact.integrity = 'sha512-invalid'; },
    prepared => { prepared.artifact.files[0].sha256 = '0'.repeat(64); },
    prepared => { prepared.source.commit = hex('e'); },
    prepared => { prepared.toolchain.npm = 'latest'; },
  ]) {
    const fixture = new Fixture(t);
    change(fixture.prepared);
    fixture.sourceFiles['prepared.json'] = JSON.stringify(fixture.prepared);
    fixture.env.PREPARED_MANIFEST_SHA256 = hash(fixture.sourceFiles['prepared.json']);
    const archive = zip(fixture.sourceFiles);
    fixture.archives.set('300', archive);
    fixture.metadata[0].digest = `sha256:${hash(archive)}`;
    fixture.env.PREPARED_ARTIFACT_DIGEST = hash(archive);
    fixture.writeSource(fixture.env.RUNNER_TEMP);
    await assert.rejects(verifyPreparedBundle({ directory: join(fixture.env.RUNNER_TEMP, 'npm-prepared'),
      approval, env: fixture.env, ...fixture.readers }));
  }
});

test('Windows checkout helper mismatch and skipped TAP cannot count as native execution', async t => {
  for (const tamper of [true, false]) {
    const fixture = new Fixture(t);
    const options = fixture.lane(2);
    if (tamper) save(join(options.root, 'bin/windows/PoolingSecurityHelper.exe'), 'wrong bytes');
    else {
      const execute = options.executor;
      options.executor = (file, args, context) => args.includes('--test')
        ? { stdout: tap.replace('# skipped 0', '# skipped 7'), stderr: '' }
        : execute(file, args, context);
    }
    await assert.rejects(runMatrix(options));
    assert.equal(existsSync(join(options.env.RUNNER_TEMP, 'npm-consumer-report')), false);
  }
});

test('matrix verifier rejects missing/duplicate artifacts and wrong/skipped/failed jobs', async t => {
  const fixture = new Fixture(t);
  await fixture.complete();
  const metadata = structuredClone(fixture.metadata);
  const jobs = structuredClone(fixture.jobs);
  for (const change of [
    () => fixture.metadata.pop(),
    () => fixture.metadata.push(structuredClone(fixture.metadata[1])),
    () => { fixture.metadata[1].expired = true; },
    () => { fixture.metadata[1].workflow_run.id = 999; },
    () => { fixture.jobs[0].conclusion = 'failure'; },
    () => { fixture.jobs[0].run_attempt = 2; },
    () => { fixture.jobs[0].head_sha = hex('e'); },
    () => { fixture.jobs[0].steps[1].conclusion = 'skipped'; },
    () => fixture.jobs.push(structuredClone(fixture.jobs[0])),
  ]) {
    change();
    await assert.rejects(fixture.verify());
    fixture.metadata = structuredClone(metadata);
    fixture.jobs = structuredClone(jobs);
  }
  const selection = await selectMatrixArtifacts({ approval, env: fixture.env, ...fixture.readers });
  assert.deepEqual(selection.map(item => item.metadata.id), [400, 401, 402, 403, 404, 405]);
});

test('local success-shaped report is rejected unless its bytes match the API archive', async t => {
  const fixture = new Fixture(t);
  await fixture.complete();
  save(join(fixture.reports, fixture.metadata[1].name, 'report.json'), '{}');
  await assert.rejects(fixture.verify(), /bytes differ/);
});

for (const [name, index, change] of [
  ['missing consumer mode', 0, report => report.consumers.pop()],
  ['wrong source tuple', 0, report => { report.source.tree = hex('e'); }],
  ['wrong prepared binding', 0, report => { report.sourceArtifact.preparedSha256 = '0'.repeat(64); }],
  ['wrong runner', 0, report => { report.runner.os = 'Windows'; }],
  ['wrong npm', 0, report => { report.toolchain.npm = 'latest'; }],
  ['wrong output hash', 0, report => { report.consumers[0].evidence.stdoutSha256 = '0'.repeat(64); }],
  ['wrong command', 0, report => { report.consumers[0].evidence.command.args.push('--force'); }],
  ['claimed registry verification', 0, report => { report.consumers[0].result.registrySignature = 'verified'; }],
  ['native skip', 2, report => { report.nativeWindows.stdout = tap.replace('# skipped 0', '# skipped 1'); }],
  ['claimed native rebuild', 2, report => { report.nativeWindows.rebuild = 'reproduced'; }],
]) {
  test(`even authenticated report bytes cannot waive ${name}`, async t => {
    const fixture = new Fixture(t);
    await fixture.complete();
    fixture.rewriteReport(index, change);
    await assert.rejects(fixture.verify());
  });
}

test('ZIP traversal, duplicate names and unsupported compression are rejected', () => {
  assert.throws(() => zipFiles(zip({ '../outside.json': '{}' })));
  assert.throws(() => zipFiles(zip({ 'report.json': '{}', 'REPORT.json': '{}' })));
  const archive = zip({ 'report.json': '{}' });
  const central = archive.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  archive.writeUInt16LE(99, central + 10);
  assert.throws(() => zipFiles(archive));
});

test('read-only adapter scopes its token to GitHub API and never forwards it to signed archive storage', async () => {
  const calls = [];
  const archive = zip({ 'report.json': '{}' });
  const fetcher = async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/zip')) {
      return { status: 302, headers: new Headers({ location: 'https://artifact-storage.example.test/signed' }) };
    }
    assert.equal(String(url), 'https://artifact-storage.example.test/signed');
    assert.equal(options.headers, undefined);
    return { status: 200, body: (async function* () { yield archive; })() };
  };
  const readers = githubReaders({ GITHUB_TOKEN: 'read-token' }, { fetcher });
  assert.deepEqual(await readers.readArtifactArchive('123'), archive);
  assert.equal(calls[0].options.headers.authorization, 'Bearer read-token');
  assert.equal(calls[0].options.redirect, 'manual');
  assert.equal(calls[1].options.redirect, 'error');
  assert.ok(calls.every(call => call.options.method === undefined));
  await assert.rejects(readers.readArtifactArchive('../escape'));
});

test('consumer npm installer uses Node plus known CLI, exact pins, empty config and no token fallback', t => {
  for (const index of [2, 3]) {
    const fixture = new Fixture(t);
    const options = fixture.lane(index);
    const bootstrap = bootstrapNpmCli(options.runtime.execPath, options.runtime.platform);
    save(join(dirname(bootstrap), '../package.json'), '{"name":"npm"}');
    options.env.GITHUB_ENV = join(fixture.dir, 'github-env');
    const commands = [];
    const executor = (file, args, context) => {
      commands.push({ file, args, context });
      assert.equal(file, options.runtime.execPath);
      assert.equal(context.env.GITHUB_TOKEN, undefined);
      assert.equal(context.env.NPM_TOKEN, undefined);
      assert.equal(context.env.NODE_AUTH_TOKEN, undefined);
      assert.equal(context.env.NODE_OPTIONS, undefined);
      assert.equal(context.env.npm_config_registry, POLICY.registry);
      assert.equal(readFileSync(context.env.npm_config_userconfig, 'utf8'), '');
      assert.equal(readFileSync(context.env.npm_config_globalconfig, 'utf8'), '');
      if (args.includes('install')) {
        assert.equal(args[0], bootstrap);
        assert.ok(args.includes(`npm@${MATRIX[index].npm}`));
        assert.ok(args.includes('--ignore-scripts'));
        const prefix = args[args.indexOf('--prefix') + 1];
        save(join(prefix, 'node_modules/npm/package.json'), JSON.stringify({ name: 'npm', version: MATRIX[index].npm }));
        save(join(prefix, 'node_modules/npm/bin/npm-cli.js'), 'not executed');
      }
      return { stdout: MATRIX[index].npm, stderr: '' };
    };
    const result = installConsumerToolchain({ ...options, executor });
    assert.equal(result.npm, MATRIX[index].npm);
    assert.equal(commands.length, 2);
    assert.match(readFileSync(options.env.GITHUB_ENV, 'utf8'), /^NPM_CONSUMER_CLI=/);
    options.env.ACTUAL_RUNNER_ENVIRONMENT = 'self-hosted';
    assert.throws(() => installConsumerToolchain({ ...options, executor }));
    assert.equal(commands.length, 2);
  }
});

test('workflow is manual, pins six lanes, transfers exact IDs and protects both OIDC jobs', () => {
  const yaml = readFileSync(new URL('../.github/workflows/npm-publish.yml', import.meta.url), 'utf8');
  assert.match(yaml, /workflow_dispatch:/);
  assert.doesNotMatch(yaml, /^\s+(?:push|pull_request|release|schedule):/m);
  assert.match(yaml, /cancel-in-progress: false/);
  for (const lane of MATRIX) {
    assert.ok(yaml.includes(`platform: ${lane.platform}, image: ${lane.image}, node: '${lane.node}', npm: '${lane.npm}'`));
  }
  assert.equal((yaml.match(/id-token: write/g) ?? []).length, 2);
  assert.ok(yaml.indexOf('id-token: write') > yaml.indexOf('\n  sign-bootstrap:'));
  assert.match(yaml, /environment: npm-publish/);
  assert.match(yaml, /needs: \[source, consumers\]/);
  assert.match(yaml, /artifact-ids: \$\{\{ steps.matrix.outputs.matrix-artifact-ids \}\}/);
  assert.match(yaml, /matrix\.mjs run/);
  assert.match(yaml, /run\.mjs finalize/);
  assert.doesNotMatch(yaml, /GITHUB_(?:SHA|REF):/);
  if (yaml.includes('node tools/publication-scanners/install.mjs')) {
    assert.ok(existsSync(new URL('../tools/publication-scanners/install.mjs', import.meta.url)));
  }
  for (const action of yaml.matchAll(/uses: actions\/[^@]+@([^\s]+)/g)) assert.match(action[1], /^[a-f0-9]{40}$/);
  assert.equal(MATRIX.length, 6);
  assert.throws(() => matrixLane({ MATRIX_PLATFORM: 'linux', MATRIX_NODE: '20', MATRIX_NPM: '12.0.2' }));
  assert.deepEqual(readdirSync(new URL('../tools/npm-publication/', import.meta.url)).filter(name => name === 'matrix.mjs'),
    ['matrix.mjs']);
});
