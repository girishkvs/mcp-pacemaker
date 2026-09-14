import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { digest, POLICY } from '../tools/npm-publication/policy.mjs';
import { inspectTarball } from '../tools/npm-publication/tarball.mjs';
import {
  MATRIX, githubReaders, matrixLane, runMatrix, selectMatrixArtifacts, verifyMatrixReports, verifyPreparedBundle, zipFiles,
} from '../tools/npm-publication/matrix.mjs';
import {
  bootstrapNpmCli, installConsumerToolchain,
} from '../tools/npm-publication/install-consumer-toolchain.mjs';

// Every subprocess and API boundary is injected. These tests never install or start a consumer.
const hash = data => digest(data).sha256;
const hex = value => value.repeat(40);
const approval = {
  schemaVersion: 1, scope: 'prepare', approver: POLICY.owner, name: POLICY.name, version: '1.3.1',
  ref: 'refs/tags/v1.3.1', tagObject: hex('a'), commit: hex('b'), tree: hex('c'),
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

function packageFixture() {
  const pkg = {
    name: POLICY.name, version: approval.version, repository: { url: `git+https://github.com/${POLICY.repository}.git` },
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
      .map(name => [`bin/windows/src/${name}.cs`, 'fixture source'])),
  };
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
  constructor(t) {
    this.dir = mkdtempSync(join(tmpdir(), 'pacemaker-matrix-unit-'));
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
    this.package = packageFixture();
    const sourceReport = Buffer.from('{"schemaVersion":1}\n');
    this.prepared = {
      schemaVersion: 1, status: 'prepared-awaiting-platform-gates', name: POLICY.name, version: approval.version,
      source: { ref: approval.ref, tagObject: approval.tagObject, commit: approval.commit, tree: approval.tree },
      toolchain: { node: POLICY.node, npm: POLICY.npm }, sourceReportSha256: hash(sourceReport),
      artifact: { filename: 'candidate.tgz', ...digest(this.package.tarball),
        files: inspectTarball(this.package.tarball, approval).files },
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
    return verifyMatrixReports({ directory: this.reports, approval, prepared: this.prepared,
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

test('workflow is manual, pins six lanes, transfers exact IDs and keeps OIDC in protected stage only', () => {
  const yaml = readFileSync(new URL('../.github/workflows/npm-publish.yml', import.meta.url), 'utf8');
  assert.match(yaml, /workflow_dispatch:/);
  assert.doesNotMatch(yaml, /^\s+(?:push|pull_request|release|schedule):/m);
  assert.match(yaml, /cancel-in-progress: false/);
  for (const lane of MATRIX) {
    assert.ok(yaml.includes(`platform: ${lane.platform}, image: ${lane.image}, node: '${lane.node}', npm: '${lane.npm}'`));
  }
  assert.equal((yaml.match(/id-token: write/g) ?? []).length, 1);
  assert.ok(yaml.indexOf('id-token: write') > yaml.indexOf('\n  stage:'));
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
