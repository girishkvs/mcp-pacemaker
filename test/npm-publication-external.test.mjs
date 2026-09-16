import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  aggregateExternalGates, ARTIFACT_GATES, collectGitIdentity, externalCli, externalExitCode,
  normalizeMatrix, SOURCE_GATES, verifyArtifactFiles, verifyNativeIdentity, verifyReplacement, verifyRuntimeClosure,
  verifyWindowsExecution,
} from '../tools/npm-publication/external-gates.mjs';
import { CONSUMER_TOOLCHAINS } from '../tools/npm-publication/gates.mjs';
import { CURRENT_REF, LEGACY_REF } from '../tools/compatibility/fixtures.mjs';
import { inspectRuntimeLicenses } from '../tools/npm-publication/runtime-licenses.mjs';
import {
  assertHostedScannerContext, installScanners, releaseExecutable, SCANNER_RELEASES,
} from '../tools/npm-publication/install-scanners.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const commit = 'a'.repeat(40);
const artifact = { sha256: 'b'.repeat(64), sha512: 'c'.repeat(128),
  integrity: `sha512-${Buffer.from('c'.repeat(128), 'hex').toString('base64')}` };
const mit = 'MIT License\nCopyright Synthetic Fixture\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files.';
const nativePaths = [
  'bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json',
  'bin/windows/src/AssemblyInfo.cs', 'bin/windows/src/PoolingNativeFiles.cs',
  'bin/windows/src/PoolingSecurityHelper.cs', 'bin/windows/src/PoolingSecurityReader.cs',
  'tools/windows-security-helper/build.ps1',
];
function write(root, path, value) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), typeof value === 'object' && !Buffer.isBuffer(value) ? JSON.stringify(value) : value);
}
function fixture(t, temporaryParent = tmpdir()) {
  const root = mkdtempSync(join(realpathSync.native(temporaryParent), 'publication-external-unit-'));
  t.after(() => rmSync(root, { recursive: true }));
  assert.equal(realpathSync.native(root), root, 'Owned external fixture must use the native canonical path');
  const sourceRoot = join(root, 'source');
  const extractedRoot = join(root, 'payload');
  mkdirSync(sourceRoot);
  mkdirSync(extractedRoot);
  const pkg = { name: 'mcp-pacemaker', version: '2.0.1', license: 'MIT' };
  const paths = [
    'bin/cli.mjs', 'bin/mcp-bridge.mjs', 'bin/service-control.mjs', 'bin/pooling-writer.mjs',
    'bin/pooling-config.mjs', 'bin/pooling-editor.mjs', 'bin/pooling-files.mjs',
    'bin/pooling-execution.mjs', 'bin/pooling-batches.mjs', 'bin/pooling-batch-scheduler.mjs',
    'supervisor/supervise.mjs', 'supervisor/bridge-child.mjs',
    'supervisor/supervise.sh', 'supervisor/supervise.ps1', 'ui/dist/index.html', 'ui/dist/assets/app.js',
    ...nativePaths,
  ];
  for (const path of paths) {
    write(sourceRoot, path, `synthetic ${path}`);
    write(extractedRoot, path, `synthetic ${path}`);
  }
  for (const directory of [sourceRoot, extractedRoot]) {
    write(directory, 'package.json', pkg);
    write(directory, 'LICENSE', mit);
  }
  write(extractedRoot, 'THIRD_PARTY_NOTICES.txt', 'synthetic notices');
  write(extractedRoot, 'ui/dist/THIRD_PARTY_NOTICES.txt', 'synthetic notices');
  write(extractedRoot, 'ui/dist/third-party-manifest.json', { fixture: true });
  write(sourceRoot, 'node_modules/fixture-public/package.json',
    { name: 'fixture-public', version: '1.0.0', license: 'MIT' });
  write(sourceRoot, 'node_modules/fixture-public/LICENSE', mit);
  const nativeIdentity = { baselineCommit: CURRENT_REF, reproducibilityBuild: 'not-executed-in-this-run',
    buildScript: {
      path: nativePaths.at(-1), comparison: 'exact-declared-crlf-checkout', attributesSource: commit,
      attributes: { text: 'set', eol: 'crlf', filter: 'unspecified', 'working-tree-encoding': 'unspecified', ident: 'unspecified' },
      baselineSha256: hash(`synthetic ${nativePaths.at(-1)}`),
      baselineBytes: Buffer.byteLength(`synthetic ${nativePaths.at(-1)}`),
      sourceBlobSha256: hash(`synthetic ${nativePaths.at(-1)}`),
      checkoutSha256: hash(`synthetic ${nativePaths.at(-1)}`),
      checkoutBytes: Buffer.byteLength(`synthetic ${nativePaths.at(-1)}`),
    },
    files: nativePaths.map(path => ({ path, sha256: hash(readFileSync(join(sourceRoot, path))) }))
      .sort((a, b) => a.path.localeCompare(b.path)) };
  const request = { schemaVersion: 1, phase: 'source', sourceRoot, root: sourceRoot, commit,
    name: pkg.name, version: pkg.version, requiredGates: SOURCE_GATES,
    publicPackages: ['fixture-public'] };
  return { root, sourceRoot, extractedRoot, request, nativeIdentity };
}
function gitRunner(f, { missing = false } = {}) {
  const paths = nativePaths.filter(path => f.request.version === '2.0.1' ||
    path !== 'bin/windows/src/PoolingNativeFiles.cs');
  return async (file, args) => {
    assert.equal(file, 'git');
    assert.ok(args.includes('safe.bareRepository=explicit'), 'Keep the explicit-bare safeguard');
    const at = args.indexOf('-C');
    const cwd = args[at + 1];
    const command = args.slice(at + 2);
    const gitDirectory = command[0]?.startsWith('--git-dir=') ? command.shift() : undefined;
    if (cwd !== f.sourceRoot &&
        command[0] !== 'init') {
      assert.equal(gitDirectory, `--git-dir=${cwd}`, 'Owned bare repositories must be selected explicitly');
    }
    let stdout = '';
    if (command[0] === 'rev-parse') stdout = command.includes('--git-path')
      ? join(f.sourceRoot, '.git/info/attributes') : command[1] === 'HEAD' ? `${commit}\n` : 'false\n';
    else if (command[0] === 'rev-list') stdout = '1\n';
    else if (command[0] === 'log') stdout = `${commit}\0Private Fixture\0private@example.invalid\0Private Committer\0committer@example.invalid\0\n`;
    else if (command[0] === 'cat-file' &&
        command[1] === '-e') return { code: missing ? 1 : 0, stdout: '' };
    else if (command[0] === 'ls-tree') stdout = paths.map((path, index) =>
      `100644 blob ${String(index + 1).padStart(40, '0')}\t${path}\0`).join('');
    else if (command[0] === 'check-attr') stdout = Object.entries(f.nativeIdentity.buildScript.attributes)
      .flatMap(([key, value]) => [nativePaths.at(-1), key, value]).join('\0') + '\0';
    else if (command[0] === 'cat-file') stdout = Buffer.from(`synthetic ${command[2].includes(':')
      ? nativePaths.at(-1) : paths[Number(command[2]) - 1]}`);
    else if (command[0] === 'init') assert.notEqual(cwd, f.sourceRoot);
    else if (command[0] === 'fetch') {
      assert.notEqual(cwd, f.sourceRoot);
      assert.equal(command.at(-1), f.request.version === '2.0.1' ? CURRENT_REF : LEGACY_REF);
      assert.equal(command.at(-2), 'https://github.com/girishkvs/mcp-pacemaker.git');
    } else assert.fail(`Unexpected synthetic git operation: ${command[0]}`);
    return { code: 0, stdout, stderr: '' };
  };
}
async function scanner({ request, policyPath, publicPackages }) {
  assert.deepEqual(publicPackages, ['fixture-public']);
  assert.equal(request.matrix, undefined);
  return {
    schemaVersion: 1, phase: request.phase, commit: request.commit, artifact: request.artifact,
    status: policyPath ? 'passed' : 'not-run', scannerDetails: { synthetic: true },
    gates: Object.fromEntries(request.requiredGates.map(name => [name, {
      status: name.endsWith('private-identifiers') && !policyPath ? 'not-run' : 'passed',
      ...(name.endsWith('private-identifiers') ? { ownerReview: 'pending' } : {}),
      evidence: [{ description: `Synthetic injected ${name}`, sha256: hash(name) }],
    }])),
  };
}
function commandEvidence(args, stdout = '') {
  const command = { file: resolve('synthetic-node'), args, cwd: resolve('synthetic-root') };
  return { exitCode: 0, command, commandSha256: hash(JSON.stringify(command)),
    stdoutSha256: hash(stdout), stderrSha256: hash('') };
}
function matrixFixture(nativeIdentity) {
  const matrix = { consumerLanes: [], artifactEvidence: [], nativeWindowsEvidence: [] };
  let index = 0;
  for (const platform of ['linux', 'win32', 'darwin']) {
    for (const toolchain of CONSUMER_TOOLCHAINS) {
      index++;
      const artifactId = String(index);
      const jobId = String(index + 100);
      matrix.artifactEvidence.push({ id: artifactId, jobId, runId: '42', attempt: 1,
        digest: `sha256:${hash(artifactId)}`, reportSha256: hash(jobId) });
      for (const mode of ['npm-default', 'disabled']) {
        const result = { name: 'mcp-pacemaker', version: '2.0.1', sha256: artifact.sha256,
          node: toolchain.node, npm: toolchain.npm, platform, installScripts: mode, producerLockCopied: false,
          installedBin: true, bridgeAndUi: true, registrySignature: 'pending-publication',
          provenance: 'not-verified-by-consumer-smoke',
          dependencies: [{ name: 'fixture-public', version: '1.0.0', integrity: null }] };
        matrix.consumerLanes.push({ platform, node: toolchain.node.slice(1), npm: toolchain.npm,
          mode, result, evidence: commandEvidence(['consumer:check'], JSON.stringify(result)), artifactId, jobId });
      }
      if (platform === 'win32') {
        const stdout = [
          'ok 1 - real helper inspection emits only one fingerprint and does not change file contents',
          'ok 2 - real helper prepares both files with matching security without writing config data',
          'ok 3 - real helper refuses a stale fingerprint without writing config data',
          '# tests 9', '# pass 9', '# fail 0', '# cancelled 0', '# skipped 0', '# todo 0', '',
        ].join('\n');
        matrix.nativeWindowsEvidence.push({
          platform, node: toolchain.node.slice(1), npm: toolchain.npm, artifactId, jobId,
          status: 'actual-windows-execution',
          files: nativeIdentity.files.filter(file => file.path.startsWith('bin/windows/')),
          counts: { tests: 9, pass: 9, fail: 0, cancelled: 0, skipped: 0, todo: 0 }, stdout,
          evidence: commandEvidence(['--test', 'test/windows-security-helper.test.mjs'], stdout),
          rebuild: 'not-performed', ordinaryDesktopToken: 'not-proven', inheritedBaseline: 'not-verified-by-matrix',
        });
      }
    }
  }
  return matrix;
}
function replacementFixture(f) {
  const visit = (prefix = '') => readdirSync(join(f.extractedRoot, prefix), { withFileTypes: true })
    .flatMap(entry => {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      return entry.isDirectory() ? visit(path) : [{ path, sha256: hash(readFileSync(join(f.extractedRoot, path))) }];
    });
  const files = visit();
  const legacyFiles = files.map(file => file.path === 'bin/windows/PoolingSecurityHelper.exe'
    ? { ...file, sha256: hash('synthetic legacy helper') } : file);
  const approvedArtifacts = {
    legacy: { version: '1.3.1', sha256: 'd'.repeat(64), files: legacyFiles },
    current: { version: '2.0.1', sha256: artifact.sha256, files },
  };
  const result = {
    gate: 'T32-service-replacement', node: CONSUMER_TOOLCHAINS[1].node, platform: 'linux',
    artifacts: Object.fromEntries(Object.entries(approvedArtifacts).map(([role, { files: ignored, ...value }]) => [role, value])),
    steps: [0, 1, 2, 3].map(index => ({
      from: index % 2 ? '2.0.1' : '1.3.1', to: index % 2 ? '1.3.1' : '2.0.1',
      timing: index < 2 ? 'before-first-write' : 'after-worker-loaded',
      fromInstanceId: `instance-${index}`, instanceId: `instance-${index + 1}`,
      heldBeforeAndAfterReplacement: true, ui: { version: index % 2 ? '1.3.1' : '2.0.1',
        files: files.filter(file => file.path.startsWith('ui/dist/')) },
    })),
    currentWrite: { applyBatch: 'apply', undoBatch: 'undo', workerObserved: true },
    legacyBefore: { scope: 'posix', status: 200, writeSupported: true },
    legacyAfter: { scope: 'posix', status: 200, writeSupported: true },
    secondInstanceUnchanged: 'other-instance',
    nativeHelper: { executed: false, sha256: {
      legacy: hash('synthetic legacy helper'),
      current: files.find(file => file.path === 'bin/windows/PoolingSecurityHelper.exe').sha256,
    } },
  };
  const stdout = JSON.stringify(result);
  const args = [join(f.sourceRoot, 'tools/service-replacement/check.mjs'),
    '--legacy-tarball', join(f.root, 'legacy.tgz'), '--legacy-sha256', approvedArtifacts.legacy.sha256,
    '--current-tarball', join(f.root, 'current.tgz'), '--current-sha256', artifact.sha256];
  const evidence = commandEvidence(args, stdout);
  evidence.command.cwd = f.sourceRoot;
  evidence.commandSha256 = hash(JSON.stringify(evidence.command));
  return { result, stdout, approvedArtifacts, evidence };
}
function artifactRequest(f) {
  return { ...f.request, phase: 'artifact', root: f.extractedRoot, extractedRoot: f.extractedRoot,
    requiredGates: ARTIFACT_GATES, artifact, tarball: join(f.root, 'current.tgz'),
    matrix: matrixFixture(f.nativeIdentity), replacement: replacementFixture(f),
    sourceReport: { phase: 'source', commit, nativeIdentity: f.nativeIdentity,
      gates: { 'native-release-identity': { status: 'passed' } } } };
}
const fakeNotices = () => ({ runtimeNotices: [] });

test('source combines actual injected git/scanner evidence; humans and missing policy never pass', async t => {
  const f = fixture(t);
  const report = await aggregateExternalGates(f.request, { run: gitRunner(f), scanPublication: scanner });
  assert.equal(report.status, 'pending-owner-review');
  assert.equal(externalExitCode(report), 0);
  assert.equal(report.gates['source-private-identifiers'].status, 'not-run');
  assert.equal(report.gates['author-identity'].status, 'pending-owner-review');
  assert.equal(report.gates['historical-risk-disposition'].status, 'pending-owner-review');
  assert.deepEqual(report.nativeIdentity, f.nativeIdentity);
  assert.equal(report.authorIdentity.authors, 1);
  assert.equal(report.authorIdentity.committers, 1);
  assert.doesNotMatch(JSON.stringify(report), /private@example|Private Fixture|committer@example/);
});

test('literal scanner success remains pending human review', async t => {
  const f = fixture(t);
  const report = await aggregateExternalGates(f.request, {
    run: gitRunner(f), scanPublication: scanner, policyPath: join(f.root, 'policy.json'),
  });
  assert.equal(report.gates['source-private-identifiers'].status, 'pending-owner-review');
  assert.equal(report.gates['source-private-identifiers'].literalStatus, 'passed');
  assert.equal(report.gates['source-private-identifiers'].ownerReview, 'pending');
});

test('public approval missing blocks before scanners; findings are not owner-review exceptions', async t => {
  const f = fixture(t);
  let calls = 0;
  const denied = await aggregateExternalGates({ ...f.request, publicPackages: undefined }, {
    scanPublication: async () => { calls++; throw new Error('must not run'); },
  });
  assert.equal(calls, 0);
  assert.equal(externalExitCode(denied), 1);
  const failed = await aggregateExternalGates(f.request, {
    scanPublication: async options => {
      const report = await scanner(options);
      report.status = 'findings';
      report.gates['source-gitleaks'].status = 'failed';
      return report;
    },
  });
  assert.equal(externalExitCode(failed), 1);
  assert.equal(failed.gates['source-gitleaks'].status, 'failed');
});

test('scanner execution errors block aggregation despite pending private review and preserve safe evidence', async t => {
  const f = fixture(t);
  const diagnostic = 'Error waiting for git command to complete.';
  const provenance = { synthetic: true, executionSha256: hash(diagnostic) };
  for (const failedGate of [undefined, 'source-trufflehog']) {
    let downstreamCalls = 0;
    const report = await aggregateExternalGates(f.request, {
      run: async () => { downstreamCalls++; throw new Error('Must not run after scanner failure'); },
      scanPublication: async options => {
        const scanned = await scanner(options);
        scanned.status = 'error';
        scanned.scannerDetails = provenance;
        if (failedGate) scanned.gates[failedGate].status = 'failed';
        return scanned;
      },
    });
    assert.equal(report.status, 'failed');
    assert.equal(externalExitCode(report), 1);
    assert.equal(downstreamCalls, 0);
    assert.deepEqual(report.scannerDetails, provenance);
    assert.equal(report.nativeIdentity, undefined);
    assert.equal(report.authorIdentity, undefined);
    assert.ok(!JSON.stringify(report).includes(diagnostic));
  }
});

test('native changed bytes fail; missing baseline fetch is exact SHA in an owned bare repo', async t => {
  const f = fixture(t);
  let owned;
  const injected = gitRunner(f, { missing: true });
  const run = async (file, args, options) => {
    if (args.includes('fetch')) owned = args[args.indexOf('-C') + 1];
    return injected(file, args, options);
  };
  assert.deepEqual(await verifyNativeIdentity(f.request, { run }), f.nativeIdentity);
  assert.equal(existsSync(owned), false);
  write(f.sourceRoot, nativePaths[0], 'changed');
  await assert.rejects(verifyNativeIdentity(f.request, { run: gitRunner(f) }));
});

class NativeCheckoutFixture {
  constructor(t, version = '2.0.1') {
    this.fixture = fixture(t);
    this.paths = nativePaths.filter(path => version === '2.0.1' ||
      path !== 'bin/windows/src/PoolingNativeFiles.cs');
    if (version === '1.3.1') rmSync(join(this.fixture.sourceRoot, 'bin/windows/src/PoolingNativeFiles.cs'));
    this.script = nativePaths.at(-1);
    this.blob = Buffer.from("# UTF-8 fixture: \u03bb\nparam()\nWrite-Output 'unit only'\n");
    write(this.fixture.sourceRoot, this.script, this.blob);
    write(this.fixture.sourceRoot, '.gitattributes', '* text=auto\n*.ps1 text eol=crlf\n');
    this.git(['init', '--quiet']);
    for (const path of ['.gitattributes', ...this.paths]) this.index(path);
    this.tree = this.git(['write-tree']).toString().trim();
    this.request = { ...this.fixture.request, version, commit: this.tree };
    this.git(['checkout-index', '--all', '--force']);
  }

  git(args, input) {
    const result = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
      '-c', 'core.attributesFile=', '-c', 'core.hooksPath=', '-C', this.fixture.sourceRoot, ...args], {
      input, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
        HOME: this.fixture.root, USERPROFILE: this.fixture.root, GIT_CONFIG_NOSYSTEM: '1',
        GIT_ATTR_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' },
    });
    assert.equal(result.status, 0, 'Offline fixture Git command failed');
    return result.stdout;
  }

  index(path) {
    const object = this.git(['hash-object', '-w', '--stdin'],
      readFileSync(join(this.fixture.sourceRoot, path))).toString().trim();
    this.git(['update-index', '--add', '--cacheinfo', `100644,${object},${path}`]);
  }

  run(file, args, options) {
    assert.equal(file, 'git');
    assert.equal(args.includes('fetch'), false, 'This real-checkout unit fixture must remain offline');
    const ref = this.request.version === '2.0.1' ? CURRENT_REF : LEGACY_REF;
    // Only the immutable baseline lookup is injected; object reads, attributes and checkout are real Git.
    const translated = args.map(arg => arg === ref ? this.tree :
      arg === `${ref}^{commit}` ? `${this.tree}^{tree}` : arg);
    const result = spawnSync(file, translated, options);
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  verify() {
    return verifyNativeIdentity(this.request, { run: this.run.bind(this) });
  }
}

for (const version of ['2.0.1', '1.3.1']) {
  for (const [autocrlf, eol] of [['false', 'lf'], ['false', 'crlf'], ['true', 'crlf']]) {
    test(`Native source checkout preserves exact LF bytes: ${version}, autocrlf=${autocrlf}, eol=${eol}`, t => {
      const f = new NativeCheckoutFixture(t, version);
      const sources = f.paths.filter(path => path.endsWith('.cs'));
      const bytes = Buffer.from('namespace CheckoutFixture\n{\n    internal sealed class NativeSource { }\n}\n');
      write(f.fixture.sourceRoot, '.gitattributes', readFileSync(new URL('../.gitattributes', import.meta.url)));
      f.index('.gitattributes');
      for (const path of sources) {
        write(f.fixture.sourceRoot, path, bytes);
        f.index(path);
        rmSync(join(f.fixture.sourceRoot, path));
      }
      f.git(['-c', `core.autocrlf=${autocrlf}`, '-c', `core.eol=${eol}`, 'checkout-index', '--', ...sources]);
      for (const path of sources) assert.deepEqual(readFileSync(join(f.fixture.sourceRoot, path)), bytes, path);
    });
  }

  test(`NativeIdentity real Git checkout accepts only the declared build-script representation: ${version}`, async t => {
    const f = new NativeCheckoutFixture(t, version);
    const checkout = readFileSync(join(f.fixture.sourceRoot, f.script));
    assert.deepEqual(checkout, Buffer.from(f.blob.toString().replace(/\n/g, '\r\n')));
    assert.notEqual(hash(checkout), hash(f.blob));
    const identity = await f.verify();
    assert.equal(identity.files.length, f.paths.length);
    assert.equal(identity.files.find(file => file.path === f.script).sha256, hash(checkout));
    assert.equal(identity.buildScript.baselineSha256, hash(f.blob));
    assert.equal(identity.buildScript.checkoutSha256, hash(checkout));
    assert.equal(identity.buildScript.comparison, 'exact-declared-crlf-checkout');
    assert.equal(identity.reproducibilityBuild, 'not-executed-in-this-run');
  });
}

test('NativeIdentity rejects script content, mixed endings and encoding changes without touching native bytes', async t => {
  const f = new NativeCheckoutFixture(t);
  const path = join(f.fixture.sourceRoot, f.script);
  const original = readFileSync(path);
  for (const [name, bytes] of [
    ['content', Buffer.concat([original, Buffer.from('# changed\r\n')])],
    ['whitespace', Buffer.from(original.toString().replace('param()', 'param( )'))],
    ['LF instead of declared CRLF', f.blob],
    ['mixed endings', Buffer.from(original.toString().replace('\r\n', '\n'))],
    ['bare CR', Buffer.from(original.toString().replace('\r\n', '\r'))],
    ['double CR', Buffer.from(original.toString().replace('\r\n', '\r\r\n'))],
    ['missing final newline', original.subarray(0, -2)],
    ['UTF-8 BOM', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), original])],
    ['UTF-16', Buffer.from(original.toString(), 'utf16le')],
    ['invalid UTF-8', Buffer.concat([original, Buffer.from([0xff])])],
    ['NUL', Buffer.concat([original, Buffer.from([0])])],
  ]) {
    await t.test(name, async () => {
      writeFileSync(path, bytes);
      await assert.rejects(f.verify());
      writeFileSync(path, original);
    });
  }
  await f.verify();
});

test('NativeIdentity retains strict binary metadata and every C# byte and inventory guard', async t => {
  const f = new NativeCheckoutFixture(t);
  for (const path of f.paths.filter(path => path !== f.script)) {
    await t.test(path, async () => {
      const original = readFileSync(join(f.fixture.sourceRoot, path));
      write(f.fixture.sourceRoot, path, Buffer.concat([original, Buffer.from('\r\n')]));
      await assert.rejects(f.verify());
      write(f.fixture.sourceRoot, path, original);
    });
  }
  write(f.fixture.sourceRoot, 'bin/windows/unapproved.cs', 'unit only');
  await assert.rejects(f.verify());
  rmSync(join(f.fixture.sourceRoot, 'bin/windows/unapproved.cs'));
  await f.verify();
});

test('NativeIdentity checks the committed script and committed attributes, not a replacement working file', async t => {
  const f = new NativeCheckoutFixture(t);
  const original = readFileSync(join(f.fixture.sourceRoot, f.script));
  write(f.fixture.sourceRoot, f.script, Buffer.concat([f.blob, Buffer.from('# changed source\n')]));
  f.index(f.script);
  f.request.commit = f.git(['write-tree']).toString().trim();
  write(f.fixture.sourceRoot, f.script, original);
  await assert.rejects(f.verify());
  write(f.fixture.sourceRoot, f.script, f.blob);
  f.index(f.script);
  write(f.fixture.sourceRoot, f.script, original);
  for (const attributes of ['-text eol=crlf', 'text eol=lf', 'text eol=crlf filter=custom',
    'text eol=crlf working-tree-encoding=UTF-16', 'text eol=crlf ident']) {
    write(f.fixture.sourceRoot, '.gitattributes', `*.ps1 ${attributes}\n`);
    f.index('.gitattributes');
    f.request.commit = f.git(['write-tree']).toString().trim();
    write(f.fixture.sourceRoot, '.gitattributes', '*.ps1 text eol=crlf\n');
    await assert.rejects(f.verify());
  }
});

test('NativeIdentity rejects noncanonical immutable script encodings even when checkout bytes agree', async t => {
  const f = new NativeCheckoutFixture(t);
  for (const bytes of [
    Buffer.from([0xff]), Buffer.from([0xef, 0xbb, 0xbf, 0x61]),
    Buffer.from('unit', 'utf16le'), Buffer.from('unit\r\n'), Buffer.from('unit\0'),
  ]) {
    write(f.fixture.sourceRoot, f.script, bytes);
    f.index(f.script);
    f.tree = f.git(['write-tree']).toString().trim();
    f.request.commit = f.tree;
    await assert.rejects(f.verify());
  }
});

test('NativeIdentity refuses local attributes that mask changed committed attributes', async t => {
  const f = new NativeCheckoutFixture(t);
  write(f.fixture.sourceRoot, '.gitattributes', '*.ps1 text eol=lf\n');
  f.index('.gitattributes');
  f.request.commit = f.git(['write-tree']).toString().trim();
  write(f.fixture.sourceRoot, '.git/info/attributes', '*.ps1 text eol=crlf\n');
  await assert.rejects(f.verify());
});

test('legacy uses LEGACY_REF, not current baseline; incomplete reachable history fails', async t => {
  const f = fixture(t);
  f.request.version = '1.3.1';
  rmSync(join(f.sourceRoot, 'bin/windows/src/PoolingNativeFiles.cs'));
  const identity = await verifyNativeIdentity(f.request, { run: gitRunner(f, { missing: true }) });
  assert.equal(identity.baselineCommit, LEGACY_REF);
  const base = gitRunner(f);
  await assert.rejects(collectGitIdentity(f.request, { run: async (file, args, options) => args.includes('rev-list')
    ? { code: 0, stdout: '2\n' } : base(file, args, options) }));
});

test('artifact aggregator uses two Linux npm12 adapter summaries and all12 OSV graphs', async t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  let adapterCalls = 0;
  let advisoryCalls = 0;
  const report = await aggregateExternalGates(request, {
    scanPublication: async options => {
      adapterCalls++;
      assert.equal(options.request.consumers.length, 2);
      assert.ok(options.request.consumers.every(item => item.platform === 'linux' &&
        item.npm === CONSUMER_TOOLCHAINS[1].npm));
      assert.equal(options.request.requiredGates.includes('consumer-advisories'), false);
      return scanner(options);
    },
    advisories: async options => {
      advisoryCalls++;
      assert.equal(options.consumers.length, 12);
      assert.deepEqual(options.publicPackages, ['fixture-public']);
      assert.equal(options.locks, undefined);
      assert.equal(options.localArtifact.sha256, artifact.sha256);
      return { schemaVersion: 1, status: 'passed', synthetic: true };
    },
    licenses: options => inspectRuntimeLicenses(options, { verifyNotices: fakeNotices }),
    artifactFiles: async () => [{ path: 'synthetic-test-only', sha256: hash('fixture') }],
  });
  assert.equal(adapterCalls, 1);
  assert.equal(advisoryCalls, 1);
  assert.equal(report.status, 'pending-owner-review', JSON.stringify(report.error));
  for (const name of ARTIFACT_GATES.filter(name => name !== 'payload-private-identifiers')) {
    assert.equal(report.gates[name].status, 'passed', name);
  }
  assert.equal(report.nativeWindows[0].ordinaryDesktopToken, 'not-proven');
  assert.equal(report.nativeWindows[0].rebuild, 'not-performed');
  assert.equal(report.runtimeLicenses.coverage.consumerGraphs, 12);
  assert.doesNotMatch(JSON.stringify(report), /private@example|synthetic-root|synthetic-node/);
});

test('all12 matrix rejects missing, duplicate, substituted hash/toolchain, or --version-only lanes', t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  assert.equal(normalizeMatrix(request)[0].node, 'v22.23.2');
  const changes = [
    value => value.matrix.consumerLanes.pop(),
    value => { value.matrix.consumerLanes[1] = value.matrix.consumerLanes[0]; },
    value => { value.matrix.consumerLanes[0].result.sha256 = 'e'.repeat(64); },
    value => { value.matrix.consumerLanes[0].result.node = '22.23.2'; },
    value => { value.matrix.consumerLanes[0].result.bridgeAndUi = false; },
    value => { value.matrix.consumerLanes[0].result.producerLockCopied = true; },
    value => { value.matrix.artifactEvidence[0].digest = 'unverified'; },
    value => { value.consumers = value.matrix.consumerLanes.slice(0, 2).map(item => item.result); },
  ];
  for (const change of changes) {
    const copy = structuredClone(request);
    change(copy);
    assert.throws(() => normalizeMatrix(copy));
  }
});

test('runtime closure needs the actual lazy writer, not only a version result', t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  const consumers = normalizeMatrix(request);
  assert.ok(verifyRuntimeClosure(request, consumers).files.some(file => file.path === 'bin/pooling-writer.mjs'));
  rmSync(join(f.extractedRoot, 'bin/pooling-writer.mjs'));
  assert.throws(() => verifyRuntimeClosure(request, consumers));
});

test('missing replacement cannot pass artifact aggregation; OSV finding blocks licenses', async t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  const injected = {
    scanPublication: scanner, advisories: async () => ({ status: 'passed' }),
    licenses: options => inspectRuntimeLicenses(options, { verifyNotices: fakeNotices }),
    artifactFiles: async () => [],
  };
  const report = await aggregateExternalGates({ ...request, replacement: undefined }, injected);
  assert.equal(report.status, 'failed');
  assert.equal(report.gates['service-replacement'].status, 'failed');
  let licenseCalls = 0;
  const findings = await aggregateExternalGates(request, { ...injected,
    advisories: async () => ({ status: 'findings', synthetic: true }),
    licenses: async () => { licenseCalls++; throw new Error('must not run'); },
  });
  assert.equal(findings.gates['consumer-advisories'].status, 'failed');
  assert.equal(licenseCalls, 0);
});

test('artifact bytes and full extracted tree must match the actual tar inspector result', t => {
  const f = fixture(t);
  const root = join(f.root, 'tiny-extraction');
  mkdirSync(root);
  write(root, 'package.json', 'tiny fixture');
  const tarball = join(f.root, 'synthetic.tgz');
  write(f.root, 'synthetic.tgz', 'synthetic archive input');
  const bytes = readFileSync(tarball);
  const request = { ...f.request, extractedRoot: root, tarball,
    artifact: { sha256: hash(bytes), sha512: createHash('sha512').update(bytes).digest('hex') } };
  const inspect = actual => {
    assert.deepEqual(actual, bytes);
    return { files: [{ path: 'package.json', sha256: hash('tiny fixture') }] };
  };
  assert.equal(verifyArtifactFiles(request, { inspect }).length, 1);
  write(root, 'extra.txt', 'unscanned file');
  assert.throws(() => verifyArtifactFiles(request, { inspect }));
  write(f.root, 'synthetic.tgz', 'altered');
  assert.throws(() => verifyArtifactFiles(request, { inspect }));
});

test('Windows execution requires baseline bytes, both lanes, real test names, and zero skips', t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  assert.equal(verifyWindowsExecution(request, f.nativeIdentity).length, 2);
  for (const change of [
    value => value.matrix.nativeWindowsEvidence.pop(),
    value => { value.sourceReport.nativeIdentity.baselineCommit = LEGACY_REF; },
    value => { value.matrix.nativeWindowsEvidence[0].files[0].sha256 = 'e'.repeat(64); },
    value => { value.matrix.nativeWindowsEvidence[0].counts.skipped = 1; },
    value => { value.matrix.nativeWindowsEvidence[0].ordinaryDesktopToken = 'proven'; },
  ]) {
    const copy = structuredClone(request);
    change(copy);
    assert.throws(() => verifyWindowsExecution(copy, copy.sourceReport.nativeIdentity));
  }
  write(f.extractedRoot, nativePaths[0], 'different tarball helper');
  assert.throws(() => verifyWindowsExecution(request, f.nativeIdentity));
});

test('Native inventory finalizer accepts the real five legacy paths and rejects baseline substitution', t => {
  const f = fixture(t);
  const currentOnly = 'bin/windows/src/PoolingNativeFiles.cs';
  f.request.version = '1.3.1';
  f.nativeIdentity.baselineCommit = LEGACY_REF;
  f.nativeIdentity.files = f.nativeIdentity.files.filter(file => file.path !== currentOnly);
  for (const root of [f.sourceRoot, f.extractedRoot]) rmSync(join(root, currentOnly));
  const request = artifactRequest(f);
  for (const lane of request.matrix.consumerLanes) lane.result.version = '1.3.1';
  assert.equal(f.nativeIdentity.files.filter(file => file.path.startsWith('bin/windows/')).length, 5);
  const verified = verifyWindowsExecution(request, f.nativeIdentity);
  assert.equal(verified.length, 2);
  assert.ok(verified.every(report => report.files.length === 5));
  assert.throws(() => verifyWindowsExecution(request, { ...f.nativeIdentity, baselineCommit: CURRENT_REF }));
  for (const files of [f.nativeIdentity.files.slice(1),
    [...f.nativeIdentity.files, { path: 'bin/windows/unapproved.cs', sha256: hash('extra') }],
    f.nativeIdentity.files.map((file, index) => index ? file : { ...file, sha256: hash('changed') })]) {
    assert.throws(() => verifyWindowsExecution(request, { ...f.nativeIdentity, files }));
  }
});

test('T32 requires supplied actual command result, four ordered replacements and both approved artifacts', t => {
  const f = fixture(t);
  const request = artifactRequest(f);
  assert.equal(verifyReplacement(request).steps.length, 4);
  assert.throws(() => verifyReplacement({ ...request, replacement: undefined }));
  for (const change of [
    receipt => { receipt.approvedArtifacts.legacy.sha256 = 'e'.repeat(64); },
    receipt => { receipt.result.steps[0].heldBeforeAndAfterReplacement = false; },
    receipt => { receipt.result.steps[0].timing = 'after-worker-loaded'; },
    receipt => { receipt.result.steps[1].fromInstanceId = 'unrelated'; },
    receipt => { receipt.result.steps[0].ui.files = []; },
    receipt => { receipt.result.secondInstanceUnchanged = receipt.result.steps[0].instanceId; },
    receipt => { receipt.result.currentWrite.workerObserved = false; },
    receipt => { receipt.result.nativeHelper.sha256.current = hash('wrong helper'); },
    receipt => { receipt.approvedArtifacts.current.files[0].sha256 = hash('wrong own file'); },
    receipt => { receipt.evidence.exitCode = 1; },
  ]) {
    const copy = structuredClone(request);
    change(copy.replacement);
    copy.replacement.stdout = JSON.stringify(copy.replacement.result);
    copy.replacement.evidence.stdoutSha256 = hash(copy.replacement.stdout);
    assert.throws(() => verifyReplacement(copy));
  }
});

test('real installed license text covers exact graphs only; uninstalled version never uses producer lock', async t => {
  const f = fixture(t);
  const consumers = normalizeMatrix(artifactRequest(f));
  const input = { sourceRoot: f.sourceRoot, extractedRoot: f.extractedRoot, consumers,
    name: 'mcp-pacemaker', version: '2.0.1' };
  const report = await inspectRuntimeLicenses(input, { verifyNotices: fakeNotices });
  assert.equal(report.packages.length, 2);
  assert.ok(report.packages.every(pkg => pkg.license === 'MIT' &&
    pkg.files[0].sha256 === hash(mit)));
  assert.doesNotMatch(JSON.stringify(report), /Copyright Synthetic|publication-external-unit/);
  consumers[0].dependencies[0].version = '1.0.1';
  await assert.rejects(inspectRuntimeLicenses(input, { verifyNotices: fakeNotices }),
    /Exact-version license review required: fixture-public@1.0.1/);
});

test('unknown declaration, absent text, wrong text, and packed notice failure all block', async t => {
  const f = fixture(t);
  const input = { sourceRoot: f.sourceRoot, extractedRoot: f.extractedRoot,
    consumers: normalizeMatrix(artifactRequest(f)), name: 'mcp-pacemaker', version: '2.0.1' };
  const path = 'node_modules/fixture-public/package.json';
  write(f.sourceRoot, path, { name: 'fixture-public', version: '1.0.0', license: 'UNREVIEWED' });
  await assert.rejects(inspectRuntimeLicenses(input, { verifyNotices: fakeNotices }), /unknown or missing/);
  write(f.sourceRoot, path, { name: 'fixture-public', version: '1.0.0', license: 'MIT' });
  write(f.sourceRoot, 'node_modules/fixture-public/LICENSE', 'unrelated '.repeat(30));
  await assert.rejects(inspectRuntimeLicenses(input, { verifyNotices: fakeNotices }), /text does not support/);
  rmSync(join(f.sourceRoot, 'node_modules/fixture-public/LICENSE'));
  await assert.rejects(inspectRuntimeLicenses(input, { verifyNotices: fakeNotices }), /no standalone license/);
  await assert.rejects(inspectRuntimeLicenses(input, { verifyNotices: () => { throw new Error('packed notices changed'); } }),
    /packed notices changed/);
});

test('Yoga missing LICENSE is covered only by exact reviewed installed/packed supplement', async t => {
  const f = fixture(t);
  write(f.sourceRoot, 'node_modules/yoga-layout/package.json', { name: 'yoga-layout', version: '3.2.1', license: 'MIT' });
  const consumers = normalizeMatrix(artifactRequest(f));
  for (const consumer of consumers) consumer.dependencies = [{ name: 'yoga-layout', version: '3.2.1', integrity: null }];
  const input = { sourceRoot: f.sourceRoot, extractedRoot: f.extractedRoot,
    consumers, name: 'mcp-pacemaker', version: '2.0.1' };
  const supplement = { name: 'yoga-layout', version: '3.2.1', license: 'MIT', distribution: 'separately-installed',
    licenses: [{ file: 'upstream/yoga-LICENSE.txt', text: mit, sha256: hash(mit) }] };
  const options = { verifyNotices: () => ({ runtimeNotices: [supplement] }), readSupplements: () => [structuredClone(supplement)] };
  const report = await inspectRuntimeLicenses(input, options);
  assert.equal(report.packages.find(pkg => pkg.name === 'yoga-layout').source,
    'reviewed-exact-installed-version-and-packed-supplement');
  await assert.rejects(inspectRuntimeLicenses(input, { ...options,
    readSupplements: () => [{ ...supplement, version: '3.2.2' }] }), /changed reviewed packed supplement/);
  consumers[0].dependencies[0].version = '3.2.2';
  await assert.rejects(inspectRuntimeLicenses(input, options), /Exact-version license review required: yoga-layout@3.2.2/);
});

test('CLI writes only new outside-root safe reports; no overwrite or unknown options', async t => {
  const f = fixture(t);
  const input = join(f.root, 'request.json');
  const output = join(f.root, 'output.json');
  write(f.root, 'request.json', f.request);
  const injected = { scanPublication: scanner, run: gitRunner(f) };
  assert.equal(await externalCli(['--request', input, '--output', output], injected), 0);
  assert.equal(JSON.parse(readFileSync(output)).gates['author-identity'].status, 'pending-owner-review');
  await assert.rejects(externalCli(['--request', input, '--output', output], injected));
  await assert.rejects(externalCli(['--request', input, '--output', join(f.sourceRoot, 'out.json')], injected));
  await assert.rejects(externalCli(['--request', input, '--fake-approval', output], injected));
});

test('owned external fixtures canonicalize real aliased temp parents', async t => {
  const parent = mkdtempSync(join(realpathSync.native(tmpdir()), 'publication-external-alias-'));
  t.after(() => rmSync(parent, { recursive: true }));
  const physical = join(parent, 'physical');
  const alias = join(parent, 'alias');
  const linkType = process.platform === 'win32' ? 'junction' : 'dir';
  mkdirSync(physical);
  symlinkSync(physical, alias, linkType);
  assert.notEqual(realpathSync(alias), resolve(alias));

  await t.test('canonical fixtures reach source, license and exclusive CLI checks', async child => {
    const f = fixture(child, alias);
    assert.equal(dirname(f.root), physical);
    assert.equal(realpathSync.native(f.root), f.root);
    const injected = { scanPublication: scanner, run: gitRunner(f) };
    const native = await verifyNativeIdentity(f.request, injected);
    assert.equal(native.baselineCommit, CURRENT_REF);
    const consumers = normalizeMatrix(artifactRequest(f));
    const licenses = await inspectRuntimeLicenses({
      sourceRoot: f.sourceRoot, extractedRoot: f.extractedRoot, consumers,
      name: 'mcp-pacemaker', version: '2.0.1',
    }, { verifyNotices: fakeNotices });
    assert.equal(licenses.packages.length, 2);
    const input = join(f.root, 'request.json');
    const output = join(f.root, 'output.json');
    write(f.root, 'request.json', f.request);
    assert.equal(await externalCli(['--request', input, '--output', output], injected), 0);
    const bytes = readFileSync(output);
    assert.equal(JSON.parse(bytes).gates['author-identity'].status, 'pending-owner-review');
    await assert.rejects(externalCli(['--request', input, '--output', output], injected));
    assert.deepEqual(readFileSync(output), bytes);
  });

  await t.test('external aliases and linked child evidence remain rejected', async child => {
    const f = fixture(child, alias);
    const request = artifactRequest(f);
    const externalAlias = join(alias, basename(f.root));
    assert.throws(() => verifyRuntimeClosure({
      ...request, extractedRoot: join(externalAlias, 'payload'),
    }), /Linked evidence path/);
    write(f.root, 'request.json', f.request);
    await assert.rejects(externalCli([
      '--request', join(f.root, 'request.json'), '--output', join(externalAlias, 'rejected.json'),
    ], { scanPublication: scanner, run: gitRunner(f) }), /Output parent must not be a link/);
    assert.equal(existsSync(join(f.root, 'rejected.json')), false);
    const retainedBin = join(f.root, 'retained-bin');
    const bin = join(f.extractedRoot, 'bin');
    const original = readFileSync(join(bin, 'cli.mjs'));
    renameSync(bin, retainedBin);
    symlinkSync(retainedBin, bin, linkType);
    assert.throws(() => verifyRuntimeClosure(request), /Linked evidence path/);
    assert.deepEqual(readFileSync(join(retainedBin, 'cli.mjs')), original);
    const dependency = join(f.sourceRoot, 'node_modules', 'fixture-public');
    const retainedDependency = join(f.root, 'retained-dependency');
    renameSync(dependency, retainedDependency);
    symlinkSync(retainedDependency, dependency, linkType);
    await assert.rejects(inspectRuntimeLicenses({
      sourceRoot: f.sourceRoot, extractedRoot: f.extractedRoot, consumers: normalizeMatrix(request),
      name: 'mcp-pacemaker', version: '2.0.1',
    }, { verifyNotices: fakeNotices }), /Linked installed dependency/);
    assert.equal(readFileSync(join(retainedDependency, 'LICENSE'), 'utf8'), mit);
  });
});

test('scanner bootstrap refuses local/self-hosted/wrong platform before network or execution', async t => {
  const f = fixture(t);
  let calls = 0;
  const fail = async () => { calls++; throw new Error('must not call'); };
  await assert.rejects(installScanners({ env: {}, fetchBytes: fail, run: fail }), /approved hosted/);
  const env = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Linux',
    RUNNER_ARCH: 'X64', ImageOS: 'ubuntu24', GITHUB_REPOSITORY: 'girishkvs/mcp-pacemaker',
    RUNNER_TEMP: f.root, GITHUB_ENV: join(f.root, 'github-env') };
  assertHostedScannerContext(env, { platform: 'linux', arch: 'x64' });
  for (const [key, value] of [['RUNNER_ENVIRONMENT', 'self-hosted'], ['ImageOS', 'ubuntu22'],
    ['GITHUB_REPOSITORY', 'fork/example']]) {
    assert.throws(() => assertHostedScannerContext({ ...env, [key]: value }, { platform: 'linux', arch: 'x64' }));
  }
  assert.equal(calls, 0);
  write(f.root, 'github-env', '');
  await assert.rejects(installScanners({ env, runtime: { platform: 'linux', arch: 'x64' },
    fetchBytes: async url => {
      assert.equal(url, 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt');
      return Buffer.from('unknown download cannot bless itself');
    }, run: fail }), /checksum file changed/);
  assert.equal(readFileSync(env.GITHUB_ENV, 'utf8'), '');
  assert.equal(calls, 0);
  assert.equal(SCANNER_RELEASES.gitleaks.version, '8.30.1');
  assert.equal(SCANNER_RELEASES.trufflehog.version, '3.97.1');
});

function tinyArchive(name = 'gitleaks', type = '0', companions = []) {
  const bytes = Buffer.from('tiny executable fixture; never executed');
  const records = [...companions, { name, type }].flatMap(entry => {
    const header = Buffer.alloc(512);
    header.write(entry.name);
    header.write('0000700\0', 100);
    header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124);
    header.fill(32, 148, 156);
    header.write(entry.type ?? '0', 156);
    if (entry.prefix) header.write(entry.prefix, 345);
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
    return [header, bytes, Buffer.alloc(512 - bytes.length)];
  });
  return { bytes, archive: gzipSync(Buffer.concat([...records, Buffer.alloc(1024)])) };
}

test('release reader accepts nested regular documentation in pinned scanner archives', () => {
  const fixture = tinyArchive('trufflehog', '0', [
    { name: 'LICENSE' }, { name: 'README.md' }, { name: 'docs/man/trufflehog.1' },
  ]);
  assert.deepEqual(releaseExecutable(fixture.archive, 'trufflehog'), fixture.bytes);
  const prefixed = tinyArchive('trufflehog', '0', [{ prefix: 'docs/man', name: 'trufflehog.1' }]);
  assert.deepEqual(releaseExecutable(prefixed.archive, 'trufflehog'), prefixed.bytes);
});

test('release reader rejects unsafe companion paths, links, and duplicate members', () => {
  for (const name of ['/manual', '../manual', 'docs/../manual', './manual', 'docs//manual',
    'docs\\manual', 'C:/manual', '.', '..']) {
    assert.throws(() => releaseExecutable(tinyArchive('trufflehog', '0', [{ name }]).archive, 'trufflehog'),
      /Unreviewed release archive entry/);
  }
  for (const type of ['1', '2', '5']) {
    const fixture = tinyArchive('trufflehog', '0', [{ name: 'docs/manual', type }]);
    assert.throws(() => releaseExecutable(fixture.archive, 'trufflehog'), /Unreviewed release archive entry/);
  }
  const duplicate = tinyArchive('trufflehog', '0', [
    { name: 'docs/man/trufflehog.1' }, { name: 'docs/man/trufflehog.1' },
  ]);
  assert.throws(() => releaseExecutable(duplicate.archive, 'trufflehog'), /Unreviewed release archive entry/);
  assert.throws(() => releaseExecutable(tinyArchive('bin/trufflehog').archive, 'trufflehog'),
    /Pinned release executable missing/);
});

test('release reader extracts exact fixed member; refuses links/traversal/wrong member/truncation', () => {
  const fixture = tinyArchive();
  assert.deepEqual(releaseExecutable(fixture.archive, 'gitleaks'), fixture.bytes);
  assert.throws(() => releaseExecutable(tinyArchive('../gitleaks').archive, 'gitleaks'));
  assert.throws(() => releaseExecutable(tinyArchive('gitleaks', '2').archive, 'gitleaks'));
  assert.throws(() => releaseExecutable(fixture.archive, 'trufflehog'));
  assert.throws(() => releaseExecutable(fixture.archive.subarray(0, 10), 'gitleaks'));
});
