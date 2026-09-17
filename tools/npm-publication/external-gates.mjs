import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CURRENT_REF, LEGACY_REF } from '../compatibility/fixtures.mjs';
import { scanAdvisories, scanPublicationRequest } from '../publication-scanners/index.mjs';
import { CONSUMER_TOOLCHAINS, validateConsumerMatrix } from './gates.mjs';
import { inspectRuntimeLicenses, LICENSE_FAILURE_HINTS, safeLicenseDiagnostic } from './runtime-licenses.mjs';
import { inspectTarball } from './tarball.mjs';

export const SOURCE_GATES = Object.freeze([
  'source-gitleaks', 'source-trufflehog', 'source-private-identifiers', 'producer-advisories',
  'author-identity', 'native-release-identity', 'historical-risk-disposition',
]);
export const ARTIFACT_GATES = Object.freeze([
  'payload-gitleaks', 'payload-trufflehog', 'payload-private-identifiers', 'consumer-advisories',
  'licenses-notices', 'runtime-closure', 'consumer-npm11', 'consumer-npm12',
  'consumer-platforms', 'native-windows-execution', 'service-replacement',
]);
const PRIVATE = new Set(['source-private-identifiers', 'payload-private-identifiers']);
const HUMAN = new Set(['author-identity', 'historical-risk-disposition', ...PRIVATE]);
const hash = value => createHash('sha256').update(value).digest('hex');
const evidence = (description, value) => ({ description, sha256: hash(JSON.stringify(value)) });
const pass = (description, value) => ({ status: 'passed', evidence: [evidence(description, value)] });
const sha = value => assert.match(value ?? '', /^[a-f0-9]{64}$/);
const id = value => {
  assert.match(String(value ?? ''), /^[1-9][0-9]*$/);
  return String(value);
};
const equal = (left, right) => assert.deepEqual(left, right);
const baseline = version => {
  assert.ok(['1.3.1', '2.0.1'].includes(version), 'Unsupported native baseline version');
  return version === '1.3.1' ? LEGACY_REF : CURRENT_REF;
};
const BUILD_SCRIPT = 'tools/windows-security-helper/build.ps1';
const BUILD_ATTRIBUTES = Object.freeze({
  text: 'set', eol: 'crlf', filter: 'unspecified', 'working-tree-encoding': 'unspecified', ident: 'unspecified',
});

function inside(root, path) {
  const name = relative(resolve(root), resolve(path));
  return name === '' ||
    name !== '..' &&
    !name.startsWith(`..${sep}`) &&
    !isAbsolute(name);
}

function filesUnder(root, prefix) {
  const files = [];
  const visit = path => {
    const full = join(root, path);
    assert.equal(realpathSync(full), resolve(full), 'Linked evidence path');
    const info = lstatSync(full);
    assert.equal(info.isSymbolicLink(), false);
    if (info.isDirectory()) {
      for (const name of readdirSync(full).sort()) visit(`${path}/${name}`);
    } else {
      assert.ok(info.isFile() &&
        info.size > 0, 'Empty or special evidence file');
      files.push({ path, sha256: hash(readFileSync(full)) });
    }
  };
  visit(prefix);
  return files;
}

function command(file, args, options) {
  const result = spawnSync(file, args, { ...options, shell: false,
    timeout: 120_000, maxBuffer: 64 * 1024 * 1024 });
  return { code: result.error ? -1 : result.status, stdout: result.stdout ?? Buffer.alloc(0),
    stderr: result.stderr ?? Buffer.alloc(0) };
}

async function gitRead(root, args, run, { allowFailure = false, home = tmpdir(), gitDirectory } = {}) {
  const env = {
    PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
    HOME: home, USERPROFILE: home, TMPDIR: home, TEMP: home, TMP: home,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_ATTR_NOSYSTEM: '1',
  };
  const result = await run('git', ['-c', 'core.hooksPath=', '-c', 'credential.helper=',
    '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=', '-c', 'safe.bareRepository=explicit', '-C', root,
    ...(gitDirectory ? [`--git-dir=${gitDirectory}`] : []), ...args], { cwd: root, env });
  if (!allowFailure) assert.equal(result.code, 0, 'Git evidence command failed');
  return { ...result, stdout: Buffer.from(result.stdout ?? '') };
}

export async function collectGitIdentity(request, { run = command } = {}) {
  equal((await gitRead(request.sourceRoot, ['rev-parse', 'HEAD'], run)).stdout.toString().trim(), request.commit);
  equal((await gitRead(request.sourceRoot, ['rev-parse', '--is-shallow-repository'], run)).stdout.toString().trim(), 'false');
  const count = Number((await gitRead(request.sourceRoot, ['rev-list', '--count', request.commit], run)).stdout.toString().trim());
  const bytes = (await gitRead(request.sourceRoot,
    ['log', '--no-use-mailmap', '--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00', request.commit, '--'], run)).stdout;
  const records = bytes.toString('utf8').trimEnd().split('\0\n');
  assert.ok(Number.isSafeInteger(count) &&
    count > 0 &&
    records.length === count, 'Incomplete reachable identity history');
  const authors = new Set();
  const committers = new Set();
  const commits = new Set();
  for (const record of records) {
    const fields = record.replace(/\0$/, '').split('\0');
    assert.equal(fields.length, 5);
    assert.match(fields[0], /^[a-f0-9]{40}$/);
    commits.add(fields[0]);
    authors.add(hash(JSON.stringify(fields.slice(1, 3))));
    committers.add(hash(JSON.stringify(fields.slice(3, 5))));
  }
  assert.equal(commits.size, count);
  assert.ok(commits.has(request.commit));
  return { commit: request.commit, scope: 'HEAD and all reachable ancestors; raw author and committer fields, no mailmap',
    commits: count, authors: authors.size, committers: committers.size, evidenceSha256: hash(bytes),
    review: 'pending-owner-review; hashes/counts do not approve identities or settle historical failures' };
}

export async function verifyNativeIdentity(request, { run = command } = {}) {
  const baselineCommit = baseline(request.version);
  let repository = request.sourceRoot;
  let owned;
  try {
    const probe = await gitRead(repository, ['cat-file', '-e', `${baselineCommit}^{commit}`], run, { allowFailure: true });
    if (probe.code !== 0) {
      owned = mkdtempSync(join(tmpdir(), 'publication-native-baseline-'));
      repository = owned;
      await gitRead(repository, ['init', '--bare', '.'], run, { home: owned });
      await gitRead(repository, ['fetch', '--no-tags', '--depth=1',
        'https://github.com/girishkvs/mcp-pacemaker.git', baselineCommit], run,
      { home: owned, gitDirectory: owned });
    }
    const repositoryOptions = owned ? { home: owned, gitDirectory: owned } : {};
    const tree = (await gitRead(repository, ['ls-tree', '-r', '-z', baselineCommit, '--',
      'bin/windows', 'tools/windows-security-helper/build.ps1'], run, repositoryOptions)).stdout.toString();
    const entries = tree.split('\0').filter(Boolean).map(line => {
      const match = line.match(/^(100644|100755) blob ([a-f0-9]{40})\t(.+)$/);
      assert.ok(match, 'Unreviewed native git object');
      const path = match[3];
      assert.ok(path.startsWith('bin/windows/') ||
        path === 'tools/windows-security-helper/build.ps1');
      assert.ok(!path.split('/').includes('..'));
      return { object: match[2], path };
    });
    const local = [...filesUnder(request.sourceRoot, 'bin/windows'),
      ...filesUnder(request.sourceRoot, 'tools/windows-security-helper/build.ps1')];
    equal(local.map(file => file.path).sort(), entries.map(file => file.path).sort());
    equal(entries.length, request.version === '1.3.1' ? 6 : 7);
    for (const path of ['bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json',
      'tools/windows-security-helper/build.ps1']) assert.ok(entries.some(file => file.path === path));
    let buildScript;
    for (const entry of entries) {
      const bytes = (await gitRead(repository, ['cat-file', 'blob', entry.object], run, repositoryOptions)).stdout;
      const actual = local.find(file => file.path === entry.path);
      if (entry.path === BUILD_SCRIPT) {
        buildScript = await verifyBuildScriptCheckout(request, bytes, actual, run);
      } else equal(hash(bytes), actual.sha256);
    }
    return { baselineCommit, files: local.sort((a, b) => a.path.localeCompare(b.path)),
      buildScript, reproducibilityBuild: 'not-executed-in-this-run' };
  } finally {
    if (owned) rmSync(owned, { recursive: true });
  }
}

async function verifyBuildScriptCheckout(request, baselineBytes, actual, run) {
  const source = (await gitRead(request.sourceRoot,
    ['cat-file', 'blob', `${request.commit}:${BUILD_SCRIPT}`], run)).stdout;
  equal(source, baselineBytes);
  const infoAttributes = (await gitRead(request.sourceRoot,
    ['rev-parse', '--path-format=absolute', '--git-path', 'info/attributes'], run)).stdout.toString().trim();
  assert.ok(isAbsolute(infoAttributes));
  equal(lstatSync(infoAttributes, { throwIfNoEntry: false }), undefined);
  const output = (await gitRead(request.sourceRoot,
    ['check-attr', `--source=${request.commit}`, '-z', ...Object.keys(BUILD_ATTRIBUTES), '--', BUILD_SCRIPT], run)).stdout;
  const fields = output.toString('utf8').split('\0');
  equal(fields.pop(), '');
  equal(fields, Object.entries(BUILD_ATTRIBUTES).flatMap(([key, value]) => [BUILD_SCRIPT, key, value]));
  assert.ok(baselineBytes.length > 0 &&
    baselineBytes.length <= 128 * 1024, 'Unexpected build script size');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(baselineBytes);
  assert.doesNotMatch(text, /[\u0000-\u0008\u000b-\u001f\u007f\ufeff]/u,
    'Build script must be a BOM-free UTF-8 Git blob with LF endings');
  equal(Buffer.from(text), baselineBytes);
  const checkout = readFileSync(join(request.sourceRoot, BUILD_SCRIPT));
  equal(hash(checkout), actual.sha256);
  // Render only the committed, explicitly declared checkout form. Never normalize payload/native bytes.
  equal(checkout, Buffer.from(text.replace(/\n/g, '\r\n')));
  return {
    path: BUILD_SCRIPT, comparison: 'exact-declared-crlf-checkout',
    attributesSource: request.commit, attributes: { ...BUILD_ATTRIBUTES },
    baselineSha256: hash(baselineBytes), baselineBytes: baselineBytes.length,
    sourceBlobSha256: hash(source), checkoutSha256: hash(checkout), checkoutBytes: checkout.length,
  };
}

function checkCommandEvidence(value, stdout) {
  equal(value.exitCode, 0);
  assert.ok(typeof value.command?.file === 'string' &&
    Array.isArray(value.command.args) &&
    value.command.args.every(arg => typeof arg === 'string') &&
    typeof value.command.cwd === 'string', 'Missing actual command vector');
  sha(value.commandSha256);
  sha(value.stdoutSha256);
  sha(value.stderrSha256);
  equal(value.commandSha256, hash(JSON.stringify(value.command)));
  if (stdout !== undefined) equal(value.stdoutSha256, hash(stdout));
}

export function normalizeMatrix(request) {
  const matrix = request.matrix;
  assert.ok(matrix, 'Verified hosted matrix receipt required');
  assert.equal(matrix.artifactEvidence?.length, 6);
  const archives = new Map();
  const jobs = new Set();
  const runs = new Set();
  for (const archive of matrix.artifactEvidence) {
    const key = id(archive.id);
    assert.ok(!archives.has(key));
    assert.ok(!jobs.has(id(archive.jobId)));
    archives.set(key, archive);
    jobs.add(id(archive.jobId));
    runs.add(id(archive.runId));
    equal(archive.attempt, 1);
    assert.match(archive.digest, /^sha256:[a-f0-9]{64}$/);
    sha(archive.reportSha256);
  }
  equal(runs.size, 1);
  const consumers = matrix.consumerLanes.map(lane => {
    const archive = archives.get(id(lane.artifactId));
    assert.ok(archive);
    equal(id(lane.jobId), id(archive.jobId));
    equal(lane.result.platform, lane.platform);
    equal(lane.result.node, `v${lane.node.replace(/^v/, '')}`);
    equal(lane.result.npm, lane.npm);
    equal(lane.result.installScripts, lane.mode);
    checkCommandEvidence(lane.evidence);
    return lane.result;
  });
  validateConsumerMatrix(consumers, { version: request.version, artifact: request.artifact });
  if (request.consumers !== undefined) {
    const linux12 = consumers.filter(item => item.platform === 'linux' &&
      item.npm === CONSUMER_TOOLCHAINS[1].npm);
    equal(request.consumers.toSorted((a, b) => a.installScripts.localeCompare(b.installScripts)),
      linux12.toSorted((a, b) => a.installScripts.localeCompare(b.installScripts)));
  }
  for (const [key] of archives) {
    const lanes = matrix.consumerLanes.filter(lane => id(lane.artifactId) === key);
    equal(lanes.length, 2);
    equal(new Set(lanes.map(lane => `${lane.platform}/${lane.node}/${lane.npm}`)).size, 1);
  }
  return consumers;
}

export function verifyArtifactFiles(request, { inspect = inspectTarball } = {}) {
  const info = lstatSync(request.tarball);
  assert.ok(info.isFile() &&
    !info.isSymbolicLink() &&
    info.size > 0 &&
    info.size <= 32 * 1024 * 1024, 'Invalid candidate archive');
  const bytes = readFileSync(request.tarball);
  equal(hash(bytes), request.artifact.sha256);
  equal(createHash('sha512').update(bytes).digest('hex'), request.artifact.sha512);
  const inspection = inspect(bytes, { name: request.name, version: request.version, commit: request.commit });
  const extracted = readdirSync(request.extractedRoot).sort()
    .flatMap(path => filesUnder(request.extractedRoot, path))
    .sort((a, b) => a.path.localeCompare(b.path));
  equal(extracted, inspection.files.map(({ path, sha256 }) => ({ path, sha256 }))
    .sort((a, b) => a.path.localeCompare(b.path)));
  return extracted;
}

export function verifyWindowsExecution(request, nativeIdentity) {
  equal(nativeIdentity.baselineCommit, baseline(request.version));
  equal(nativeIdentity.reproducibilityBuild, 'not-executed-in-this-run');
  const expected = nativeIdentity.files.filter(file => file.path.startsWith('bin/windows/'))
    .sort((a, b) => a.path.localeCompare(b.path));
  const paths = ['bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json',
    'bin/windows/src/AssemblyInfo.cs', 'bin/windows/src/PoolingSecurityHelper.cs',
    'bin/windows/src/PoolingSecurityReader.cs'];
  if (request.version === '2.0.1') paths.push('bin/windows/src/PoolingNativeFiles.cs');
  equal(expected.map(file => file.path).sort(), paths.sort());
  equal(filesUnder(request.extractedRoot, 'bin/windows').sort((a, b) => a.path.localeCompare(b.path)), expected);
  const reports = request.matrix.nativeWindowsEvidence;
  equal(reports.length, 2);
  return CONSUMER_TOOLCHAINS.map(toolchain => {
    const matches = reports.filter(report => report.platform === 'win32' &&
      `v${report.node.replace(/^v/, '')}` === toolchain.node &&
      report.npm === toolchain.npm);
    equal(matches.length, 1);
    const report = matches[0];
    const archive = request.matrix.artifactEvidence.find(item => id(item.id) === id(report.artifactId));
    assert.ok(archive);
    equal(id(report.jobId), id(archive.jobId));
    assert.ok(request.matrix.consumerLanes.some(lane => lane.platform === 'win32' &&
      lane.npm === toolchain.npm &&
      id(lane.artifactId) === id(report.artifactId)));
    equal(report.status, 'actual-windows-execution');
    equal(report.files.toSorted((a, b) => a.path.localeCompare(b.path)), expected);
    equal(report.rebuild, 'not-performed');
    equal(report.ordinaryDesktopToken, 'not-proven');
    equal(report.inheritedBaseline, 'not-verified-by-matrix');
    checkCommandEvidence(report.evidence, report.stdout);
    const counts = {};
    for (const key of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
      const found = [...report.stdout.matchAll(new RegExp(`^# ${key} (\\d+)\\r?$`, 'gm'))];
      equal(found.length, 1);
      counts[key] = Number(found[0][1]);
    }
    equal(counts, report.counts);
    assert.ok(counts.tests >= 9);
    equal(counts.pass, counts.tests);
    for (const key of ['fail', 'cancelled', 'skipped', 'todo']) equal(counts[key], 0);
    assert.ok(!/^(?:not ok\b|ok .+# (?:SKIP|TODO)\b)/im.test(report.stdout));
    for (const name of ['real helper inspection emits only one fingerprint and does not change file contents',
      'real helper prepares both files with matching security without writing config data',
      'real helper refuses a stale fingerprint without writing config data']) {
      assert.ok(report.stdout.split(/\r?\n/).some(line => /^ok \d+ - /.test(line) &&
        line.endsWith(name)));
    }
    return { platform: 'win32', node: toolchain.node, npm: toolchain.npm, files: expected,
      counts, stdoutSha256: report.evidence.stdoutSha256, artifactId: id(report.artifactId),
      jobId: id(report.jobId), baselineCommit: nativeIdentity.baselineCommit,
      inheritedBaseline: 'matched-source-release-identity', rebuild: 'not-performed',
      ordinaryDesktopToken: 'not-proven' };
  });
}

export function verifyRuntimeClosure(request, consumers) {
  const required = [
    'bin/cli.mjs', 'bin/mcp-bridge.mjs', 'bin/service-control.mjs', 'bin/pooling-writer.mjs',
    'bin/pooling-config.mjs', 'bin/pooling-editor.mjs', 'bin/pooling-files.mjs',
    'bin/windows', 'supervisor/supervise.mjs', 'supervisor/bridge-child.mjs',
    'supervisor/supervise.sh', 'supervisor/supervise.ps1', 'ui/dist',
  ];
  if (request.version === '2.0.1') required.push('bin/pooling-execution.mjs', 'bin/pooling-batches.mjs',
    'bin/pooling-batch-scheduler.mjs');
  const files = required.flatMap(path => filesUnder(request.extractedRoot, path));
  assert.ok(files.some(file => file.path === 'ui/dist/index.html'));
  assert.ok(files.some(file => /^ui\/dist\/assets\/.+\.js$/.test(file.path)));
  for (const consumer of consumers) {
    equal(consumer.installedBin, true);
    equal(consumer.bridgeAndUi, true);
    equal(consumer.sha256, request.artifact.sha256);
  }
  return { files, consumers: consumers.map(({ platform, node, npm, installScripts, installedBin, bridgeAndUi }) =>
    ({ platform, node, npm, installScripts, installedBin, bridgeAndUi })),
  limitation: 'Actual parent installed-bin and bridge/UI checks plus extracted path hashes, not --version alone; native execution and service replacement are separate gates' };
}

// Receipt from main's executed check.mjs and independently verified own/peer bundle inspections.
export function verifyReplacement(request) {
  const receipt = request.replacement;
  assert.ok(receipt, 'Actual T32 service replacement receipt required');
  const result = receipt.result;
  equal(JSON.parse(receipt.stdout), result);
  checkCommandEvidence(receipt.evidence, receipt.stdout);
  equal(result.gate, 'T32-service-replacement');
  equal(result.node, `v${CONSUMER_TOOLCHAINS[1].node.replace(/^v/, '')}`);
  equal(result.platform, 'linux');
  const approved = receipt.approvedArtifacts;
  const ownRole = request.version === '1.3.1' ? 'legacy' : 'current';
  equal(approved[ownRole].sha256, request.artifact.sha256);
  const args = receipt.evidence.command.args;
  equal(args.length, 9);
  equal(resolve(args[0]), join(request.sourceRoot, 'tools/service-replacement/check.mjs'));
  equal(resolve(receipt.evidence.command.cwd), resolve(request.sourceRoot));
  assert.ok(isAbsolute(receipt.evidence.command.file));
  for (const [index, role, version] of [[1, 'legacy', '1.3.1'], [5, 'current', '2.0.1']]) {
    equal(args[index], `--${role}-tarball`);
    assert.ok(isAbsolute(args[index + 1]));
    equal(args[index + 2], `--${role}-sha256`);
    sha(approved[role].sha256);
    equal(args[index + 3], approved[role].sha256);
    equal(approved[role].version, version);
    equal(result.artifacts[role], { version, sha256: approved[role].sha256 });
    assert.ok(Array.isArray(approved[role].files) &&
      approved[role].files.length > 0, 'Verified own/peer file manifests required');
    for (const file of approved[role].files) {
      assert.match(file.path, /^[A-Za-z0-9_./@+-]+$/);
      assert.ok(!file.path.split('/').some(part => ['', '.', '..'].includes(part)));
      sha(file.sha256);
    }
  }
  const ownFiles = readdirSync(request.extractedRoot).flatMap(path => filesUnder(request.extractedRoot, path))
    .sort((a, b) => a.path.localeCompare(b.path));
  equal(approved[ownRole].files.map(({ path, sha256 }) => ({ path, sha256 }))
    .sort((a, b) => a.path.localeCompare(b.path)), ownFiles);
  equal(result.nativeHelper.executed, false);
  for (const role of ['legacy', 'current']) {
    const helper = approved[role].files.find(file => file.path === 'bin/windows/PoolingSecurityHelper.exe');
    assert.ok(helper);
    equal(result.nativeHelper.sha256[role], helper.sha256);
  }
  equal(result.steps.length, 4);
  const sequence = [
    ['1.3.1', '2.0.1', 'before-first-write'], ['2.0.1', '1.3.1', 'before-first-write'],
    ['1.3.1', '2.0.1', 'after-worker-loaded'], ['2.0.1', '1.3.1', 'after-worker-loaded'],
  ];
  let previous;
  const instances = new Set();
  for (const [index, step] of result.steps.entries()) {
    equal([step.from, step.to, step.timing], sequence[index]);
    assert.ok(typeof step.fromInstanceId === 'string' &&
      step.fromInstanceId.length > 0 &&
      typeof step.instanceId === 'string' &&
      step.instanceId.length > 0 &&
      step.fromInstanceId !== step.instanceId);
    if (previous) equal(step.fromInstanceId, previous);
    previous = step.instanceId;
    instances.add(step.instanceId);
    equal(step.heldBeforeAndAfterReplacement, true);
    equal(step.ui.version, step.to);
    const role = step.to === '1.3.1' ? 'legacy' : 'current';
    const expected = approved[role].files.filter(file => file.path.startsWith('ui/dist/'))
      .map(({ path, sha256 }) => ({ path, sha256 })).sort((a, b) => a.path.localeCompare(b.path));
    assert.ok(expected.some(file => /^ui\/dist\/assets\/.+\.js$/.test(file.path)));
    equal(step.ui.files.toSorted((a, b) => a.path.localeCompare(b.path)), expected);
  }
  equal(instances.size, 4);
  assert.ok(typeof result.secondInstanceUnchanged === 'string' &&
    result.secondInstanceUnchanged.length > 0 &&
    !instances.has(result.secondInstanceUnchanged) &&
    result.steps[0].fromInstanceId !== result.secondInstanceUnchanged);
  equal(result.currentWrite.workerObserved, true);
  assert.ok(result.currentWrite.applyBatch &&
    result.currentWrite.undoBatch &&
    result.currentWrite.applyBatch !== result.currentWrite.undoBatch);
  equal(result.legacyBefore, { scope: 'posix', status: 200, writeSupported: true });
  equal(result.legacyAfter, result.legacyBefore);
  return { artifacts: result.artifacts, steps: result.steps.map(({ from, to, timing, heldBeforeAndAfterReplacement, ui }) =>
    ({ from, to, timing, heldBeforeAndAfterReplacement, ui })),
  workerObserved: true, secondInstanceEvidenceSha256: hash(result.secondInstanceUnchanged),
  nativeHelper: { executed: false, sha256: result.nativeHelper.sha256 },
  commandSha256: receipt.evidence.commandSha256, stdoutSha256: receipt.evidence.stdoutSha256,
  limitations: 'Owned Linux managed holds, actual stop/restart/HTTP UI byte checks and loaded writers; not OS autostart registration, ordinary Windows token, or browser rendering' };
}

function validateRequest(request) {
  equal(request.schemaVersion, 1);
  assert.ok(['source', 'artifact'].includes(request.phase));
  assert.match(request.commit ?? '', /^[a-f0-9]{40}$/);
  equal(request.name, 'mcp-pacemaker');
  baseline(request.version);
  for (const path of [request.sourceRoot, request.root]) assert.ok(typeof path === 'string' &&
    isAbsolute(path));
  const required = request.phase === 'source' ? SOURCE_GATES : ARTIFACT_GATES;
  assert.ok(Array.isArray(request.requiredGates) &&
    request.requiredGates.length > 0);
  assert.equal(new Set(request.requiredGates).size, request.requiredGates.length);
  for (const gate of request.requiredGates) assert.ok(required.includes(gate), 'Unknown external gate');
  assert.ok(Array.isArray(request.publicPackages) &&
    request.publicPackages.length > 0 &&
    request.publicPackages.every(name => typeof name === 'string' &&
      /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)), 'Explicit owner-approved public package list required before scanner/OSV calls');
  if (request.phase === 'source') equal(resolve(request.root), resolve(request.sourceRoot));
  else {
    for (const path of [request.extractedRoot, request.tarball]) assert.ok(typeof path === 'string' &&
      isAbsolute(path));
    equal(resolve(request.root), resolve(request.extractedRoot));
    sha(request.artifact.sha256);
    assert.match(request.artifact.sha512, /^[a-f0-9]{128}$/);
    equal(request.artifact.integrity, `sha512-${Buffer.from(request.artifact.sha512, 'hex').toString('base64')}`);
  }
}

// The matrix receipt must already have passed matrix.mjs verifyMatrixReports in the caller.
// Injected operations are for unit tests, never approval overrides in request JSON.
export async function aggregateExternalGates(request, {
  run = command, scanPublication = scanPublicationRequest, advisories = scanAdvisories,
  licenses = inspectRuntimeLicenses, artifactFiles = verifyArtifactFiles,
  policyPath, exemptionsPath, tools, fetchImpl,
} = {}) {
  const report = { schemaVersion: 1, phase: request?.phase, commit: request?.commit,
    ...(request?.phase === 'artifact' ? { artifact: Object.fromEntries(['sha256', 'sha512', 'integrity']
      .map(key => [key, request.artifact?.[key]])) } : {}), gates: {} };
  let active = 'request-validation';
  try {
    validateRequest(request);
    policyPath ??= request.policyPath;
    exemptionsPath ??= request.exemptionsPath;
    for (const path of [policyPath, exemptionsPath]) {
      if (path !== undefined) assert.ok(typeof path === 'string' &&
        isAbsolute(path), 'Policy/exemption paths must be explicit absolute local paths');
    }
    let consumers;
    if (request.phase === 'artifact') {
      active = 'consumer-platforms';
      consumers = normalizeMatrix(request);
      active = 'runtime-closure';
      report.artifactFiles = await artifactFiles(request);
    }
    active = 'scanner-adapter';
    const scannerNames = request.phase === 'source' ? SOURCE_GATES.slice(0, 4) : ARTIFACT_GATES.slice(0, 3);
    const scannerRequest = { ...request, requiredGates: scannerNames,
      ...(consumers ? { consumers: consumers.filter(item => item.platform === 'linux' &&
        item.npm === CONSUMER_TOOLCHAINS[1].npm) } : {}) };
    // Do not pass receipts, private JSON, or author/history evidence into scanner request details.
    for (const key of ['matrix', 'replacement', 'sourceReport', 'publicPackages', 'policyPath', 'exemptionsPath']) {
      delete scannerRequest[key];
    }
    const scanned = await scanPublication({ request: scannerRequest, policyPath, exemptionsPath,
      publicPackages: request.publicPackages, tools, fetchImpl });
    equal(scanned.schemaVersion, 1);
    equal(scanned.phase, request.phase);
    equal(scanned.commit, request.commit);
    if (request.phase === 'artifact') {
      for (const key of ['sha256', 'sha512', 'integrity']) equal(scanned.artifact[key], request.artifact[key]);
    }
    report.scannerDetails = scanned.scannerDetails;
    for (const name of scannerNames) {
      active = name;
      const gate = scanned.gates?.[name];
      assert.ok(gate);
      assert.ok(Array.isArray(gate.evidence) &&
        gate.evidence.length > 0);
      for (const item of gate.evidence) sha(item.sha256);
      report.gates[name] = gate;
      if (PRIVATE.has(name)) {
        equal(gate.ownerReview, 'pending');
        assert.ok(['passed', 'not-run'].includes(gate.status), 'Private literal findings block publication');
        if (gate.status === 'passed') report.gates[name] = { ...gate, status: 'pending-owner-review', literalStatus: 'passed' };
      } else equal(gate.status, 'passed');
    }
    assert.ok(!['error', 'findings'].includes(scanned.status), 'Scanner finding or error blocks publication');
    if (request.phase === 'source') {
      active = 'author-identity';
      report.authorIdentity = await collectGitIdentity(request, { run });
      report.gates['author-identity'] = { status: 'pending-owner-review', ownerReview: 'pending',
        evidence: [evidence('Actual reachable author/committer evidence; owner identity review required', report.authorIdentity)] };
      active = 'historical-risk-disposition';
      report.gates[active] = { status: 'pending-owner-review', ownerReview: 'pending',
        evidence: [evidence('Reachable history binding only; fresh tests do not resolve prior timeout/CI uncertainty',
          { commit: request.commit, historySha256: report.authorIdentity.evidenceSha256 })] };
      active = 'native-release-identity';
      report.nativeIdentity = await verifyNativeIdentity(request, { run });
      report.gates[active] = pass('Native helper bytes match immutable same-major release; build script matches its Git blob and declared CRLF checkout; no rebuild', report.nativeIdentity);
    } else {
      report.consumerLanes = consumers.map(({ licenseEvidence, ...consumer }) => ({
        ...consumer, licenseEvidenceSha256: hash(JSON.stringify(licenseEvidence)),
      }));
      for (const major of ['11', '12']) {
        const name = `consumer-npm${major}`;
        report.gates[name] = pass(`Actual npm ${major} installed-bin/bridge/UI and fresh graphs across three platforms and both modes`,
          consumers.filter(item => item.npm.startsWith(`${major}.`)));
      }
      report.gates['consumer-platforms'] = pass('All 12 verified hosted consumer receipts and six immutable artifact archives',
        { consumers, archives: request.matrix.artifactEvidence });
      active = 'consumer-advisories';
      const advisory = await advisories({ consumers, publicPackages: request.publicPackages, exemptionsPath, fetchImpl,
        localArtifact: { name: request.name, version: request.version, sha256: request.artifact.sha256,
          integrity: request.artifact.integrity } });
      report.consumerAdvisories = advisory;
      equal(advisory.status, 'passed');
      report.gates[active] = pass('OSV checks of ALL 12 actual independent consumer graphs; approved public coordinates only', advisory);
      active = 'licenses-notices';
      report.runtimeLicenses = await licenses({ sourceRoot: request.sourceRoot, extractedRoot: request.extractedRoot,
        consumers, name: request.name, version: request.version });
      report.gates[active] = pass('Packed notice verification and hash-bound fresh consumer license/text coverage for every exact path/name/version/integrity',
        report.runtimeLicenses);
      active = 'runtime-closure';
      report.runtimeClosure = verifyRuntimeClosure(request, consumers);
      report.gates[active] = pass('Extracted bridge/CLI/supervisor/lazy writer/helper/UI files and actual consumers', report.runtimeClosure);
      active = 'native-windows-execution';
      const source = request.sourceReport;
      equal(source?.phase, 'source');
      equal(source.commit ?? source.source?.commit, request.commit);
      equal(source.gates?.['native-release-identity']?.status, 'passed');
      report.nativeWindows = verifyWindowsExecution(request, source.nativeIdentity);
      report.gates[active] = pass('Both actual Windows helper suites executed the tarball helper bytes matching source release identity; no new rebuild or desktop-token proof',
        report.nativeWindows);
      active = 'service-replacement';
      report.serviceReplacement = verifyReplacement(request);
      report.gates[active] = pass('Actual T32 command, both approved artifacts, four replacements, held launch and second-instance evidence',
        report.serviceReplacement);
    }
    for (const name of request.requiredGates) {
      active = name;
      const gate = report.gates[name];
      assert.ok(gate);
      assert.ok(gate.status === 'passed' ||
        HUMAN.has(name) &&
        ['pending-owner-review', 'not-run'].includes(gate.status));
    }
    report.status = Object.values(report.gates).some(gate => gate.status !== 'passed') ? 'pending-owner-review' : 'passed';
    report.ownerApproval = 'not-supplied-by-automation';
  } catch (error) {
    const known = [...SOURCE_GATES, ...ARTIFACT_GATES].includes(active);
    report.status = 'failed';
    report.error = { gate: active, code: 'external-gate-rejected',
      diagnosticSha256: hash(String(error?.message ?? error)) };
    if (known) report.gates[active] = { status: 'failed',
      evidence: [evidence(`${active}: actual evidence missing, inconsistent, finding, or execution error`, report.error)] };
    // Only reviewed public-coordinate diagnostics or fixed recovery hints are safe to print.
    const reviewRequired = safeLicenseDiagnostic(error?.message, active) ?? LICENSE_FAILURE_HINTS[active];
    if (request.phase === 'artifact' &&
        reviewRequired) {
      report.error.reviewRequired = reviewRequired;
    }
  }
  return report;
}

export function externalExitCode(report) {
  return ['passed', 'pending-owner-review'].includes(report.status) ? 0 : 1;
}

export async function externalCli(args, injected = {}) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    assert.ok(['--request', '--output', '--policy', '--exemptions'].includes(name) &&
      !Object.hasOwn(options, name) &&
      typeof args[index + 1] === 'string' &&
      isAbsolute(args[index + 1]), 'Expected unique option with absolute local path');
    options[name] = args[index + 1];
  }
  assert.ok(options['--request'] &&
    options['--output'], 'Usage: --request <absolute.json> --output <absolute.json> [--policy <absolute.json>] [--exemptions <absolute.json>]');
  const request = JSON.parse(readFileSync(options['--request'], 'utf8'));
  for (const root of [request.root, request.sourceRoot]) assert.ok(!inside(root, options['--output']),
    'Output must be outside source and extracted roots');
  const outputParent = resolve(options['--output'], '..');
  assert.equal(realpathSync(outputParent), outputParent, 'Output parent must not be a link');
  const report = await aggregateExternalGates(request, { ...injected,
    policyPath: options['--policy'] ?? request.policyPath,
    exemptionsPath: options['--exemptions'] ?? request.exemptionsPath });
  writeFileSync(options['--output'], `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return externalExitCode(report);
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = await externalCli(process.argv.slice(2)); }
  catch {
    console.error('External gate request/output failed; no approval supplied.');
    process.exitCode = 1;
  }
}
