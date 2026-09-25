import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join, win32 } from 'node:path';
import { CURRENT_REF, LEGACY_REF, checkLockfile } from '../compatibility/fixtures.mjs';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { captureConsumerLicenseEvidence } from '../npm-consumer/license-evidence.mjs';
import { inspectRuntimeLicenses } from './runtime-licenses.mjs';
import { retainedDependencies, testArguments, testTotals, uiTestArguments } from './local-gate.mjs';
import { validatePackage } from './policy.mjs';
import { safeName, physical } from './local-inputs.mjs';
import { treeEntries } from './local-source.mjs';
import { readLocalBytes, readLocalJson } from './local-evidence.mjs';
import { exactLocalKeys, localHash, localSha, LOCAL_NODES } from './local-regression.mjs';
import { validateStageProof } from './stage-proof-contract.mjs';
import { auditEvidence } from './local-audit-report.mjs';

const SOURCE = 'C:\\source';
const EMPTY_GIT = 'C:\\work\\empty-git-config';
const BUILD = 'tools/windows-security-helper/build.ps1';
const ATTRIBUTES = Object.freeze({
  text: 'set', eol: 'crlf', filter: 'unspecified', 'working-tree-encoding': 'unspecified', ident: 'unspecified',
});
const FORBIDDEN_SECTIONS = new Set(['include', 'includeif', 'filter', 'alias', 'diff', 'merge']);
const FORBIDDEN_KEYS = new Set(['core.worktree', 'extensions.worktreeconfig', 'core.sshcommand',
  'core.gitproxy', 'core.hookspath', 'core.fsmonitor', 'core.attributesfile']);

function lowerHex(value, length) {
  assert.ok(typeof value === 'string' &&
    value.length === length &&
    [...value].every(character => '0123456789abcdef'.includes(character)), 'Missing or invalid digest/object identity');
}

function decode(command, field) {
  const value = command[field];
  assert.equal(typeof value, 'string');
  if (command.encoding === 'utf8') return Buffer.from(value);
  assert.equal(command.encoding, 'base64');
  const bytes = Buffer.from(value, 'base64');
  assert.equal(bytes.toString('base64'), value, 'Noncanonical binary command receipt');
  return bytes;
}

export function validateLocalArtifact(artifact, schemaVersion) {
  exactLocalKeys(artifact, ['sha256', 'sha512', 'integrity', 'files', 'publicationCandidate',
    'fixtureCommit', 'kind', 'releaseReady', ...([2, 3, 4].includes(schemaVersion) ? ['evidenceFile'] : [])]);
  localSha(artifact.sha256);
  lowerHex(artifact.sha512, 128);
  assert.equal(artifact.integrity, `sha512-${Buffer.from(artifact.sha512, 'hex').toString('base64')}`);
  lowerHex(artifact.fixtureCommit, 40);
  assert.equal(artifact.publicationCandidate, false);
  assert.equal(artifact.releaseReady, false);
  assert.equal(artifact.kind, 'offline-npm12-pack-fixture');
  if ([2, 3, 4].includes(schemaVersion)) assert.equal(artifact.evidenceFile, 'fixture.tgz');
  assert.ok(Array.isArray(artifact.files) &&
    artifact.files.length > 0 &&
    artifact.files.length <= 10_000, 'Missing canonical package inventory');
  const names = new Set();
  let total = 0;
  for (const file of artifact.files) {
    exactLocalKeys(file, ['path', 'size', 'mode', 'sha256']);
    safeName(file.path);
    assert.equal(names.has(file.path.toLowerCase()), false, 'Duplicate package inventory path');
    names.add(file.path.toLowerCase());
    assert.ok(Number.isSafeInteger(file.size) &&
      file.size >= 0 &&
      file.size <= 128 * 1024 ** 2);
    total += file.size;
    assert.ok(total <= 128 * 1024 ** 2);
    assert.ok([0o644, 0o755].includes(file.mode), 'Invalid package mode');
    localSha(file.sha256);
  }
  assert.deepEqual(artifact.files.map(file => file.path),
    artifact.files.map(file => file.path).sort((a, b) => a.localeCompare(b)), 'Noncanonical inventory order');
}

export class LocalCaseReplay {
  constructor(commands, gate, root, version, { checkout } = {}) {
    this.commands = commands;
    this.gate = gate;
    this.root = physical(root);
    this.version = version;
    this.checkoutBinding = checkout;
    this.index = 0;
    this.pkg = readLocalJson(join(root, 'package.json'));
    validatePackage(this.pkg, { version });
    assert.equal(gate.version, version);
    assert.equal(gate.platform, 'win32');
    assert.ok(LOCAL_NODES.some(node => gate.node === `v${node}`));
    assert.equal(gate.publisherNode, 'v24.21.0');
    assert.equal(gate.npm, '12.0.2');
    lowerHex(gate.source?.head, 40);
    assert.ok(Array.isArray(gate.source.files) &&
      gate.source.files.length > 0);
    const seen = new Set();
    for (const file of gate.source.files) {
      exactLocalKeys(file, ['path', 'sha256']);
      safeName(file.path);
      localSha(file.sha256);
      assert.equal(seen.has(file.path.toLowerCase()), false);
      seen.add(file.path.toLowerCase());
      assert.equal(localHash(readLocalBytes(join(root, file.path), 64 * 1024 ** 2)), file.sha256,
        'Frozen source differs from the recorded source bytes');
    }
    this.sourceNames = gate.source.files.map(file => file.path);
    assert.deepEqual(this.sourceNames, [...this.sourceNames].sort());
  }

  take(label, executable, args, cwd, encoding = 'utf8') {
    const command = this.commands[this.index++];
    assert.ok(command, `Missing supporting command: ${label}`);
    assert.equal(command.label, label, 'Missing or reordered supporting command');
    assert.equal(command.executable, executable);
    assert.deepEqual(command.args, args, 'Supporting command vector changed');
    assert.equal(command.cwd, cwd, 'Supporting command cwd changed');
    assert.equal(command.encoding, encoding);
    decode(command, 'stderr');
    return decode(command, 'stdout');
  }

  git(cwd, args, binary = false) {
    const config = this.take('Parse local Git configuration', 'git',
      ['-C', EMPTY_GIT, '-c', 'extensions.worktreeConfig=false', 'config', '--no-includes',
        '--null', '--name-only', '--file', win32.join(cwd, '.git/config'), '--list'], EMPTY_GIT);
    const keys = config.toString('utf8').split('\0');
    assert.equal(keys.pop(), '', 'Incomplete Git configuration receipt');
    assert.ok(keys.length > 0 &&
      config.length <= 1024 * 1024);
    for (const key of keys) {
      const normalized = key.toLowerCase();
      const dot = normalized.indexOf('.');
      assert.ok(dot > 0 &&
        dot < normalized.length - 1);
      assert.ok(!FORBIDDEN_SECTIONS.has(normalized.slice(0, dot)) &&
        !FORBIDDEN_KEYS.has(normalized), 'Executable/inherited Git configuration in receipt');
      if (cwd.startsWith('C:\\work\\checkout-')) {
        assert.notEqual(normalized, 'core.eol', 'Unrecorded checkout EOL configuration is forbidden');
      }
    }
    const prefix = ['-c', `core.worktree=${cwd}`, '-c', 'extensions.worktreeConfig=false',
      '-c', `core.hooksPath=${EMPTY_GIT}`, '-c', `init.templateDir=${EMPTY_GIT}`,
      '-c', 'credential.helper=', '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=',
      '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', '-c', 'commit.gpgsign=false',
      '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always'];
    const bytes = this.take('Local Git', 'git', [...prefix, ...args], cwd, binary ? 'base64' : 'utf8');
    return binary ? bytes : bytes.toString('utf8').trimEnd();
  }

  snapshot(cwd) {
    const bytes = this.git(cwd, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'], true);
    const names = bytes.toString('utf8').split('\0');
    assert.equal(names.pop(), '');
    for (const name of names) safeName(name);
    assert.deepEqual([...names].sort(), this.sourceNames, 'Incomplete source-inventory command');
  }

  checkout(cwd, autocrlf) {
    this.git(SOURCE, ['clone', '--quiet', '--no-hardlinks', '--no-checkout', SOURCE, cwd]);
    this.git(cwd, ['read-tree', '--empty']);
    this.git(cwd, ['-c', 'core.autocrlf=false', 'add', '--all', '--force', '--', '.']);
    this.git(cwd, ['commit', '--quiet', '--allow-empty', '-m', 'Local gate fixture - never publish']);
    this.git(cwd, ['-c', `core.autocrlf=${autocrlf}`,
      ...(this.gate.schemaVersion >= 4 ? ['-c', 'core.eol=crlf'] : []),
      'checkout', '--force', 'HEAD', '--', '.']);
    this.snapshot(cwd);
  }

  native(cwd) {
    const commit = this.git(cwd, ['rev-parse', 'HEAD']);
    lowerHex(commit, 40);
    const baseline = this.version === '1.3.1' ? LEGACY_REF : CURRENT_REF;
    assert.equal(this.git(cwd, ['cat-file', '-e', `${baseline}^{commit}`]), '');
    const read = args => this.git(cwd, ['-c', 'core.hooksPath=', '-c', 'credential.helper=',
      '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=', '-c', 'safe.bareRepository=explicit',
      '-C', cwd, ...args], true);
    assert.equal(read(['cat-file', '-e', `${baseline}^{commit}`]).length, 0);
    const entries = treeEntries(read(['ls-tree', '-r', '-z', baseline, '--', 'bin/windows', BUILD]).toString('utf8'));
    assert.equal(entries.length, this.version === '1.3.1' ? 6 : 7);
    const expected = this.filesUnder('bin/windows').map(file => file.path).concat(BUILD).sort();
    assert.deepEqual(entries.map(file => file.path).sort(), expected);
    for (const path of ['bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json', BUILD]) {
      assert.ok(expected.includes(path));
    }
    const files = [];
    let buildScript;
    for (const entry of entries) {
      assert.ok(entry.path.startsWith('bin/windows/') ||
        entry.path === BUILD);
      const blob = read(['cat-file', 'blob', entry.blob]);
      const object = createHash('sha1').update(`blob ${blob.length}\0`).update(blob).digest('hex');
      assert.equal(object, entry.blob, 'Native raw Git blob does not match its object ID');
      const checkout = readLocalBytes(join(this.root, entry.path));
      if (entry.path === BUILD) {
        const source = read(['cat-file', 'blob', `${commit}:${BUILD}`]);
        assert.deepEqual(source, blob, 'Native build-script source differs from baseline');
        const attributesPath = read(['rev-parse', '--path-format=absolute', '--git-path', 'info/attributes'])
          .toString('utf8').trim();
        const expectedPath = win32.join(cwd, '.git/info/attributes');
        assert.ok([expectedPath, expectedPath.replaceAll('\\', '/')].includes(attributesPath),
          'Unexpected recorded Git attributes path');
        assert.equal(existsSync(join(this.root, '.git/info/attributes')), false);
        const fields = read(['check-attr', `--source=${commit}`, '-z', ...Object.keys(ATTRIBUTES), '--', BUILD])
          .toString('utf8').split('\0');
        assert.deepEqual(fields, [...Object.entries(ATTRIBUTES).flatMap(([key, value]) => [BUILD, key, value]), '']);
        assert.ok(blob.length > 0 &&
          blob.length <= 128 * 1024);
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(blob);
        for (const character of text) {
          const code = character.charCodeAt(0);
          assert.ok(code !== 0x7f &&
            code !== 0xfeff &&
            (code >= 0x20 ||
              code === 9 ||
              code === 10), 'Native build-script blob must remain BOM-free UTF-8/LF');
        }
        assert.deepEqual(Buffer.from(text), blob);
        assert.deepEqual(checkout, Buffer.from(text.replaceAll('\n', '\r\n')),
          'Native build-script checkout must use the exact declared CRLF form');
        buildScript = { path: BUILD, comparison: 'exact-declared-crlf-checkout', attributesSource: commit,
          attributes: { ...ATTRIBUTES }, baselineSha256: localHash(blob), baselineBytes: blob.length,
          sourceBlobSha256: localHash(source), checkoutSha256: localHash(checkout), checkoutBytes: checkout.length };
      } else assert.deepEqual(checkout, blob, 'Native checkout differs from the actual baseline blob');
      files.push({ path: entry.path, sha256: localHash(checkout) });
    }
    return { baselineCommit: baseline, files: files.sort((a, b) => a.path.localeCompare(b.path)),
      buildScript, reproducibilityBuild: 'not-executed-in-this-run' };
  }

  filesUnder(name) {
    safeName(name);
    const directory = physical(join(this.root, name));
    return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
      const path = `${name}/${entry.name}`;
      safeName(path);
      physical(join(this.root, path));
      if (entry.isDirectory()) return this.filesUnder(path);
      assert.ok(entry.isFile(), 'Special source inventory member');
      const bytes = readLocalBytes(join(this.root, path));
      return [{ path, size: bytes.length, sha256: localHash(bytes) }];
    });
  }

  inventory(artifact, packed) {
    validateLocalArtifact(artifact, this.gate.schemaVersion);
    const expected = new Set(['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md']);
    assert.ok(Array.isArray(this.pkg.files) &&
      this.pkg.files.length > 0);
    for (const name of this.pkg.files) {
      assert.equal(typeof name, 'string');
      if (name.endsWith('/')) for (const file of this.filesUnder(name.slice(0, -1))) expected.add(file.path);
      else { safeName(name); expected.add(name); }
    }
    assert.deepEqual(artifact.files.map(file => file.path).sort(), [...expected].sort(),
      'Package inventory is incomplete or outside the canonical allowlist');
    for (const file of artifact.files) {
      assert.ok(!file.path.split('/').some(part => ['.git', '.npmrc', 'node_modules', 'package-lock.json'].includes(part)));
      const bytes = readLocalBytes(join(this.root, file.path), 128 * 1024 ** 2);
      assert.equal(bytes.length, file.size);
      assert.equal(localHash(bytes), file.sha256, 'Packed record differs from frozen source bytes; do not guess EOL conversion');
    }
    exactLocalKeys(packed, ['id', 'name', 'version', 'size', 'unpackedSize', 'shasum', 'integrity',
      'filename', 'files', 'entryCount', 'bundled']);
    assert.equal(packed.name, 'mcp-pacemaker');
    assert.equal(packed.version, this.version);
    assert.equal(packed.id, `mcp-pacemaker@${this.version}`);
    assert.equal(packed.filename, `mcp-pacemaker-${this.version}.tgz`);
    assert.ok(Number.isSafeInteger(packed.size) &&
      packed.size > 0 &&
      packed.size <= 32 * 1024 ** 2);
    assert.equal(packed.unpackedSize, artifact.files.reduce((sum, file) => sum + file.size, 0));
    lowerHex(packed.shasum, 40);
    assert.equal(packed.integrity, artifact.integrity);
    assert.equal(packed.entryCount, artifact.files.length);
    assert.deepEqual(packed.bundled, []);
    assert.ok(Array.isArray(packed.files));
    for (const file of packed.files) exactLocalKeys(file, ['path', 'size', 'mode']);
    assert.deepEqual([...packed.files].sort((a, b) => a.path.localeCompare(b.path)),
      artifact.files.map(({ path, size, mode }) => ({ path, size, mode })));
  }

  reviewedHash(file, name) {
    const text = readLocalBytes(join(this.root, 'tools/npm-publication', file)).toString('utf8');
    const prefix = `export const ${name} = '`;
    const first = text.indexOf(prefix);
    assert.ok(first >= 0 &&
      text.indexOf(prefix, first + prefix.length) === -1);
    const start = first + prefix.length;
    assert.equal(text.slice(start + 64, start + 66), "';");
    const hash = text.slice(start, start + 64);
    localSha(hash);
    return hash;
  }

  sdk(value) {
    const common = ['status', 'kind', 'node', 'npm', 'version', 'contract', 'networkAttempts', 'subprocessAttempts',
      'authenticated', 'published', 'releaseReady', 'provenanceVerified', 'signatureVerified'];
    exactLocalKeys(value, [...common, ...(this.version === '1.3.1'
      ? ['module', 'verifier'] : ['profileSourceSha256', 'provenanceSourceSha256'])]);
    assert.equal(value.status, 'passed');
    assert.equal(value.kind, 'fresh-child-offline-sdk-load');
    assert.equal(value.node, 'v24.21.0');
    assert.equal(value.npm, '12.0.2');
    assert.equal(value.version, this.version);
    assert.equal(value.contract, this.version === '1.3.1' ? 'legacy-staged-signature' : 'owner-sdk-and-provenance');
    if (this.version === '1.3.1') {
      assert.equal(value.module, 'verify-staged.mjs');
      assert.equal(value.verifier, 'sigstore@5.0.0 (npm@12.0.2)');
    } else {
      assert.equal(value.profileSourceSha256, this.reviewedHash('owner-sdk.mjs', 'PROFILE_SOURCE_SHA256'));
      assert.equal(value.provenanceSourceSha256, this.reviewedHash('provenance.mjs', 'PROVENANCE_SOURCE_SHA256'));
    }
    for (const key of ['networkAttempts', 'subprocessAttempts']) assert.equal(value[key], 0);
    for (const key of ['authenticated', 'published', 'releaseReady', 'provenanceVerified', 'signatureVerified']) {
      assert.equal(value[key], false);
    }
  }

  async licenses(directory, summary) {
    exactLocalKeys(summary, ['kind', 'file', 'sha256', 'packages', 'freshRegistryEvidence', 'installedInThisRun', 'releaseReady']);
    assert.equal(summary.kind, 'retained-graph-finalizer-contract-fixture');
    assert.equal(summary.file, 'retained-license-contract.json');
    localSha(summary.sha256);
    const bytes = readLocalBytes(join(directory, summary.file));
    assert.equal(localHash(bytes), summary.sha256);
    const receipt = JSON.parse(bytes.toString('utf8'));
    const dependencies = retainedDependencies(this.root);
    const licenseEvidence = captureConsumerLicenseEvidence(this.root, dependencies);
    const result = await inspectRuntimeLicenses({ sourceRoot: this.root, extractedRoot: this.root,
      consumers: [{ schemaVersion: 2, producerLockCopied: false, dependencies, licenseEvidence }],
      name: this.pkg.name, version: this.version });
    const expected = { schemaVersion: 1, kind: summary.kind, releaseReady: false, freshRegistryEvidence: false,
      installedInThisRun: false, producerLockCopied: false,
      integrityMeaning: 'Retained lock metadata, not registry verification or a fresh resolution',
      dependencies, licenseEvidence, packages: result.packages.map(item => ({
        ...item, source: item.source === 'extracted-candidate' ? item.source : 'retained-license-fixture',
      })), notices: result.notices };
    assert.deepEqual(receipt, expected, 'Retained license receipt/coverage differs from actual frozen package bytes');
    assert.equal(summary.packages, result.packages.length);
    for (const key of ['freshRegistryEvidence', 'installedInThisRun', 'releaseReady']) assert.equal(summary[key], false);
  }

  async verify(directory) {
    assert.equal(this.take('Pinned publisher runtime', 'C:\\publisher-node.exe',
      ['-p', 'process.version'], SOURCE).toString('utf8').trim(), 'v24.21.0');
    this.snapshot(SOURCE);
    assert.equal(this.git(SOURCE, ['rev-parse', 'HEAD']), this.gate.source.head);
    for (const file of ['package-lock.json', 'ui/package-lock.json']) checkLockfile(join(this.root, file));
    exactLocalKeys(this.gate.checks, ['publicLockfiles', 'checkout-false', 'checkout-true']);
    assert.equal(this.gate.checks.publicLockfiles, true);
    let packOutput;
    for (const autocrlf of ['false', 'true']) {
      const cwd = `C:\\work\\checkout-${autocrlf}`;
      const checks = this.gate.checks[`checkout-${autocrlf}`];
      const fields = ['kind', 'autocrlf', 'sourceNode', 'uiNode', 'publisherNode', 'nativeIdentity', 'uiRebuild'];
      exactLocalKeys(checks, [...fields, ...(autocrlf === 'false'
        ? ['sourceTests', 'uiTests', 'artifact', 'extractedFiles', 'notices', 'sdk', 'retainedGraphLicenseContract',
          ...(this.gate.schemaVersion >= 3 ? ['stageCapture'] : [])] : [])]);
      assert.equal(checks.kind, 'unpublishable-local-checkout-fixture');
      assert.equal(checks.autocrlf, autocrlf);
      assert.equal(checks.sourceNode, this.gate.node);
      assert.equal(checks.uiNode, 'v24.21.0');
      assert.equal(checks.publisherNode, 'v24.21.0');
      this.checkout(cwd, autocrlf);
      const native = this.native(cwd);
      assert.deepEqual(checks.nativeIdentity, native, 'Native records differ from supporting raw Git evidence');
      this.take('Actual UI rebuild and notice comparison', 'C:\\publisher-node.exe',
        ['tools/third-party-notices/check.mjs'], cwd);
      assert.equal(checks.uiRebuild, true);
      this.snapshot(cwd);
      if (autocrlf === 'true') continue;
      const selected = testArguments(this.pkg.scripts.test);
      assert.deepEqual(selected.slice(2).sort(), readdirSync(join(this.root, 'test'))
        .filter(name => name.endsWith('.test.mjs')).map(name => `test/${name}`).sort());
      const sourceOutput = this.take('Complete source suite', 'C:\\node.exe', selected, cwd).toString('utf8');
      assert.deepEqual(checks.sourceTests, testTotals(sourceOutput));
      if (this.gate.schemaVersion >= 3) auditEvidence(sourceOutput, this.version, this.gate.node);
      this.take('UI typecheck', 'C:\\publisher-node.exe',
        ['node_modules/typescript/bin/tsc', '--noEmit'], `${cwd}\\ui`);
      const ui = uiTestArguments(this.root, this.version);
      if (ui === null) {
        assert.deepEqual(checks.uiTests, { status: 'not-defined', executed: false,
          reason: 'Legacy 1.3.1 defines neither a UI test script nor a ui/test directory' });
      } else assert.deepEqual(checks.uiTests,
        testTotals(this.take('UI tests', 'C:\\publisher-node.exe', ui, `${cwd}\\ui`).toString('utf8')));
      this.snapshot(cwd);
      packOutput = this.take('Real offline npm pack', 'C:\\publisher-node.exe',
        ['C:\\input\\npm\\bin\\npm-cli.js', 'pack', '--offline', '--ignore-scripts', '--json',
          '--pack-destination', 'C:\\work\\pack'], cwd).toString('utf8');
      assert.equal(this.git(cwd, ['rev-parse', 'HEAD']), native.buildScript.attributesSource);
      assert.equal(checks.artifact.fixtureCommit, native.buildScript.attributesSource);
      const packed = JSON.parse(packOutput);
      exactLocalKeys(packed, ['mcp-pacemaker']);
      this.inventory(checks.artifact, packed['mcp-pacemaker']);
      assert.deepEqual(checks.extractedFiles, checks.artifact.files.map(({ path, sha256 }) => ({ path, sha256 })),
        'Extracted records do not exactly cover the canonical package');
      for (const file of native.files) assert.deepEqual(checks.extractedFiles.find(item => item.path === file.path), file);
      assert.deepEqual(checks.notices, verifyArtifacts(this.root), 'Notices do not match actual frozen artifacts');
      const sdk = JSON.parse(this.take('Actual lane SDK/signature load, no transport', 'C:\\publisher-node.exe',
        ['tools/npm-publication/local-sdk-check.mjs', 'C:\\input\\npm\\bin\\npm-cli.js'], cwd).toString('utf8'));
      assert.deepEqual(checks.sdk, sdk);
      this.sdk(sdk);
      if (this.gate.schemaVersion >= 3) {
        const invocation = { root: cwd, cli: 'C:\\input\\npm\\bin\\npm-cli.js',
          node: 'C:\\publisher-node.exe', home: 'C:\\work\\stage-proof-fixtures' };
        const proof = JSON.parse(this.take('Actual pinned npm stage capture, offline fixtures', invocation.node,
          ['tools/npm-publication/local-stage-check.mjs', invocation.cli, invocation.home], cwd).toString('utf8'));
        assert.deepEqual(checks.stageCapture, proof);
        validateStageProof(proof, { root: this.root, version: this.version, invocation,
          checkout: this.checkoutBinding, sourceHead: this.gate.source.head });
      }
      await this.licenses(directory, checks.retainedGraphLicenseContract);
      this.snapshot(cwd);
    }
    this.snapshot(SOURCE);
    assert.equal(this.git(SOURCE, ['rev-parse', 'HEAD']), this.gate.source.head);
    assert.equal(this.index, this.commands.length, 'Unused or extra command receipts');
    return packOutput;
  }
}
