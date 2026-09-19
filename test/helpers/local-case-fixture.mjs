import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname, win32 } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { CURRENT_REF, LEGACY_REF } from '../../tools/compatibility/fixtures.mjs';
import { digest } from '../../tools/npm-publication/policy.mjs';
import { inspectTarball } from '../../tools/npm-publication/tarball.mjs';
import { renderNotices, verifyArtifacts, sha256 } from '../../tools/third-party-notices/inventory.mjs';
import { captureConsumerLicenseEvidence } from '../../tools/npm-consumer/license-evidence.mjs';
import { inspectRuntimeLicenses } from '../../tools/npm-publication/runtime-licenses.mjs';
import { retainedDependencies } from '../../tools/npm-publication/local-gate.mjs';
import { bindStageProofCheckout, STAGE_PROOF_FILES } from '../../tools/npm-publication/stage-proof-contract.mjs';
import { stageProofFixture } from './stage-proof-fixture.mjs';
import { AUDIT_DIAGNOSTIC, AUDIT_MODE, AUDIT_TEST_NAME, AUDIT_WORKER_TIMEOUT_MS } from '../../tools/npm-publication/local-audit-report.mjs';

// Producer-complete SYNTHETIC unit receipts. No subprocess, SDK, Git, npm or network is executed.
export class LocalCaseFixture {
  constructor(t, version = '2.0.1') {
    this.base = mkdtempSync(join(tmpdir(), 'case-unit-'));
    t.after(() => rmSync(this.base, { recursive: true, force: true }));
    this.root = join(this.base, 'source');
    this.directory = join(this.base, 'receipts');
    mkdirSync(this.root);
    mkdirSync(this.directory);
    this.version = version;
    this.commands = [];
    this.savedCommands = new Map();
    this.nativeBlobs = new Map();
    this.license = 'Copyright Synthetic Unit Fixture. Permission is hereby granted, free of charge, to any person obtaining a copy of this synthetic fixture to use it for tests only.\n';
    this.totals = { tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
    this.tap = 'TAP version 13\nok 1 - synthetic unit\n1..1\n' +
      Object.entries(this.totals).map(([key, value]) => `# ${key} ${value}\n`).join('');
    const audit = {
      normal: { medium: true, securityPrivilegeAbsent: true, nodeVersion: 'v24.21.0', cases: 19 },
      audit: { sourceExplicit: 1, sourceInherited: 1, candidateExplicit: 0, candidateInherited: 1, previousExact: true },
      securityVerified: true,
      worker: { mode: AUDIT_MODE, budgetMilliseconds: AUDIT_WORKER_TIMEOUT_MS, elapsedMilliseconds: 40000, cleanupVerified: true },
    };
    this.sourceTap = version === '2.0.1'
      ? this.tap.replace('ok 1 - synthetic unit', `ok 1 - ${AUDIT_TEST_NAME}\n# ${AUDIT_DIAGNOSTIC}${JSON.stringify(audit)}`)
      : this.tap;
  }

  write(path, value) {
    const file = join(this.root, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, typeof value === 'object' && !Buffer.isBuffer(value) ? JSON.stringify(value) : value);
  }

  files(directory = this.root, prefix = '') {
    return readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
      .flatMap(entry => {
        if (entry.name === 'node_modules') return [];
        const path = `${prefix}${entry.name}`;
        return entry.isDirectory() ? this.files(join(directory, entry.name), `${path}/`) : [path];
      }).sort();
  }

  command(label, args, cwd, stdout = '', binary = false, executable = 'C:\\publisher-node.exe') {
    this.commands.push({ label, executable, args, cwd, elapsedMs: 1,
      timeoutMs: label === 'Complete source suite' ? 1500000 : 900000,
      exitCode: 0, signal: null, error: null, encoding: binary ? 'base64' : 'utf8',
      stdout: binary ? Buffer.from(stdout).toString('base64') : stdout, stderr: '' });
  }

  git(cwd, args, stdout = '', binary = false) {
    const empty = 'C:\\work\\empty-git-config';
    this.command('Parse local Git configuration', ['-C', empty, '-c', 'extensions.worktreeConfig=false',
      'config', '--no-includes', '--null', '--name-only', '--file', win32.join(cwd, '.git/config'), '--list'],
    empty, 'core.repositoryformatversion\0core.filemode\0core.bare\0', false, 'git');
    this.command('Local Git', ['-c', `core.worktree=${cwd}`, '-c', 'extensions.worktreeConfig=false',
      '-c', `core.hooksPath=${empty}`, '-c', `init.templateDir=${empty}`, '-c', 'credential.helper=',
      '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=', '-c', 'core.autocrlf=false',
      '-c', 'core.safecrlf=false', '-c', 'commit.gpgsign=false', '-c', 'protocol.allow=never',
      '-c', 'protocol.file.allow=always', ...args], cwd, stdout, binary, 'git');
  }

  snapshot(cwd) {
    this.git(cwd, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'],
      `${this.names.join('\0')}\0`, true);
  }

  native(cwd, commit) {
    const baseline = this.version === '1.3.1' ? LEGACY_REF : CURRENT_REF;
    const build = 'tools/windows-security-helper/build.ps1';
    this.git(cwd, ['rev-parse', 'HEAD'], `${commit}\n`);
    this.git(cwd, ['cat-file', '-e', `${baseline}^{commit}`]);
    const nativeGit = (args, output = '') => this.git(cwd, ['-c', 'core.hooksPath=', '-c', 'credential.helper=',
      '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=', '-c', 'safe.bareRepository=explicit',
      '-C', cwd, ...args], output, true);
    const objects = [...this.nativeBlobs].sort(([a], [b]) => a < b ? -1 : 1).map(([path, bytes]) => ({
      path, bytes, object: createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),
    }));
    nativeGit(['cat-file', '-e', `${baseline}^{commit}`]);
    nativeGit(['ls-tree', '-r', '-z', baseline, '--', 'bin/windows', build],
      objects.map(item => `100644 blob ${item.object}\t${item.path}\0`).join(''));
    let buildScript;
    for (const item of objects) {
      nativeGit(['cat-file', 'blob', item.object], item.bytes);
      if (item.path !== build) continue;
      const attributes = { text: 'set', eol: 'crlf', filter: 'unspecified',
        'working-tree-encoding': 'unspecified', ident: 'unspecified' };
      nativeGit(['cat-file', 'blob', `${commit}:${build}`], item.bytes);
      nativeGit(['rev-parse', '--path-format=absolute', '--git-path', 'info/attributes'],
        `${cwd.replaceAll('\\', '/')}/.git/info/attributes\n`);
      nativeGit(['check-attr', `--source=${commit}`, '-z', ...Object.keys(attributes), '--', build],
        `${Object.entries(attributes).flatMap(([key, value]) => [build, key, value]).join('\0')}\0`);
      const checkout = readFileSync(join(this.root, build));
      buildScript = { path: build, comparison: 'exact-declared-crlf-checkout', attributesSource: commit,
        attributes, baselineSha256: sha256(item.bytes), baselineBytes: item.bytes.length,
        sourceBlobSha256: sha256(item.bytes), checkoutSha256: sha256(checkout), checkoutBytes: checkout.length };
    }
    return { baselineCommit: baseline, files: objects.map(item => ({
      path: item.path, sha256: sha256(readFileSync(join(this.root, item.path))),
    })).sort((a, b) => a.path.localeCompare(b.path)), buildScript, reproducibilityBuild: 'not-executed-in-this-run' };
  }

  tar(files) {
    const chunks = [];
    for (const path of files) {
      const bytes = readFileSync(join(this.root, path));
      const header = Buffer.alloc(512);
      header.write(`package/${path}`);
      const mode = ['bin/cli.mjs', 'bin/mcp-bridge.mjs'].includes(path) ? 0o755 : 0o644;
      header.write(`${mode.toString(8).padStart(7, '0')}\0`, 100);
      header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124);
      header.fill(32, 148, 156);
      header.write('0', 156);
      header.write(`${[...header].reduce((a, b) => a + b, 0).toString(8).padStart(6, '0')}\0 `, 148);
      chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
    }
    return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
  }

  checkoutSource() {
    const blobs = new Map();
    const entries = this.names.map(path => {
      const bytes = readFileSync(join(this.root, path));
      const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
      blobs.set(blob, bytes);
      return { path, mode: '100644', blob };
    });
    const identity = { schemaVersion: 1, clean: true, version: this.version,
      head: this.gate.source.head, tree: 'd'.repeat(40), entries,
      files: this.names.map(path => {
        const bytes = readFileSync(join(this.root, path));
        return { path, size: bytes.length, sha256: sha256(bytes) };
      }) };
    const readGit = args => {
      if (args[0] === 'rev-parse') {
        const value = args[1] === 'HEAD' ? identity.head : args[1] === 'HEAD^{tree}' ? identity.tree :
          join(this.root, '.git/info/attributes');
        return Buffer.from(`${value}\n`);
      }
      if (args[0] === 'ls-tree') {
        return Buffer.from(entries.map(value => `${value.mode} blob ${value.blob}\t${value.path}\0`).join(''));
      }
      if (args[0] === 'check-attr') {
        const attributes = { text: 'set', eol: 'lf', filter: 'unspecified',
          'working-tree-encoding': 'unspecified', ident: 'unspecified' };
        return Buffer.from(STAGE_PROOF_FILES.flatMap(path =>
          Object.entries(attributes).flatMap(([key, value]) => [path, key, value])).join('\0') + '\0');
      }
      if (args[0] === 'cat-file') return blobs.get(args[2]);
      const path = args.find(value => value.startsWith('--path='))?.slice(7);
      if (args.includes('hash-object')) return Buffer.from(`${entries.find(value => value.path === path).blob}\n`);
      if (path) return readFileSync(join(this.root, path));
      throw new Error('Unexpected SYNTHETIC Git read');
    };
    return bindStageProofCheckout({ root: this.root, identity, readGit });
  }

  async create() {
    const pkg = { name: 'mcp-pacemaker', version: this.version, license: 'MIT',
      repository: { url: 'git+https://github.com/girishkvs/mcp-pacemaker.git' },
      dependencies: { 'smol-toml': '^1.8.0' }, bin: { 'mcp-pacemaker': 'bin/cli.mjs', 'mcp-bridge': 'bin/mcp-bridge.mjs' },
      files: ['bin/', 'ui/dist/', 'tools/windows-security-helper/', 'LICENSE', 'THIRD_PARTY_NOTICES.txt'],
      scripts: { test: 'node --test test/unit.test.mjs' } };
    this.write('package.json', pkg);
    this.write('.gitattributes', '*.mjs text eol=lf\n*.cjs text eol=lf\n*.json text eol=lf\n');
    for (const path of ['README.md', 'CHANGELOG.md', 'bin/cli.mjs', 'bin/mcp-bridge.mjs',
      'test/unit.test.mjs', 'ui/dist/index.html', 'ui/src/main.js']) this.write(path, 'synthetic fixture; never executed\n');
    this.write('LICENSE', this.license);
    const ui = { version: this.version, scripts: { typecheck: 'tsc --noEmit', build: 'vite build' } };
    if (this.version === '2.0.1') {
      ui.scripts.test = 'node --test test/unit.test.mjs';
      this.write('ui/test/unit.test.mjs', 'synthetic UI fixture; never executed\n');
    }
    this.write('ui/package.json', ui);
    const dependency = { version: '1.8.0', license: 'MIT', resolved: 'https://registry.npmjs.org/smol-toml/-/smol-toml-1.8.0.tgz',
      integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}` };
    this.write('node_modules/smol-toml/package.json', { name: 'smol-toml', version: '1.8.0', license: 'MIT' });
    this.write('node_modules/smol-toml/LICENSE', this.license);
    this.write('node_modules/.package-lock.json', { lockfileVersion: 3, packages: { 'node_modules/smol-toml': dependency } });
    this.write('package-lock.json', { lockfileVersion: 3, packages: { '': pkg, 'node_modules/smol-toml': dependency } });
    this.write('ui/package-lock.json', { lockfileVersion: 3, packages: {} });
    const license = { file: 'LICENSE', text: this.license, sha256: sha256(this.license) };
    const bundled = [{ name: 'unit-ui', version: '1.0.0', license: 'MIT', licenses: [license], comments: [] }];
    const runtime = [{ name: 'unit-runtime', version: '1.0.0', license: 'MIT', distribution: 'separately-installed',
      licenses: [license], comments: [] }];
    const notices = renderNotices(bundled, runtime);
    this.write('THIRD_PARTY_NOTICES.txt', notices);
    this.write('ui/dist/THIRD_PARTY_NOTICES.txt', notices);
    this.write('ui/dist/third-party-manifest.json', { schemaVersion: 1,
      chunks: [{ modules: [] }], packages: bundled, runtimeNotices: runtime,
      sources: [{ path: 'src/main.js', sha256: sha256(readFileSync(join(this.root, 'ui/src/main.js'))) }],
      projectLicenseSha256: sha256(this.license), noticesSha256: sha256(notices),
      artifacts: [{ file: 'index.html', sha256: sha256(readFileSync(join(this.root, 'ui/dist/index.html'))) }] });
    const native = ['bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json',
      'bin/windows/src/AssemblyInfo.cs', 'bin/windows/src/PoolingSecurityHelper.cs', 'bin/windows/src/PoolingSecurityReader.cs',
      ...(this.version === '2.0.1' ? ['bin/windows/src/PoolingNativeFiles.cs'] : []),
      'tools/windows-security-helper/build.ps1'];
    for (const path of native) {
      const bytes = Buffer.from(`synthetic native fixture ${path}\n`);
      this.nativeBlobs.set(path, bytes);
      this.write(path, path.endsWith('.ps1') ? bytes.toString().replaceAll('\n', '\r\n') : bytes);
    }
    this.write('tools/npm-publication/owner-sdk.mjs', `export const PROFILE_SOURCE_SHA256 = '${'a'.repeat(64)}';\n`);
    this.write('tools/npm-publication/provenance.mjs', `export const PROVENANCE_SOURCE_SHA256 = '${'b'.repeat(64)}';\n`);
    for (const path of STAGE_PROOF_FILES) this.write(path, `Synthetic offline-proof source fixture: ${path}\n`);
    this.names = this.files();
    this.gate = { schemaVersion: 4, kind: 'local-publication-regression', status: 'passed', releaseReady: false,
      publicationCandidate: false, originalPreserved: true, version: this.version, platform: 'win32',
      node: 'v24.21.0', publisherNode: 'v24.21.0', npm: '12.0.2',
      source: { head: 'a'.repeat(40), files: this.names.map(path => ({ path, sha256: sha256(readFileSync(join(this.root, path))) })) },
      checks: { publicLockfiles: true } };
    this.checkoutBinding = this.checkoutSource();
    this.command('Pinned publisher runtime', ['-p', 'process.version'], 'C:\\source', 'v24.21.0\n');
    this.snapshot('C:\\source');
    this.git('C:\\source', ['rev-parse', 'HEAD'], `${this.gate.source.head}\n`);
    for (const [index, autocrlf] of ['false', 'true'].entries()) {
      const cwd = `C:\\work\\checkout-${autocrlf}`;
      this.git('C:\\source', ['clone', '--quiet', '--no-hardlinks', '--no-checkout', 'C:\\source', cwd]);
      this.git(cwd, ['read-tree', '--empty']);
      this.git(cwd, ['-c', 'core.autocrlf=false', 'add', '--all', '--force', '--', '.']);
      this.git(cwd, ['commit', '--quiet', '--allow-empty', '-m', 'Local gate fixture - never publish']);
      this.git(cwd, ['-c', `core.autocrlf=${autocrlf}`, '-c', 'core.eol=crlf',
        'checkout', '--force', 'HEAD', '--', '.']);
      this.snapshot(cwd);
      const commit = (index === 0 ? 'b' : 'c').repeat(40);
      const checks = this.gate.checks[`checkout-${autocrlf}`] = {
        kind: 'unpublishable-local-checkout-fixture', autocrlf, sourceNode: this.gate.node,
        uiNode: 'v24.21.0', publisherNode: 'v24.21.0', nativeIdentity: this.native(cwd, commit), uiRebuild: true };
      this.command('Actual UI rebuild and notice comparison', ['tools/third-party-notices/check.mjs'], cwd);
      this.snapshot(cwd);
      if (autocrlf === 'true') continue;
      this.command('Complete source suite', ['--test', '--test-reporter=tap', 'test/unit.test.mjs'], cwd, this.sourceTap, false, 'C:\\node.exe');
      checks.sourceTests = { ...this.totals };
      this.command('UI typecheck', ['node_modules/typescript/bin/tsc', '--noEmit'], `${cwd}\\ui`);
      if (this.version === '2.0.1') {
        this.command('UI tests', ['--test', '--test-reporter=tap', 'test/unit.test.mjs'], `${cwd}\\ui`, this.tap);
        checks.uiTests = { ...this.totals };
      } else checks.uiTests = { status: 'not-defined', executed: false,
        reason: 'Legacy 1.3.1 defines neither a UI test script nor a ui/test directory' };
      this.snapshot(cwd);
      const packedNames = this.names.filter(path => ['package.json', 'README.md', 'CHANGELOG.md', 'LICENSE',
        'THIRD_PARTY_NOTICES.txt'].includes(path) || path.startsWith('bin/') ||
        path.startsWith('ui/dist/') || path.startsWith('tools/windows-security-helper/'));
      this.tarball = this.tar(packedNames);
      const inspection = inspectTarball(this.tarball, { version: this.version, commit });
      checks.artifact = { ...digest(this.tarball), files: inspection.files, evidenceFile: 'fixture.tgz',
        publicationCandidate: false, fixtureCommit: commit, kind: 'offline-npm12-pack-fixture', releaseReady: false };
      const item = { id: `mcp-pacemaker@${this.version}`, name: 'mcp-pacemaker', version: this.version,
        size: this.tarball.length, unpackedSize: inspection.files.reduce((sum, file) => sum + file.size, 0),
        shasum: createHash('sha1').update(this.tarball).digest('hex'), integrity: checks.artifact.integrity,
        filename: `mcp-pacemaker-${this.version}.tgz`,
        files: inspection.files.map(({ path, size, mode }) => ({ path, size, mode })),
        entryCount: inspection.files.length, bundled: [] };
      this.command('Real offline npm pack', ['C:\\input\\npm\\bin\\npm-cli.js', 'pack', '--offline',
        '--ignore-scripts', '--json', '--pack-destination', 'C:\\work\\pack'], cwd, JSON.stringify({ 'mcp-pacemaker': item }));
      this.git(cwd, ['rev-parse', 'HEAD'], `${commit}\n`);
      checks.extractedFiles = inspection.files.map(({ path, sha256 }) => ({ path, sha256 }));
      checks.notices = verifyArtifacts(this.root);
      checks.sdk = { status: 'passed', kind: 'fresh-child-offline-sdk-load', node: 'v24.21.0', npm: '12.0.2',
        version: this.version, ...(this.version === '1.3.1' ? { contract: 'legacy-staged-signature',
          module: 'verify-staged.mjs', verifier: 'sigstore@5.0.0 (npm@12.0.2)' } : {
          contract: 'owner-sdk-and-provenance', profileSourceSha256: 'a'.repeat(64), provenanceSourceSha256: 'b'.repeat(64) }),
        networkAttempts: 0, subprocessAttempts: 0, authenticated: false, published: false,
        releaseReady: false, provenanceVerified: false, signatureVerified: false };
      this.command('Actual lane SDK/signature load, no transport',
        ['tools/npm-publication/local-sdk-check.mjs', 'C:\\input\\npm\\bin\\npm-cli.js'], cwd, JSON.stringify(checks.sdk));
      const invocation = { root: cwd, cli: 'C:\\input\\npm\\bin\\npm-cli.js',
        node: 'C:\\publisher-node.exe', home: 'C:\\work\\stage-proof-fixtures' };
      checks.stageCapture = stageProofFixture(this.root, this.version, invocation);
      this.command('Actual pinned npm stage capture, offline fixtures',
        ['tools/npm-publication/local-stage-check.mjs', invocation.cli, invocation.home],
        cwd, JSON.stringify(checks.stageCapture));
      const dependencies = retainedDependencies(this.root);
      const licenseEvidence = captureConsumerLicenseEvidence(this.root, dependencies);
      const result = await inspectRuntimeLicenses({ sourceRoot: this.root, extractedRoot: this.root,
        consumers: [{ schemaVersion: 2, producerLockCopied: false, dependencies, licenseEvidence }],
        name: 'mcp-pacemaker', version: this.version });
      this.licenses = { schemaVersion: 1, kind: 'retained-graph-finalizer-contract-fixture', releaseReady: false,
        freshRegistryEvidence: false, installedInThisRun: false, producerLockCopied: false,
        integrityMeaning: 'Retained lock metadata, not registry verification or a fresh resolution',
        dependencies, licenseEvidence, packages: result.packages.map(item => ({
          ...item, source: item.source === 'extracted-candidate' ? item.source : 'retained-license-fixture',
        })), notices: result.notices };
      checks.retainedGraphLicenseContract = { kind: this.licenses.kind, file: 'retained-license-contract.json',
        sha256: sha256(JSON.stringify(this.licenses)), packages: result.packages.length,
        freshRegistryEvidence: false, installedInThisRun: false, releaseReady: false };
      this.snapshot(cwd);
    }
    this.snapshot('C:\\source');
    this.git('C:\\source', ['rev-parse', 'HEAD'], `${this.gate.source.head}\n`);
    this.original = structuredClone({ gate: this.gate, commands: this.commands, licenses: this.licenses });
    this.save();
    return this;
  }

  reset() {
    ({ gate: this.gate, commands: this.commands, licenses: this.licenses } = structuredClone(this.original));
  }

  save() {
    const next = new Map();
    this.gate.steps = this.commands.map((command, index) => {
      const file = `command-${index + 1}.json`;
      const bytes = JSON.stringify(command);
      if (this.savedCommands.get(file) !== bytes) writeFileSync(join(this.directory, file), bytes);
      next.set(file, bytes);
      return { label: command.label, file, sha256: sha256(bytes), exitCode: command.exitCode, error: command.error, signal: command.signal };
    });
    for (const name of this.savedCommands.keys()) {
      if (!next.has(name)) rmSync(join(this.directory, name));
    }
    this.savedCommands = next;
    const licenses = JSON.stringify(this.licenses);
    this.gate.checks['checkout-false'].retainedGraphLicenseContract.sha256 = sha256(licenses);
    writeFileSync(join(this.directory, 'retained-license-contract.json'), licenses);
    writeFileSync(join(this.directory, 'fixture.tgz'), this.tarball);
  }
}
