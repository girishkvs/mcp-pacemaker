import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync,
  realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep, toNamespacedPath, win32 } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { POLICY, digest, npm12Contents, validatePackage } from './policy.mjs';
import { verifyArtifactFiles, verifyNativeIdentity } from './external-gates.mjs';
import { extractTarball } from './tarball.mjs';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { checkLockfile, CURRENT_REF, LEGACY_REF } from '../compatibility/fixtures.mjs';
import { captureConsumerLicenseEvidence } from '../npm-consumer/license-evidence.mjs';
import { inspectRuntimeLicenses } from './runtime-licenses.mjs';
import { LocalGitConfig } from './local-git.mjs';
import { windowsSystemEnvironment } from './local-environment.mjs';
import { validateStageProof } from './stage-proof-contract.mjs';
import { auditEnvironment, auditEvidence } from './local-audit-report.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const json = path => JSON.parse(readFileSync(path, 'utf8'));
export const SOURCE_SUITE_TIMEOUT_MS = 25 * 60 * 1000;
export const HOSTED_BOUNDARIES = Object.freeze([
  'Fresh registry resolution and advisory/signature checks',
  'GitHub OIDC, protected environments and fresh owner approval',
  'Authentic source/history/scanner and cross-platform consumer evidence',
  'Actual staged provenance retrieval, signing, submission and publication',
]);

export function testArguments(script) {
  assert.equal(typeof script, 'string', 'An executable Node test script is required');
  const args = script.trim().split(/\s+/);
  assert.equal(args.shift(), 'node');
  assert.equal(args.shift(), '--test');
  assert.ok(args.length > 0, 'Empty test selection');
  for (const file of args) {
    assert.match(file, /^test\/[\w./-]+\.test\.mjs$/, 'Unsupported test selector');
    assert.ok(file.split('/').every(part => part !== '.' &&
      part !== '..' &&
      part !== ''), 'Invalid test path');
  }
  assert.equal(new Set(args).size, args.length, 'Duplicate test selection');
  return ['--test', '--test-reporter=tap', ...args];
}

export function testTotals(stdout) {
  const keys = ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'];
  const counts = Object.fromEntries(keys.map(key => [key, 0]));
  const values = {};
  const totals = {};
  let start = 0;
  for (let end = 0; end <= stdout.length; end++) {
    const code = stdout.charCodeAt(end);
    const boundary = end === stdout.length ||
      code === 10 ||
      code === 13 ||
      code === 0x2028 ||
      code === 0x2029;
    if (!boundary) continue;
    const line = stdout.slice(start, end);
    start = end + 1;
    if (!line.startsWith('# ')) continue;
    const space = line.indexOf(' ', 2);
    if (space === -1) continue;
    const key = line.slice(2, space);
    if (!keys.includes(key)) continue;
    const digits = line.slice(space + 1);
    if (!digits.length) continue;
    let numeric = true;
    for (let index = 0; index < digits.length; index++) {
      const digit = digits.charCodeAt(index);
      if (digit < 48 ||
          digit > 57) {
        numeric = false;
        break;
      }
    }
    if (!numeric) continue;
    counts[key]++;
    values[key] = Number(digits);
  }
  for (const key of keys) {
    assert.equal(counts[key], 1, `Missing or ambiguous test total: ${key}`);
    totals[key] = values[key];
    assert.ok(Number.isSafeInteger(totals[key]));
  }
  assert.ok(totals.tests > 0 &&
    totals.pass > 0, 'No passing tests executed');
  for (const key of ['fail', 'cancelled', 'todo']) assert.equal(totals[key], 0, `Test ${key}`);
  assert.equal(totals.tests, totals.pass + totals.skipped, 'Incomplete test accounting');
  return totals;
}

export function uiTestArguments(root, version) {
  assert.ok(['1.3.1', '2.0.1'].includes(version), 'Unsupported UI test lane');
  const ui = json(join(root, 'ui/package.json'));
  assert.equal(ui.version, version, 'UI version differs from source lane');
  assert.equal(ui.scripts.typecheck, 'tsc --noEmit', 'UI typecheck script changed');
  assert.equal(ui.scripts.build, 'vite build', 'UI build script changed');
  const directory = join(root, 'ui/test');
  if (!Object.hasOwn(ui.scripts, 'test') &&
      !existsSync(directory)) {
    assert.equal(version, '1.3.1', 'The 2.0.1 UI suite is required');
    return null;
  }
  const selected = testArguments(ui.scripts.test);
  const files = readdirSync(directory, { recursive: true })
    .filter(file => file.endsWith('.test.mjs')).map(file => `test/${file.split(sep).join('/')}`);
  assert.deepEqual(selected.slice(2).sort(), files.sort(), 'The complete UI suite must execute');
  return selected;
}

export function localEnvironment(parent, home, node = process.execPath) {
  mkdirSync(home);
  const env = {
    PATH: `${dirname(node)}${process.platform === 'win32' ? ';' : ':'}${parent.PATH ?? parent.Path ?? ''}`,
    HOME: home, USERPROFILE: home, APPDATA: home, LOCALAPPDATA: home,
    TEMP: home, TMP: home, TMPDIR: home,
    XDG_CACHE_HOME: home, XDG_CONFIG_HOME: home, XDG_STATE_HOME: home,
    NO_COLOR: '1', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never',
    GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_AUTHOR_NAME: 'Local gate fixture', GIT_COMMITTER_NAME: 'Local gate fixture',
    GIT_AUTHOR_EMAIL: 'fixture@local.invalid', GIT_COMMITTER_EMAIL: 'fixture@local.invalid',
    npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false',
    npm_config_update_notifier: 'false', npm_config_ignore_scripts: 'true',
    npm_config_registry: POLICY.registry, npm_config_cache: join(home, 'npm-cache'),
  };
  Object.assign(env, windowsSystemEnvironment(parent));
  for (const name of ['user', 'global']) {
    const path = join(home, `${name}.npmrc`);
    writeFileSync(path, '', { flag: 'wx' });
    env[`npm_config_${name}config`] = path;
  }
  return env;
}

export function validateContainment(containment, root, output, work, platform = process.platform) {
  assert.equal(platform, 'win32', 'Full local gate requires the isolated Windows guest');
  assert.equal(containment?.kind, 'hyperv-network-none', 'Full local gate requires parent containment options');
  assert.equal(containment.root, 'C:\\source');
  assert.equal(containment.output, 'C:\\output');
  assert.match(containment.manifestSha256 ?? '', /^[a-f0-9]{64}$/, 'Frozen input manifest digest required');
  assert.equal(win32.resolve(root).toLowerCase(), containment.root.toLowerCase());
  assert.equal(win32.resolve(output).toLowerCase(), 'c:\\output\\gate',
    'Gate evidence must use the guest gate directory');
  assert.ok(typeof work === 'string' &&
    win32.isAbsolute(work), 'Guest work root is required');
  assert.equal(win32.resolve(work).toLowerCase(), 'c:\\work',
    'Full local gate requires work outside the exported output at C:\\work');
}

export function retainedDependencies(root) {
  const lock = json(join(root, 'package-lock.json'));
  const installed = json(join(root, 'node_modules/.package-lock.json'));
  const dependencies = [];
  const visit = (directory, prefix) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const path = `${prefix}/${entry.name}`;
      const full = join(root, path);
      assert.ok(entry.isDirectory() &&
        !entry.isSymbolicLink() &&
        realpathSync.native(full) === resolve(full), `Linked or special retained dependency: ${path}`);
      if (entry.name.startsWith('@')) {
        visit(full, path);
        continue;
      }
      const pkg = json(join(full, 'package.json'));
      const recorded = installed.packages[path];
      const locked = lock.packages[path];
      assert.ok(recorded &&
        locked, `Unrecorded retained dependency: ${path}`);
      assert.equal(pkg.version, recorded.version, `Retained version mismatch: ${path}`);
      for (const field of ['version', 'integrity', 'resolved']) {
        assert.equal(recorded[field], locked[field], `Retained lock mismatch: ${path}/${field}`);
      }
      assert.equal(locked.link, undefined, 'Linked retained dependencies are not supported');
      dependencies.push({ path, name: pkg.name, version: pkg.version, integrity: recorded.integrity });
      const nested = join(full, 'node_modules');
      if (existsSync(nested)) visit(nested, `${path}/node_modules`);
    }
  };
  visit(join(root, 'node_modules'), 'node_modules');
  assert.ok(dependencies.length > 0, 'Empty retained dependency graph');
  assert.deepEqual(dependencies.map(item => item.path).sort(), Object.keys(installed.packages).sort(),
    'Retained installed lock does not match the physical package graph');
  return dependencies.sort((a, b) => a.path.localeCompare(b.path));
}

export class LocalGate {
  constructor({ root = ROOT, output, workRoot, npmCli, publisherNode = process.execPath,
    containment, parentEnvironment = process.env }) {
    for (const path of [root, output, npmCli, publisherNode]) {
      assert.ok(typeof path === 'string' &&
        isAbsolute(path), 'Absolute paths required');
    }
    this.root = realpathSync.native(root);
    this.output = resolve(output);
    const work = workRoot === undefined ? join(this.output, 'work') : workRoot;
    assert.ok(typeof work === 'string' &&
      isAbsolute(work), 'Absolute work root required');
    this.work = resolve(work);
    const outside = relative(this.root, this.output);
    assert.ok(outside.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) ||
      isAbsolute(outside), 'Evidence must be outside the source checkout');
    assert.equal(existsSync(this.output), false, 'Use a new evidence directory; no overwrite or retry');
    const workOutside = relative(this.root, this.work);
    assert.ok(workOutside.startsWith(`..${sep}`) ||
      isAbsolute(workOutside), 'Work must be outside the source checkout');
    assert.notEqual(this.work, this.output, 'Work and evidence directories must differ');
    assert.equal(existsSync(this.work), false, 'Use a new work directory; no overwrite or retry');
    this.npmCli = realpathSync.native(npmCli);
    this.publisherNode = realpathSync.native(publisherNode);
    this.containment = containment ? structuredClone(containment) : undefined;
    const npm = json(resolve(dirname(this.npmCli), '../package.json'));
    assert.equal(npm.name, 'npm');
    assert.equal(npm.version, POLICY.npm, 'Retained reviewed npm is required; this gate never installs it');
    mkdirSync(this.output);
    mkdirSync(this.work);
    this.env = localEnvironment(parentEnvironment, join(this.work, 'home'));
    this.env.npm_execpath = this.npmCli;
    this.gitEmpty = join(this.work, 'empty-git-config');
    mkdirSync(this.gitEmpty);
    this.steps = [];
  }

  command(label, executable, args, cwd = this.root, binary = false, timeout = 15 * 60 * 1000,
    environment = this.env) {
    assert.ok(Number.isSafeInteger(timeout) &&
      timeout > 0 &&
      timeout <= SOURCE_SUITE_TIMEOUT_MS, 'Invalid command deadline');
    const index = this.steps.length + 1;
    const started = Date.now();
    const result = spawnSync(executable, args, {
      cwd, env: environment, shell: false, windowsHide: true, encoding: binary ? null : 'utf8',
      timeout, maxBuffer: 16 * 1024 * 1024,
    });
    const record = {
      label, executable, args, cwd, timeoutMs: timeout, elapsedMs: Date.now() - started,
      exitCode: result.status, signal: result.signal, error: result.error?.code ?? null,
      encoding: binary ? 'base64' : 'utf8',
      stdout: binary ? (result.stdout ?? Buffer.alloc(0)).toString('base64') : result.stdout ?? '',
      stderr: binary ? (result.stderr ?? Buffer.alloc(0)).toString('base64') : result.stderr ?? '',
    };
    const file = `command-${index}.json`;
    const bytes = Buffer.from(`${JSON.stringify(record)}\n`);
    writeFileSync(join(this.output, file), bytes, { flag: 'wx', flush: true });
    this.steps.push({ label, file, sha256: digest(bytes).sha256,
      exitCode: record.exitCode, signal: record.signal, error: record.error });
    assert.equal(result.error, undefined, `${label}: executable/timeout/output failure; see ${file}`);
    assert.equal(result.signal, null, `${label}: terminated; see ${file}`);
    assert.equal(result.status, 0, `${label}: failed; see ${file}`);
    return result.stdout;
  }

  git(args, cwd = this.root, binary = false) {
    const forbidden = ['fetch', 'push', 'pull', 'submodule', 'ls-remote', 'remote'];
    assert.ok(!args.some(arg => forbidden.includes(arg)), 'Local gate forbids remote Git operations');
    const config = new LocalGitConfig(cwd, this.gitEmpty,
      options => this.command('Parse local Git configuration', 'git', options, this.gitEmpty));
    try {
      const output = this.command('Local Git', 'git', [
        ...config.options(),
        '-c', `core.hooksPath=${this.gitEmpty}`, '-c', `init.templateDir=${this.gitEmpty}`,
        '-c', 'credential.helper=', '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=',
        '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', '-c', 'commit.gpgsign=false',
        '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always', ...args,
      ], cwd, binary);
      return binary ? output : output.trimEnd();
    } finally {
      config.verify();
    }
  }

  snapshot(root = this.root) {
    const files = this.git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'], root, true)
      .toString('utf8').split('\0').filter(Boolean).sort();
    let size = 0;
    return files.filter(file => existsSync(join(root, file))).map(file => {
      assert.ok(file.split('/').every(part => part &&
        part !== '.' &&
        part !== '..' &&
        !['.git', '.npmrc', 'node_modules'].includes(part.toLowerCase())) &&
        !/[\\:\0\r\n]/.test(file), `Unsupported source path: ${file}`);
      const path = join(root, file);
      const stat = lstatSync(path);
      size += stat.size;
      assert.ok(stat.size <= 64 * 1024 * 1024 &&
        size <= 512 * 1024 * 1024, 'Source snapshot exceeds the local gate limit');
      assert.ok(stat.isFile() &&
        !stat.isSymbolicLink() &&
        realpathSync.native(path) === resolve(path), `Linked or special source input: ${file}`);
      return { path: file, sha256: digest(readFileSync(path)).sha256 };
    });
  }

  checkout(snapshot, autocrlf) {
    const target = join(this.work, `checkout-${autocrlf}`);
    this.git(['clone', '--quiet', '--no-hardlinks', '--no-checkout', this.root, target]);
    // Start from an empty index, not the baseline tree. Candidate deletions must stay deleted.
    this.git(['read-tree', '--empty'], target);
    for (const { path } of snapshot) {
      mkdirSync(dirname(join(target, path)), { recursive: true });
      cpSync(join(this.root, path), join(target, path), { errorOnExist: true, force: false });
    }
    this.git(['-c', 'core.autocrlf=false', 'add', '--all', '--force', '--', '.'], target);
    this.git(['commit', '--quiet', '--allow-empty', '-m', 'Local gate fixture - never publish'], target);
    // This is a private fixture only. Force a real checkout through the candidate's attributes.
    for (const { path } of snapshot) rmSync(join(target, path));
    this.git(['-c', `core.autocrlf=${autocrlf}`, '-c', 'core.eol=crlf',
      'checkout', '--force', 'HEAD', '--', '.'], target);
    for (const directory of ['node_modules', 'ui/node_modules']) {
      cpSync(join(this.root, directory), join(target, directory), { recursive: true, dereference: false });
    }
    return target;
  }

  node(label, args, cwd) {
    return this.command(label, process.execPath, args, cwd);
  }

  sourceSuite(root, version, selected) {
    const environment = auditEnvironment({ ...this.env, CI: 'true' }, version);
    const temporary = join(this.work, 'source-test-temp');
    const alias = join(this.work, 'source-test-temp-alias');
    mkdirSync(temporary);
    symlinkSync(temporary, alias, process.platform === 'win32' ? 'junction' : 'dir');
    for (const key of ['TEMP', 'TMP', 'TMPDIR']) environment[key] = alias;
    return this.command('Complete source suite', process.execPath, selected,
      root, false, SOURCE_SUITE_TIMEOUT_MS, environment);
  }

  publisher(label, args, cwd) {
    return this.command(label, this.publisherNode, args, cwd);
  }

  sdk(root) {
    const environment = localEnvironment(this.env, join(this.work, 'sdk-home'), this.publisherNode);
    return JSON.parse(this.command('Actual lane SDK/signature load, no transport', this.publisherNode,
      ['tools/npm-publication/local-sdk-check.mjs', this.npmCli], root, false, 15 * 60 * 1000, environment));
  }

  stageCapture(root, version) {
    const home = join(this.work, 'stage-proof-fixtures');
    const environment = localEnvironment(this.env, join(this.work, 'stage-proof-driver-home'), this.publisherNode);
    const report = JSON.parse(this.command('Actual pinned npm stage capture, offline fixtures', this.publisherNode,
      ['tools/npm-publication/local-stage-check.mjs', this.npmCli, home],
      root, false, 15 * 60 * 1000, environment));
    return validateStageProof(report, { root, version, invocation: {
      root, cli: this.npmCli, node: this.publisherNode, home,
    } });
  }

  async native(root, version) {
    const commit = this.git(['rev-parse', 'HEAD'], root);
    const baseline = version === '1.3.1' ? LEGACY_REF : CURRENT_REF;
    this.git(['cat-file', '-e', `${baseline}^{commit}`], root);
    return verifyNativeIdentity({ sourceRoot: root, commit, version }, {
      run: (file, args, options) => {
        assert.equal(file, 'git');
        assert.equal(options.cwd, root);
        // The verifier supplies its own safe Git switches. This adapter keeps blobs as raw bytes.
        return { code: 0, stdout: this.git(args, options.cwd, true), stderr: Buffer.alloc(0) };
      },
    });
  }

  async retainedLicenses(root, extracted, pkg) {
    const dependencies = retainedDependencies(root);
    const project = join(this.work, 'retained-license-fixture');
    mkdirSync(project);
    // No install and no producer lock in this fixture. Only previously retained package bytes.
    cpSync(join(root, 'node_modules'), join(project, 'node_modules'), {
      recursive: true, dereference: false,
      filter: path => !relative(toNamespacedPath(join(root, 'node_modules')), toNamespacedPath(path)).split(sep)
        .some(part => part.startsWith('.')),
    });
    const licenseEvidence = captureConsumerLicenseEvidence(project, dependencies);
    const fixture = { schemaVersion: 2, producerLockCopied: false, dependencies, licenseEvidence };
    const licenses = await inspectRuntimeLicenses({
      sourceRoot: root, extractedRoot: extracted, name: pkg.name, version: pkg.version, consumers: [fixture],
    });
    // The production helper's fresh-consumer wording is not authority for these retained inputs.
    const result = {
      schemaVersion: 1, kind: 'retained-graph-finalizer-contract-fixture', releaseReady: false,
      freshRegistryEvidence: false, installedInThisRun: false, producerLockCopied: false,
      integrityMeaning: 'Retained lock metadata, not registry verification or a fresh resolution',
      dependencies, licenseEvidence,
      packages: licenses.packages.map(item => ({
        ...item, source: item.source === 'extracted-candidate' ? item.source : 'retained-license-fixture',
      })),
      notices: licenses.notices,
    };
    const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
    const file = 'retained-license-contract.json';
    writeFileSync(join(this.output, file), bytes, { flag: 'wx', flush: true });
    return { kind: result.kind, file, sha256: digest(bytes).sha256, packages: result.packages.length,
      freshRegistryEvidence: false, installedInThisRun: false, releaseReady: false };
  }

  async run() {
    // Accidental-invocation guard only. The parent's Hyper-V/network-none container is the boundary.
    validateContainment(this.containment, this.root, this.output, this.work);
    const report = {
      schemaVersion: 4, kind: 'local-publication-regression', status: 'failed', releaseReady: false,
      node: process.version, platform: process.platform, npm: POLICY.npm,
      containment: this.containment, publicationCandidate: false,
      hostedBoundaries: HOSTED_BOUNDARIES, checks: {}, steps: this.steps,
    };
    let snapshot;
    let failure;
    try {
      report.publisherNode = this.publisher('Pinned publisher runtime', ['-p', 'process.version'], this.root).trim();
      assert.equal(report.publisherNode, `v${POLICY.node}`, 'Reviewed publisher Node is required');
      snapshot = this.snapshot();
      report.source = { head: this.git(['rev-parse', 'HEAD']), files: snapshot };
      const pkg = json(join(this.root, 'package.json'));
      validatePackage(pkg, { version: pkg.version });
      report.version = pkg.version;
      const uiSelected = uiTestArguments(this.root, pkg.version);
      for (const file of ['package-lock.json', 'ui/package-lock.json']) checkLockfile(join(this.root, file));
      report.checks.publicLockfiles = true;
      const selected = testArguments(pkg.scripts.test);
      const listed = selected.slice(2).sort();
      assert.deepEqual(listed, readdirSync(join(this.root, 'test')).filter(file => file.endsWith('.test.mjs'))
        .map(file => `test/${file}`).sort(), 'The complete source suite must execute');
      for (const autocrlf of ['false', 'true']) {
        const root = this.checkout(snapshot, autocrlf);
        const checks = report.checks[`checkout-${autocrlf}`] = {
          kind: 'unpublishable-local-checkout-fixture', autocrlf, sourceNode: process.version,
          uiNode: report.publisherNode, publisherNode: report.publisherNode,
        };
        const before = this.snapshot(root);
        checks.nativeIdentity = await this.native(root, pkg.version);
        this.publisher('Actual UI rebuild and notice comparison', ['tools/third-party-notices/check.mjs'], root);
        checks.uiRebuild = true;
        assert.deepEqual(this.snapshot(root), before, 'UI rebuild modified checkout files');
        if (autocrlf === 'true') continue;
        const sourceOutput = this.sourceSuite(root, pkg.version, selected);
        checks.sourceTests = testTotals(sourceOutput);
        auditEvidence(sourceOutput, pkg.version, process.version);
        this.publisher('UI typecheck', ['node_modules/typescript/bin/tsc', '--noEmit'], join(root, 'ui'));
        checks.uiTests = uiSelected === null
          ? { status: 'not-defined', executed: false,
            reason: 'Legacy 1.3.1 defines neither a UI test script nor a ui/test directory' }
          : testTotals(this.publisher('UI tests', uiSelected, join(root, 'ui')));
        assert.deepEqual(this.snapshot(root), before, 'Source/UI tests modified checkout files');
        const packed = join(this.work, 'pack');
        mkdirSync(packed);
        const stdout = this.publisher('Real offline npm pack', [
          this.npmCli, 'pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', packed,
        ], root);
        const tarball = join(packed, `${POLICY.name}-${pkg.version}.tgz`);
        const bytes = readFileSync(tarball);
        writeFileSync(join(this.output, 'fixture.tgz'), bytes, { flag: 'wx', flush: true });
        const fixtureCommit = this.git(['rev-parse', 'HEAD'], root);
        const approval = { version: pkg.version, commit: fixtureCommit };
        const metadata = npm12Contents(stdout, approval, bytes);
        const extracted = join(this.work, 'extracted');
        mkdirSync(extracted);
        const inspected = extractTarball(bytes, approval, extracted);
        assert.deepEqual(metadata.files.map(({ path, size, mode }) => ({ path, size, mode }))
          .sort((a, b) => a.path.localeCompare(b.path)),
        inspected.files.map(({ path, size, mode }) => ({ path, size, mode })));
        checks.artifact = { ...digest(bytes), files: inspected.files, evidenceFile: 'fixture.tgz', publicationCandidate: false,
          fixtureCommit, kind: 'offline-npm12-pack-fixture', releaseReady: false };
        const extractedFiles = verifyArtifactFiles({
          tarball, extractedRoot: extracted, artifact: checks.artifact, name: pkg.name,
          version: pkg.version, commit: fixtureCommit,
        });
        for (const nativeFile of checks.nativeIdentity.files) {
          assert.deepEqual(extractedFiles.find(file => file.path === nativeFile.path), nativeFile,
            `Packed native bytes differ: ${nativeFile.path}`);
        }
        checks.extractedFiles = extractedFiles;
        checks.notices = verifyArtifacts(extracted);
        checks.sdk = this.sdk(root);
        assert.equal(checks.sdk.status, 'passed');
        assert.equal(checks.sdk.networkAttempts, 0);
        assert.equal(checks.sdk.subprocessAttempts, 0);
        assert.equal(checks.sdk.authenticated, false);
        assert.equal(checks.sdk.published, false);
        assert.equal(checks.sdk.provenanceVerified, false);
        assert.equal(checks.sdk.signatureVerified, false);
        assert.equal(checks.sdk.version, pkg.version);
        assert.equal(checks.sdk.contract, pkg.version === '1.3.1'
          ? 'legacy-staged-signature' : 'owner-sdk-and-provenance');
        assert.equal(checks.sdk.node, report.publisherNode);
        assert.equal(checks.sdk.npm, POLICY.npm);
        assert.equal(checks.sdk.releaseReady, false);
        checks.stageCapture = this.stageCapture(root, pkg.version);
        checks.retainedGraphLicenseContract = await this.retainedLicenses(root, extracted, pkg);
        assert.deepEqual(this.snapshot(root), before, 'Packaging or SDK check modified checkout files');
      }
      report.status = 'passed';
    } catch (error) {
      failure = error;
      report.error = error.message;
    } finally {
      if (snapshot) {
        try {
          assert.deepEqual(this.snapshot(), snapshot, 'Original source changed during gate');
          assert.equal(this.git(['rev-parse', 'HEAD']), report.source.head, 'Original HEAD changed during gate');
          report.originalPreserved = true;
        } catch (error) {
          report.originalPreserved = false;
          report.originalError = error.message;
          failure ??= error;
        }
      }
      if (failure) {
        report.status = 'failed';
        report.error ??= failure.message;
      }
      writeFileSync(join(this.output, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', flush: true });
    }
    if (failure) throw failure;
    return report;
  }
}

export async function main(args = process.argv.slice(2)) {
  assert.equal(args.length, 4, 'Usage: local-gate.mjs --npm-cli ABSOLUTE_PATH --output NEW_ABSOLUTE_DIRECTORY');
  assert.equal(args[0], '--npm-cli');
  assert.equal(args[2], '--output');
  const gate = new LocalGate({ npmCli: args[1], output: args[3] });
  const result = await gate.run();
  console.log(JSON.stringify({ status: result.status, version: result.version, releaseReady: false,
    report: join(gate.output, 'result.json') }));
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
