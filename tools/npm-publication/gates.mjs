import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync,
  readFileSync, readSync, realpathSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  fixturePlan, ownedDirectory, removeOwnedDirectory,
} from '../compatibility/fixtures.mjs';
import { POLICY, digest, sameDigests, validatePackage, validateGateStatus } from './policy.mjs';
import { lockedCoordinates } from '../publication-scanners/advisories.mjs';
import { scannerEnvironment, temporaryEnvironment } from './gate-environment.mjs';
import { validateConsumerLicenseEvidence } from '../npm-consumer/license-evidence.mjs';
import { safeLicenseDiagnostic } from './runtime-licenses.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const SOURCE_EXTERNAL = Object.freeze([
  'source-gitleaks', 'source-trufflehog', 'source-private-identifiers',
  'producer-advisories', 'author-identity', 'native-release-identity', 'historical-risk-disposition',
]);
export const ARTIFACT_EXTERNAL = Object.freeze([
  'payload-gitleaks', 'payload-trufflehog', 'payload-private-identifiers',
  'consumer-advisories', 'licenses-notices', 'runtime-closure',
  'consumer-npm11', 'consumer-npm12', 'consumer-platforms', 'native-windows-execution', 'service-replacement',
]);
export const CONSUMER_TOOLCHAINS = Object.freeze([
  { node: 'v22.23.2', npm: '11.6.1' },
  { node: `v${POLICY.node}`, npm: POLICY.npm },
]);

export function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function fileIdentity(stat) {
  return { dev: String(stat.dev), ino: String(stat.ino), birthtimeNs: String(stat.birthtimeNs) };
}

function boundedJson(path, limit) {
  const before = lstatSync(path, { bigint: true });
  assert.ok(before.isFile() &&
    !before.isSymbolicLink() &&
    before.nlink === 1n &&
    before.size > 0n &&
    before.size <= BigInt(limit));
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd, { bigint: true });
    assert.deepEqual(fileIdentity(opened), fileIdentity(before));
    assert.equal(opened.size, before.size);
    assert.equal(opened.nlink, 1n);
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    assert.ok(length <= limit);
    const after = fstatSync(fd, { bigint: true });
    for (const key of ['dev', 'ino', 'birthtimeNs', 'size', 'mtimeNs', 'ctimeNs', 'nlink']) assert.equal(after[key], opened[key]);
    const current = lstatSync(path, { bigint: true });
    assert.equal(current.isSymbolicLink(), false);
    assert.deepEqual(fileIdentity(current), fileIdentity(before));
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length)));
  } finally {
    closeSync(fd);
  }
}

function checkExternalOwner(owned) {
  assert.equal(owned.marker, `${owned.dir}.compat-owner`);
  const directory = lstatSync(owned.dir, { bigint: true });
  assert.ok(directory.isDirectory() &&
    !directory.isSymbolicLink());
  assert.deepEqual(fileIdentity(directory), owned.identity);
  const canonicalDirectory = realpathSync.native(owned.dir);
  assert.deepEqual(fileIdentity(lstatSync(canonicalDirectory, { bigint: true })), owned.identity);
  const marker = lstatSync(owned.marker, { bigint: true });
  assert.ok(marker.isFile() &&
    !marker.isSymbolicLink() &&
    marker.nlink === 1n);
  assert.deepEqual(fileIdentity(marker), owned.markerIdentity);
  const canonicalMarker = realpathSync.native(owned.marker);
  assert.equal(canonicalMarker, `${canonicalDirectory}.compat-owner`);
  assert.deepEqual(fileIdentity(lstatSync(canonicalMarker, { bigint: true })), owned.markerIdentity);
  assert.deepEqual(boundedJson(canonicalMarker, 16 * 1024), owned);
  return canonicalDirectory;
}

export function externalFailureSummary(owned, phase, binding) {
  const unavailable = { gate: 'report-unavailable', code: 'external-report-unavailable' };
  try {
    assert.ok(['source', 'artifact'].includes(phase));
    const directory = checkExternalOwner(owned);
    const report = boundedJson(join(directory, `${phase}-external.json`), 1024 * 1024);
    assert.equal(checkExternalOwner(owned), directory);
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.phase, phase);
    assert.equal(report.commit, binding.commit);
    if (phase === 'artifact') sameDigests(report.artifact, binding.artifact);
    assert.equal(report.status, 'failed');
    const names = phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL;
    assert.ok([...names, 'request-validation', 'scanner-adapter'].includes(report.error?.gate));
    assert.equal(report.error.code, 'external-gate-rejected');
    const reviewRequired = phase === 'artifact' ?
      safeLicenseDiagnostic(report.error.reviewRequired, report.error.gate) : undefined;
    return { gate: report.error.gate, code: 'external-gate-rejected',
      ...(reviewRequired ? { reviewRequired } : {}) };
  } catch {
    return unavailable;
  }
}

export function gateOptions(args, required) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    assert.ok(required.includes(name), `Unknown gate option: ${name}`);
    assert.ok(!Object.hasOwn(options, name), `Repeated gate option: ${name}`);
    const value = args[index + 1];
    assert.ok(value &&
      isAbsolute(value), `${name} requires an absolute path`);
    options[name] = resolve(value);
  }
  for (const name of required) assert.ok(options[name], `Missing gate option: ${name}`);
  return options;
}

export function passed(...evidence) {
  return { status: 'passed', evidence };
}

export function evidenceFor(description, value) {
  return { description, sha256: digest(Buffer.from(value)).sha256 };
}

export function externalGates(report, phase, binding) {
  assert.equal(report?.schemaVersion, 1, 'Missing external check report');
  assert.equal(report.phase, phase);
  assert.equal(report.commit, binding.commit);
  if (phase === 'artifact') sameDigests(report.artifact, binding.artifact);
  const required = phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL;
  const gates = {};
  for (const name of required) {
    const gate = report.gates?.[name];
    validateGateStatus(name, gate);
    assert.ok(Array.isArray(gate.evidence) &&
      gate.evidence.length > 0, `Missing external evidence: ${name}`);
    gates[name] = { ...gate, evidence: gate.evidence.map(item => {
      assert.ok(typeof item.description === 'string' &&
        item.description.trim(), `Missing external evidence description: ${name}`);
      assert.match(item.sha256 ?? '', /^[a-f0-9]{64}$/, `Missing external evidence digest: ${name}`);
      return { description: item.description, sha256: item.sha256 };
    }) };
  }
  return gates;
}

export function consumerSummary(value, binding, toolchain, platform, mode) {
  const licenseEvidence = validateConsumerLicenseEvidence(value);
  assert.equal(value?.name, POLICY.name);
  assert.equal(value.version, binding.version);
  assert.equal(value.sha256, binding.artifact.sha256);
  assert.equal(value.node, toolchain.node);
  assert.equal(value.npm, toolchain.npm);
  assert.equal(value.platform, platform);
  assert.equal(value.installScripts, mode);
  assert.equal(value.producerLockCopied, false);
  assert.equal(value.installedBin, true);
  assert.equal(value.bridgeAndUi, true);
  assert.equal(value.registrySignature, 'pending-publication');
  assert.equal(value.provenance, 'not-verified-by-consumer-smoke');
  assert.ok(Array.isArray(value.dependencies) &&
    value.dependencies.length > 0, 'Missing actual consumer dependency graph');
  const dependencies = value.dependencies.map(item => {
    assert.ok(typeof item.name === 'string' &&
      typeof item.version === 'string', 'Incomplete consumer dependency graph');
    assert.ok(item.integrity === null ||
      typeof item.integrity === 'string', 'Invalid consumer dependency integrity');
    return { path: item.path, name: item.name, version: item.version, integrity: item.integrity };
  });
  const candidate = dependencies.filter(item => item.name === POLICY.name);
  assert.equal(candidate.length, 1, 'Expected one canonical consumer candidate');
  assert.equal(candidate[0].version, binding.version);
  assert.equal(candidate[0].integrity, binding.artifact.integrity, 'Consumer candidate integrity mismatch');
  return {
    schemaVersion: 2, name: value.name, version: value.version, sha256: value.sha256,
    node: value.node, npm: value.npm, platform: value.platform, installScripts: value.installScripts,
    producerLockCopied: false, installedBin: true, bridgeAndUi: true, dependencies, licenseEvidence,
    registrySignature: value.registrySignature, provenance: value.provenance,
  };
}

export function validateConsumerMatrix(lanes, binding) {
  assert.ok(Array.isArray(lanes), 'Missing actual cross-platform consumer reports');
  assert.equal(lanes.length, 12, 'Expected all 12 exact platform/npm/script-mode consumer lanes');
  for (const platform of ['linux', 'win32', 'darwin']) {
    for (const toolchain of CONSUMER_TOOLCHAINS) {
      for (const mode of ['npm-default', 'disabled']) {
        const matches = lanes.filter(item => item.platform === platform &&
          item.node === toolchain.node &&
          item.npm === toolchain.npm &&
          item.installScripts === mode);
        assert.equal(matches.length, 1, `Missing or ambiguous consumer lane: ${platform}/${toolchain.npm}/${mode}`);
        consumerSummary(matches[0], binding, toolchain, platform, mode);
      }
    }
  }
}

export class GateRunner {
  constructor(root = ROOT, context = {}) {
    this.root = root;
    this.context = context;
    this.package = readJson(join(root, 'package.json'));
    this.uiPackage = readJson(join(root, 'ui/package.json'));
    assert.equal(process.versions.node, POLICY.node, 'Use the reviewed publishing Node patch');
    this.cli = resolve(process.env.npm_execpath ?? process.env.NPM_PUBLICATION_CLI ?? '');
    const npmPackage = readJson(resolve(dirname(this.cli), '../package.json'));
    assert.equal(npmPackage.name, 'npm');
    assert.equal(npmPackage.version, POLICY.npm);
    for (const [name, value] of Object.entries(process.env)) {
      assert.ok(!/^(NPM_TOKEN|NODE_AUTH_TOKEN|NPM_ID_TOKEN|SIGSTORE_ID_TOKEN|NODE_OPTIONS)$/i.test(name) ||
        !value, 'Credentials and Node injection are forbidden in gate runners');
    }
    temporaryEnvironment(tmpdir());
    this.owned = ownedDirectory();
    this.logs = [];
    const home = join(this.owned.dir, 'home');
    mkdirSync(home, { mode: 0o700 });
    this.config = { user: join(home, 'user.npmrc'), global: join(home, 'global.npmrc') };
    for (const path of Object.values(this.config)) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
    this.env = this.environment(process.env, home);
  }

  environment(source, home, tempRoot = tmpdir()) {
    const env = {
      PATH: source.PATH ?? source.Path,
      HOME: home, USERPROFILE: home, ...temporaryEnvironment(tempRoot),
      XDG_CACHE_HOME: home, XDG_CONFIG_HOME: home, XDG_STATE_HOME: home,
      PLAYWRIGHT_BROWSERS_PATH: join(home, 'browsers'),
      CI: 'true', NO_COLOR: '1', GIT_TERMINAL_PROMPT: '0',
      ...scannerEnvironment(source),
    };
    for (const name of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) {
      if (source[name]) env[name] = source[name];
    }
    return env;
  }

  requireScripts(names, pkg = this.package) {
    for (const name of names) {
      assert.ok(typeof pkg.scripts?.[name] === 'string' &&
        pkg.scripts[name].trim(), `Required executable package script is missing: ${name}`);
    }
  }

  publicCoordinates() {
    for (const path of ['package-lock.json', 'ui/package-lock.json']) {
      lockedCoordinates(readJson(join(this.root, path)), { publicPackages: this.context.publicPackages });
    }
  }

  verifyArtifact(path, artifact) {
    sameDigests(digest(readFileSync(path)), artifact);
  }

  run(label, executable, args, cwd = this.root) {
    const result = spawnSync(executable, args, {
      cwd, env: this.env, encoding: 'utf8', shell: false, maxBuffer: 32 * 1024 * 1024,
    });
    const transcript = JSON.stringify({
      exitCode: result.status, signal: result.signal,
      stdout: result.stdout ?? '', stderr: result.stderr ?? '',
    });
    const log = join(this.owned.dir, `command-${this.logs.length + 1}.json`);
    writeFileSync(log, transcript, { flag: 'wx', mode: 0o600 });
    this.logs.push(log);
    assert.equal(result.error, undefined, `${label}: executable failed to start; no retry`);
    assert.equal(result.status, 0, `${label} failed; private evidence: ${log}; no retry`);
    return {
      stdout: (result.stdout ?? '').trim(),
      rawStdout: result.stdout ?? '',
      evidence: {
        ...evidenceFor(`${label}; Node ${POLICY.node}; npm ${POLICY.npm}`, transcript),
        exitCode: result.status,
        command: { file: executable, args, cwd },
        commandSha256: digest(Buffer.from(JSON.stringify({ file: executable, args, cwd }))).sha256,
        stdoutSha256: digest(Buffer.from(result.stdout ?? '')).sha256,
        stderrSha256: digest(Buffer.from(result.stderr ?? '')).sha256,
      },
    };
  }

  npm(args, label) {
    return this.run(label, process.execPath, [this.cli,
      `--userconfig=${this.config.user}`, `--globalconfig=${this.config.global}`,
      `--registry=${POLICY.registry}`, `--cache=${join(this.owned.dir, 'cache')}`, ...args]);
  }

  script(name, args = []) {
    return this.npm(['--silent', 'run', name, ...(args.length ? ['--', ...args] : [])], `npm run ${name}`);
  }

  node(file, args, label) {
    return this.run(label, process.execPath, [join(this.root, file), ...args]);
  }

  snapshot() {
    const git = args => this.run('Read exact Git source', 'git', ['-c', 'core.autocrlf=false', ...args]).stdout;
    assert.equal(git(['status', '--porcelain', '--untracked-files=all']), '', 'Source is not clean');
    validatePackage(this.package, { version: this.package.version });
    return {
      commit: git(['rev-parse', 'HEAD']), tree: git(['rev-parse', 'HEAD^{tree}']),
      name: this.package.name, version: this.package.version,
      rootLockSha256: digest(readFileSync(join(this.root, 'package-lock.json'))).sha256,
      uiLockSha256: digest(readFileSync(join(this.root, 'ui/package-lock.json'))).sha256,
    };
  }

  compatibility(binding) {
    assert.ok(!existsSync(join(this.root, 'node_modules/.cache/pacemaker-compat.json')),
      'Existing compatibility fixture is not owned by this gate run; clean it separately');
    const args = binding ? ['--candidate-tarball', binding.tarball, '--candidate-sha256', binding.artifact.sha256] : [];
    const evidence = [this.script('compat:prepare', args).evidence];
    let failure;
    try {
      const fixtureReport = this.node('tools/npm-publication/compatibility-report.mjs', [],
        'Validate actual compatibility fixture ownership, source and file hashes');
      const manifest = JSON.parse(fixtureReport.stdout);
      evidence.push(fixtureReport.evidence);
      assert.equal(manifest.npmVersion, POLICY.npm, 'Compatibility fixtures must record the reviewed npm version');
      assert.equal(manifest.runtimeMajor, POLICY.node.split('.')[0], 'Compatibility fixtures used a different Node major');
      assert.deepEqual(manifest.plan, fixturePlan(this.package.version));
      if (binding) {
        const role = this.package.version === '1.3.1' ? 'legacy' : 'candidate';
        assert.equal(manifest.sources[role].archiveSha256, binding.artifact.sha256,
          'Compatibility fixtures did not use the approved tarball');
      }
      evidence.push(evidenceFor('Exact compatibility source/version/archive/file manifest',
        JSON.stringify(manifest)));
      evidence.push(this.script('test:compat').evidence);
      evidence.push(this.script('test:compat:browser').evidence);
    } catch (error) {
      failure = error;
    }
    try { evidence.push(this.script('compat:clean').evidence); }
    catch (error) {
      throw failure ? new AggregateError([failure, error], 'Compatibility check and cleanup failed') : error;
    }
    if (failure) throw failure;
    return evidence;
  }

  external(phase, binding, additional = {}) {
    assert.ok(['source', 'artifact'].includes(phase));
    const request = join(this.owned.dir, `${phase}-request.json`);
    const output = join(this.owned.dir, `${phase}-external.json`);
    assert.equal(existsSync(output), false, 'External report already exists; no retry');
    writeFileSync(request, JSON.stringify({
      schemaVersion: 1, phase, sourceRoot: this.root, root: additional.extractedRoot ?? this.root,
      commit: binding.commit, version: binding.version, name: POLICY.name,
      requiredGates: phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL,
      publicPackages: this.context.publicPackages,
      ...(binding.artifact ? { artifact: binding.artifact, tarball: binding.tarball } : {}),
      ...additional,
    }), { flag: 'wx', mode: 0o600 });
    try {
      const execution = this.node('tools/npm-publication/external-gates.mjs',
        ['--request', request, '--output', output], 'Execute real external gate aggregator');
      const report = readJson(output);
      const gates = externalGates(report, phase, binding);
      for (const gate of Object.values(gates)) gate.evidence.push(execution.evidence);
      return { ...report, gates };
    } catch (error) {
      try {
        const summary = externalFailureSummary(this.owned, phase, binding);
        console.error(`External gate failure: gate=${summary.gate}; code=${summary.code}`);
        if (summary.reviewRequired) console.error(summary.reviewRequired);
      } catch { /* Reporting must not replace the original failure. */ }
      throw error;
    }
  }

  writeReport(path, report) {
    const target = relative(this.root, resolve(path));
    assert.ok(target === '..' ||
      target.startsWith(`..${sep}`) ||
      isAbsolute(target), 'Gate output must be outside the checkout');
    writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }

  finish(success) {
    if (success) removeOwnedDirectory(this.owned);
    else console.error(`Failed gate evidence retained privately: ${this.owned.dir}; owner marker: ${this.owned.marker}`);
  }
}
