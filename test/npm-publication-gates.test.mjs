import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, join, posix } from 'node:path';
import { tmpdir } from 'node:os';
import { runInNewContext } from 'node:vm';
import { servicePaths } from '../bin/service-control.mjs';
import {
  ARTIFACT_EXTERNAL, SOURCE_EXTERNAL, CONSUMER_TOOLCHAINS, GateRunner,
  consumerSummary, evidenceFor, externalFailureSummary, externalGates, gateOptions, passed, validateConsumerMatrix,
} from '../tools/npm-publication/gates.mjs';
import { main as sourceMain, runSourceChecks, validateAudit } from '../tools/npm-publication/source-gates.mjs';
import { main as artifactMain, runArtifactChecks } from '../tools/npm-publication/artifact-gates.mjs';
import { POLICY, digest } from '../tools/npm-publication/policy.mjs';
import { fixturePlan, ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import { cleanNpmEnvironment } from '../tools/npm-publication/run.mjs';
import { temporaryEnvironment } from '../tools/npm-publication/gate-environment.mjs';

for (const [platform, tempRoot] of [
  ['linux', '/home/runner/work/_temp'],
  ['darwin', '/Users/runner/work/_temp'],
  ['darwin', '/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/T'],
]) {
  test(`Full publication HOME -> gate -> T32 socket path fits on ${platform}: ${tempRoot}`, () => {
    let prefix;
    const allocation = new Error('Controlled allocation probe; no files created');
    assert.throws(() => ownedDirectory({
      mkdtempSync(value) { prefix = basename(value); throw allocation; },
    }), error => error === allocation);
    const home = posix.join(tempRoot, 'npm-publication-home');
    const outer = cleanNpmEnvironment({ PATH: '/usr/bin', RUNNER_TEMP: tempRoot }, home);
    const gateDirectory = posix.join(outer.TMPDIR, `${prefix}ABC123`);
    const gateHome = posix.join(gateDirectory, 'home');
    const gate = GateRunner.prototype.environment.call({ owned: { dir: gateDirectory } },
      outer, gateHome, outer.TMPDIR);
    const replacementDirectory = posix.join(gate.TMPDIR, `${prefix}DEF456`);
    const socket = posix.join(replacementDirectory, 'service-45000.sock');
    temporaryEnvironment(gate.TMPDIR, platform);
    assert.ok(Buffer.byteLength(socket) <= 103,
      `Full production caller chain exceeds 103 UTF-8 bytes: ${Buffer.byteLength(socket)}`);
    const productionPaths = runInNewContext(`(${servicePaths.toString()})`, {
      createHash, Buffer, dirname: posix.dirname, resolve: posix.resolve, join: posix.join,
      process: { platform },
    });
    assert.equal(productionPaths(posix.join(replacementDirectory, 'servers.json'), 45000).socket, socket);
    const oldNested = posix.join(home, `${prefix}ABC123`, `${prefix}DEF456`, 'servers.json');
    assert.throws(() => productionPaths(oldNested, 45000), /103 UTF-8 bytes/);
    assert.equal(outer.HOME, home);
    assert.equal(gate.HOME, gateHome);
    assert.notEqual(gate.HOME, outer.HOME);
    for (const env of [outer, gate]) {
      for (const name of ['TMPDIR', 'TMP', 'TEMP']) assert.equal(env[name], tempRoot);
    }
    assert.equal(posix.dirname(replacementDirectory), posix.dirname(gateDirectory));
  });
}

test('Publication scratch qualification counts UTF-8 bytes and refuses long roots without fallback', () => {
  const suffix = '/pacemaker-compat-XXXXXX/service-65535.sock';
  const boundary = `/${'x'.repeat(103 - Buffer.byteLength(suffix) - 1)}`;
  for (const platform of ['linux', 'darwin']) {
    assert.equal(temporaryEnvironment(boundary, platform).TMPDIR, boundary);
    for (const root of [`${boundary}x`, `${boundary}é`, '/tmp/'.concat('界'.repeat(30))]) {
      assert.throws(() => temporaryEnvironment(root, platform), /too long for T32/);
    }
  }
  for (const root of ['', 'relative', '/tmp/\0bad', '/tmp/\nbad']) {
    assert.throws(() => temporaryEnvironment(root), /absolute path/);
  }
});

test('Flat scratch siblings retain independent directory and marker ownership checks', () => {
  const gate = ownedDirectory();
  const replacement = ownedDirectory();
  try {
    const home = join(gate.dir, 'home');
    mkdirSync(home, { mode: 0o700 });
    const env = GateRunner.prototype.environment.call({ owned: gate }, {}, home);
    assert.equal(env.TMPDIR, tmpdir());
    assert.equal(env.HOME, home);
    assert.notEqual(gate.dir, replacement.dir);
    assert.notEqual(gate.marker, replacement.marker);
    assert.throws(() => removeOwnedDirectory({
      ...replacement, identity: { ...replacement.identity, ino: 'different' },
    }), /identity changed/);
    assert.ok(existsSync(replacement.dir));
    assert.ok(existsSync(replacement.marker));
  } finally {
    removeOwnedDirectory(replacement);
    removeOwnedDirectory(gate);
  }
});

const evidence = evidenceFor('Controlled executor fixture; not real publication gate evidence', 'fixture');
const source = { commit: 'a'.repeat(40), tree: 'b'.repeat(40), name: POLICY.name, version: '2.0.1',
  rootLockSha256: 'c'.repeat(64), uiLockSha256: 'd'.repeat(64) };
const binding = {
  source, commit: source.commit, version: source.version, artifact: digest(Buffer.from('fixture')),
  sourceReportSha256: 'a'.repeat(64),
  tarball: join(tmpdir(), 'not-a-real-publication-candidate.tgz'), extractedRoot: join(tmpdir(), 'not-extracted'),
  files: [{ path: 'package.json', size: 7, mode: 0o644, sha256: evidence.sha256 }],
};
const humanGates = [
  'source-private-identifiers', 'payload-private-identifiers', 'author-identity', 'historical-risk-disposition',
];

function lane(toolchain, platform, mode, artifact = binding) {
  return {
    name: POLICY.name, version: artifact.version, sha256: artifact.artifact.sha256,
    ...toolchain, platform, installScripts: mode, producerLockCopied: false,
    installedBin: true, bridgeAndUi: true,
    dependencies: [{ name: POLICY.name, version: artifact.version, integrity: null }],
    registrySignature: 'pending-publication', provenance: 'not-verified-by-consumer-smoke',
  };
}

function lanes(artifact = binding) {
  return ['linux', 'win32', 'darwin'].flatMap(platform => CONSUMER_TOOLCHAINS.flatMap(toolchain =>
    ['npm-default', 'disabled'].map(mode => lane(toolchain, platform, mode, artifact))));
}

function gates(names) {
  return Object.fromEntries(names.map(name => [name, humanGates.includes(name)
    ? { status: 'pending-owner-review', ownerReview: 'pending', evidence: [evidence] }
    : passed(evidence)]));
}

function cleanAudit() {
  return {
    auditReportVersion: 2, vulnerabilities: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
  };
}

class ControlledRunner {
  constructor(artifact = binding) {
    this.calls = [];
    this.uiPackage = { scripts: { typecheck: 'fixture', test: 'fixture', build: 'fixture' } };
    this.failure = undefined;
    this.source = artifact.source;
    this.package = { version: artifact.version, scripts: Object.fromEntries(
      ['test', 'compat:prepare', 'compat:clean', 'test:compat', 'test:compat:browser']
        .map(name => [name, 'controlled fixture'])) };
    this.context = {
      publicPackages: [POLICY.name, 'smol-toml'],
      matrix: { consumerLanes: lanes(artifact).map(result => ({ result })), artifactEvidence: [evidence] },
      peer: {
        tarball: join(tmpdir(), 'not-a-real-peer.tgz'),
        prepared: { version: artifact.version === '1.3.1' ? '2.0.1' : '1.3.1',
          artifact: digest(Buffer.from('controlled opposite candidate fixture')) },
        inspection: { files: [] }, evidence,
      },
    };
    this.nativeIdentity = { fixtureOnly: true, reproducibilityBuild: 'not-executed-in-this-run' };
    this.authorIdentity = { fixtureOnly: true, review: 'pending-owner-review' };
    this.serviceStdout = `${JSON.stringify({ fixtureOnly: true, gate: 'T32-service-replacement' })}\n`;
  }

  requireScripts(names, pkg = this.package) {
    this.calls.push({ type: 'require', names });
    GateRunner.prototype.requireScripts.call(this, names, pkg);
  }

  snapshot() {
    return structuredClone(this.source);
  }

  publicCoordinates() {
    this.calls.push({ type: 'publicCoordinates' });
    if (this.failure === 'publicCoordinates') throw new Error('Controlled disclosure approval failure');
  }

  verifyArtifact(tarball, artifact) {
    this.calls.push({ type: 'verifyArtifact', tarball, artifact });
    if (this.failure === 'verifyArtifact') throw new Error('Controlled peer digest mismatch');
  }

  npm(args, label) {
    this.calls.push({ type: 'npm', args, label });
    if (this.failure === label) throw new Error(`Controlled failure: ${label}`);
    return { stdout: args.includes('audit') ? JSON.stringify(cleanAudit()) : POLICY.npm,
      evidence: evidenceFor(`Controlled ${label}`, `fixture: ${label}`) };
  }

  script(name, args = []) {
    this.calls.push({ type: 'script', name, args });
    if (this.failure === name) throw new Error(`Controlled failure: ${name}`);
    assert.notEqual(name, 'consumer:check', 'Finalizer must not repeat hosted consumer modes');
    return { stdout: '', evidence };
  }

  node(file, args, label) {
    this.calls.push({ type: 'node', file, args, label });
    if (this.failure === file) throw new Error(`Controlled failure: ${file}`);
    if (file === 'tools/service-replacement/check.mjs') {
      return { stdout: this.serviceStdout.trim(), rawStdout: this.serviceStdout, evidence };
    }
    return { stdout: '', evidence };
  }

  compatibility(artifact) {
    this.calls.push({ type: 'compatibility', artifact });
    if (this.failure === 'compatibility') throw new Error('Controlled compatibility failure');
    return [evidence];
  }

  external(phase, artifact, additional) {
    this.calls.push({ type: 'external', phase, artifact, additional });
    if (this.failure === 'external') throw new Error('Controlled external gate failure');
    return {
      gates: gates(phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL),
      nativeIdentity: this.nativeIdentity, authorIdentity: this.authorIdentity,
      nativeWindows: { fixtureOnly: true }, serviceReplacement: { fixtureOnly: true },
      runtimeLicenses: { fixtureOnly: true },
    };
  }
}

function sourceReport(artifact = binding) {
  return runSourceChecks(new ControlledRunner(artifact));
}

test('Controlled source orchestration checks disclosure before restores/audits and defers compatibility', () => {
  const runner = new ControlledRunner();
  const result = runSourceChecks(runner);
  assert.deepEqual(result.gates['producer-advisories'].evidence, [
    evidence, ...['root', 'UI'].map(name => evidenceFor(`Controlled Audit actual ${name} producer graph`,
      `fixture: Audit actual ${name} producer graph`)),
  ]);
  assert.equal(result.nativeIdentity, runner.nativeIdentity);
  assert.equal(result.authorIdentity, runner.authorIdentity);
  assert.equal(result.checks.compatibility, 'pending-exact-tarball');
  assert.equal(result.checks.uiTests.status, 'passed');
  assert.equal(runner.calls.filter(call => call.type === 'npm' && call.args.includes('ci')).length, 2);
  assert.ok(runner.calls.some(call => call.type === 'script' && call.name === 'test'));
  assert.ok(runner.calls.some(call => call.type === 'node' &&
    call.file === 'tools/third-party-notices/check.mjs'));
  assert.ok(!runner.calls.some(call => call.type === 'compatibility'));
  assert.ok(runner.calls.findIndex(call => call.type === 'publicCoordinates') <
    runner.calls.findIndex(call => call.type === 'npm'));
  assert.deepEqual(runner.calls.filter(call => call.type === 'npm' &&
    call.args.includes('ci')).map(call => call.args), [
    ['ci', '--ignore-scripts', '--no-audit', '--no-fund'],
    ['--prefix', 'ui', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
  ]);
  for (const name of humanGates.filter(name => SOURCE_EXTERNAL.includes(name))) {
    assert.equal(result.gates[name].status, 'pending-owner-review');
    assert.equal(result.gates[name].ownerReview, 'pending');
  }
  assert.ok(runner.calls.some(call => call.type === 'external' && call.phase === 'source'));
  assert.ok(!runner.calls.some(call => call.args?.some(arg => ['publish', 'pack'].includes(arg))));
});

test('Missing UI test script is explicit not-applicable, not a manufactured test pass', () => {
  const runner = new ControlledRunner();
  delete runner.uiPackage.scripts.test;
  const result = runSourceChecks(runner);
  assert.equal(result.checks.uiTests.status, 'not-applicable');
  assert.ok(!runner.calls.some(call => call.label === 'UI tests'));
});

test('Missing hooks and failed executable checks cannot produce a source success report', () => {
  for (const [target, name] of [['package', 'test'], ['uiPackage', 'typecheck'], ['uiPackage', 'build']]) {
    const missing = new ControlledRunner();
    delete missing[target].scripts[name];
    assert.throws(() => runSourceChecks(missing), /missing/);
    assert.equal(missing.calls.filter(call => call.type === 'npm').length, 0);
  }
  for (const failure of ['test', 'UI typecheck', 'UI tests', 'Build actual UI and bundled notices',
    'tools/third-party-notices/check.mjs', 'external']) {
    const runner = new ControlledRunner();
    runner.failure = failure;
    assert.throws(() => runSourceChecks(runner), /Controlled/);
  }
});

test('Disclosure rejection stops source and artifact checks before any producer npm call', () => {
  for (const phase of ['source', 'artifact']) {
    const runner = new ControlledRunner();
    runner.failure = 'publicCoordinates';
    assert.throws(() => phase === 'source' ? runSourceChecks(runner) :
      runArtifactChecks(runner, binding, sourceReport(), evidence), /disclosure/);
    assert.ok(!runner.calls.some(call => ['npm', 'node', 'script', 'external'].includes(call.type)));
  }
});

test('Public-coordinate adapter checks both actual lock fixtures against the explicit approval', () => {
  const owned = ownedDirectory();
  try {
    mkdirSync(join(owned.dir, 'ui'));
    for (const [path, name] of [['package-lock.json', 'root-fixture'], ['ui/package-lock.json', 'ui-fixture']]) {
      writeFileSync(join(owned.dir, path), JSON.stringify({ lockfileVersion: 3, packages: {
        [`node_modules/${name}`]: { version: '1.0.0',
          resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz` },
      } }));
    }
    const runner = { root: owned.dir, context: { publicPackages: ['root-fixture', 'ui-fixture'] } };
    GateRunner.prototype.publicCoordinates.call(runner);
    for (const publicPackages of [undefined, [], ['root-fixture'], ['ui-fixture']]) {
      runner.context.publicPackages = publicPackages;
      assert.throws(() => GateRunner.prototype.publicCoordinates.call(runner));
    }
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('Producer audit requires actual npm12 report schema and zero findings at every severity', () => {
  validateAudit(JSON.stringify(cleanAudit()));
  assert.throws(() => validateAudit('{}'));
  for (const severity of Object.keys(cleanAudit().metadata.vulnerabilities)) {
    const report = cleanAudit();
    report.metadata.vulnerabilities[severity] = 1;
    assert.throws(() => validateAudit(JSON.stringify(report)), /Producer advisories/);
  }
});

test('Source mutation after executable checks invalidates the source report', () => {
  const runner = new ControlledRunner();
  let reads = 0;
  runner.snapshot = () => ({ ...source, tree: reads++ ? 'e'.repeat(40) : source.tree });
  assert.throws(() => runSourceChecks(runner), /changed/);
});

test('Controlled finalizer consumes all 12 receipts and binds compatibility/T32 to exact own and peer artifacts', () => {
  for (const version of ['1.3.1', '2.0.1']) {
    const artifact = { ...binding, version, source: { ...source, version } };
    const runner = new ControlledRunner(artifact);
    const report = sourceReport(artifact);
    const result = runArtifactChecks(runner, artifact, report, evidence);
    const peer = runner.context.peer;
    const own = { tarball: artifact.tarball, version, ...artifact.artifact, files: artifact.files };
    const opposite = { tarball: peer.tarball, version: peer.prepared.version,
      ...peer.prepared.artifact, files: peer.inspection.files };
    const pair = version === '1.3.1' ? { legacy: own, current: opposite } : { legacy: opposite, current: own };
    const calls = runner.calls;
    assert.ok(!calls.some(call => call.name === 'consumer:check'));
    assert.equal(calls.find(call => call.type === 'compatibility').artifact, artifact);
    assert.deepEqual(calls.find(call => call.file === 'tools/service-replacement/check.mjs').args, [
      '--legacy-tarball', pair.legacy.tarball, '--legacy-sha256', pair.legacy.sha256,
      '--current-tarball', pair.current.tarball, '--current-sha256', pair.current.sha256,
    ]);
    assert.deepEqual(calls.filter(call => call.type === 'verifyArtifact'), [
      { type: 'verifyArtifact', tarball: peer.tarball, artifact: peer.prepared.artifact },
    ]);
    const external = calls.find(call => call.type === 'external');
    assert.equal(external.artifact, artifact);
    assert.equal(external.additional.matrix, runner.context.matrix);
    assert.equal(external.additional.sourceReport, report);
    assert.deepEqual(external.additional.consumers, lanes(artifact).filter(item =>
      item.platform === 'linux' &&
      item.npm === POLICY.npm));
    assert.equal(external.additional.consumers.length, 2);
    assert.deepEqual(external.additional.replacement.approvedArtifacts, pair);
    assert.equal(external.additional.replacement.stdout, runner.serviceStdout);
    assert.deepEqual(external.additional.replacement.result, JSON.parse(runner.serviceStdout));
    assert.equal(external.additional.replacement.evidence, evidence);
    assert.deepEqual(calls.filter(call => call.type === 'npm' &&
      call.args.includes('ci')).map(call => call.args), [
      ['ci', '--ignore-scripts', '--no-audit', '--no-fund'],
      ['--prefix', 'ui', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
    ]);
    const browser = calls.find(call => call.file === 'ui/node_modules/playwright/cli.js');
    assert.deepEqual(browser.args, ['install', '--with-deps', 'chromium']);
    assert.ok(calls.indexOf(browser) < calls.findIndex(call => call.type === 'compatibility'));
    assert.ok(calls.findIndex(call => call.type === 'verifyArtifact') < calls.indexOf(external));
    assert.deepEqual(result.consumers, lanes(artifact));
    assert.equal(result.coverage.consumerLanes.length, 12);
    assert.equal(result.coverage.registrySignatures, 'pending-publication');
    assert.equal(result.coverage.provenance, 'pending-stage');
    assert.equal(result.coverage.privateContentReview, 'pending-owner-review');
    assert.equal(result.matrixArtifacts, runner.context.matrix.artifactEvidence);
    assert.equal(result.peerArtifact, peer.evidence);
    assert.equal(result.gates.compatibility.status, 'passed');
    assert.equal(result.sourceChecks.compatibility, 'pending-exact-tarball');
    assert.equal(result.gates['consumer-npm12'].evidence.length, 1);
    for (const name of humanGates) assert.equal(result.gates[name].status, 'pending-owner-review');
    assert.ok(!calls.some(call => call.args?.includes('pack')));
  }
});

test('Final report binds raw source report bytes, not a reserialized JSON hash', () => {
  const report = sourceReport();
  const raw = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  const exact = { ...binding, sourceReportSha256: digest(raw).sha256 };
  const result = runArtifactChecks(new ControlledRunner(), exact, report, evidence);
  assert.equal(result.sourceReportSha256, digest(raw).sha256);
  assert.notEqual(result.sourceReportSha256, digest(Buffer.from(JSON.stringify(report))).sha256);
  assert.throws(() => runArtifactChecks(new ControlledRunner(),
    { ...binding, sourceReportSha256: undefined }, report, evidence), /file digest/);
});

test('Wrong matrix consumer identity/toolchain/bin/UI fails before external checks or finalizer restores', () => {
  for (const field of ['name', 'sha256', 'version', 'npm', 'node', 'platform', 'installScripts',
    'producerLockCopied', 'installedBin', 'bridgeAndUi', 'registrySignature', 'provenance', 'dependencies']) {
    const runner = new ControlledRunner();
    runner.context.matrix.consumerLanes[11].result[field] = 'wrong';
    assert.throws(() => runArtifactChecks(runner, binding, sourceReport(), evidence));
    assert.ok(!runner.calls.some(call => ['npm', 'node', 'compatibility', 'external', 'publicCoordinates'].includes(call.type)));
  }
  const runner = new ControlledRunner();
  const report = sourceReport();
  report.source.commit = 'e'.repeat(40);
  assert.throws(() => runArtifactChecks(runner, binding, report, evidence), /bound/);
});

test('Missing matrix, raw lanes without result wrappers, missing modes and duplicate modes fail before restores', () => {
  const variants = [
    undefined, {}, { consumerLanes: lanes() },
    ...lanes().map((_, index) => ({ consumerLanes: lanes().filter((item, at) => at !== index)
      .map(result => ({ result })) })),
    ...lanes().map((_, index) => {
      const results = lanes();
      results[index] = results[index ^ 1];
      return { consumerLanes: results.map(result => ({ result })) };
    }),
  ];
  for (const matrix of variants) {
    const runner = new ControlledRunner();
    runner.context.matrix = matrix;
    assert.throws(() => runArtifactChecks(runner, binding, sourceReport(), evidence));
    assert.ok(!runner.calls.some(call => ['npm', 'node', 'compatibility', 'external'].includes(call.type)));
  }
});

test('Missing peer, failed exact compatibility/T32, malformed output and changed peer bytes cannot finalize', () => {
  for (const peer of [undefined, {}, { tarball: '' }]) {
    const runner = new ControlledRunner();
    runner.context.peer = peer;
    assert.throws(() => runArtifactChecks(runner, binding, sourceReport(), evidence), /peer source artifact/);
    assert.ok(!runner.calls.some(call => call.type === 'external' ||
      call.file === 'tools/service-replacement/check.mjs'));
  }
  for (const failure of ['Restore finalizer root dependencies', 'Restore finalizer UI dependencies',
    'ui/node_modules/playwright/cli.js', 'compatibility', 'tools/service-replacement/check.mjs', 'verifyArtifact']) {
    const runner = new ControlledRunner();
    runner.failure = failure;
    assert.throws(() => runArtifactChecks(runner, binding, sourceReport(), evidence), /Controlled/);
    assert.ok(!runner.calls.some(call => call.type === 'external'));
  }
  const malformed = new ControlledRunner();
  malformed.serviceStdout = 'not JSON';
  assert.throws(() => runArtifactChecks(malformed, binding, sourceReport(), evidence), SyntaxError);
  assert.ok(!malformed.calls.some(call => call.type === 'external'));
});

test('External evidence is phase/source/payload bound; only designated owner-pending gates survive', () => {
  for (const phase of ['source', 'artifact']) {
    const names = phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL;
    const report = { schemaVersion: 1, phase, commit: binding.commit, artifact: binding.artifact, gates: gates(names) };
    externalGates(report, phase, binding);
    for (const name of names.filter(name => humanGates.includes(name))) {
      assert.equal(externalGates(report, phase, binding)[name].status, 'pending-owner-review');
      const missingOwner = structuredClone(report);
      delete missingOwner.gates[name].ownerReview;
      assert.throws(() => externalGates(missingOwner, phase, binding), /not passed/);
    }
    for (const name of names) {
      const pending = structuredClone(report);
      pending.gates[name].status = 'pending';
      assert.throws(() => externalGates(pending, phase, binding), /not passed/);
      delete pending.gates[name];
      assert.throws(() => externalGates(pending, phase, binding), /not passed/);
    }
    assert.throws(() => externalGates({ ...report, commit: 'f'.repeat(40) }, phase, binding));
    if (phase === 'artifact') {
      assert.throws(() => externalGates({ ...report, artifact: digest(Buffer.from('wrong')) }, phase, binding));
    }
  }
});

test('External adapter calls the node entrypoint directly without an undefined package-script hook', () => {
  const owned = ownedDirectory();
  try {
    for (const phase of ['source', 'artifact']) {
      const calls = [];
      const runner = {
        root: owned.dir, owned, context: { publicPackages: [POLICY.name] },
        script() { assert.fail('No publication:external-gates package script is required'); },
        node(file, args) {
          calls.push({ file, args });
          const request = JSON.parse(readFileSync(args[1], 'utf8'));
          assert.equal(request.phase, phase);
          assert.deepEqual(request.publicPackages, this.context.publicPackages);
          writeFileSync(args[3], JSON.stringify({
            schemaVersion: 1, phase, commit: binding.commit, artifact: binding.artifact,
            gates: gates(phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL),
          }));
          return { evidence };
        },
      };
      const report = GateRunner.prototype.external.call(runner, phase, binding);
      assert.deepEqual(calls, [{ file: 'tools/npm-publication/external-gates.mjs', args: [
        '--request', join(owned.dir, `${phase}-request.json`),
        '--output', join(owned.dir, `${phase}-external.json`),
      ] }]);
      assert.equal(report.gates[phase === 'source' ? 'source-gitleaks' : 'payload-gitleaks'].evidence.length, 2);
    }
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('External adapter exposes only the safe subgate and preserves the original execution failure', t => {
  const owned = ownedDirectory();
  t.after(() => removeOwnedDirectory(owned));
  const messages = [];
  t.mock.method(console, 'error', (...values) => messages.push(values.join(' ')));
  const failure = new Error('Private synthetic execution failure');
  failure.exitCode = 17;
  const runner = {
    root: owned.dir, owned, context: { publicPackages: [POLICY.name] },
    node(file, args) {
      writeFileSync(args[3], JSON.stringify({
        schemaVersion: 1, phase: 'source', commit: binding.commit, status: 'failed',
        error: { gate: 'native-release-identity', code: 'external-gate-rejected',
          message: 'Private synthetic message', reviewRequired: 'Private synthetic review',
          diagnosticSha256: 'f'.repeat(64) },
        stdout: 'Private synthetic stdout', policy: { private: 'Private synthetic policy' },
      }));
      throw failure;
    },
  };
  assert.throws(() => GateRunner.prototype.external.call(runner, 'source', binding), error => error === failure);
  assert.deepEqual(messages, [
    'External gate failure: gate=native-release-identity; code=external-gate-rejected',
  ]);
  assert.equal(failure.exitCode, 17);
});

class ExternalFailureFixture {
  constructor(t, phase = 'source') {
    this.owned = ownedDirectory();
    t.after(() => removeOwnedDirectory(this.owned));
    this.phase = phase;
    this.path = join(this.owned.dir, `${phase}-external.json`);
    this.report = { schemaVersion: 1, phase, commit: binding.commit, status: 'failed',
      ...(phase === 'artifact' ? { artifact: binding.artifact } : {}),
      error: { gate: 'scanner-adapter', code: 'external-gate-rejected' } };
  }

  write(value = this.report) {
    writeFileSync(this.path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value));
  }

  summary(owned = this.owned) {
    return externalFailureSummary(owned, this.phase, binding);
  }
}

const unavailable = { gate: 'report-unavailable', code: 'external-report-unavailable' };

test('Safe external failures pin an owned root through a temporary-directory alias', () => {
  const sandbox = realpathSync.native(mkdtempSync(join(tmpdir(), 'external-owner-alias-')));
  const target = join(sandbox, 'target');
  const other = join(sandbox, 'other');
  const alias = join(sandbox, 'alias');
  const linkType = process.platform === 'win32' ? 'junction' : 'dir';
  const previous = Object.fromEntries(['TMPDIR', 'TMP', 'TEMP'].map(name => [name, process.env[name]]));
  let owned;
  try {
    mkdirSync(target);
    mkdirSync(other);
    symlinkSync(target, alias, linkType);
    for (const name of Object.keys(previous)) process.env[name] = alias;
    owned = ownedDirectory();
    const marker = readFileSync(owned.marker);
    writeFileSync(join(owned.dir, 'source-external.json'), JSON.stringify({
      schemaVersion: 1, phase: 'source', commit: binding.commit, status: 'failed',
      error: { gate: 'native-release-identity', code: 'external-gate-rejected' },
    }));
    const expected = { gate: 'native-release-identity', code: 'external-gate-rejected' };
    assert.deepEqual(externalFailureSummary(owned, 'source', binding), expected);
    const canonical = realpathSync.native(owned.dir);
    assert.deepEqual(externalFailureSummary({
      ...owned, dir: canonical, marker: `${canonical}.compat-owner`,
    }, 'source', binding), unavailable, 'Ownership records cannot be relabeled.');
    const replacement = join(other, basename(owned.dir));
    mkdirSync(replacement);
    writeFileSync(`${replacement}.compat-owner`, marker);
    writeFileSync(join(replacement, 'source-external.json'), readFileSync(join(owned.dir, 'source-external.json')));
    unlinkSync(alias);
    symlinkSync(other, alias, linkType);
    try {
      assert.deepEqual(externalFailureSummary(owned, 'source', binding), unavailable);
    } finally {
      unlinkSync(alias);
      symlinkSync(target, alias, linkType);
    }
    assert.deepEqual(externalFailureSummary(owned, 'source', binding), expected);
    assert.deepEqual(readFileSync(owned.marker), marker);
  } finally {
    try {
      if (owned) removeOwnedDirectory(owned);
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      rmSync(sandbox, { recursive: true, force: true });
    }
  }
});

for (const phase of ['source', 'artifact']) {
  test(`Safe external failures allow only phase-bound gate/code fields: ${phase}`, t => {
    const f = new ExternalFailureFixture(t, phase);
    for (const gate of [...(phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL),
      'request-validation', 'scanner-adapter']) {
      f.report.error.gate = gate;
      f.report.error.private = 'Private synthetic exception and policy';
      f.report.private = { stdout: 'Private synthetic stdout', stderr: 'Private synthetic stderr' };
      f.write();
      assert.deepEqual(f.summary(), { gate, code: 'external-gate-rejected' });
    }
  });
}

for (const [name, transform] of [
  ['malformed JSON', () => '{"Private synthetic":'],
  ['empty report', () => ''],
  ['oversized report', () => ' '.repeat(1024 * 1024 + 1)],
  ['invalid UTF-8', () => Buffer.from([0xff])],
  ['BOM', r => `\ufeff${JSON.stringify(r)}`],
  ['null', () => 'null'],
  ['wrong schema', r => ({ ...r, schemaVersion: 2 })],
  ['wrong commit', r => ({ ...r, commit: 'f'.repeat(40) })],
  ['wrong phase', r => ({ ...r, phase: 'artifact' })],
  ['success report after execution failure', r => ({ ...r, status: 'passed' })],
  ['missing error', r => ({ ...r, error: undefined })],
  ['other-phase gate', r => ({ ...r, error: { ...r.error, gate: 'payload-gitleaks' } })],
  ['private gate', r => ({ ...r, error: { ...r.error, gate: 'Private synthetic\n::error::injected' } })],
  ['private code', r => ({ ...r, error: { ...r.error, code: 'Private synthetic code' } })],
  ['non-string gate', r => ({ ...r, error: { ...r.error, gate: ['scanner-adapter'] } })],
]) {
  test(`Safe external failure marks ${name} unavailable`, t => {
    const f = new ExternalFailureFixture(t);
    f.write(transform(f.report));
    assert.deepEqual(f.summary(), unavailable);
  });
}

test('Safe external failure rejects missing, unowned, linked and payload-substituted reports', t => {
  const f = new ExternalFailureFixture(t, 'artifact');
  assert.deepEqual(f.summary(), unavailable);
  f.write({ ...f.report, artifact: digest(Buffer.from('different unit tarball')) });
  assert.deepEqual(f.summary(), unavailable);
  f.write();
  assert.deepEqual(f.summary({ ...f.owned, identity: { ...f.owned.identity, ino: 'changed' } }), unavailable);
  assert.deepEqual(f.summary({ ...f.owned, markerIdentity: { ...f.owned.markerIdentity, ino: 'changed' } }), unavailable);
  const marker = readFileSync(f.owned.marker);
  writeFileSync(f.owned.marker, '{"private":"synthetic changed marker"}');
  assert.deepEqual(f.summary(), unavailable);
  writeFileSync(f.owned.marker, marker);
  linkSync(f.path, join(f.owned.dir, 'unit-hardlink.json'));
  assert.deepEqual(f.summary(), unavailable);
  rmSync(join(f.owned.dir, 'unit-hardlink.json'));
  rmSync(f.path);
  mkdirSync(f.path);
  assert.deepEqual(f.summary(), unavailable);
});

test('Real controlled child exit and private transcript survive safe external reporting without replay', t => {
  const owned = ownedDirectory();
  t.after(() => removeOwnedDirectory(owned));
  const messages = [];
  t.mock.method(console, 'error', (...args) => messages.push(args.join(' ')));
  let original;
  let calls = 0;
  const runner = {
    root: owned.dir, owned, logs: [], env: {}, context: { publicPackages: [POLICY.name] },
    node(file, args) {
      calls++;
      const script = `require('node:fs').writeFileSync(process.argv[1], JSON.stringify({
        schemaVersion:1,phase:'source',commit:'${binding.commit}',status:'failed',
        error:{gate:'producer-advisories',code:'external-gate-rejected'}
      })); console.log('Private synthetic stdout'); console.error('Private synthetic stderr'); process.exit(23);`;
      try { return GateRunner.prototype.run.call(this, 'Controlled failing child', process.execPath, ['-e', script, args[3]]); }
      catch (error) { original = error; throw error; }
    },
  };
  assert.throws(() => GateRunner.prototype.external.call(runner, 'source', binding), error => error === original);
  assert.equal(original.actual, 23);
  assert.equal(calls, 1);
  assert.match(readFileSync(runner.logs[0], 'utf8'), /Private synthetic stdout/);
  assert.deepEqual(messages, ['External gate failure: gate=producer-advisories; code=external-gate-rejected']);
});

test('Unavailable reports and a failed diagnostic sink cannot replace or retry the original failure', t => {
  const f = new ExternalFailureFixture(t);
  t.mock.method(console, 'error', () => { throw new Error('Controlled diagnostic sink failure'); });
  const failure = new Error('Controlled original failure');
  let calls = 0;
  const runner = { owned: f.owned, root: f.owned.dir, context: {},
    node() { calls++; throw failure; } };
  assert.throws(() => GateRunner.prototype.external.call(runner, 'source', binding), error => error === failure);
  assert.equal(calls, 1);
});

test('A preexisting external report cannot be replayed for a new execution', t => {
  const f = new ExternalFailureFixture(t);
  f.write();
  const runner = { owned: f.owned, root: f.owned.dir, context: {},
    node() { assert.fail('Must not execute with an existing report'); } };
  assert.throws(() => GateRunner.prototype.external.call(runner, 'source', binding), /already exists/);
});

test('All exact platform/npm/script-mode lanes are mandatory; wrong-byte and duplicate reports fail', () => {
  validateConsumerMatrix(lanes(), binding);
  assert.throws(() => validateConsumerMatrix(lanes().slice(1), binding), /12 exact/);
  const duplicate = lanes();
  duplicate[0] = duplicate[1];
  assert.throws(() => validateConsumerMatrix(duplicate, binding), /Missing or ambiguous/);
  const wrongBytes = lanes();
  wrongBytes[7].sha256 = 'f'.repeat(64);
  assert.throws(() => validateConsumerMatrix(wrongBytes, binding));
  assert.throws(() => consumerSummary({ ...lanes()[0], dependencies: [] }, binding,
    CONSUMER_TOOLCHAINS[0], 'linux', 'npm-default'), /graph/);
});

test('Compatibility adapter passes exact-tarball override and cleans only its own newly prepared fixture', () => {
  const calls = [];
  const runner = {
    root: join(tmpdir(), 'uncreated-publication-runner-fixture'),
    package: { version: binding.version },
    script(name, args) {
      calls.push({ name, args });
      if (name === 'test:compat') throw new Error('Controlled CLI/API failure');
      return { stdout: '', evidence };
    },
    node() {
      return { evidence, stdout: JSON.stringify({
        plan: fixturePlan(binding.version), sources: { candidate: { archiveSha256: binding.artifact.sha256 } },
        npmVersion: POLICY.npm, runtimeMajor: POLICY.node.split('.')[0],
      }) };
    },
  };
  assert.throws(() => GateRunner.prototype.compatibility.call(runner, binding), /Controlled CLI/);
  assert.deepEqual(calls[0].args, ['--candidate-tarball', binding.tarball, '--candidate-sha256', binding.artifact.sha256]);
  assert.equal(calls.at(-1).name, 'compat:clean');
});

test('Compatibility evidence requires the reviewed npm and the exact root-role tarball in both release lines', () => {
  for (const version of ['1.3.1', '2.0.1']) {
    const role = version === '1.3.1' ? 'legacy' : 'candidate';
    for (const change of [undefined,
      manifest => { manifest.npmVersion = '11.6.1'; },
      manifest => { delete manifest.npmVersion; },
      manifest => { manifest.runtimeMajor = '22'; },
      manifest => { manifest.sources[role].archiveSha256 = 'f'.repeat(64); }]) {
      const manifest = {
        plan: fixturePlan(version), npmVersion: POLICY.npm, runtimeMajor: POLICY.node.split('.')[0],
        sources: { [role]: { archiveSha256: binding.artifact.sha256 } },
      };
      change?.(manifest);
      const calls = [];
      const runner = {
        root: join(tmpdir(), 'uncreated-publication-runner-fixture'),
        package: { version },
        script(name, args) {
          calls.push({ name, args });
          return { stdout: '', evidence };
        },
        node() {
          return { stdout: JSON.stringify(manifest), evidence };
        },
      };
      const invoke = () => GateRunner.prototype.compatibility.call(runner, { ...binding, version });
      if (change) {
        assert.throws(invoke);
        assert.deepEqual(calls.map(call => call.name), ['compat:prepare', 'compat:clean']);
      } else {
        invoke();
        assert.equal(manifest.plan[role].source, 'root');
        assert.deepEqual(calls.map(call => call.name),
          ['compat:prepare', 'test:compat', 'test:compat:browser', 'compat:clean']);
      }
      assert.deepEqual(calls[0].args,
        ['--candidate-tarball', binding.tarball, '--candidate-sha256', binding.artifact.sha256]);
    }
  }
});

test('Gate CLI requires explicit absolute paths and rejects duplicates and unknown actions', () => {
  const output = join(tmpdir(), 'gate-output.json');
  assert.equal(gateOptions(['--output', output], ['--output'])['--output'], output);
  for (const args of [[], ['--output', 'relative'], ['--output', output, '--output', output],
    ['--stage', output]]) {
    assert.throws(() => gateOptions(args, ['--output']));
  }
  for (const [main, required] of [
    [sourceMain, ['--context', '--output']],
    [artifactMain, ['--tarball', '--source-report', '--context', '--output']],
  ]) {
    const values = required.flatMap(name => [name, join(tmpdir(), `${name.slice(2)}-fixture.json`)]);
    assert.deepEqual(Object.keys(gateOptions(values, required)), required);
    for (let index = 0; index < required.length; index++) {
      const missing = values.filter((_, at) => Math.floor(at / 2) !== index);
      assert.throws(() => main(missing), /Missing gate option/);
      const relative = [...values];
      relative[index * 2 + 1] = 'relative.json';
      assert.throws(() => main(relative), /absolute path/);
    }
    assert.throws(() => main([...values, '--output', output]), /Repeated gate option/);
    assert.throws(() => main([...values, '--stage', output]), /Unknown gate option/);
  }
});
