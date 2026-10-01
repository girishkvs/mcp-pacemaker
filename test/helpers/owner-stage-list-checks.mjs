import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, openSync, closeSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import test from 'node:test';
import { StageListAudit, OWNER_LIST_LIMITS as LIMITS, boundedOwnerJson } from '../../tools/npm-publication/owner-stage-list-audit.mjs';
import { OwnerStageListTransport } from '../../tools/npm-publication/owner-stage-list-child.mjs';
import { publishOwnerListJson, readOwnerListJson, writeOwnerListBytes } from '../../tools/npm-publication/owner-stage-list-io.mjs';
import { ownerListSourceBinding, ownerListExecutableHash } from '../../tools/npm-publication/owner-stage-list-io.mjs';
import { OwnerListTestLifecycle } from './owner-stage-list-model.mjs';

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const cli = process.env.OWNER_LIST_TEST_CLI;
const integration = Boolean(cli && process.versions.node === '24.21.0');
const lifecycle = new OwnerListTestLifecycle();
class Fixture {
  item(index) {
    return { id: `${index.toString(16).padStart(8, '0')}-abcd-4abc-8abc-123456789abc`, packageName: 'mcp-pacemaker' };
  }
  options(page = 0) {
    return { registry: 'https://registry.npmjs.org/', query: { page, perPage: 100, package: 'mcp-pacemaker' } };
  }
  page(offset, count) {
    return Array.from({ length: count }, (_, index) => this.item(offset + index));
  }
  envelope(bytes, items = [], total = items.length) {
    const value = { modelMarker: 'owner-list-response', items, total, padding: '' };
    value.padding = 'x'.repeat(bytes - Buffer.byteLength(JSON.stringify(value)));
    assert.equal(Buffer.byteLength(JSON.stringify(value)), bytes);
    return value;
  }
  audit(envelopes, output) {
    const audit = new StageListAudit();
    envelopes.forEach((envelope, index) => {
      audit.begin('/-/stage', this.options(index));
      audit.accept(envelope);
    });
    return audit.finish(output ?? JSON.stringify(envelopes.flatMap(envelope => envelope.items)));
  }
  async sdk(envelopes, guarded) {
    const require = createRequire(cli);
    const registry = require('npm-registry-fetch');
    const StageList = require('./../lib/commands/stage/list.js');
    const original = registry.json;
    const audit = new StageListAudit();
    const outputs = [];
    let count = 0;
    const listener = (level, value) => { if (level === 'standard') outputs.push(value); };
    process.on('output', listener);
    registry.json = async (uri, options) => {
      if (guarded) audit.begin(uri, options);
      assert.ok(count < envelopes.length);
      const response = structuredClone(envelopes[count++]);
      if (guarded) audit.accept(response);
      return response;
    };
    try {
      const npm = { flatOptions: { registry: 'https://registry.npmjs.org/' }, config: {
        validate() {},
        get(name) {
          if (name === 'json') return true;
          if (name === 'workspaces') return false;
          if (name === 'workspace') return [];
          assert.fail(`Unexpected minimal config key ${name}`);
        },
      } };
      await new StageList(npm).exec(['mcp-pacemaker']);
      assert.equal(outputs.length, 1);
      return guarded ? audit.finish(outputs[0]) : JSON.parse(outputs[0]);
    } finally {
      registry.json = original;
      process.removeListener('output', listener);
    }
  }
  async run(model, { timeoutMs = LIMITS.commandMs, closeOutput = false,
    lifecycleControl, evidenceRoot = process.env.OWNER_LIST_TEST_EVIDENCE ?? tmpdir() } = {}) {
    assert.equal(process.platform, 'win32',
      'This bounded diagnostic requires the qualified Windows job fixture; no single-PID cleanup fallback');
    const budget = lifecycle.budget(timeoutMs);
    const directory = mkdtempSync(join(tmpdir(), 'owner-list-test-'));
    const evidence = join(evidenceRoot, `diagnostic-${directory.split(/[\\/]/).at(-1)}`);
    mkdirSync(evidence, { recursive: true });
    const home = join(directory, 'home');
    mkdirSync(home);
    const token = model.token ?? 'NONSECRET_OWNER_LIST_MODEL_TOKEN';
    writeFileSync(join(home, '.npmrc'), `//registry.npmjs.org/:_authToken=${token}\nregistry=https://wrong-config.invalid/\n`);
    const destination = join(directory, 'observation');
    const modelPath = join(directory, 'model.json');
    writeFileSync(modelPath, JSON.stringify({ ...model, destination, token }));
    const environment = { HOME: home, USERPROFILE: home, APPDATA: home, LOCALAPPDATA: home,
      TMP: directory, TEMP: directory, TMPDIR: directory, PATH: dirname(process.execPath),
      OWNER_LIST_MODEL_FILE: modelPath, OWNER_LIST_TEST_CLI: cli, NO_COLOR: '1' };
    for (const name of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) if (process.env[name]) environment[name] = process.env[name];
    const hook = pathToFileURL(join(root, 'test/helpers/owner-stage-list-model.mjs')).href;
    const args = ['--import', hook];
    if (timeoutMs === LIMITS.commandMs) {
      args.push(join(root, 'tools/npm-publication/owner-stage-list.mjs'), cli, destination);
    } else {
      const source = `import { runOwnerStageList } from ${JSON.stringify(pathToFileURL(join(root, 'tools/npm-publication/owner-stage-list.mjs')).href)};
        try { await runOwnerStageList({cli:process.env.OWNER_LIST_TEST_CLI,directory:${JSON.stringify(destination)},timeoutMs:${timeoutMs}}); }
        catch { process.exitCode=1; }`;
      const entry = join(directory, 'owner-stage-list-test-parent.mjs');
      writeFileSync(entry, source);
      args.push(entry);
    }
    if (lifecycleControl) {
      assert.equal(lifecycleControl, 'missing-parent-boundary');
      args.splice(0, args.length, '-e', 'process.exitCode = 0');
    }
    const hash = bytes => createHash('sha256').update(bytes).digest('hex');
    const binding = () => ({
      production: ownerListSourceBinding(), node: process.version,
      nodePath: process.execPath, nodeSha256: ownerListExecutableHash(process.execPath),
      cli, cliSha256: hash(readFileSync(cli)),
      testSha256: hash(readFileSync(fileURLToPath(import.meta.url))),
      modelSha256: hash(readFileSync(fileURLToPath(hook))),
      selectedEntrySha256: hash(readFileSync(join(root, 'test/npm-publication-proof.test.mjs'))),
    });
    const before = binding();
    lifecycle.write(evidence, 'context.json', { before, directory, evidence, budget,
      nonsecretExternalModelOnly: true, model, argv: [process.execPath, ...args],
      scope: lifecycleControl ?? 'actual npm CLI with external service modeled',
      environment: { names: Object.keys(environment).sort(), HOME: home, PATH: environment.PATH,
        inheritedConfig: false, token: 'explicit nonsecret fixture token; no owner credentials' } });
    let child, timer, value, launchResult, job;
    const failures = [];
    const chunks = { stdout: [], stderr: [] };
    const lengths = { stdout: 0, stderr: 0 };
    const hashes = { stdout: createHash('sha256'), stderr: createHash('sha256') };
    const captureLimit = 128 * 1024;
    let emergencyWatchdog = false;
    const started = performance.now();
    try {
      const command = lifecycle.windowsCommand(directory, args, Date.now() + budget.watchdogMs);
      lifecycle.write(evidence, 'launcher.json', { ...command, sha256: ownerListExecutableHash(command.file) });
      child = spawn(command.file, command.args, { cwd: home, env: environment,
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      lifecycle.write(evidence, 'controller-spawn.json', { pid: child.pid,
        at: new Date().toISOString(), identityMechanism: 'ChildProcess retained OS process handle' });
      if (closeOutput) child.stdout.destroy();
      for (const name of ['stdout', 'stderr']) {
        child[name].on('data', bytes => {
          lengths[name] += bytes.length;
          hashes[name].update(bytes);
          if (lengths[name] <= captureLimit) chunks[name].push(bytes);
          else lifecycle.write(directory, 'stop-request.json', { reason: 'fixture-output-budget', stream: name });
        });
      }
      timer = setTimeout(() => {
        emergencyWatchdog = true;
        lifecycle.write(evidence, 'emergency-watchdog.json', {
          reason: 'job controller did not close after command/startup/cleanup budget',
          pid: child.pid, elapsedMs: performance.now() - started,
          action: 'Kill retained controller handle; kernel KILL_ON_JOB_CLOSE contains descendants',
        });
        child.kill('SIGKILL');
      }, budget.watchdogMs + budget.cleanupMs);
      launchResult = await new Promise((resolveChild, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => resolveChild({ code, signal }));
      });
    } catch (error) {
      failures.push(error);
    } finally {
      clearTimeout(timer);
      if (child &&
          child.exitCode === null &&
          child.signalCode === null) {
        const closed = new Promise(resolveClose => child.once('close', resolveClose));
        child.kill('SIGKILL');
        await closed;
      }
      const read = name => {
        try { return lifecycle.read(directory, name); } catch (error) {
          failures.push(error);
          return null;
        }
      };
      job = read('job-result.json');
      const receipt = existsSync(join(destination, 'receipt.json')) ? readOwnerListJson(join(destination, 'receipt.json')) : undefined;
      value = { code: job?.code, signal: job?.signal,
        stdout: Buffer.concat(chunks.stdout).toString(), stderr: Buffer.concat(chunks.stderr).toString(),
        elapsedMs: performance.now() - started,
        job, launchResult, emergencyWatchdog, before, after: binding(), budget,
        receipt, requests: read('physical-requests.json') ?? [], child: read('child-boundary.json'),
        parent: read('parent-boundary.json'), actualChild: read('actual-child-argv.json'),
        actualChildExit: read('actual-child-result.json'),
        nativeOutput: read('native-child-output.json'),
        externalArrival: read('external-arrival.json'),
        nativeFdFailure: read('native-fd-failure.json'),
        childOutputClosed: read('actual-child-output-close.json'),
        directoryRemovedOnFailure: !existsSync(destination),
        receiptBytes: receipt ? readFileSync(join(destination, 'receipt.json')).length : 0 };
      const streamEvidence = name => ({ bytes: lengths[name], sha256: hashes[name].digest('hex'),
        rawRetained: false, prefix: value[name].split(token).join('[MODELED_TOKEN_REDACTED]').slice(0, 4096),
        projection: 'Redacted, bounded nonsecret model output prefix; hash binds captured stream' });
      const retained = { ...value, stdout: streamEvidence('stdout'), stderr: streamEvidence('stderr'),
        errors: failures.map(error => ({ name: error.name, code: error.code ?? null })),
        missingParentBoundary: value.parent === null };
      lifecycle.write(evidence, 'result-before-cleanup.json', retained);
      for (const name of ['parent-phases.jsonl', 'child-phases.jsonl', 'job-live.json', 'job-result.json',
        'actual-child-argv.json', 'actual-child-result.json', 'parent-boundary.json', 'child-boundary.json', 'physical-requests.json']) {
        if (existsSync(join(directory, name))) {
          const bytes = readFileSync(join(directory, name));
          assert.ok(bytes.length <= 2 * 1024 * 1024, 'Fixture evidence copy bound');
          writeFileSync(join(evidence, name), bytes);
        }
      }
      try {
        assert.equal(job?.allClosed, true, 'Owned process termination not proven; case retained');
        assert.equal(job?.jobHandleClosed, true);
        assert.equal(job.activeProcesses, 0);
        assert.deepEqual(job.errors, []);
        rmSync(directory, { recursive: true, force: true });
        retained.directoryRemoved = !existsSync(directory);
      } catch (error) {
        failures.push(error);
        retained.cleanupError = { name: error.name, code: error.code ?? null };
        retained.directoryRemoved = false;
      }
      lifecycle.write(evidence, 'result.json', retained);
    }
    try {
      assert.equal(failures.length, 0, `Fixture lifecycle failed; retained evidence: ${evidence}`);
      assert.equal(emergencyWatchdog, false);
      assert.deepEqual(launchResult, { code: 0, signal: null });
      assert.equal(job.watchdogReason, null, 'Fixture watchdog is not a product result');
      assert.deepEqual(value.after, before, 'Fixture/source binding changed');
      assert.equal(value.stdout.includes(token), false);
      assert.equal(value.stderr.includes(token), false);
      assert.equal(JSON.stringify(value.receipt ?? {}).includes(token), false);
      assert.ok(value.parent, 'Missing parent boundary is a fixture failure');
      assert.deepEqual(value.parent.denied, []);
      if (value.child) assert.deepEqual(value.child.denied, []);
      return value;
    } catch (error) {
      lifecycle.write(evidence, 'assertion-failure.json', { name: error.name, code: error.code ?? null,
        message: error.message.split(token).join('[MODELED_TOKEN_REDACTED]').slice(0, 4096) });
      throw error;
    }
  }
}
const f = new Fixture();
const options = () => f.options();
const item = index => f.item(index);
const page = (offset, count) => f.page(offset, count);

test('fixture lifecycle: old watchdog preempts a valid product interval; derived budget does not', () => {
  assert.equal(LIMITS.commandMs, 30_000);
  const budget = lifecycle.budget(LIMITS.commandMs);
  assert.ok(15_000 < budget.commandMs, 'Original 15s ordering is invalid even without startup');
  for (const startup of [0, budget.startupMs - 1, budget.startupMs]) {
    const productLastValid = startup + budget.commandMs - 1;
    const closed = productLastValid + budget.cleanupMs - 1;
    assert.ok(15_000 < productLastValid);
    assert.ok(closed < budget.watchdogMs);
  }
  assert.deepEqual(budget, { commandMs: 30_000, startupMs: 10_000, cleanupMs: 5000, watchdogMs: 45_000 });
  assert.equal(lifecycle.budget(5000).watchdogMs, 20_000);
  for (const value of [0, -1, 0.5, 30_001, NaN, Infinity, '30000']) {
    assert.throws(() => lifecycle.budget(value));
  }
});
test('fixture lifecycle: exact UTF8 diagnostic bounds and actual malformed-read failure', () => {
  const directory = mkdtempSync(join(tmpdir(), 'owner-list-lifecycle-'));
  try {
    const value = { padding: 'x'.repeat(2 * 1024 * 1024 - Buffer.byteLength(JSON.stringify({ padding: '' }, null, 2))) };
    lifecycle.write(directory, 'boundary.json', value);
    assert.deepEqual(lifecycle.read(directory, 'boundary.json'), value);
    assert.throws(() => lifecycle.write(directory, 'overflow.json', { padding: value.padding + 'x' }));
    writeFileSync(join(directory, 'bad.json'), '{');
    assert.throws(() => lifecycle.read(directory, 'bad.json'), SyntaxError);
    assert.equal(lifecycle.read(directory, 'absent.json'), null);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('fixture lifecycle: actual missing-parent assertion retains evidence before removing its owned case',
  { skip: process.platform !== 'win32' || !integration }, async () => {
    const directory = join(process.env.OWNER_LIST_TEST_EVIDENCE ?? tmpdir(), `mp-${randomUUID().slice(0, 8)}`);
    mkdirSync(directory);
    await assert.rejects(f.run({ responses: [] }, { lifecycleControl: 'missing-parent-boundary', evidenceRoot: directory }),
      /Missing parent boundary is a fixture failure/);
    const { readdirSync } = await import('node:fs');
    const cases = readdirSync(directory);
    assert.equal(cases.length, 1);
    const evidence = join(directory, cases[0]);
    const before = lifecycle.read(evidence, 'result-before-cleanup.json');
    const after = lifecycle.read(evidence, 'result.json');
    assert.equal(before.parent, null);
    assert.equal(before.missingParentBoundary, true);
    assert.equal(before.job.allClosed, true);
    assert.equal(after.directoryRemoved, true);
    assert.equal(existsSync(lifecycle.read(evidence, 'context.json').directory), false);
    assert.ok(lifecycle.read(evidence, 'assertion-failure.json'));
  });
for (const scenario of ['watchdog', 'natural-exit']) {
test(`fixture lifecycle: ${scenario} closes outer and actual owned child`,
  { skip: process.platform !== 'win32' || !integration }, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'owner-list-job-control-'));
    const evidence = join(process.env.OWNER_LIST_TEST_EVIDENCE ?? tmpdir(),
      `diagnostic-${directory.split(/[\\/]/).at(-1)}`);
    mkdirSync(evidence, { recursive: true });
    let result;
    try {
      const childSource = scenario === 'watchdog' ? 'setInterval(()=>{},1000)' :
        `const fs=require('node:fs'); const path=require('node:path');
        const timer=setInterval(()=>{if(fs.existsSync(path.join(${JSON.stringify(directory)},
          'process-identity-'+process.pid+'.json'))){clearInterval(timer)}},10);`;
      const waitSource = scenario === 'watchdog' ?
        'Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,60000);' : '';
      const source = `const {spawn}=require('node:child_process'); const fs=require('node:fs');
        const child=spawn(process.execPath,['-e',${JSON.stringify(childSource)}],{stdio:'ignore',windowsHide:true});
        fs.writeFileSync(${JSON.stringify(join(directory, 'expected-pids.json.tmp'))},
          JSON.stringify({outer:process.pid,child:child.pid}));
        fs.renameSync(${JSON.stringify(join(directory, 'expected-pids.json.tmp'))},
          ${JSON.stringify(join(directory, 'expected-pids.json'))});
        ${waitSource}`;
      if (scenario === 'watchdog') {
        lifecycle.write(directory, 'watchdog-control.json', {
          kind: 'pure-test-lifecycle-control-not-product', identityCount: 2, delayMs: 50,
        });
      }
      const command = lifecycle.windowsCommand(directory, ['-e', source], Date.now() + 15_000);
      const child = spawn(command.file, command.args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      child.stdout.resume();
      child.stderr.resume();
      const timer = setTimeout(() => child.kill('SIGKILL'), 20_000);
      const ended = await new Promise((resolveChild, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => resolveChild({ code, signal }));
      });
      clearTimeout(timer);
      result = lifecycle.read(directory, 'job-result.json');
      lifecycle.write(evidence, 'result.json', { ended, result, expected: lifecycle.read(directory, 'expected-pids.json') });
      assert.deepEqual(ended, { code: 0, signal: null });
      assert.deepEqual(result.errors, []);
      assert.equal(result.watchdogReason, scenario === 'watchdog' ? 'fixture-deadline' : null);
      assert.equal(result.code, scenario === 'watchdog' ? 124 : 0);
      assert.equal(result.activeProcesses, 0);
      assert.equal(result.allClosed, true);
      assert.equal(result.jobHandleClosed, true);
      if (scenario === 'watchdog') assert.equal(result.controlArmed, true);
      assert.ok(result.waits.every(row => row.final === 0));
      const expected = lifecycle.read(directory, 'expected-pids.json');
      for (const pid of [expected.outer, expected.child]) {
        const identity = result.identities.find(row => row.pid === pid);
        assert.ok(identity, 'Both exact controlled Node identities must be observed');
        assert.equal(identity.image.toLowerCase(), process.execPath.toLowerCase());
      }
      for (const identity of result.identities) {
        assert.match(identity.creationFileTime, /^[1-9]\d+$/);
        assert.equal(identity.jobMembershipVerified, true);
      }
    } finally {
      if (result?.allClosed) rmSync(directory, { recursive: true, force: true });
    }
  });
}

for (const [name, envelope] of [
  ['empty-total1', { items: [], total: 1 }], ['missing-total', { items: [] }],
  ['short-page', { items: [item(1)], total: 2 }],
]) {
  test(`RED unchanged StageList accepts incomplete ${name}`, { skip: !integration }, async () => {
    assert.deepEqual(await f.sdk([envelope], false), envelope.items);
  });
  test(`guard rejects incomplete ${name}`, () => assert.throws(() => f.audit([envelope])));
}
test('logical complete empty', () => assert.equal(f.audit([{ items: [], total: 0 }]).total, 0));
test('logical complete nonempty', () => assert.equal(f.audit([{ items: [item(1)], total: 1 }]).mutationAuthorized, false));
test('logical two pages', () => assert.equal(f.audit([{ items: page(1, 100), total: 101 }, { items: [item(101)], total: 101 }]).total, 101));
for (const total of [undefined, null, true, '0', -1, 0.5, NaN, Infinity, 2001]) {
  test(`invalid total ${String(total)}`, () => assert.throws(() => f.audit([{ items: [], total }])));
}
for (const [name, envelopes] of [
  ['decreases', [{ items: page(1, 100), total: 101 }, { items: [], total: 100 }]],
  ['increases', [{ items: page(1, 100), total: 101 }, { items: page(101, 2), total: 102 }]],
  ['empty-continuation', [{ items: page(1, 100), total: 101 }, { items: [], total: 101 }]],
  ['overshoot', [{ items: page(1, 2), total: 1 }]],
  ['duplicate-page', [{ items: [item(1), item(1)], total: 2 }]],
  ['duplicate-pages', [{ items: page(1, 100), total: 101 }, { items: [item(1)], total: 101 }]],
  ['wrong-package', [{ items: [{ ...item(1), packageName: 'other' }], total: 1 }]],
  ['bad-id', [{ items: [{ ...item(1), id: 'bad' }], total: 1 }]],
  ['newline-id', [{ items: [{ ...item(1), id: `${item(1).id}\n` }], total: 1 }]],
  ['items-object', [{ items: {}, total: 0 }]], ['items-missing', [{ total: 0 }]],
  ['case-duplicate', [{ items: [item(1), { ...item(1), id: item(1).id.toUpperCase() }], total: 2 }]],
]) test(`logical reject ${name}`, () => assert.throws(() => f.audit(envelopes)));
for (const [name, uri, opt] of [
  ['endpoint', '/wrong', options()], ['method', '/-/stage', { ...options(), method: 'POST' }],
  ['registry', '/-/stage', { ...options(), registry: 'https://wrong.invalid/' }],
  ['page', '/-/stage', f.options(1)], ['perPage', '/-/stage', { ...options(), query: { ...options().query, perPage: 99 } }],
  ['package', '/-/stage', { ...options(), query: { ...options().query, package: 'other' } }],
  ['GET-body', '/-/stage', { ...options(), body: 'unexpected' }],
]) test(`invalid request ${name}`, () => assert.throws(() => new StageListAudit().begin(uri, opt)));
test('no requests reject', () => assert.throws(() => new StageListAudit().finish('[]')));
test('unfinished request rejects', () => { const a = new StageListAudit(); a.begin('/-/stage', options()); assert.throws(() => a.finish('[]')); });
test('output mismatch rejects', () => assert.throws(() => f.audit([{ items: [item(1)], total: 1 }], '[]')));
test('poisoned audit cannot recover', () => {
  const a = new StageListAudit(); a.begin('/-/stage', options());
  assert.throws(() => a.accept({ items: [], total: 1 }));
  assert.throws(() => a.accept({ items: [], total: 0 }));
  assert.throws(() => a.finish('[]'));
});
test('consumed audit cannot repeat', () => {
  const a = new StageListAudit(); a.begin('/-/stage', options()); a.accept({ items: [], total: 0 }); a.finish('[]');
  assert.throws(() => a.finish('[]')); assert.throws(() => a.begin('/-/stage', options()));
});
test('twenty logical pages bounded', () => assert.equal(f.audit(Array.from({ length: 20 }, (_, i) =>
  ({ items: page(i * 100 + 1, 100), total: 2000 }))).total, 2000));
test('parsed response exact byte boundary and one-byte excess', () => {
  assert.equal(f.audit([f.envelope(LIMITS.responseBytes)]).total, 0);
  assert.throws(() => f.audit([f.envelope(LIMITS.responseBytes + 1)]));
});
test('response limits measure UTF8 bytes rather than JavaScript string length', () => {
  const response = { items: [], total: 0, padding: '' };
  const available = LIMITS.responseBytes - Buffer.byteLength(JSON.stringify(response));
  response.padding = '💡'.repeat(Math.floor(available / 4)) + 'x'.repeat(available % 4);
  assert.equal(Buffer.byteLength(JSON.stringify(response)), LIMITS.responseBytes);
  assert.ok(JSON.stringify(response).length < LIMITS.responseBytes);
  assert.equal(f.audit([response]).total, 0);
  assert.throws(() => f.audit([{ ...response, padding: response.padding + 'x' }]));
});
test('pure output exact byte boundary and one-byte excess', () => {
  assert.equal(f.audit([{ items: [], total: 0 }], ' '.repeat(LIMITS.stdoutBytes - 2) + '[]').total, 0);
  assert.throws(() => f.audit([{ items: [], total: 0 }], ' '.repeat(LIMITS.stdoutBytes - 1) + '[]'));
});
test('create-only receipt exact UTF8 byte boundary, excess, existing path and real closed FD', () => {
  const directory = mkdtempSync(join(tmpdir(), 'owner-list-io-'));
  try {
    const value = { padding: 'x'.repeat(LIMITS.receiptBytes - Buffer.byteLength('{"padding":""}')) };
    const bytes = boundedOwnerJson(value, LIMITS.receiptBytes);
    assert.equal(bytes.length, LIMITS.receiptBytes);
    const written = publishOwnerListJson(directory, 'receipt.json', value);
    assert.equal(written.bytes, LIMITS.receiptBytes);
    assert.deepEqual(readOwnerListJson(written.path), value);
    assert.throws(() => publishOwnerListJson(directory, 'receipt.json', {}), { code: 'EEXIST' });
    assert.throws(() => publishOwnerListJson(directory, 'overflow.json', { padding: value.padding + 'x' }));
    const fd = openSync(join(directory, 'fd-proof'), 'wx'); closeSync(fd);
    assert.throws(() => writeOwnerListBytes(fd, Buffer.from('actual closed fd')), { code: 'EBADF' });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('lower transport rejects body and enforces actual response timeout', async () => {
  const audit = new StageListAudit(); audit.begin('/-/stage', options());
  let calls = 0;
  const transport = new OwnerStageListTransport(async () => { calls++; return new Promise(() => {}); }, audit, Response, 20);
  await assert.rejects(transport.request('https://registry.npmjs.org/-/stage?page=0&perPage=100&package=mcp-pacemaker', { body: 'bad' }));
  assert.equal(calls, 0);
  const a = new StageListAudit(); a.begin('/-/stage', options());
  const timed = new OwnerStageListTransport(async () => new Promise(() => {}), a, Response, 20);
  await assert.rejects(timed.request('https://registry.npmjs.org/-/stage?page=0&perPage=100&package=mcp-pacemaker'));
  assert.throws(() => a.finish('[]'));
});
test('time-limit configuration accepts exactly30000ms and rejects30001ms,zero and fractions', () => {
  const make = value => new OwnerStageListTransport(async () => {}, new StageListAudit(), Response, value);
  assert.ok(make(30_000));
  for (const value of [30_001, 0, -1, 0.5]) assert.throws(() => make(value));
});
test('bounded replay preserves the actual SDK response-stream contract', { skip: !integration }, async () => {
  const require = createRequire(cli);
  const { Response } = require('make-fetch-happen');
  const bytes = Buffer.from('{"items":[],"total":0}');
  assert.equal(typeof new Response(bytes).body.on, 'undefined');
  const audit = new StageListAudit(); audit.begin('/-/stage', options());
  const transport = new OwnerStageListTransport(async () =>
    new Response(Readable.from([bytes]), { status: 200 }), audit, Response);
  const response = await transport.request('https://registry.npmjs.org/-/stage?page=0&perPage=100&package=mcp-pacemaker');
  assert.equal(typeof response.body.on, 'function');
  assert.deepEqual(await response.json(), { items: [], total: 0 });
});

const native = (name, fn) => test(`native npm CLI: ${name}`, { skip: !integration }, fn);
native('complete empty preserves owner config and produces bounded read-only evidence', async () => {
  const r = await f.run({ responses: [{ body: { items: [], total: 0 } }] });
  assert.equal(r.code, 0, r.stderr); assert.equal(r.receipt.pendingAssessment, 'none');
  assert.equal(r.actualChildExit.pid, r.actualChild.pid);
  assert.equal(r.actualChildExit.code, 0);
  assert.equal(r.actualChildExit.signal, null);
  assert.equal(r.receipt.mutationAuthorized, false); assert.equal(r.requests.length, 1);
  assert.ok(r.receiptBytes <= LIMITS.receiptBytes);
});
native('nonempty is owner review only and extra response/output fields are not retained', async () => {
  const r = await f.run({ responses: [{ body: { items: [{ ...item(1), privateField: 'NONSECRET_OWNER_LIST_MODEL_TOKEN' }], total: 1, extra: 'not retained' } }] });
  assert.equal(r.code, 0, r.stderr); assert.equal(r.receipt.pendingAssessment, 'requires-owner-review');
  assert.equal(r.receipt.observation.pages[0].response.items[0].privateField, undefined);
});
native('credential echoed as an otherwise valid stage ID is never retained', async () => {
  const token = item(1).id;
  const r = await f.run({ token, responses: [{ body: { items: [item(1)], total: 1 } }] });
  assert.equal(r.code, 1); assert.equal(r.receipt, undefined); assert.equal(r.requests.length, 1);
});
native('actual two-page pagination is unchanged', async () => {
  const r = await f.run({ responses: [{ body: { items: page(1, 100), total: 101 } }, { body: { items: [item(101)], total: 101 } }] });
  assert.equal(r.code, 0, r.stderr); assert.equal(r.requests.length, 2); assert.equal(r.receipt.total, 101);
});
for (const [name, responses] of [
  ['incomplete', [{ body: { items: [], total: 1 } }]], ['missing-total', [{ body: { items: [] } }]],
  ['drifting-total', [{ body: { items: page(1, 100), total: 101 } }, { body: { items: [item(101)], total: 102 } }]],
  ['duplicate', [{ body: { items: [item(1), item(1)], total: 2 } }]],
  ['redirect-302', [{ status: 302, headers: { location: 'https://untrusted.invalid/' }, raw: 'do not retain' }]],
  ['redirect-307', [{ status: 307, headers: { location: 'https://registry.npmjs.org/other' }, raw: 'do not retain' }]],
  ['lost', [{ reject: true }]], ['non200', [{ status: 503, raw: 'NONSECRET_OWNER_LIST_MODEL_TOKEN' }]],
  ['malformed-json', [{ raw: '{invalid json' }]],
]) native(`reject ${name} without accepted empty or retry`, async () => {
  const r = await f.run({ responses });
  assert.equal(r.code, 1); assert.equal(r.receipt, undefined); assert.equal(r.directoryRemovedOnFailure, true);
  assert.equal(r.requests.length, responses.length);
  assert.equal(r.child.arrivals.length, responses.length);
});
native('response byte limit enforced before JSON.parse at exactly128KiB and128KiB+1', async () => {
  const good = await f.run({ responses: [{ body: f.envelope(LIMITS.responseBytes) }] });
  assert.equal(good.code, 0, good.stderr);
  assert.deepEqual(good.child.parsedResponseBytes, [LIMITS.responseBytes]);
  const bad = await f.run({ responses: [{ body: f.envelope(LIMITS.responseBytes + 1) }] });
  assert.equal(bad.code, 1); assert.deepEqual(bad.child.parsedResponseBytes, []);
});
native('cumulative response boundary is512KiB and the next response fails before parse', async () => {
  const good = await f.run({ responses: Array.from({ length: 4 }, (_, i) => ({ body: f.envelope(LIMITS.responseBytes, page(i * 100 + 1, 100), 400) })) });
  assert.equal(good.code, 0, good.stderr); assert.equal(good.receipt.responseBytes, LIMITS.responseTotalBytes);
  const bad = await f.run({ responses: [...Array.from({ length: 4 }, (_, i) => ({ body: f.envelope(LIMITS.responseBytes, page(i * 100 + 1, 100), 401) })),
    { body: { modelMarker: 'owner-list-response', items: [item(401)], total: 401 } }] });
  assert.equal(bad.code, 1); assert.equal(bad.child.parsedResponseBytes.length, 4);
});
for (const fault of ['exit-after-output', 'child-output-stream', 'child-observation-write', 'receipt-write',
  'receipt-write-fd', 'receipt-fsync-fd',
  'stdout-overflow', 'stderr-overflow', 'module-cache', 'source-binding']) {
  native(`fail closed on actual ${fault}`, async () => {
    const r = await f.run({ fault, responses: [{ body: { items: [], total: 0 } }] });
    assert.equal(r.code, 1); assert.equal(r.receipt, undefined); assert.equal(r.directoryRemovedOnFailure, true);
    if (fault === 'child-observation-write') {
      assert.equal(r.actualChildExit.pid, r.actualChild.pid);
      assert.equal(r.actualChildExit.code, 1, 'Late guard failure must reach the actual child OS exit');
      assert.equal(r.actualChildExit.signal, null);
    }
    if (fault === 'exit-after-output') assert.equal(r.actualChildExit.code, 9);
    if (['exit-after-output', 'child-output-stream', 'child-observation-write', 'receipt-write', 'receipt-write-fd', 'receipt-fsync-fd'].includes(fault)) {
      assert.equal(r.requests.length, 1);
      if (fault !== 'child-output-stream') assert.equal(r.nativeOutput.prefix, '[]\n');
      else assert.equal(r.childOutputClosed.realPipeReaderClosed, true);
      if (fault.endsWith('-fd') &&
          fault.startsWith('receipt-')) {
        assert.equal(r.nativeFdFailure.code, 'EBADF');
        assert.equal(r.nativeFdFailure.actualNativeCall, true);
        assert.equal(r.nativeFdFailure.callbackThrewSyntheticError, false);
      }
    } else {
      assert.equal(r.requests.length, 0);
    }
  });
}
native('stderr boundary is exactly64KiB and excess is rejected', async () => {
  const good = await f.run({ stderrBytes: LIMITS.stderrBytes, responses: [{ body: { items: [], total: 0 } }] });
  assert.equal(good.code, 0, good.stderr);
  assert.equal(good.receipt.stderr.bytes, LIMITS.stderrBytes);
});
native('native stdout boundary is exactly256KiB and one-byte excess is rejected', async () => {
  const responsesFor = bytes => {
    const items = page(1, 101);
    items[0].large = '';
    items[100].large = '';
    const responses = [
      { body: { modelMarker: 'owner-list-response', items: items.slice(0, 100), total: 101 } },
      { body: { modelMarker: 'owner-list-response', items: items.slice(100), total: 101 } },
    ];
    const padding = bytes - Buffer.byteLength(JSON.stringify(items, null, 2) + '\n');
    const first = LIMITS.responseBytes - Buffer.byteLength(JSON.stringify(responses[0].body));
    items[0].large = 'x'.repeat(first);
    items[100].large = 'x'.repeat(padding - first);
    assert.equal(Buffer.byteLength(JSON.stringify(items, null, 2) + '\n'), bytes);
    assert.ok(responses.every(row => Buffer.byteLength(JSON.stringify(row.body)) <= LIMITS.responseBytes));
    return responses;
  };
  const good = await f.run({ responses: responsesFor(LIMITS.stdoutBytes) });
  assert.equal(good.code, 0, good.stderr);
  assert.equal(good.receipt.stdout.bytes, LIMITS.stdoutBytes);
  const bad = await f.run({ responses: responsesFor(LIMITS.stdoutBytes + 1) });
  assert.equal(bad.code, 1); assert.equal(bad.receipt, undefined); assert.equal(bad.requests.length, 2);
});
native('whole-command deadline rejects a child held alive after valid output', async () => {
  const r = await f.run({ fault: 'hang-after-output', responses: [{ body: { items: [], total: 0 } }] }, { timeoutMs: 5000 });
  assert.equal(r.code, 1); assert.equal(r.receipt, undefined); assert.equal(r.requests.length, 1);
  assert.equal(r.nativeOutput.prefix, '[]\n');
  assert.ok(r.elapsedMs >= 5000 &&
    r.elapsedMs < 10_000);
});
native('actual closed parent stdout FD removes already-created receipt', async () => {
  const r = await f.run({ responses: [{ body: { items: [], total: 0 } }] }, { closeOutput: true });
  assert.equal(r.code, 1); assert.equal(r.receipt, undefined);
});
