// Synthetic bridges and owned temporary roots only. No OS service registration or fixed ports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer, connect } from 'node:net';
import { get } from 'node:http';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { servicePaths, stopManagedService, resumeService } from '../bin/service-control.mjs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const fakeBridge = `
import { createServer } from 'node:http';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { ensureWindowsProcessLifetime } from './windows-process-lifetime.mjs';
import { execFileSync } from 'node:child_process';
const { values } = parseArgs({ options: { port: { type: 'string' }, config: { type: 'string' } } });
const log = values.config + '.lifetime';
const settings = JSON.parse(readFileSync(values.config, 'utf8'));
const instanceId = randomUUID();
if (settings.gateLifetime) {
  appendFileSync(log, 'before-native\\n');
  while (!existsSync(values.config + '.continue')) await new Promise(resolve => setTimeout(resolve, 10));
}
const lifetime = await ensureWindowsProcessLifetime();
if (lifetime) {
  writeFileSync(log + '.owner', JSON.stringify(lifetime));
  await new Promise(resolve => {
    const observed = message => {
      if (message !== 'upgrade-lifetime-observed') return;
      process.off('message', observed);
      resolve();
    };
    process.on('message', observed);
    process.send({ type: 'upgrade-lifetime', lifetime });
  });
}
let creationTicks;
if (process.platform === 'win32') {
  const captured = JSON.parse(execFileSync('pwsh.exe', [
    '-NoProfile', '-NonInteractive', '-File', process.env.MCP_SUPERVISOR_TEST_IDENTITY,
    '-ProcessId', String(process.pid),
  ], { encoding: 'utf8', windowsHide: true }));
  if (captured.gone || !captured.creationTicks) throw new Error('Owned creation identity was not captured.');
  creationTicks = captured.creationTicks;
}
appendFileSync(log + '.processes', JSON.stringify({
  pid: process.pid, instanceId, creationTicks,
  supervisorGeneration: process.env.MCP_SUPERVISOR_TEST_GENERATION,
}) + '\\n');
const status = { service: 'mcp-pacemaker', version: '1.3.0', instanceId, servers: [], sessions: 0 };
let requests = 0;
const server = createServer((req, res) => {
  if (req.url === '/finish-stop') {
    res.end(JSON.stringify({ ok: true }), finishStop);
    return;
  }
  if (req.url === '/crash') {
    res.end('crashing', () => { appendFileSync(log, 'crashed\\n'); process.exit(1); });
    return;
  }
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ ...status, requests: ++requests }));
});
server.listen(Number(values.port), '127.0.0.1', () => appendFileSync(log, 'started\\n'));
function finishStop() {
  appendFileSync(log, 'stopped\\n');
  server.close(() => process.exit(0));
}
process.on('SIGTERM', () => {
  if (settings.deferStop) {
    appendFileSync(log, 'stop-requested\\n');
    return;
  }
  finishStop();
});
`;

async function waitFor(check, description = 'the owned fixture signal') {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    const result = await check();
    if (result) return result;
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  throw new Error(`Timed out waiting for ${description}.`);
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

function recordedProcessAlive(record) {
  if (process.platform !== 'win32') return processAlive(record.pid);
  if (typeof record.creationTicks !== 'string' ||
      !record.creationTicks) throw new Error('Missing owned process creation identity; retain its fixture.');
  const result = JSON.parse(execFileSync('pwsh.exe', [
    '-NoProfile', '-NonInteractive', '-File',
    fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity.ps1', import.meta.url)),
    '-ProcessId', String(record.pid), '-CreationTicks', record.creationTicks,
  ], { encoding: 'utf8', windowsHide: true, timeout: 10000 }));
  return result.gone !== true;
}

function ownedBridgesExited(records, supervisors, probe = recordedProcessAlive) {
  return records.every(record => {
    if (!Number.isSafeInteger(record.pid) ||
        record.pid < 1 ||
        typeof record.supervisorGeneration !== 'string' ||
        (process.platform === 'win32' && !record.creationTicks)) throw new Error('Invalid captured bridge identity.');
    const supervisor = supervisors.find(child => child.fixtureGeneration === record.supervisorGeneration);
    if (!supervisor) throw new Error('Unrecognized fixture supervisor generation.');
    return !probe(record);
  });
}

function listenerAlive(port) {
  return new Promise((resolveProbe, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.on('connect', () => { socket.destroy(); resolveProbe(true); });
    socket.on('error', (error) => {
      if (error.code === 'ECONNREFUSED') resolveProbe(false);
      else reject(error);
    });
    socket.setTimeout(2000, () => socket.destroy(new Error('Fixture listener probe timed out')));
  });
}

async function withFixtures(fixtures, run, report = console.error) {
  let originalError;
  try {
    await run();
  } catch (error) {
    originalError = error;
  }
  const results = await Promise.allSettled(fixtures.map((service) => service.cleanup()));
  const cleanupErrors = results.filter((result) => result.status === 'rejected').map((result) => result.reason);
  for (const error of cleanupErrors) report(`Fixture cleanup failed: ${error.stack || error}`);
  if (originalError) throw originalError;
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Fixture shutdown was not verified; owned roots retained.');
}

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

function httpStatus(port, path = '/api/status') {
  return new Promise((resolveRequest, reject) => {
    const request = get(`http://127.0.0.1:${port}${path}`, (response) => {
      let body = '';
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolveRequest(path === '/crash' ? body : JSON.parse(body)));
    });
    request.on('error', reject);
    request.setTimeout(2000, () => request.destroy(new Error('Fixture HTTP timeout')));
  });
}

async function fixture({ removeHold = false, deferStop = false, separateTemp = false, gateLifetime = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'mcp-supervisor-test-'));
  const processes = [];
  mkdirSync(join(root, 'supervisor'));
  mkdirSync(join(root, 'bin'));
  mkdirSync(join(root, 'bin', 'windows-lifetime'));
  mkdirSync(join(root, 'state'));
  const childTemp = join(root, 'child-temp');
  mkdirSync(childTemp);
  writeFileSync(join(root, 'package.json'), JSON.stringify(pkg));
  for (const file of [
    'supervisor/supervise.mjs', 'supervisor/bridge-child.mjs', 'bin/service-control.mjs',
    'bin/windows-process-lifetime.mjs', 'bin/windows-lifetime/ProcessLifetimeHelper.exe',
    'bin/windows-lifetime/ProcessLifetimeHelper.build.json',
  ]) {
    copyFileSync(new URL(`../${file}`, import.meta.url), join(root, file));
  }
  if (removeHold) {
    const path = join(root, 'supervisor', 'supervise.mjs');
    const source = readFileSync(path, 'utf8');
    const line = "writeFileSync(paths.hold, JSON.stringify({ id: identity.id, root, config, port }) + '\\n', { mode: 0o600 });";
    const receipt = "writeFileSync(paths.hold, JSON.stringify({ id: identity.id, root, config, port, stopped: true,\n          ...(stopAuthorization ? { quiescedInstanceId: stopAuthorization } : {}) }) + '\\n', { mode: 0o600, flush: true });";
    assert.equal(source.includes(line), true, 'regression must remove the real hold write');
    assert.equal(source.includes(receipt), true, 'regression must remove the completed hold too');
    writeFileSync(path, source.replace(line, '').replace(receipt, ''));
  }
  writeFileSync(join(root, 'bin', 'mcp-bridge.mjs'), fakeBridge);
  const config = join(root, 'state', 'servers.json');
  writeFileSync(config, JSON.stringify({ deferStop, gateLifetime }));
  const port = await freePort();
  const paths = servicePaths(config, port);
  const log = () => existsSync(config + '.lifetime') ? readFileSync(config + '.lifetime', 'utf8') : '';
  const bridgeProcesses = () => existsSync(config + '.lifetime.processes')
    ? readFileSync(config + '.lifetime.processes', 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
    : [];
  async function verifyExit() {
    const observed = bridgeProcesses();
    assert.notEqual(observed.length, 0, 'a bridge PID must be recorded before shutdown can be verified');
    await waitFor(() => ownedBridgesExited(observed, processes),
      `captured bridge identities [${observed.map(({ pid }) => pid).join(', ')}] to exit (root ${root})`);
    return observed;
  }
  function launch() {
    const generation = randomUUID();
    const child = spawn(process.execPath, [join(root, 'supervisor', 'supervise.mjs'), '--port', String(port), '--config', config], {
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
      env: {
        ...process.env, HOME: root, USERPROFILE: root,
        MCP_SUPERVISOR_TEST_GENERATION: generation,
        MCP_SUPERVISOR_TEST_IDENTITY: fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity.ps1', import.meta.url)),
        ...(separateTemp ? { TMPDIR: childTemp, TMP: childTemp, TEMP: childTemp } : {}),
      },
    });
    child.output = '';
    child.fixtureGeneration = generation;
    child.stdout.on('data', (chunk) => { child.output += chunk; });
    child.stderr.on('data', (chunk) => { child.output += chunk; });
    child.finished = new Promise((resolveExit, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => resolveExit({ code, signal }));
    });
    processes.push(child);
    return child;
  }
  async function cleanup() {
    let observed = [];
    try {
      observed = bridgeProcesses();
      for (const child of processes) {
        if (child.exitCode !== null ||
            child.signalCode !== null) continue;
        await stopManagedService({ root, config, port });
        await waitFor(() => child.exitCode !== null || child.signalCode !== null,
          `owned supervisor ${child.pid} to exit (root ${root})`);
      }
      observed = bridgeProcesses();
      if (observed.length) await verifyExit();
      else {
        assert.equal(processes.length, 0, 'a launched supervisor has no bridge lifetime evidence; retain its root');
        assert.equal(await listenerAlive(port), false, `fixture listener :${port} is still active`);
      }
      rmSync(root, { recursive: true, force: true });
    } catch (error) {
      const diagnostics = processes.map((child) => ({ pid: child.pid, exitCode: child.exitCode, signalCode: child.signalCode, output: child.output }));
      for (const child of processes) {
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
      }
      throw new Error(`Retained owned fixture ${root}; shutdown/cleanup unverified: ${error.message}. Supervisors: ${JSON.stringify(diagnostics)}. Bridge records: ${JSON.stringify(observed)}`, { cause: error });
    }
  }
  return { root, config, port, paths, log, launch, cleanup, verifyExit, bridgeProcesses };
}

test('T31/T33/T35 selected supervisor exits gracefully, holds autostart, and leaves the second instance alive', { timeout: 30000 }, async () => {
  const fixtures = [];
  await withFixtures(fixtures, async () => {
    const first = await fixture();
    fixtures.push(first);
    const firstProcess = first.launch();
    await waitFor(() => first.log().includes('started'));
    const second = await fixture();
    fixtures.push(second);
    second.launch();
    await waitFor(() => second.log().includes('started'));
    const before = await httpStatus(second.port);
    await stopManagedService(first);
    assert.deepEqual(await firstProcess.finished, { code: 0, signal: null }, firstProcess.output);
    assert.equal(first.log(), 'started\nstopped\n');
    assert.equal(existsSync(first.paths.hold), true);
    assert.equal((await stopManagedService(first)).alreadyStopped, true);
    const after = await httpStatus(second.port);
    assert.equal(after.instanceId, before.instanceId);
    assert.equal(after.requests > before.requests, true);
    assert.notEqual(first.paths.socket, second.paths.socket);

    const autostart = first.launch();
    assert.deepEqual(await autostart.finished, { code: 0, signal: null }, autostart.output);
    assert.equal(first.log(), 'started\nstopped\n', 'autostart must not launch a new bridge');

    resumeService(first.config, first.port);
    const resumed = first.launch();
    await waitFor(() => first.log() === 'started\nstopped\nstarted\n');
    await stopManagedService(first);
    assert.deepEqual(await resumed.finished, { code: 0, signal: null }, resumed.output);

    const cli = spawn(process.execPath, [fileURLToPath(new URL('../bin/cli.mjs', import.meta.url)), 'start', '--port', String(second.port)], {
      env: { ...process.env, HOME: second.root, USERPROFILE: second.root },
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    let output = '';
    cli.stdout.on('data', (chunk) => { output += chunk; });
    cli.stderr.on('data', (chunk) => { output += chunk; });
    const code = await new Promise((resolveExit, reject) => { cli.on('error', reject); cli.on('exit', resolveExit); });
    assert.equal(code, 0, output);
    assert.match(output, new RegExp(`installed CLI ${pkg.version.replaceAll('.', '\\.')}`));
    assert.match(output, /running backend 1\.3\.0/);
    assert.match(output, /adopted/);
    assert.equal((await httpStatus(second.port)).instanceId, before.instanceId);
  });
});

test('T33 stop during crash backoff does not depend on a listening bridge', { timeout: 20000 }, async () => {
  const service = await fixture();
  await withFixtures([service], async () => {
    const child = service.launch();
    await waitFor(() => service.log().includes('started'));
    await httpStatus(service.port, '/crash');
    await waitFor(() => service.log().includes('crashed'));
    await stopManagedService(service);
    assert.deepEqual(await child.finished, { code: 0, signal: null }, child.output);
    const retry = service.launch();
    assert.deepEqual(await retry.finished, { code: 0, signal: null }, retry.output);
    assert.equal(service.log(), 'started\ncrashed\n');
  });
});

test('owned Windows stop during child import waits for subsequently armed native lifetime', {
  timeout: 30000, skip: process.platform !== 'win32',
}, async () => {
  const service = await fixture({ gateLifetime: true });
  await withFixtures([service], async () => {
    const supervisor = service.launch();
    await waitFor(() => service.log().includes('before-native'));
    let completed = false;
    const stopping = stopManagedService(service).then(receipt => { completed = true; return receipt; });
    await waitFor(() => existsSync(service.paths.hold));
    assert.equal(completed, false);
    assert.equal(JSON.parse(readFileSync(service.paths.hold, 'utf8')).stopped, undefined);
    writeFileSync(service.config + '.continue', 'continue');
    await stopping;
    assert.deepEqual(await supervisor.finished, { code: 0, signal: null }, supervisor.output);
    const owner = JSON.parse(readFileSync(service.config + '.lifetime.owner', 'utf8'));
    const ownerTicks = (BigInt(owner.ownerCreationTime) + 504911232000000000n).toString();
    assert.equal(recordedProcessAlive({ pid: owner.ownerPid, creationTicks: ownerTicks }), false,
      'The captured native owner must finish drain before stop completes.');
    assert.equal(JSON.parse(readFileSync(service.paths.hold, 'utf8')).stopped, true);
    await service.verifyExit();
  });
});

test('targeted control reaches a supervisor with a different TMPDIR on each supported OS', { timeout: 20000 }, async () => {
  const service = await fixture({ separateTemp: true });
  await withFixtures([service], async () => {
    const child = service.launch();
    await waitFor(() => service.log().includes('started'));
    const record = JSON.parse(readFileSync(service.paths.record, 'utf8'));
    assert.equal(record.socket, service.paths.socket);
    await stopManagedService(service);
    assert.deepEqual(await child.finished, { code: 0, signal: null }, child.output);
    await service.verifyExit();
  });
});

test('a real child exiting after the unchanged shutdown deadline can be explicitly reconciled', { timeout: 20000 }, async () => {
  const service = await fixture({ deferStop: true });
  await withFixtures([service], async () => {
    const child = service.launch();
    await waitFor(() => service.log().includes('started'));
    const unverified = assert.rejects(stopManagedService(service), /did not verify shutdown/);
    await waitFor(() => service.log().includes('stop-requested'));
    assert.equal(await listenerAlive(service.port), true);
    assert.equal(JSON.parse(readFileSync(service.paths.hold, 'utf8')).stopped, undefined);
    await unverified;
    assert.equal(await listenerAlive(service.port), true, 'A deadline must not pretend the child exited');
    const held = readFileSync(service.paths.hold, 'utf8');
    await httpStatus(service.port, '/finish-stop');
    await service.verifyExit();
    assert.equal(processAlive(child.pid), true, 'Supervisor must remain available for explicit reconciliation');
    assert.equal(readFileSync(service.paths.hold, 'utf8'), held, 'Late exit must not silently complete the failed stop');
    const reconciled = await stopManagedService(service);
    assert.equal(reconciled.alreadyStopped, undefined);
    assert.deepEqual(await child.finished, { code: 0, signal: null }, child.output);
    assert.equal(JSON.parse(readFileSync(service.paths.hold, 'utf8')).stopped, true);
    assert.equal((await stopManagedService(service)).alreadyStopped, true);
  });
});

test('supervisor termination closes the recorded bridge without requiring a JS signal-handler marker', { timeout: 20000 }, async (t) => {
  const service = await fixture();
  await withFixtures([service], async () => {
    const child = service.launch();
    await waitFor(() => service.log().includes('started'));
    child.kill();
    await child.finished;
    const observed = await service.verifyExit();
    t.diagnostic(`Captured bridge identity exited for PID ${observed[0].pid}; JS stopped marker: ${service.log().includes('stopped')}.`);
    assert.equal(existsSync(service.paths.hold), false);
    const restarted = service.launch();
    await waitFor(() => (service.log().match(/started/g)?.length || 0) === 2);
    assert.notEqual(service.bridgeProcesses()[1].instanceId, observed[0].instanceId);
    await stopManagedService(service);
    assert.deepEqual(await restarted.finished, { code: 0, signal: null }, restarted.output);
  });
});

test('regression control: an isolated supervisor without the hold write fails the no-restart assertion', { timeout: 20000 }, async () => {
  const service = await fixture({ removeHold: true });
  await withFixtures([service], async () => {
    const child = service.launch();
    await waitFor(() => service.log().includes('started'));
    await stopManagedService(service);
    await child.finished;
    service.launch();
    await waitFor(() => service.log() === 'started\nstopped\nstarted\n');
    assert.throws(() => assert.equal(service.log(), 'started\nstopped\n'), { code: 'ERR_ASSERTION' });
  });
});

test('cleanup failure preserves the original error and reports retained fixture evidence', async () => {
  const original = new Error('original operation failed');
  const diagnostics = [];
  const failedCleanup = { cleanup: async () => { throw new Error('retained fixture: shutdown unverified'); } };
  await assert.rejects(withFixtures([failedCleanup], async () => { throw original; }, (message) => diagnostics.push(message)),
    (error) => error === original);
  assert.match(diagnostics.join('\n'), /retained fixture: shutdown unverified/);
  await assert.rejects(withFixtures([failedCleanup], async () => {}, () => {}), /owned roots retained/);
});

test('unreadable lifetime evidence retains the real fixture root without masking the operation error', async () => {
  const service = await fixture();
  const evidence = service.config + '.lifetime.processes';
  const original = new Error('operation failed before cleanup');
  const diagnostics = [];
  const repairFixture = {
    cleanup: async () => {
      // No process was launched; repair only this fixture's injected corrupt evidence.
      if (existsSync(service.root)) writeFileSync(evidence, '');
      await service.cleanup();
    },
  };
  await withFixtures([repairFixture], async () => {
    writeFileSync(evidence, '{incomplete\n');
    await assert.rejects(withFixtures([service], async () => { throw original; }, (message) => diagnostics.push(message)),
      (error) => error === original);
    assert.equal(existsSync(service.root), true, 'unverified fixture root must be retained');
    assert.equal(readFileSync(evidence, 'utf8'), '{incomplete\n', 'failure evidence must remain unchanged');
    assert.match(diagnostics.join('\n'), /shutdown\/cleanup unverified/);
  });
  assert.equal(existsSync(service.root), false);
});

test('an exited supervisor cannot certify a still-live captured bridge identity', () => {
  const record = { pid: 123, creationTicks: '1', supervisorGeneration: 'owned-generation' };
  const originalExited = [{ fixtureGeneration: 'owned-generation', exitCode: 0 }];
  let probes = 0;
  const sameIdentityAlive = captured => {
    probes++;
    assert.deepEqual(captured, record);
    return true;
  };
  assert.equal(ownedBridgesExited([record], originalExited, sameIdentityAlive), false);
  assert.equal(probes, 1, 'Always probe the captured identity, even after supervisor exit 0.');
  assert.equal(ownedBridgesExited([record], [{ ...originalExited[0], exitCode: null }], sameIdentityAlive), false);
  assert.throws(() => ownedBridgesExited([{ ...record, supervisorGeneration: 'unknown' }], originalExited));
});

test('a reused PID passes cleanup only when the captured creation identity is gone', () => {
  const record = { pid: 123, creationTicks: '1', supervisorGeneration: 'owned-generation' };
  let probes = 0;
  const differentIdentity = captured => {
    probes++;
    assert.deepEqual(captured, record);
    return false;
  };
  assert.equal(ownedBridgesExited([record], [
    { fixtureGeneration: 'owned-generation', exitCode: 0 },
  ], differentIdentity), true);
  assert.equal(probes, 1);
});

test('a different Windows creation identity is not an owned survivor and is not touched', {
  skip: process.platform !== 'win32',
}, () => {
  assert.equal(recordedProcessAlive({ pid: process.pid, creationTicks: '1' }), false);
  assert.equal(processAlive(process.pid), true);
});

test('verified fixture cleanup leaves a new foreign listener on the reused port untouched', { timeout: 30000 }, async () => {
  const service = await fixture();
  const foreign = createServer(socket => {
    socket.on('error', error => { if (error.code !== 'ECONNRESET') throw error; });
    socket.end();
  });
  const resources = [
    { cleanup: async () => { if (existsSync(service.root)) await service.cleanup(); } },
    { cleanup: async () => {
      if (!foreign.listening) return;
      await new Promise((resolveClose, reject) => foreign.close(error => error ? reject(error) : resolveClose()));
    } },
  ];
  await withFixtures(resources, async () => {
    const supervisor = service.launch();
    await waitFor(() => service.log().includes('started'));
    await stopManagedService(service);
    assert.deepEqual(await supervisor.finished, { code: 0, signal: null });
    await new Promise((resolveListen, reject) => {
      foreign.once('error', reject);
      foreign.listen(service.port, '127.0.0.1', resolveListen);
    });
    assert.equal(await listenerAlive(service.port), true,
      'RED: the original cleanup predicate requires this unrelated listener to disappear.');
    await service.cleanup();
    assert.equal(existsSync(service.root), false);
    assert.equal(await listenerAlive(service.port), true, 'Do not stop or wait on the foreign listener.');
  });
});
