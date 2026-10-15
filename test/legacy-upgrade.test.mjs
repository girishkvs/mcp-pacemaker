import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, unlinkSync, cpSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { request, createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { backendStatus } from '../bin/managed-runtime.mjs';
import { readManagedJson } from '../bin/managed-state.mjs';
import { describeUpgrade, discoverInstances, ManagedUpgrader } from '../bin/managed-upgrade.mjs';
import { confirmLegacyUpgrade, LEGACY_WARNING, verifyLegacyPackage } from '../bin/legacy-installation.mjs';
import { LegacyUpgrader } from '../bin/legacy-upgrade.mjs';
import { WindowsLegacyTaskAdapter } from '../bin/legacy-task.mjs';
import { LegacyUpgradeFixture } from './helpers/legacy-upgrade-fixture.mjs';
import { verifyLegacyFeature, verifyLegacyExecution } from '../tools/npm-publication/legacy-broker-gate.mjs';
import { LEGACY_BROKER_TEST, LEGACY_BROKER_REQUIRED_TESTS } from '../tools/windows-legacy/inventory.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 300000 };
const source = fileURLToPath(new URL('../', import.meta.url));

test('candidate crash before first journal stays outside discovery and retry finds the live legacy service', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    const artifact = fixture.artifact();
    const archive = join(fixture.directory, 'candidate.tgz');
    writeFileSync(archive, artifact.bytes);
    const input = join(fixture.directory, 'early-crash.json');
    writeFileSync(input, JSON.stringify({
      plan: { ...plan, legacyRuntime: undefined }, archive, integrity: artifact.integrity,
      phase: 'legacy-candidate-created', taskPath: fixture.taskPath,
    }));
    const child = spawn(process.execPath, [
      fileURLToPath(new URL('./fixtures/legacy-upgrade-crash.mjs', import.meta.url)), input,
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', bytes => { output += bytes; });
    child.stderr.on('data', bytes => { output += bytes; });
    const code = await new Promise((resolveExit, reject) => {
      child.once('error', reject);
      child.once('exit', resolveExit);
    });
    assert.equal(code, 86, output);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.equal(discoverInstances(fixture.home).length, 0, 'A candidate without a journal must not become discoverable.');
    const retry = await fixture.plan();
    assert.equal(retry.from, '1.3.0');
    assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
    const lock = join(fixture.home, 'legacy-upgrade', 'upgrade.lock');
    assert.equal(readManagedJson(lock).pid, child.pid);
    await fixture.approve(retry);
    await assert.rejects(fixture.upgrader().execute(retry), /preparation lock remains/);
    unlinkSync(lock);
    const confirmed = await fixture.plan();
    await fixture.approve(confirmed);
    assert.equal((await fixture.upgrader().execute(confirmed)).status, 'upgraded');
  } finally { await fixture.cleanup(); }
});

test('candidate CLI sharing denial before first journal leaves legacy discovery and retry intact', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  let holder;
  let holderExit;
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const upgrader = fixture.upgrader(undefined, { checkpoint: async phase => {
      if (phase !== 'legacy-candidate-created') return;
      holder = spawn('pwsh', ['-NoProfile', '-File',
        fileURLToPath(new URL('./fixtures/legacy-cli-lock.ps1', import.meta.url)),
        '-Path', join(fixture.root, 'bin', 'cli.mjs')], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      holderExit = new Promise(resolveExit => holder.once('exit', resolveExit));
      await new Promise((resolveHeld, reject) => {
        const deadline = setTimeout(() => reject(new Error('Owned CLI lock did not become ready.')), 10000);
        holder.once('error', reject);
        holder.stdout.once('data', bytes => {
          clearTimeout(deadline);
          assert.equal(bytes.toString().trim(), 'held');
          resolveHeld();
        });
      });
    } });
    await assert.rejects(upgrader.execute(plan), /busy|access|inspect|stage|transaction/i);
    holder.stdin.end('\n');
    assert.equal(await holderExit, 0);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.equal(discoverInstances(fixture.home).length, 0, 'An I/O failure must not publish a journal-less candidate.');
    const retry = await fixture.plan();
    assert.equal(retry.from, '1.3.0');
    await fixture.approve(retry);
    assert.equal((await fixture.upgrader().execute(retry)).status, 'upgraded');
  } finally {
    if (holder?.exitCode === null) holder.stdin.end('\n');
    await holderExit;
    await fixture.cleanup();
  }
});

test('damaged rolled-back target stays dormant for a new ordinary legacy upgrade', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    await fixture.start();
    const pair = JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File',
      fileURLToPath(new URL('./fixtures/legacy-restoration-xml.ps1', import.meta.url)), '-UseInputRecord'],
    { input: JSON.stringify(fixture.originalTask), encoding: 'utf8', windowsHide: true, timeout: 15000 }));
    const hash = text => createHash('sha256').update(text).digest('hex');
    fixture.originalTask = { ...fixture.originalTask, xml: pair.originalXml, xmlSha256: hash(pair.originalXml) };
    const initialTask = fixture.task.read();
    initialTask.current = fixture.originalTask;
    writeFileSync(fixture.taskPath, JSON.stringify(initialTask));
    fixture.task.assertRestored = (port, actual, original) => new WindowsLegacyTaskAdapter().assertRestored(port, actual, original);
    fixture.task.restore = (port, expected, original) => {
      fixture.task.check(expected);
      const state = fixture.task.read();
      state.current = { ...structuredClone(original), xml: pair.actualXml, xmlSha256: hash(pair.actualXml) };
      state.actions.push('restore');
      writeFileSync(fixture.taskPath, JSON.stringify(state));
      return structuredClone(state.current);
    };
    const plan = await fixture.plan();
    await fixture.approve(plan);
    let damaged;
    const upgrader = fixture.upgrader(undefined, { checkpoint: (phase, journal) => {
      if (phase !== 'legacy-stopped' ||
          damaged) return;
      damaged = join(journal.target.root, 'bin', 'mcp-bridge.mjs');
      unlinkSync(damaged);
    } });
    await assert.rejects(upgrader.execute(plan), /ENOENT|package|bytes/);
    const journalPath = join(plan.instance.directory, 'journal.json');
    const bytes = readFileSync(journalPath);
    assert.equal(readManagedJson(journalPath).phase, 'legacy-rolled-back');
    assert.notEqual(readManagedJson(journalPath).legacy.taskCurrent.xml, readManagedJson(journalPath).legacy.registration.xml);
    assert.equal(discoverInstances(fixture.home).length, 0, 'Restored raw XML differences do not reactivate a settled candidate.');
    const old = await backendStatus(fixture.port);
    const retry = await fixture.plan();
    assert.equal(retry.from, '1.3.0');
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.equal(existsSync(damaged), false);
    assert.deepEqual(readFileSync(journalPath), bytes);
    const mutations = [
      value => { value.binding.port++; },
      value => { value.phase = 'legacy-aborted'; },
      value => { value.restoredLegacyProcesses.root = fixture.directory; },
      value => { value.legacy.taskCurrent.security.sha256 = '0'.repeat(64); },
      value => { value.phase = 'committed'; },
    ];
    for (const mutate of mutations) {
      const corrupt = JSON.parse(bytes);
      mutate(corrupt);
      try {
        writeFileSync(journalPath, JSON.stringify(corrupt));
        assert.throws(() => discoverInstances(fixture.home));
      } finally { writeFileSync(journalPath, bytes); }
    }
    await fixture.approve(retry);
    assert.equal((await fixture.upgrader().execute(retry)).status, 'upgraded');
  } finally { await fixture.cleanup(); }
});

test('cache-backed legacy roots cannot become retained rollback installations', windows, async () => {
  const fixture = new LegacyUpgradeFixture({ cacheBacked: true });
  try {
    assert.throws(() => verifyLegacyPackage(fixture.root), /Cache-backed npx roots/);
    assert.deepEqual(fixture.instances, []);
  } finally { await fixture.cleanup(); }
});

test('legacy publication gate requires the separate exact inventory and actual broker TAP cases', () => {
  const legacyBroker = verifyLegacyFeature(source);
  assert.equal(legacyBroker.status, 'source-and-binary-hashes-verified');
  const report = {
    legacyBroker, evidence: { command: { args: ['--test', LEGACY_BROKER_TEST] } },
    stdout: LEGACY_BROKER_REQUIRED_TESTS.map((name, index) => `ok ${index + 1} - ${name}`).join('\n'),
  };
  const inspection = { files: [...legacyBroker.files, { path: 'bin/legacy-upgrade.mjs' }] };
  verifyLegacyExecution(report, inspection);
  const missingFile = structuredClone(inspection);
  missingFile.files.shift();
  assert.throws(() => verifyLegacyExecution(report, missingFile));
  assert.throws(() => verifyLegacyExecution({ ...report, stdout: '' }, inspection), /Missing executed/);
  assert.throws(() => verifyLegacyExecution({ ...report, evidence: { command: { args: [] } } }, inspection), /must execute/);
  verifyLegacyExecution({ ...report, legacyBroker: undefined }, { files: [] });
});

async function ownedRequest(port, path, body) {
  return new Promise((resolveResponse, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' } }, res => {
      res.resume();
      res.on('end', () => resolveResponse(res.statusCode));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('Owned request timed out.')));
    req.end(JSON.stringify(body));
  });
}

test('legacy confirmation is exact-plan scoped and --yes confirms the plan shown', async () => {
  const plan = { to: '2.0.3', registry: 'https://owned.invalid/', instance: { id: 'owned' }, legacy: { protocol: 1 } };
  let prompts = 0;
  const confirm = async () => { prompts++; return true; };
  await assert.rejects(confirmLegacyUpgrade(plan, { interactive: false, confirm }), /needs confirmation/);
  assert.equal(prompts, 0);
  assert.equal(await confirmLegacyUpgrade(plan, { interactive: true, confirm: async () => false }), false);
  await assert.rejects(confirmLegacyUpgrade(plan, {
    interactive: true, confirm: async () => { plan.to = '2.0.4'; return true; },
  }), /changed during confirmation/);
  assert.equal(await confirmLegacyUpgrade(plan, { yes: true, interactive: false, confirm }), true);
  assert.equal(prompts, 0, '--yes does not prompt.');
  assert.match(LEGACY_WARNING, /Open sessions and calls in progress end/);
  assert.match(LEGACY_WARNING, /servers\.json, every server setting in it and your client setup are kept/);
});

test('legacy stop receipts need a verified root stop and cannot be replaced by modern complete-tree proof', () => {
  const upgrader = new LegacyUpgrader();
  for (const receipt of [
    { stopped: true, activeProcesses: 0 },
    { legacyRootStopVerified: false, observedDescendantsStopped: true, treeCompleteness: 'unproven', errors: [] },
    { legacyRootStopVerified: true, observedDescendantsStopped: true, treeCompleteness: 'complete', errors: [] },
    { legacyRootStopVerified: true, observedDescendantsStopped: true, treeCompleteness: 'unproven', errors: [], activeProcesses: 0 },
  ]) assert.throws(() => upgrader.assertPartialStop(receipt), /not verified/);
  upgrader.assertPartialStop({
    legacyRootStopVerified: true, observedDescendantsStopped: true, treeCompleteness: 'unproven', errors: [],
  });
  upgrader.assertPartialStop({
    legacyRootStopVerified: true, observedDescendantsStopped: false, treeCompleteness: 'unproven', errors: ['4242:Win32Exception:5'],
  });
});

test('exact retained 1.3 read-only plan and an unconfirmed execute leave service, config, task and CLI unchanged', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const cli = readFileSync(join(fixture.root, 'bin', 'cli.mjs'));
    const plan = await fixture.plan();
    assert.match(describeUpgrade(plan), /Open sessions and calls in progress end/);
    assert.equal(plan.legacy.processes.treeCompleteness, 'unproven');
    assert.deepEqual(plan.legacy.processes.observed, []);
    assert.equal(existsSync(plan.instance.directory), false);
    await assert.rejects(confirmLegacyUpgrade(plan, { interactive: false }), /needs confirmation/);
    await assert.rejects(fixture.upgrader().execute(plan), /no matching confirmation/);
    assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
    assert.deepEqual(readFileSync(join(fixture.root, 'bin', 'cli.mjs')), cli);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.equal(await fixture.cliVersion(), '1.3.0');
  } finally { await fixture.cleanup(); }
});

test('restart-only legacy migration selects new backend and actual old shim on the same port', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const result = await fixture.upgrader().execute(plan);
    assert.equal(result.status, 'upgraded');
    assert.equal(result.port, fixture.port);
    assert.equal(result.legacyStop.legacyRootStopVerified, true);
    assert.equal(result.legacyStop.observedDescendantsStopped, true);
    assert.equal(result.legacyStop.descendantsStopped, result.legacyStop.descendantsFound);
    assert.equal(result.legacyStop.treeCompleteness, 'unproven');
    assert.equal('activeProcesses' in result.legacyStop, false);
    assert.match(result.warning, /sessions and calls in progress were ended/);
    const status = await backendStatus(fixture.port);
    assert.equal(status.version, '2.0.3');
    assert.notEqual(status.instanceId, old.instanceId);
    assert.equal(await fixture.cliVersion(), '2.0.3');
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
    assert.deepEqual(readFileSync(join(fixture.home, 'state.json')), fixture.originalState);
    assert.equal(readManagedJson(join(result.directory, 'journal.json')).phase, 'committed');
    assert.deepEqual(fixture.task.read().actions, ['fixture-registered', 'hold', 'repoint', 'enable']);
    await assert.rejects(fixture.upgrader().execute(plan), /no matching confirmation/);
  } finally { await fixture.cleanup(); }
});

test('a busy 1.3 bridge is upgraded while its sessions start and end, and the config is kept', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  let churning = true;
  let sessionsStarted = 0;
  const lanes = [];
  try {
    await fixture.start({
      echo: { command: process.execPath, args: [fileURLToPath(new URL('./fixtures/echo-mcp-server.mjs', import.meta.url))] },
    });
    const endpoint = `http://127.0.0.1:${fixture.port}/echo/mcp`;
    // Each round trip makes 1.3 start a session process and rewrite sessions.json twice.
    const lane = async () => {
      while (churning) {
        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
              params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'owned', version: '1' } } }),
          });
          await response.text();
          const session = response.headers.get('mcp-session-id');
          if (session) {
            sessionsStarted++;
            await fetch(endpoint, { method: 'DELETE', headers: { 'mcp-session-id': session } });
          }
        } catch { await new Promise(resolveWait => setTimeout(resolveWait, 50)); }
      }
    };
    for (let index = 0; index < 3; index++) lanes.push(lane());
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const before = sessionsStarted;
    const result = await fixture.upgrader().execute(plan);
    assert.equal(result.status, 'upgraded');
    assert.ok(sessionsStarted > before, 'Sessions kept starting and ending during the upgrade.');
    assert.equal(result.legacyStop.legacyRootStopVerified, true);
    assert.equal((await backendStatus(fixture.port)).version, '2.0.3');
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
  } finally {
    churning = false;
    await Promise.all(lanes);
    await fixture.cleanup();
  }
});

test('1.3 session records too large to inspect never strand an upgrade after the stop', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    // Resumable records for servers no longer configured; together over the 1 MiB inspection limit.
    const records = Object.fromEntries(Array.from({ length: 9000 }, () => [randomUUID(), {
      server: 'retired', initialize: { protocolVersion: '2025-06-18', clientInfo: { name: 'client', version: '1.0.0' } },
      at: Date.now(),
    }]));
    writeFileSync(join(dirname(fixture.config), 'sessions.json'), JSON.stringify(records));
    // A target that still compares the records when it starts refuses before anything stops.
    const refused = await fixture.plan();
    await fixture.approve(refused);
    await assert.rejects(fixture.upgrader().execute(refused), /over 1 MiB[\s\S]*Nothing was stopped/);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
    // A target that ignores them reads them only after the stop, and only for the journal.
    const plan = await fixture.plan({ to: '2.1.2' });
    await fixture.approve(plan);
    const result = await fixture.upgrader(fixture.artifact(undefined, '2.1.2')).execute(plan);
    assert.equal(result.status, 'upgraded');
    const journal = readManagedJson(join(result.directory, 'journal.json'));
    assert.equal(journal.phase, 'committed');
    assert.equal(journal.sessionState, null);
    assert.equal(journal.legacy.sessions, null);
    assert.equal((await backendStatus(fixture.port)).version, '2.1.2');
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
  } finally { await fixture.cleanup(); }
});

test('1.3 session records unreadable after the stop restart 1.3 for a target that compares them', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    let grown = false;
    // The records grow past what can be read only after the size check, just before the stop.
    const upgrader = fixture.upgrader(undefined, { checkpoint: phase => {
      if (phase !== 'legacy-stopping' ||
          grown) return;
      grown = true;
      writeFileSync(join(dirname(fixture.config), 'sessions.json'), JSON.stringify({ padding: 'x'.repeat(1024 * 1024) }));
    } });
    await assert.rejects(upgrader.execute(plan), /could not be read after the old version stopped/);
    assert.equal(readManagedJson(join(plan.instance.directory, 'journal.json')).phase, 'legacy-rolled-back');
    const status = await backendStatus(fixture.port);
    assert.equal(status.version, '1.3.0');
    assert.notEqual(status.instanceId, old.instanceId);
    assert.equal(discoverInstances(fixture.home).length, 0);
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
  } finally { await fixture.cleanup(); }
});

test('a server 1.3 runs through cmd.exe is stopped with the bridge instead of being left running', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  const heartbeat = join(fixture.directory, 'stubborn.heartbeat');
  try {
    // A bare command makes 1.3 start the server under cmd.exe, which Node ends with the bridge.
    // This server ignores its closed input, as many real servers do.
    await fixture.start({
      stubborn: { command: 'node', args: [fileURLToPath(new URL('./fixtures/stubborn-mcp-server.mjs', import.meta.url)), '--heartbeat', heartbeat] },
    });
    const response = await fetch(`http://127.0.0.1:${fixture.port}/stubborn/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'owned', version: '1' } } }),
    });
    assert.equal(response.status, 200);
    await response.text();
    assert.equal(existsSync(heartbeat), true);
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const result = await fixture.upgrader().execute(plan);
    assert.equal(result.status, 'upgraded');
    assert.equal(result.legacyStop.observedDescendantsStopped, true);
    assert.ok(result.legacyStop.descendantsFound >= 2, 'The cmd.exe wrapper and the server under it were found.');
    const beat = readFileSync(heartbeat, 'utf8');
    await new Promise(resolveWait => setTimeout(resolveWait, 1000));
    assert.equal(readFileSync(heartbeat, 'utf8'), beat, 'The server under the cmd.exe wrapper no longer runs.');
  } finally { await fixture.cleanup(); }
});

test('legacy download failure occurs before any selected task or service interruption', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const upgrader = new ManagedUpgrader({ acquire: async () => { throw new Error('owned download denied'); } });
    await assert.rejects(upgrader.execute(plan), /owned download denied/);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
    assert.equal(await fixture.cliVersion(), '1.3.0');
  } finally { await fixture.cleanup(); }
});

test('changed legacy registration refuses before staging or process mutation', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const changed = structuredClone(fixture.originalTask);
    changed.actions[0].arguments += ' unknown';
    fixture.task.save(changed, 'external-change');
    let acquired = false;
    const upgrader = new ManagedUpgrader({ acquire: async () => { acquired = true; throw new Error('must not acquire'); } });
    await assert.rejects(upgrader.execute(plan), /registration changed/);
    assert.equal(acquired, false);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
  } finally { await fixture.cleanup(); }
});

test('known target startup failure restores legacy task, code, backend and old shim without replay', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const cli = readFileSync(join(fixture.root, 'bin', 'cli.mjs'));
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const artifact = fixture.artifact(root => {
      const path = join(root, 'bin', 'mcp-bridge.mjs');
      const code = readFileSync(path, 'utf8');
      const anchor = "const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));";
      assert.ok(code.includes(anchor));
      writeFileSync(path, code.replace(anchor, `if (!CONFIG.includes('preflight')) throw new Error('owned target failure');\n${anchor}`));
    });
    await assert.rejects(fixture.upgrader(artifact).execute(plan), /startup/);
    const current = await backendStatus(fixture.port);
    assert.equal(current.version, '1.3.0');
    assert.notEqual(current.instanceId, old.instanceId);
    assert.equal(await fixture.cliVersion(), '1.3.0');
    assert.deepEqual(readFileSync(join(fixture.root, 'bin', 'cli.mjs')), cli);
    assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
    assert.equal(readManagedJson(join(plan.instance.directory, 'journal.json')).phase, 'legacy-rolled-back');
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
  } finally { await fixture.cleanup(); }
});

test('unverified root stop retains the task hold and never starts the target', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    const old = await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const api = await import('../bin/windows-legacy-process.mjs');
    const processes = {
      ...api,
      prepareLegacyProcesses: async options => {
        const session = await api.prepareLegacyProcesses(options);
        return {
          ...session,
          stop: async () => ({
            legacyRootStopVerified: false, observedDescendantsStopped: false,
            treeCompleteness: 'unproven', observedCount: 1, errors: ['Owned stop-failure injection'],
          }),
        };
      },
    };
    await assert.rejects(fixture.upgrader(undefined, { legacy: { task: fixture.task, processes } }).execute(plan), /not verified/);
    const journal = readManagedJson(join(plan.instance.directory, 'journal.json'));
    assert.equal(journal.phase, 'legacy-stopping');
    assert.equal(journal.legacyStop.observedDescendantsStopped, false);
    assert.equal(fixture.task.inspect()[0].enabled, false);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.equal(await fixture.cliVersion(), '1.3.0');
    await assert.rejects(fixture.upgrader().recover(plan.instance.directory), /not verified/);
  } finally { await fixture.cleanup(); }
});

test('a process the 1.3 bridge started that could not be stopped is reported and does not block activation', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const api = await import('../bin/windows-legacy-process.mjs');
    const processes = {
      ...api,
      prepareLegacyProcesses: async options => {
        const session = await api.prepareLegacyProcesses(options);
        return {
          ...session,
          // The real stop runs; only its descendant outcome is replaced.
          stop: async () => ({ ...(await session.stop()), observedDescendantsStopped: false, errors: ['4242:Win32Exception:5'] }),
        };
      },
    };
    const result = await fixture.upgrader(undefined, { legacy: { task: fixture.task, processes } }).execute(plan);
    assert.equal(result.status, 'upgraded');
    assert.equal(result.legacyStop.legacyRootStopVerified, true);
    assert.equal(result.legacyStop.observedDescendantsStopped, false);
    assert.match(result.warning, /Not every process the 1\.3 bridge started could be confirmed stopped/);
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
  } finally { await fixture.cleanup(); }
});

test('foreign listener after verified old-root stop is untouched and blocks target activation', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  const foreign = createServer(socket => {
    socket.on('error', () => {});
    socket.end('owned foreign listener');
  });
  try {
    await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const api = await import('../bin/windows-legacy-process.mjs');
    const processes = {
      ...api,
      prepareLegacyProcesses: async options => {
        const session = await api.prepareLegacyProcesses(options);
        return {
          ...session,
          stop: async () => {
            const result = await session.stop();
            await new Promise((resolveListen, reject) => {
              foreign.once('error', reject);
              foreign.listen(fixture.port, '127.0.0.1', resolveListen);
            });
            return result;
          },
        };
      },
    };
    await assert.rejects(fixture.upgrader(undefined, { legacy: { task: fixture.task, processes } }).execute(plan), /listener/);
    assert.equal(foreign.listening, true);
    assert.equal(fixture.task.inspect()[0].enabled, false);
    assert.equal(await fixture.cliVersion(), '1.3.0');
    assert.equal(readManagedJson(join(plan.instance.directory, 'journal.json')).phase, 'legacy-rollback-stopping');
  } finally {
    if (foreign.listening) await new Promise(resolveClose => foreign.close(resolveClose));
    await fixture.cleanup();
  }
});

test('config change after old-root stop refuses target activation and old replay', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    await fixture.start();
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const upgrader = fixture.upgrader(undefined, { checkpoint: phase => {
      if (phase === 'legacy-stopped') writeFileSync(fixture.config, '{"changed":true}\n');
    } });
    await assert.rejects(upgrader.execute(plan), /changed|conflict/i);
    assert.equal(fixture.task.inspect()[0].enabled, false);
    assert.equal(readManagedJson(join(plan.instance.directory, 'journal.json')).phase, 'legacy-stopped');
    assert.equal(await fixture.cliVersion(), '1.3.0');
  } finally { await fixture.cleanup(); }
});

test('HTTP work with zero legacy sessions is interrupted once and never replayed by migration', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  let calls = 0;
  let entered;
  const called = new Promise(resolveCall => { entered = resolveCall; });
  const upstream = createHttpServer((req, res) => {
    let text = '';
    req.on('data', bytes => { text += bytes; });
    req.on('end', () => {
      if (text.includes('"tools/call"')) { calls++; entered(); }
      else res.end('{}');
    });
  });
  const sockets = new Set();
  upstream.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  try {
    await new Promise(resolveListen => upstream.listen(0, '127.0.0.1', resolveListen));
    await fixture.start({ http: { type: 'http', url: `http://127.0.0.1:${upstream.address().port}/`, auth: { type: 'none' } } });
    const plan = await fixture.plan();
    await fixture.approve(plan);
    const pending = ownedRequest(fixture.port, '/http', {
      jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'owned' },
    }).catch(error => error);
    await called;
    assert.equal((await backendStatus(fixture.port)).sessions, 0);
    const result = await fixture.upgrader().execute(plan);
    assert.equal(result.status, 'upgraded');
    await pending;
    assert.equal(calls, 1, 'Migration must not replay the unknown HTTP outcome.');
    assert.match(result.warning, /No call was retried/);
  } finally {
    for (const socket of sockets) socket.destroy();
    if (upstream.listening) await new Promise(resolveClose => upstream.close(resolveClose));
    await fixture.cleanup();
  }
});

test('an orphan whose parent already exited stays alive and does not block restart', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  const identityPath = join(fixture.directory, 'old-orphan.json');
  let identity;
  try {
    await fixture.start({
      orphan: { command: process.execPath, args: [fileURLToPath(new URL('./fixtures/legacy-orphan-wrapper.mjs', import.meta.url)), identityPath] },
    });
    await ownedRequest(fixture.port, '/orphan/mcp', {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'owned', version: '1' } },
    }).catch(() => {});
    assert.equal(existsSync(identityPath), true);
    identity = readManagedJson(identityPath);
    const probe = fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity.ps1', import.meta.url));
    const alive = () => JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File', probe,
      '-ProcessId', String(identity.pid), '-CreationTicks', identity.creationTicks], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
    }));
    assert.equal(alive().gone, false);
    const plan = await fixture.plan();
    assert.equal(plan.legacy.processes.observed.some(value => value.pid === identity.pid), false);
    await fixture.approve(plan);
    const result = await fixture.upgrader().execute(plan);
    assert.equal(result.status, 'upgraded');
    assert.equal(result.legacyStop.treeCompleteness, 'unproven');
    assert.match(result.warning, /sessions and calls in progress were ended/);
    assert.equal(alive().gone, false);
    const cleaned = JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File', probe,
      '-ProcessId', String(identity.pid), '-CreationTicks', identity.creationTicks, '-StopOwned'], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
    }));
    assert.equal(cleaned.gone, true);
  } finally { await fixture.cleanup(); }
});

for (const phase of [
  'legacy-prepared', 'legacy-holding', 'legacy-held', 'legacy-stopping', 'legacy-stopped',
  'legacy-launching', 'legacy-wiring', 'legacy-cli-original-moved', 'legacy-cli-selected', 'legacy-admitting',
  'legacy-rollback-stopping', 'legacy-cli-restoring', 'legacy-task-restoring', 'legacy-rollback-launching',
]) {
  test(`actual legacy upgrader interruption at ${phase} preserves its recovery boundary`, windows, async () => {
    const fixture = new LegacyUpgradeFixture();
    try {
      await fixture.start();
      const plan = await fixture.plan();
      const rollbackBoundary = ['legacy-rollback-stopping', 'legacy-cli-restoring', 'legacy-task-restoring', 'legacy-rollback-launching'].includes(phase);
      const artifact = fixture.artifact(rollbackBoundary ? root => {
        const path = join(root, 'bin', 'mcp-bridge.mjs');
        const code = readFileSync(path, 'utf8');
        const anchor = "const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));";
        assert.ok(code.includes(anchor));
        writeFileSync(path, code.replace(anchor, `if (!CONFIG.includes('preflight')) throw new Error('owned rollback checkpoint');\n${anchor}`));
      } : undefined);
      const archive = join(fixture.directory, 'candidate.tgz');
      writeFileSync(archive, artifact.bytes);
      const input = join(fixture.directory, 'crash.json');
      writeFileSync(input, JSON.stringify({
        plan: { ...plan, legacyRuntime: undefined }, archive, integrity: artifact.integrity, phase, taskPath: fixture.taskPath,
      }));
      const child = spawn(process.execPath, [
        fileURLToPath(new URL('./fixtures/legacy-upgrade-crash.mjs', import.meta.url)), input,
      ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', bytes => { output += bytes; });
      child.stderr.on('data', bytes => { output += bytes; });
      const code = await new Promise((resolveExit, reject) => {
        child.once('error', reject);
        child.once('exit', resolveExit);
      });
      assert.equal(code, 86, output);
      const journal = readManagedJson(join(plan.instance.directory, 'journal.json'));
      const expectedPhase = ['legacy-cli-original-moved', 'legacy-cli-selected'].includes(phase) ? 'legacy-wiring' : phase;
      assert.equal(journal.phase, expectedPhase);
      for (const lock of [
        join(plan.instance.directory, 'upgrade.lock'), join(fixture.home, 'legacy-upgrade', 'upgrade.lock'),
      ]) {
        assert.equal(readManagedJson(lock).pid, child.pid);
        unlinkSync(lock);
      }
      if (['legacy-prepared', 'legacy-held'].includes(phase)) {
        const recovered = await fixture.upgrader().recover(plan.instance.directory);
        assert.equal(recovered.status, 'legacy-aborted');
        assert.deepEqual(fixture.task.inspect(), [fixture.originalTask]);
      } else if (['legacy-stopped', 'legacy-wiring', 'legacy-cli-original-moved', 'legacy-cli-selected'].includes(phase)) {
        const recovered = await fixture.upgrader().recover(plan.instance.directory);
        assert.equal(recovered.status, 'rolled-back');
        assert.equal(await fixture.cliVersion(), '1.3.0');
      } else {
        await assert.rejects(fixture.upgrader().recover(plan.instance.directory), /not verified|record|uncertain|ENOENT/);
        assert.equal(readManagedJson(join(plan.instance.directory, 'journal.json')).phase, expectedPhase);
      }
    } finally { await fixture.cleanup(); }
  });
}

test('RED retained Run08 planner rejects the same exact legacy restart plan accepted now', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    await fixture.start();
    const plan = await fixture.plan();
    assert.equal(plan.from, '1.3.0');
    const mutant = join(fixture.directory, 'old-planner');
    mkdirSync(mutant);
    cpSync(join(source, 'bin'), join(mutant, 'bin'), { recursive: true });
    const baseline = process.env.MCP_LEGACY_TEST_BASELINE;
    if (baseline) cpSync(join(baseline, 'bin', 'managed-upgrade.mjs'), join(mutant, 'bin', 'managed-upgrade.mjs'));
    else {
      const path = join(mutant, 'bin', 'managed-upgrade.mjs');
      const code = readFileSync(path, 'utf8');
      const boundary = 'const prepared = await prepareLegacyPlan(selected, { home, ...legacy });';
      assert.ok(code.includes(boundary));
      writeFileSync(path, code.replace(boundary, "throw new Error('automatic legacy migration is blocked');"));
    }
    const pkg = readManagedJson(join(source, 'package.json'));
    writeFileSync(join(mutant, 'package.json'), JSON.stringify(pkg));
    const { retainedCliDependencies } = await import('./helpers/managed-package.mjs');
    await retainedCliDependencies(mutant);
    const previous = await import(pathToFileURL(join(mutant, 'bin', 'managed-upgrade.mjs')).href);
    await assert.rejects(previous.planUpgrade({ to: '2.0.3' }, { home: fixture.home }), /automatic legacy migration is blocked/);
  } finally { await fixture.cleanup(); }
});
