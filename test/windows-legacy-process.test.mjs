import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, fork } from 'node:child_process';
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, symlinkSync, unlinkSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, basename, parse, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyLegacyBrokerAssets, LEGACY_BROKER_FILES } from '../tools/windows-legacy/inventory.mjs';
import { CachedEdgeFixture } from './helpers/cached-edge-fixture.mjs';
import { LegacyFailureFixture } from './helpers/legacy-failure-fixture.mjs';

const { prepareLegacyProcesses, verifyLegacyProcessesGone } = await import(process.env.MCP_LEGACY_TEST_MODULE
  ? pathToFileURL(process.env.MCP_LEGACY_TEST_MODULE).href : '../bin/windows-legacy-process.mjs');

class LegacyFixture {
  constructor(t, prefix = 'mcp-legacy-owned-') {
    this.directory = mkdtempSync(join(tmpdir(), prefix));
    this.records = [];
    this.sessions = [];
    this.results = [];
    this.output = '';
    if (process.env.MCP_LEGACY_TEST_EVIDENCE) {
      writeFileSync(join(process.env.MCP_LEGACY_TEST_EVIDENCE, `start-${basename(this.directory)}.json`),
        JSON.stringify({ directory: this.directory, node: process.version, runnerPid: process.pid, at: new Date().toISOString() }));
    }
    t.diagnostic(`Owned legacy broker evidence: ${this.directory}`);
    t.after(() => this.cleanup());
  }

  identity(pid, creationTicks, stop = false) {
    const script = fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity.ps1', import.meta.url));
    const args = ['-NoProfile', '-NonInteractive', '-File', script, '-ProcessId', String(pid)];
    if (creationTicks) args.push('-CreationTicks', creationTicks);
    if (stop) args.push('-StopOwned');
    const result = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  }

  capture(pid) {
    const identity = this.identity(pid);
    assert.equal(identity.gone, false);
    this.record(identity);
    return identity;
  }

  record(identity) {
    this.records.push(identity);
    writeFileSync(join(this.directory, 'identities.jsonl'), `${JSON.stringify(identity)}\n`, { flag: 'a' });
  }

  async wait(check) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const value = check();
      if (value) return value;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Owned legacy fixture readiness failed: ${this.output}`);
  }

  async start(extra = [], paths = {}) {
    mkdirSync(join(this.directory, 'bin'));
    mkdirSync(join(this.directory, 'supervisor'));
    copyFileSync(new URL('./fixtures/windows-legacy/bridge.mjs', import.meta.url),
      join(this.directory, 'bin/mcp-bridge.mjs'));
    // Same process arguments and retry shape, without cmdlet module startup. The upgrader
    // owns the separate byte-exact historical package E2E.
    writeFileSync(join(this.directory, 'supervisor/supervise.ps1'), `
param([int]$Port)
$ErrorActionPreference = 'Stop'
$bridge = [IO.Path]::Combine($PSScriptRoot, '..', 'bin', 'mcp-bridge.mjs')
if ($env:OWNED_BRIDGE_ARGUMENT) { $bridge = $env:OWNED_BRIDGE_ARGUMENT }
[IO.File]::WriteAllText([IO.Path]::Combine($env:OWNED_LEGACY_DIRECTORY, 'actual-supervisor.txt'), $PSCommandPath)
$self = [Diagnostics.Process]::GetCurrentProcess()
[IO.File]::AppendAllText([IO.Path]::Combine($env:OWNED_LEGACY_DIRECTORY, 'spawned.jsonl'),
  '{"pid":' + $self.Id + ',"creationTicks":"' + $self.StartTime.ToUniversalTime().Ticks + '"}' + "\`n")
$watch = [Diagnostics.Stopwatch]::StartNew()
while ($watch.Elapsed.TotalSeconds -lt 45) {
  $start = [Diagnostics.ProcessStartInfo]::new($env:OWNED_NODE)
  $start.UseShellExecute = $false
  $start.WorkingDirectory = $env:OWNED_LEGACY_DIRECTORY
  $start.Arguments = "\`"$bridge\`" --port $Port"
  $child = [Diagnostics.Process]::Start($start)
  [IO.File]::AppendAllText([IO.Path]::Combine($env:OWNED_LEGACY_DIRECTORY, 'spawned.jsonl'),
    '{"pid":' + $child.Id + ',"creationTicks":"' + $child.StartTime.ToUniversalTime().Ticks + '"}' + "\`n")
  while (-not $child.WaitForExit(1000)) { if ($watch.Elapsed.TotalSeconds -ge 45) { break } }
  if ($watch.Elapsed.TotalSeconds -ge 45) { break }
  [Threading.Thread]::Sleep(300)
}
`);
    if (paths.prepare) paths.prepare(this);
    const listener = createServer();
    await new Promise((resolve, reject) => {
      listener.on('error', reject);
      listener.listen(0, '127.0.0.1', resolve);
    });
    this.port = listener.address().port;
    await new Promise((resolve) => listener.close(resolve));
    const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
      '-File', paths.supervisorArgument || join(this.directory, 'supervisor/supervise.ps1'), '-Port', String(this.port), ...extra];
    this.supervisor = spawn(join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe'), args, {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], cwd: this.directory,
      env: {
        SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, ComSpec: process.env.ComSpec,
        PATH: `${dirname(process.execPath)};${process.env.SystemRoot}\\System32`,
        HOME: this.directory, USERPROFILE: this.directory, TEMP: this.directory, TMP: this.directory,
        OWNED_LEGACY_DIRECTORY: this.directory,
        OWNED_NODE: process.execPath,
        OWNED_BRIDGE_ARGUMENT: paths.bridgeArgument || '',
      },
    });
    this.supervisor.on('error', (error) => { this.output += error.message; });
    this.supervisor.stdout.on('data', (chunk) => { this.output += chunk; });
    this.supervisor.stderr.on('data', (chunk) => { this.output += chunk; });
    await new Promise((resolve, reject) => {
      this.supervisor.once('spawn', resolve);
      this.supervisor.once('error', reject);
    });
    this.capture(this.supervisor.pid);
    const ready = join(this.directory, 'ready.json');
    await this.wait(() => existsSync(ready));
    const bridge = JSON.parse(readFileSync(ready));
    this.capture(bridge.pid);
    const status = await this.request('/');
    assert.equal(status.pid, bridge.pid);
    assert.equal(status.fixture, 'owned-legacy-broker');
    return this;
  }

  request(path) {
    return new Promise((resolve, reject) => {
      const request = http.get({ host: '127.0.0.1', port: this.port, path, agent: false }, (response) => {
        let body = '';
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve(JSON.parse(body)));
      });
      request.on('error', reject);
      request.setTimeout(2000, () => request.destroy(new Error('Owned legacy HTTP deadline')));
    });
  }

  async child() {
    const response = await this.request('/spawn');
    const child = response.children.at(-1);
    this.capture(child.pid);
    await this.wait(() => existsSync(child.path));
    return child;
  }

  async prepare(expected, root = this.directory, prepare = prepareLegacyProcesses) {
    let session;
    try { session = await prepare({ port: this.port, root, expected }); }
    catch (error) {
      this.results.push({ refused: true, detail: error.detail });
      throw error;
    }
    this.sessions.push(session);
    for (const identity of [session.plan.roots.supervisor, session.plan.roots.bridge, ...session.plan.observed]) {
      this.record({ pid: identity.pid,
        creationTicks: String(BigInt(identity.creationTime) + 504911232000000000n) });
    }
    return session;
  }

  copyEvidence(source, destination) {
    // Node22's cpSync aborts on this owned Unicode/long-path combination.
    // Preserve the actual Unicode inputs using individual file operations.
    mkdirSync(destination);
    for (const entry of readdirSync(source, { withFileTypes: true })) {
      assert.equal(entry.isSymbolicLink(), false, 'Unexpected link in owned test evidence');
      const from = join(source, entry.name);
      const to = join(destination, entry.name);
      if (entry.isDirectory()) this.copyEvidence(from, to);
      else {
        assert.equal(entry.isFile(), true);
        copyFileSync(from, to, constants.COPYFILE_EXCL);
      }
    }
  }

  async cleanup() {
    const errors = [];
    for (const session of this.sessions) {
      try { await session.close(); } catch (error) { errors.push(error.message); }
    }
    const seen = new Set();
    const cleanup = [];
    const spawned = join(this.directory, 'spawned.jsonl');
    if (existsSync(spawned)) {
      for (const line of readFileSync(spawned, 'utf8').trim().split('\n')) {
        if (line) this.records.push(JSON.parse(line));
      }
    }
    // Supervisor first: it must not restart a bridge while owned cleanup runs.
    for (const record of this.records) {
      const key = `${record.pid}:${record.creationTicks}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try { cleanup.push({ ...record, ...this.identity(record.pid, record.creationTicks, true) }); }
      catch (error) { errors.push(error.message); }
    }
    writeFileSync(join(this.directory, 'receipt.json'), JSON.stringify({
      node: process.version, plans: this.sessions.map((session) => session.plan), results: this.results,
      records: this.records, cleanup, errors,
    }, null, 2));
    writeFileSync(join(this.directory, 'stdio.txt'), this.output);
    assert.deepEqual(errors, []);
    assert.ok(cleanup.every((item) => item.gone));
    if (process.env.MCP_LEGACY_TEST_EVIDENCE) {
      this.copyEvidence(this.directory, join(process.env.MCP_LEGACY_TEST_EVIDENCE, basename(this.directory)));
      rmSync(this.directory, { recursive: true });
    }
  }
}

const WINDOWS = { skip: process.platform !== 'win32', timeout: 60000 };

test('legacy API denials preserve refusal and bounded stored-only failure diagnostics', WINDOWS, async () => {
  const evidence = await new LegacyFailureFixture().run();
  assert.equal(evidence.results.length, 4);
  assert.equal(evidence.rootsUnchanged, true);
  assert.equal(evidence.taskActionsUnchanged, true);
});

test('legacy failure metadata cannot mask errors or cross concurrent operation identities', WINDOWS, () => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-legacy-failure-model-'));
  try {
    const builder = fileURLToPath(new URL('./fixtures/windows-legacy/build-failure-model.ps1', import.meta.url));
    const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', builder, '-OutputDirectory', directory],
      { encoding: 'utf8', windowsHide: true, timeout: 20000 });
    assert.equal(build.status, 0, build.stderr);
    const result = spawnSync(join(directory, 'failure-model.exe'), [],
      { encoding: 'utf8', windowsHide: true, timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    const evidence = JSON.parse(result.stdout);
    assert.deepEqual(evidence, {
      diagnosticCollectionFaultPreserved: true, immutablePerOperation: true, concurrentOperations: 4,
      processQueries: 0, modeledIdentities: true,
    });
    if (process.env.MCP_LEGACY_TEST_EVIDENCE)
      writeFileSync(join(process.env.MCP_LEGACY_TEST_EVIDENCE, 'failure-model.json'), JSON.stringify(evidence));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('legacy cached selected-root creator-PID reuse skips only the older edge and retains strict refusals', WINDOWS, async () => {
  const evidence = await new CachedEdgeFixture().run();
  const cases = evidence.result.results;
  assert.equal(cases.length, 8);
  const root = cases.find(item => item.scenario === 'older-root');
  assert.equal(root.finitePlan, true);
  assert.equal(root.selectedCount, 3);
  assert.equal(root.excludedRoot, false);
  assert.equal(root.rootParentBirthUnchanged, true);
  assert.equal(root.revalidationSkippedOnlyEdge, true);
  assert.equal(root.stopped.legacyRootStopVerified, true);
  assert.equal(root.stopped.observedDescendantsStopped, true);
  for (const item of cases.filter(item => item.scenario !== 'older-root')) assert.ok(item.refused);
  const depth = cases.find(item => item.scenario === 'actual-eight-edge-chain');
  assert.equal(depth.modeledParentMetadata, false);
  assert.equal(depth.ownedGenerations, 9);
  assert.equal(depth.refused, 'Depth bound');
});

test('legacy protected-plan model enforces 512 combined identities and UTF8 byte bounds without process queries', WINDOWS, t => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-legacy-bounds-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const builder = fileURLToPath(new URL('./fixtures/windows-legacy/build-bounds-model.ps1', import.meta.url));
  const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', builder, '-OutputDirectory', directory],
    { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.equal(build.status, 0, build.stderr);
  const run = spawnSync(join(directory, 'bounds-model.exe'), [], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  const evidence = JSON.parse(run.stdout);
  assert.equal(evidence.processQueries, 0);
  assert.equal(evidence.processMutations, 0);
  assert.equal(evidence.results.length, 10);
  assert.equal(evidence.results.find(row => row.name === 'members-512').accepted, true);
  assert.equal(evidence.results.find(row => row.name === 'combined-513').accepted, false);
  assert.equal(evidence.results.find(row => row.name === 'utf8-plan-overflow').reason, 'Plan byte bound');
  assert.ok(Object.values(evidence.cache).every(value => value === true));
  if (process.env.MCP_LEGACY_TEST_EVIDENCE) {
    writeFileSync(join(process.env.MCP_LEGACY_TEST_EVIDENCE, 'protected-plan-bounds-model.json'), JSON.stringify(evidence, null, 2));
  }
});

test('legacy expected request refuses oversized UTF8 framing before native discovery', WINDOWS, async () => {
  await assert.rejects(prepareLegacyProcesses({
    port: 1, root: dirname(dirname(fileURLToPath(import.meta.url))),
    expected: { oversized: '中'.repeat(90000) },
  }), /request exceeded bounds/);
});

class ScriptPathFixture {
  async reject(t, spelling, affected) {
    const fixture = new LegacyFixture(t);
    const claimed = mkdtempSync(join(tmpdir(), 'mcp-legacy-claimed-'));
    t.after(() => rmSync(claimed, { recursive: true }));
    const script = affected === 'bridge' ? 'bin/mcp-bridge.mjs' : 'supervisor/supervise.ps1';
    const paths = {
      prepare: () => {
        mkdirSync(join(claimed, 'bin'));
        mkdirSync(join(claimed, 'supervisor'));
        for (const relative of ['bin/mcp-bridge.mjs', 'supervisor/supervise.ps1']) {
          const suffix = relative.endsWith('.mjs') ? '\n// Different claimed-root input\n' : '\n# Different claimed-root input\n';
          writeFileSync(join(claimed, relative), readFileSync(join(fixture.directory, relative), 'utf8') + suffix);
        }
        fixture.copyEvidence(claimed, join(fixture.directory, 'claimed-inputs'));
        const ambiguous = spelling === 'relative' ? script.replaceAll('/', '\\')
          : spelling === 'drive-relative' ? `${parse(fixture.directory).root.slice(0, 2)}${script.replaceAll('/', '\\')}`
            : join(fixture.directory, script).slice(2);
        paths.supervisorArgument = affected === 'supervisor' ? ambiguous : join(claimed, 'supervisor/supervise.ps1');
        paths.bridgeArgument = affected === 'bridge' ? ambiguous : join(claimed, 'bin/mcp-bridge.mjs');
      },
    };
    await fixture.start([], paths);
    const status = await fixture.request('/');
    const actual = affected === 'bridge' ? status.script
      : readFileSync(join(fixture.directory, 'actual-supervisor.txt'), 'utf8');
    assert.equal(resolve(actual).toLowerCase(), join(fixture.directory, script).toLowerCase(),
      'The target really executed the other directory, not the claimed root');
    const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
    const realDigest = digest(join(fixture.directory, script));
    const claimedDigest = digest(join(claimed, script));
    assert.notEqual(realDigest, claimedDigest);
    const cwd = process.cwd();
    let accepted;
    let refusal;
    try {
      process.chdir(claimed);
      try { accepted = await fixture.prepare(undefined, claimed); }
      catch (error) { refusal = error; }
    } finally { process.chdir(cwd); }
    fixture.results.push({
      spelling, affected, realDirectory: fixture.directory, brokerDirectory: claimed,
      realScriptSha256: realDigest, claimedScriptSha256: claimedDigest,
      acceptedWrongRoot: Boolean(accepted), acceptedPlan: accepted?.plan,
      refusal: refusal?.detail, stopInvoked: false,
    });
    assert.equal((await fixture.request('/')).pid, status.pid, 'Refusal must not stop either target');
    if (accepted) {
      assert.equal(accepted.plan.roots[affected].scriptSha256, claimedDigest,
        'RED must demonstrate hashing the claimed file, not the actual target script');
    }
    assert.ok(refusal, `Wrong root accepted for ${affected} ${spelling}; no stop was invoked`);
    assert.equal(refusal.detail?.reason, 'Script argument not fully qualified');
  }
}

for (const spelling of ['relative', 'drive-relative', 'root-relative']) {
  for (const affected of ['bridge', 'supervisor']) {
    test(`legacy script identity rejects ${affected} ${spelling} argv without stopping targets`, WINDOWS, async (t) => {
      await new ScriptPathFixture().reject(t, spelling, affected);
    });
  }
}

test('legacy script identity accepts fully qualified Unicode and space paths', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t, 'mcp-legacy qualified ü-').start();
  const session = await fixture.prepare();
  assert.equal(session.plan.root, fixture.directory);
  await session.close();
  assert.equal((await fixture.request('/')).pid, session.plan.roots.bridge.pid);
});

test('legacy script qualification recognizes drive and UNC forms without cwd resolution', WINDOWS, (t) => {
  const variant = mkdtempSync(join(tmpdir(), 'mcp-legacy-path-forms-'));
  t.after(() => rmSync(variant, { recursive: true }));
  const script = fileURLToPath(new URL('./fixtures/windows-legacy/build-variant.ps1', import.meta.url));
  const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-OutputDirectory', variant, '-Variant', 'path-forms'],
  { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.equal(build.error, undefined, build.stderr);
  assert.equal(build.status, 0, build.stderr);
  const helper = join(variant, 'windows-legacy/LegacyProcessBroker.exe');
  const cases = [
    ['C:\\space ü\\script.ps1', 'full'],
    ['c:/space ü/script.ps1', 'full'],
    ['\\\\server\\share\\script.ps1', 'full'],
    ['//SERVER/share/script.ps1', 'full'],
    ['script.ps1', 'ambiguous'],
    ['C:script.ps1', 'ambiguous'],
    ['\\script.ps1', 'ambiguous'],
    ['/script.ps1', 'ambiguous'],
    ['\\\\server', 'ambiguous'],
    ['\\\\server\\', 'ambiguous'],
    ['\\\\server\\\\script.ps1', 'ambiguous'],
    ['\\\\?\\C:\\script.ps1', 'ambiguous'],
    ['\\\\.\\C:\\script.ps1', 'ambiguous'],
  ];
  for (const [path, expected] of cases) {
    // Test-only Main calls just the native classifier: no TCP/WMI/file lookup,
    // UNC access, or process capture occurs for these syntax cases.
    const result = spawnSync(helper, [path], { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), expected, path);
  }
});

test('legacy script identity preserves fully qualified short-path handling', WINDOWS, async (t) => {
  const fixture = new LegacyFixture(t, 'mcp-legacy short path ü-');
  const script = fileURLToPath(new URL('./fixtures/windows-legacy/short-path.ps1', import.meta.url));
  const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script, '-Path', fixture.directory],
    { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(result.error, undefined, result.stderr);
  assert.equal(result.status, 0, result.stderr);
  const short = JSON.parse(result.stdout).path;
  if (short.toLowerCase() === fixture.directory.toLowerCase()) {
    t.skip('Owned volume does not expose an 8.3 alias; no filesystem policy changed');
    return;
  }
  await fixture.start([], { supervisorArgument: join(short, 'supervisor/supervise.ps1'),
    bridgeArgument: join(short, 'bin/mcp-bridge.mjs') });
  const session = await fixture.prepare();
  await session.close();
  assert.equal((await fixture.request('/')).pid, session.plan.roots.bridge.pid);
});

test('legacy script identity does not equate a junction spelling with a different canonical root', WINDOWS, async (t) => {
  const fixture = new LegacyFixture(t);
  const parent = mkdtempSync(join(tmpdir(), 'mcp-legacy-junction-'));
  const alias = join(parent, 'alias');
  symlinkSync(fixture.directory, alias, 'junction');
  t.after(() => {
    unlinkSync(alias);
    rmSync(parent, { recursive: true });
  });
  await fixture.start([], { supervisorArgument: join(alias, 'supervisor/supervise.ps1'),
    bridgeArgument: join(alias, 'bin/mcp-bridge.mjs') });
  const status = await fixture.request('/');
  await assert.rejects(fixture.prepare(undefined, alias),
    (error) => error.detail?.reason === 'Root arguments mismatch');
  assert.equal((await fixture.request('/')).pid, status.pid);
});

test('legacy broker captures held roots and stops only its observed set with partial receipt', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const child = await fixture.child();
  const session = await fixture.prepare();
  const plan = session.plan;
  assert.equal(plan.treeCompleteness, 'unproven');
  assert.ok(plan.observed.some((identity) => identity.pid === child.pid));
  assert.equal((await session.status()).legacyRootStopVerified, false);
  const before = await verifyLegacyProcessesGone(plan);
  assert.equal(before.legacyRootStopVerified, false);
  const result = await session.stop();
  fixture.results.push(result);
  assert.equal(result.legacyRootStopVerified, true);
  assert.equal(result.observedDescendantsStopped, true);
  assert.equal(result.treeCompleteness, 'unproven');
  assert.deepEqual(result.errors, []);
  assert.equal(Object.hasOwn(result, 'stopped'), false);
  assert.equal(Object.hasOwn(result, 'activeProcesses'), false);
  const after = await verifyLegacyProcessesGone(plan);
  fixture.results.push(after);
  assert.equal(after.legacyRootStopVerified, true);
  assert.equal(after.observedDescendantsStopped, true);
  await assert.rejects(session.stop(), /consumed/);
});

test('legacy broker close is read-only and an identical expected plan can be reopened', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const first = await fixture.prepare();
  const plan = structuredClone(first.plan);
  await first.close();
  assert.equal((await fixture.request('/')).pid, plan.roots.bridge.pid);
  const second = await fixture.prepare(plan);
  assert.deepEqual(second.plan, plan);
  const result = await second.stop();
  fixture.results.push(result);
  assert.equal(result.legacyRootStopVerified, true);
});

test('legacy broker preserves an already-exited captured descendant without adopting a replacement PID', WINDOWS, async t => {
  const fixture = await new LegacyFixture(t).start();
  const child = await fixture.child();
  const session = await fixture.prepare();
  const identity = session.plan.observed.find(value => value.pid === child.pid);
  assert.ok(identity);
  const ticks = String(BigInt(identity.creationTime) + 504911232000000000n);
  assert.equal(fixture.identity(identity.pid, ticks, true).gone, true);
  const receipt = await session.stop();
  fixture.results.push(receipt);
  assert.equal(receipt.legacyRootStopVerified, true);
  assert.equal(receipt.observedDescendantsStopped, true);
  assert.deepEqual(receipt.errors, []);
  assert.equal(receipt.treeCompleteness, 'unproven');
});

test('legacy broker rejects stale generation or expanded observed plan without stopping roots', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const first = await fixture.prepare();
  const stale = structuredClone(first.plan);
  await first.close();
  stale.roots.bridge.creationTime = String(BigInt(stale.roots.bridge.creationTime) + 1n);
  stale.planSha256 = null;
  stale.planSha256 = createHash('sha256').update(JSON.stringify(stale)).digest('hex');
  await assert.rejects(fixture.prepare(stale), (error) => error.detail?.stage === 'plan');
  assert.equal((await fixture.request('/')).pid, first.plan.roots.bridge.pid);
  const second = await fixture.prepare();
  await fixture.child();
  await assert.rejects(second.stop(), (error) => error.detail?.stage === 'revalidate');
  assert.equal((await fixture.request('/')).pid, first.plan.roots.bridge.pid);
});

test('legacy broker rejects wrong root and malformed protected verification plan', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const wrong = join(fixture.directory, 'wrong');
  mkdirSync(wrong);
  await assert.rejects(fixture.prepare(undefined, wrong), (error) => error.detail?.stage === 'capture-roots');
  const session = await fixture.prepare();
  const invalid = structuredClone(session.plan);
  invalid.planSha256 = '0'.repeat(64);
  await assert.rejects(verifyLegacyProcessesGone(invalid), (error) => error.detail?.type === 'ArgumentException');
  assert.equal((await fixture.request('/')).pid, session.plan.roots.bridge.pid);
});

test('legacy broker refuses extra supervisor argv and a foreign listener without process mutation', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start(['-UnexpectedArgument']);
  await assert.rejects(fixture.prepare(), (error) => error.detail?.stage === 'capture-roots');
  assert.equal((await fixture.request('/')).fixture, 'owned-legacy-broker');
  const server = http.createServer((request, response) => response.end('foreign-owned-control'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(prepareLegacyProcesses({ port: server.address().port, root: fixture.directory }),
      (error) => error.detail?.stage === 'capture-roots');
    assert.equal(server.listening, true);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('legacy read-only recovery does not stop an unrelated process reusing the endpoint', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const session = await fixture.prepare();
  const receipt = await session.stop();
  fixture.results.push(receipt);
  assert.equal(receipt.legacyRootStopVerified, true);
  const server = http.createServer((request, response) => response.end('foreign-owned-control'));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(fixture.port, '127.0.0.1', resolve);
  });
  try {
    const result = await verifyLegacyProcessesGone(session.plan);
    fixture.results.push(result);
    assert.equal(result.legacyRootStopVerified, true);
    assert.equal(result.observedDescendantsStopped, true);
    assert.equal(server.listening, true);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('legacy native inventory rejects changed executable, source and build metadata', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-legacy-assets-'));
  t.after(() => rmSync(directory, { recursive: true }));
  for (const path of LEGACY_BROKER_FILES) {
    const destination = join(directory, path);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(new URL(`../${path}`, import.meta.url), destination);
  }
  verifyLegacyBrokerAssets(directory);
  for (const path of ['bin/windows-legacy/LegacyProcessBroker.exe',
    'bin/windows-legacy/src/LegacyProcessBroker.cs', 'tools/windows-legacy/build.ps1']) {
    const original = readFileSync(join(directory, path));
    writeFileSync(join(directory, path), Buffer.concat([original, Buffer.from('changed')]));
    assert.throws(() => verifyLegacyBrokerAssets(directory));
    writeFileSync(join(directory, path), original);
  }
});

test('legacy prepare and recovery verify refuse wrong-hash packaged helper before any discovery', WINDOWS, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-legacy-assets-'));
  t.after(() => rmSync(directory, { recursive: true }));
  mkdirSync(join(directory, 'windows-legacy'));
  const module = join(directory, 'windows-legacy-process.mjs');
  copyFileSync(new URL('../bin/windows-legacy-process.mjs', import.meta.url), module);
  copyFileSync(new URL('../bin/windows-legacy/LegacyProcessBroker.build.json', import.meta.url),
    join(directory, 'windows-legacy/LegacyProcessBroker.build.json'));
  const bytes = readFileSync(new URL('../bin/windows-legacy/LegacyProcessBroker.exe', import.meta.url));
  writeFileSync(join(directory, 'windows-legacy/LegacyProcessBroker.exe'), Buffer.concat([bytes, Buffer.from('changed')]));
  const api = await import(pathToFileURL(module).href);
  await assert.rejects(api.prepareLegacyProcesses({ port: 1, root: directory }), /identity mismatch/);
  await assert.rejects(api.verifyLegacyProcessesGone({}), /identity mismatch/);
});

test('legacy broker parent loss releases read-only capture without stopping legacy roots', WINDOWS, async (t) => {
  const fixture = await new LegacyFixture(t).start();
  const host = fork(fileURLToPath(new URL('./fixtures/windows-legacy/broker-host.mjs', import.meta.url)), [], {
    execPath: process.execPath, execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true,
  });
  const parent = fixture.capture(host.pid);
  host.stderr.on('data', (chunk) => { fixture.output += chunk; });
  let brokerPid;
  let plan;
  let error;
  host.on('message', (message) => {
    if (message.type === 'broker') brokerPid = message.pid;
    if (message.type === 'plan') plan = message.plan;
    if (message.type === 'error') error = message.message;
  });
  host.send({ port: fixture.port, root: fixture.directory });
  await fixture.wait(() => plan || error);
  assert.equal(error, undefined);
  const broker = fixture.capture(brokerPid);
  assert.equal(fixture.identity(parent.pid, parent.creationTicks, true).gone, true);
  await fixture.wait(() => host.exitCode != null || host.signalCode != null);
  assert.equal(fixture.identity(broker.pid, broker.creationTicks).gone, true);
  assert.equal((await fixture.request('/')).pid, plan.roots.bridge.pid);
  // Capture the target set for verified fixture cleanup, not for production stop.
  await fixture.prepare();
});

test('legacy broker reports captured descendant termination failure without certifying stop', WINDOWS, async (t) => {
  const variant = mkdtempSync(join(tmpdir(), 'mcp-legacy-stop-fault-'));
  const fixture = new LegacyFixture(t);
  t.after(() => rmSync(variant, { recursive: true }));
  const script = fileURLToPath(new URL('./fixtures/windows-legacy/build-variant.ps1', import.meta.url));
  const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-OutputDirectory', variant, '-Variant', 'deny-observed-stop'],
  { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.equal(build.error, undefined, build.stderr);
  assert.equal(build.status, 0, build.stderr);
  const api = await import(pathToFileURL(join(variant, 'windows-legacy-process.mjs')).href);
  await fixture.start();
  const child = await fixture.child();
  const session = await fixture.prepare(undefined, fixture.directory, api.prepareLegacyProcesses);
  const result = await session.stop();
  fixture.results.push(result);
  assert.equal(result.legacyRootStopVerified, true);
  assert.equal(result.observedDescendantsStopped, false);
  assert.equal(result.treeCompleteness, 'unproven');
  assert.ok(result.errors.length > 0);
  assert.equal(fixture.identity(child.pid).gone, false, 'Fault leaves the captured worker alive until owned cleanup');
  assert.equal((await verifyLegacyProcessesGone(session.plan)).observedDescendantsStopped, false);
});

test('legacy broker preserves Unicode plan identity across fragmented UTF8 pipe messages', WINDOWS, async (t) => {
  const variant = mkdtempSync(join(tmpdir(), 'mcp-legacy-wire-'));
  const fixture = new LegacyFixture(t, 'mcp-legacy-ü-');
  t.after(() => rmSync(variant, { recursive: true }));
  const script = fileURLToPath(new URL('./fixtures/windows-legacy/build-variant.ps1', import.meta.url));
  const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-OutputDirectory', variant, '-Variant', 'fragmented-utf8'],
  { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.equal(build.error, undefined, build.stderr);
  assert.equal(build.status, 0, build.stderr);
  const api = await import(pathToFileURL(join(variant, 'windows-legacy-process.mjs')).href);
  await fixture.start();
  const session = await fixture.prepare(undefined, fixture.directory, api.prepareLegacyProcesses);
  assert.equal(session.plan.root, fixture.directory);
  assert.equal(session.plan.treeCompleteness, 'unproven');
  await session.close();
  assert.equal((await fixture.request('/')).pid, session.plan.roots.bridge.pid);
});

test('legacy broker excludes a proven older nonmember without terminating or verifying its exit', WINDOWS, async (t) => {
  const variant = mkdtempSync(join(tmpdir(), 'mcp-legacy-older-'));
  const fixture = new LegacyFixture(t);
  t.after(() => rmSync(variant, { recursive: true }));
  const script = fileURLToPath(new URL('./fixtures/windows-legacy/build-variant.ps1', import.meta.url));
  const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-OutputDirectory', variant, '-Variant', 'older-nonmember'],
  { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.equal(build.error, undefined, build.stderr);
  assert.equal(build.status, 0, build.stderr);
  const control = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 45000)'],
    { stdio: 'ignore', windowsHide: true });
  const identity = fixture.capture(control.pid);
  await fixture.start();
  const api = await import(pathToFileURL(join(variant, 'windows-legacy-process.mjs')).href);
  const keys = ['MCP_TEST_PARENT', 'MCP_TEST_OLDER_PID', 'MCP_TEST_OLDER_BIRTH'];
  const previous = keys.map((key) => process.env[key]);
  Object.assign(process.env, { MCP_TEST_PARENT: String(fixture.supervisor.pid),
    MCP_TEST_OLDER_PID: String(control.pid), MCP_TEST_OLDER_BIRTH: identity.creationFileTime });
  try {
    // Only discovery metadata is fault-injected to model the observed reused-parent
    // case. The older control's process handle, birth and continued liveness are real.
    const session = await fixture.prepare(undefined, fixture.directory, api.prepareLegacyProcesses);
    const excluded = session.plan.excluded.find((item) => item.pid === control.pid);
    assert.equal(excluded.reason, 'predates-held-parent');
    assert.equal(excluded.creationTime, identity.creationFileTime);
    assert.equal(session.plan.observed.some((item) => item.pid === control.pid), false);
    const result = await session.stop();
    fixture.results.push(result);
    assert.equal(result.legacyRootStopVerified, true);
    assert.equal(result.observedDescendantsStopped, true);
    assert.ok(result.excludedCount >= 1);
    assert.equal(fixture.identity(control.pid, identity.creationTicks).gone, false);
    const recovered = await verifyLegacyProcessesGone(session.plan);
    assert.equal(recovered.legacyRootStopVerified, true);
    assert.equal(recovered.observedDescendantsStopped, true);
    assert.equal(fixture.identity(control.pid, identity.creationTicks).gone, false);
  } finally {
    keys.forEach((key, index) => {
      if (previous[index] === undefined) delete process.env[key];
      else process.env[key] = previous[index];
    });
  }
});
