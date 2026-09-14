import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync,
  renameSync, writeFileSync,
} from 'node:fs';
import { connect, createServer } from 'node:net';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  isolatedEnvironment, removeOwnedDirectory, run, sha256,
} from '../compatibility/fixtures.mjs';
import { inspectTarball, extractTarball } from '../npm-publication/tarball.mjs';
import {
  CompatibilityBridge, assertImmediate, assertPending, assertSnapshot, waitFor,
} from '../../test/compat/bridge.mjs';

const versions = { legacy: '1.3.1', current: '2.0.1' };
const auditUnavailable = 'Automatic pooling edits require readable audit policy so security can be preserved. No config data was written.';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function replacementOptions(args) {
  const values = {};
  const allowed = Object.keys(versions).flatMap((role) => [`--${role}-tarball`, `--${role}-sha256`]);
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    assert.ok(allowed.includes(key), `Unknown service-replacement option: ${key}`);
    assert.equal(Object.hasOwn(values, key), false, `Repeated service-replacement option: ${key}`);
    const value = args[++index];
    assert.ok(value &&
      !value.startsWith('--'), `Missing value for ${key}`);
    values[key] = value;
  }
  return Object.fromEntries(Object.entries(versions).map(([role, version]) => {
    const tarball = values[`--${role}-tarball`];
    assert.ok(tarball, `--${role}-tarball is required; source checkouts cannot substitute for artifacts`);
    assert.match(tarball, /\.tgz$/i, `--${role}-tarball must be a .tgz file`);
    const digest = values[`--${role}-sha256`];
    assert.match(digest ?? '', /^[a-f0-9]{64}$/i, `--${role}-sha256 requires 64 hexadecimal characters`);
    return [role, { tarball: resolve(tarball), sha256: digest.toLowerCase(), version }];
  }));
}

export function readArtifact(spec, version) {
  assert.equal(spec?.version, version, 'Only the exact selected patch artifact is supported');
  assert.match(spec.sha256, /^[a-f0-9]{64}$/);
  assert.match(spec.tarball, /\.tgz$/i);
  const stat = lstatSync(spec.tarball);
  assert.ok(stat.isFile() &&
    !stat.isSymbolicLink(), 'The artifact must be a regular .tgz file, not a directory or link');
  assert.ok(stat.size > 0 &&
    stat.size <= 32 * 1024 * 1024, 'Unexpected artifact size');
  const bytes = readFileSync(spec.tarball);
  assert.equal(hash(bytes), spec.sha256, 'Artifact SHA-256 mismatch');
  // Read metadata without extracting anything. gitHead is not a provenance claim here:
  // the caller-supplied digest binds this gate; source binding is a separate gate.
  const packed = JSON.parse(execFileSync('tar', ['-xzOf', '-', 'package/package.json'], {
    input: bytes, encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 20000, windowsHide: true,
  }));
  const approval = { version, commit: packed.gitHead };
  const inspection = inspectTarball(bytes, approval);
  for (const path of [
    'supervisor/supervise.mjs', 'supervisor/bridge-child.mjs', 'bin/service-control.mjs',
    'bin/pooling-writer.mjs', 'bin/windows/PoolingSecurityHelper.exe',
  ]) {
    assert.ok(inspection.files.some((file) => file.path === path &&
      file.size > 0), `Missing packed lifecycle/runtime file: ${path}`);
  }
  return { ...spec, bytes, approval, ...inspection };
}

export function assertReplacementState(state) {
  assert.equal(state.started, true, 'Replacement must exercise a previously running package');
  assert.equal(state.settled, true, 'Settle batches and transactions before replacement');
  assert.equal(state.stopped, true, 'A verified packaged stop receipt is required');
  assert.equal(state.held, true, 'A held supervisor launch must be verified before replacement');
  assert.equal(state.listenerOpen, false, 'Never replace a root while its listener is active');
  assert.ok(state.bridgePids.length > 0, 'Recorded bridge lifetime evidence is required');
  assert.deepEqual(state.livePids, [], 'Never replace a root while an owned process is alive');
}

export function replaceStoppedRoot(root, staged, retired, state) {
  assertReplacementState(state);
  renameSync(root, retired);
  renameSync(staged, root);
}

export function assertSettled(snapshot) {
  const batches = snapshot.prewarm.batches ?? [];
  for (const batch of batches) {
    assert.ok(['applied', 'cancelled'].includes(batch.status),
      `Unsettled or failed batch blocks replacement: ${JSON.stringify(batch)}`);
  }
}

function processAlive(pid) {
  assert.ok(Number.isSafeInteger(pid) &&
    pid > 0, 'Invalid recorded process ID');
  try { process.kill(pid, 0); return true; }
  catch (error) {
    if (error.code !== 'ESRCH') throw error;
    return false;
  }
}

function listenerAlive(port) {
  return new Promise((resolveProbe, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolveProbe(true); });
    socket.once('error', (error) => {
      if (error.code === 'ECONNREFUSED') resolveProbe(false);
      else reject(error);
    });
    socket.setTimeout(2000, () => socket.destroy(new Error('Owned listener probe timed out')));
  });
}

export function processRecords(path) {
  // Missing or corrupt observations are failures, not proof of an empty process tree.
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => {
    const record = JSON.parse(line);
    assert.ok(Number.isSafeInteger(record.pid) &&
      record.pid > 0 &&
      typeof record.entry === 'string' &&
      typeof record.worker === 'boolean', 'Invalid process observation');
    return record;
  });
}

export async function withCleanup(fixtures, action, report = console.error) {
  let result;
  let original;
  try { result = await action(); }
  catch (error) { original = error; }
  const failures = [];
  for (const fixture of fixtures) {
    try { await fixture.cleanup(); }
    catch (error) {
      failures.push(error);
      report(`Service-replacement cleanup failed: ${error.stack || error}`);
    }
  }
  if (original) throw original;
  if (failures.length) throw new AggregateError(failures, 'Shutdown unverified; owned fixtures retained');
  return result;
}

class ReplacementService extends CompatibilityBridge {
  constructor() {
    super();
    this.root = join(this.dir, 'install');
    this.env = isolatedEnvironment(this.dir);
    for (const key of Object.keys(this.env)) {
      if (/^(NODE_OPTIONS|NODE_PATH|NODE_AUTH_TOKEN|NPM_TOKEN|npm_config_.*)$/i.test(key)) delete this.env[key];
    }
    this.observer = join(this.dir, 'observe.mjs');
    copyFileSync(new URL('./observe.mjs', import.meta.url), this.observer);
    this.env.NODE_OPTIONS = `--import=${pathToFileURL(this.observer).href}`;
    const config = JSON.parse(this.original);
    config.alpha.sharing = 'pool';
    config.alpha.minWarm = 1;
    this.original = JSON.stringify(config, null, 2) + '\n';
    writeFileSync(this.config, this.original);
    this.children = [];
    this.observations = [];
    this.generation = 0;
    this.started = false;
    this.stopped = false;
    this.held = false;
    this.settled = false;
  }

  async install(artifact) {
    assert.equal(existsSync(this.root), false, 'Initial installation must not overwrite a root');
    mkdirSync(this.root);
    extractTarball(artifact.bytes, artifact.approval, this.root);
    await this.select(artifact);
  }

  async select(artifact) {
    this.artifact = artifact;
    this.control = await import(`${pathToFileURL(join(this.root, 'bin', 'service-control.mjs')).href}?sha256=${artifact.sha256}`);
    if (artifact.version === versions.current) {
      const module = await import(`${pathToFileURL(join(this.root, 'bin', 'pooling-files.mjs')).href}?sha256=${artifact.sha256}`);
      this.PoolingFiles = module.PoolingFiles;
    }
    this.paths = this.control.servicePaths(this.config, this.port);
  }

  async allocatePort() {
    const probe = createServer();
    await new Promise((resolveListen, reject) => {
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', resolveListen);
    });
    this.port = probe.address().port;
    await new Promise((resolveClose, reject) => probe.close((error) => error ? reject(error) : resolveClose()));
    this.base = `http://127.0.0.1:${this.port}`;
  }

  spawnSupervisor() {
    const child = spawn(process.execPath, [
      join(this.root, 'supervisor', 'supervise.mjs'), '--port', String(this.port), '--config', this.config,
    ], {
      cwd: this.dir, env: { ...this.env, MCP_REPLACEMENT_RECORD: this.recordFile },
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const running = { child, closed: false, stdout: '', stderr: '', version: this.artifact.version };
    this.children.push(running);
    this.logs.push(running);
    child.stdout.on('data', (bytes) => { running.stdout += bytes; });
    child.stderr.on('data', (bytes) => { running.stderr += bytes; });
    child.once('error', (error) => { running.error = error; });
    running.exit = new Promise((resolveExit) => child.once('close', (code, signal) => {
      running.closed = true;
      running.result = { code, signal };
      resolveExit(running.result);
    }));
    return running;
  }

  records() {
    return this.observations.flatMap(processRecords);
  }

  workers() {
    return processRecords(this.recordFile).filter((record) => record.worker &&
      record.kind === 'mcp-pooling-writer');
  }

  async start() {
    assert.equal(this.running, undefined, 'A supervisor is already selected');
    this.verifyPackage();
    const previousNonce = this.nonce;
    this.control.resumeService(this.config, this.port);
    this.recordFile = join(this.dir, `processes-${++this.generation}.jsonl`);
    writeFileSync(this.recordFile, '', { flag: 'wx' });
    this.observations.push(this.recordFile);
    this.stopped = false;
    this.held = false;
    this.settled = false;
    this.started = true;
    const running = this.spawnSupervisor();
    this.running = running;
    const snapshot = await waitFor(async () => {
      if (running.error) throw running.error;
      assert.equal(running.closed, false, `Supervisor exited during startup\n${running.stderr}`);
      try { return await this.snapshot(); }
      catch (error) {
        if (error.cause?.code !== 'ECONNREFUSED') throw error;
        return null;
      }
    }, Boolean, 'the real packaged bridge to start');
    assertSnapshot(snapshot, this.artifact.version);
    const record = this.control.validateServiceRecord(JSON.parse(readFileSync(this.paths.record, 'utf8')), this);
    assert.equal(record.pid, running.child.pid);
    assert.equal(record.version, this.artifact.version);
    assert.ok(processRecords(this.recordFile).some((item) => !item.worker &&
      item.entry === join(this.root, 'supervisor', 'bridge-child.mjs') &&
      processAlive(item.pid)), 'The actual packaged bridge PID must be observed');
    this.nonce = readFileSync(join(this.dir, 'admin.nonce'), 'utf8').trim();
    assert.ok(this.nonce);
    assert.notEqual(this.nonce, previousNonce, 'A replacement must issue a fresh backend nonce');
    assert.equal(this.text(), this.original);
    this.lastSnapshot = snapshot;
    return snapshot;
  }

  verifyPackage() {
    for (const file of this.artifact.files) {
      const path = join(this.root, file.path);
      const stat = lstatSync(path);
      assert.ok(stat.isFile() &&
        !stat.isSymbolicLink(), `Packed file was replaced by a link/non-file: ${file.path}`);
      assert.equal(sha256(path), file.sha256, `Installed bytes differ from the artifact: ${file.path}`);
    }
  }

  async uiBytes() {
    const files = this.artifact.files.filter((file) => file.path.startsWith('ui/dist/'));
    assert.ok(files.some((file) => file.path.startsWith('ui/dist/assets/') &&
      file.path.endsWith('.js')), 'Actual built dashboard assets are required');
    for (const file of files) {
      const relative = file.path.slice('ui/dist/'.length);
      let expected = readFileSync(join(this.root, file.path));
      assert.equal(hash(expected), file.sha256);
      if (relative.endsWith('.html')) expected = Buffer.from(expected.toString('utf8').replace('__MCP_NONCE__', this.nonce));
      const response = await fetch(`${this.base}/ui/${relative}`, { signal: AbortSignal.timeout(10000) });
      assert.equal(response.status, 200, `Missing packed UI file: ${relative}`);
      assert.equal(hash(Buffer.from(await response.arrayBuffer())), hash(expected), `Wrong UI generation: ${relative}`);
    }
    return { version: this.artifact.version, files: files.map(({ path, sha256: digest }) => ({ path, sha256: digest })) };
  }

  async heartbeat(instanceId) {
    const snapshot = await this.snapshot();
    assertSnapshot(snapshot, this.artifact.version);
    assert.equal(snapshot.instanceId, instanceId, 'The second service restarted or changed');
    const initialized = await this.request('POST', '/alpha/mcp', {
      jsonrpc: '2.0', id: 1, method: 'initialize', params: {},
    });
    assert.equal(initialized.status, 200, initialized.text);
    assert.ok(initialized.body.result);
    const headers = { 'mcp-session-id': initialized.headers.get('mcp-session-id') };
    assert.ok(headers['mcp-session-id']);
    const tools = await this.request('POST', '/alpha/mcp', {
      jsonrpc: '2.0', id: 2, method: 'tools/list', params: {},
    }, headers);
    assert.equal(tools.status, 200, tools.text);
    assert.ok(tools.body.result.tools.some((tool) => tool.name === 'ping'));
    const closed = await this.request('DELETE', '/alpha/mcp', undefined, headers);
    assert.ok(closed.status >= 200 &&
      closed.status < 300, closed.text);
    assert.equal((await this.snapshot()).instanceId, instanceId);
  }

  async stop() {
    if (!this.started) return;
    if (this.running) {
      const snapshot = await this.snapshot();
      if (this.lastSnapshot) {
        assert.equal(snapshot.instanceId, this.lastSnapshot.instanceId, 'The selected bridge restarted unexpectedly');
      }
      assertSettled(snapshot);
      this.settled = true;
      this.stopRecord = this.control.validateServiceRecord(JSON.parse(readFileSync(this.paths.record, 'utf8')), this);
      await this.control.stopManagedService({
        root: this.root, config: this.config, port: this.port,
      });
      await waitFor(() => this.running.closed, Boolean, 'the owned supervisor to close');
      assert.deepEqual(this.running.result, { code: 0, signal: null }, this.running.stderr);
      this.running = undefined;
      this.stopped = true;
    }
    await this.verifyStopped();
  }

  async verifyStopped() {
    const observed = this.records();
    const bridges = observed.filter((item) => !item.worker &&
      item.entry === join(this.root, 'supervisor', 'bridge-child.mjs'));
    assert.ok(bridges.length > 0, 'No bridge lifetime evidence; retain the installation root');
    const pids = [...new Set(observed.map((item) => item.pid))];
    await waitFor(async () => ({
      livePids: pids.filter(processAlive), listenerOpen: await listenerAlive(this.port),
    }), (state) => state.livePids.length === 0 &&
      state.listenerOpen === false, 'all observed owned PIDs to exit and the selected listener to close');
    for (const running of this.children) {
      assert.equal(running.closed, true, 'An owned supervisor has not closed');
    }
    const receipt = JSON.parse(readFileSync(this.paths.hold, 'utf8'));
    assert.deepEqual(receipt, {
      id: this.stopRecord.id, root: this.stopRecord.root, config: this.config, port: this.port, stopped: true,
    }, 'The completed hold must match the exact stopped service');
    this.verifySettlement();
    return { bridgePids: bridges.map((item) => item.pid), livePids: [], listenerOpen: false };
  }

  verifySettlement() {
    if (!existsSync(`${this.config}.pooling-transaction`)) return;
    assert.ok(this.PoolingFiles, 'Transaction state needs the actual 2.x reader before downgrade');
    const files = new this.PoolingFiles(this.config);
    // load() validates the journal without acquiring a lock, recovering or changing files.
    files.load();
    assert.equal(files.record?.phase, 'idle', 'An unresolved transaction blocks replacement');
    assert.equal(existsSync(files.lock), false, 'A transaction owner still holds the config');
    for (const key of ['pending', 'next', 'old']) {
      assert.equal(existsSync(files.paths[key]), false, `An unresolved ${key} file blocks replacement`);
    }
  }

  async heldLaunch() {
    await this.verifyStopped();
    const before = this.records().filter((item) => item.entry === join(this.root, 'supervisor', 'bridge-child.mjs')).length;
    const held = this.spawnSupervisor();
    await waitFor(() => {
      if (held.error) throw held.error;
      return held.closed;
    }, Boolean, 'the held autostart-equivalent launch to exit');
    assert.deepEqual(held.result, { code: 0, signal: null }, held.stderr);
    assert.match(held.stdout, /held stopped/);
    assert.equal(this.records().filter((item) => item.entry === join(this.root, 'supervisor', 'bridge-child.mjs')).length, before,
      'A held launch must not start another bridge');
    await this.verifyStopped();
    this.held = true;
  }

  async replace(artifact) {
    const proof = await this.verifyStopped();
    assertReplacementState({
      started: this.started, stopped: this.stopped, settled: this.settled, held: this.held, ...proof,
    });
    this.verifyPackage();
    const staged = join(this.dir, `staged-${this.generation}`);
    const retired = join(this.dir, `retired-${this.generation}`);
    mkdirSync(staged);
    extractTarball(artifact.bytes, artifact.approval, staged);
    // Recheck after extraction, immediately before touching the formerly running root.
    const refreshed = await this.verifyStopped();
    replaceStoppedRoot(this.root, staged, retired, {
      started: this.started, stopped: this.stopped, settled: this.settled, held: this.held, ...refreshed,
    });
    await this.select(artifact);
    this.verifyPackage();
    this.held = false;
    await this.heldLaunch();
  }

  async cleanup() {
    try {
      await this.stop();
      removeOwnedDirectory(this.owned);
    } catch (error) {
      for (const running of this.children) {
        running.child.stdout.destroy();
        running.child.stderr.destroy();
        running.child.unref();
      }
      throw new Error(`Retained owned service fixture ${this.dir}; ${error.message}\n${this.logs.map((log) =>
        `${log.version} supervisor ${log.child.pid}\n${log.stdout}\n${log.stderr}`).join('\n')}`, { cause: error });
    }
  }
}

function fileState(path) {
  const stat = lstatSync(path, { bigint: true });
  return Object.fromEntries(['dev', 'ino', 'birthtimeNs', 'mtimeNs', 'size', 'mode', 'uid', 'gid']
    .map((key) => [key, String(stat[key])]));
}

async function legacyWrite(service, baseline) {
  let scope = 'posix';
  if (process.platform === 'win32') {
    const output = await run(join(service.root, 'bin', 'windows', 'PoolingSecurityHelper.exe'), ['inspect'], {
      env: { ...service.env, MCP_POOL_SOURCE: service.config }, timeout: 10000,
    });
    assert.match(output.trim(), /^[FP]:/, 'The actual legacy helper must report audit visibility');
    scope = output.trim()[0];
  }
  const before = await service.snapshot();
  const identity = fileState(service.config);
  const response = await service.mutation({ mode: 'isolated' }, false);
  const expected = scope === 'P' ? 403 : 200;
  assert.equal(response.status, expected, response.text);
  if (expected === 403) {
    assert.equal(process.platform, 'win32');
    assert.deepEqual(response.body, { error: auditUnavailable });
    assert.equal(service.text(), service.original);
    assert.deepEqual(fileState(service.config), identity);
    assert.equal((await service.snapshot()).prewarm.revision, before.prewarm.revision);
  } else {
    assertImmediate(response.body, versions.legacy);
    assert.equal(JSON.parse(service.text()).alpha.sharing, 'isolated');
    const restored = await service.mutation({ undoId: response.body.undoId }, false);
    assert.equal(restored.status, 200, restored.text);
    assert.equal(restored.body.ok, true);
    assertSnapshot(restored.body.snapshot, versions.legacy);
    assert.equal(service.text(), service.original);
  }
  assert.ok(service.workers().length > 0, 'The legacy write/refusal must run its real lazy worker');
  const outcome = { scope, status: response.status, writeSupported: expected === 200 };
  if (baseline) assert.deepEqual(outcome, baseline, 'Legacy write support changed across the settled downgrade');
  return outcome;
}

async function currentWrite(service) {
  const changed = await service.mutation({ mode: 'isolated' });
  assert.equal(changed.status, 202, changed.text);
  assertPending(changed.body, versions.current);
  assert.equal(service.text(), service.original, 'Staging must not replace the active config');
  assert.ok(service.workers().length > 0, 'A real 2.x worker must service stageApply');
  const applied = await service.applied(changed.body.batchId);
  assert.equal(JSON.parse(service.text()).alpha.sharing, 'isolated');
  assert.equal(applied.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
  const restored = await service.mutation({ undoId: changed.body.undoId });
  assert.equal(restored.status, 202, restored.text);
  assertPending(restored.body, versions.current);
  assert.equal(JSON.parse(service.text()).alpha.sharing, 'isolated', 'Undo must stage before activation');
  const settled = await service.applied(restored.body.batchId);
  assertSettled(settled);
  assert.equal(service.text(), service.original, 'Whole-batch Undo must restore the exact active bytes');
  return { applyBatch: changed.body.batchId, undoBatch: restored.body.batchId, workerObserved: true };
}

export async function checkReplacement(options) {
  // Both exact artifacts must pass before any process or install/config fixture exists.
  const artifacts = Object.fromEntries(Object.entries(versions).map(([role, version]) =>
    [role, readArtifact(options[role], version)]));
  for (const path of ['bin/pooling-writer.mjs', 'bin/windows/PoolingSecurityHelper.exe']) {
    assert.notEqual(artifacts.legacy.files.find((file) => file.path === path).sha256,
      artifacts.current.files.find((file) => file.path === path).sha256, `Expected distinct major generations: ${path}`);
  }
  const fixtures = [];
  return withCleanup(fixtures, async () => {
    const create = async (artifact) => {
      const service = new ReplacementService();
      fixtures.push(service);
      await service.allocatePort();
      await service.install(artifact);
      return service;
    };
    const second = await create(artifacts.current);
    const secondSnapshot = await second.start();
    const heartbeat = () => second.heartbeat(secondSnapshot.instanceId);
    await heartbeat();
    const selected = await create(artifacts.legacy);
    assert.notEqual(selected.port, second.port);
    assert.notEqual(selected.root, second.root);
    let previous = await selected.start();
    const steps = [];
    const replace = async (role, timing) => {
      if (timing === 'before-first-write') assert.equal(selected.workers().length, 0, 'Cold case already started a writer');
      else assert.ok(selected.workers().length > 0, 'Loaded-worker case needs an actual worker');
      const from = selected.artifact.version;
      console.error(`[T32] ${from} -> ${artifacts[role].version}: ${timing}`);
      await selected.stop();
      await selected.heldLaunch();
      await heartbeat();
      await selected.replace(artifacts[role]);
      await heartbeat();
      const started = await selected.start();
      assert.notEqual(started.instanceId, previous.instanceId);
      assert.equal(selected.workers().length, 0, 'New backend must start with a fresh lazy writer');
      const ui = await selected.uiBytes();
      await heartbeat();
      steps.push({
        from, to: artifacts[role].version, timing, fromInstanceId: previous.instanceId,
        instanceId: started.instanceId, heldBeforeAndAfterReplacement: true, ui,
      });
      previous = started;
    };
    await replace('current', 'before-first-write');
    await replace('legacy', 'before-first-write');
    const legacyBefore = await legacyWrite(selected);
    await replace('current', 'after-worker-loaded');
    const currentWriteResult = await currentWrite(selected);
    await replace('legacy', 'after-worker-loaded');
    const legacyAfter = await legacyWrite(selected, legacyBefore);
    await heartbeat();
    for (const artifact of Object.values(artifacts)) {
      assert.equal(sha256(artifact.tarball), artifact.sha256, 'Input artifact changed during the gate');
    }
    return {
      gate: 'T32-service-replacement', node: process.version, platform: process.platform,
      artifacts: Object.fromEntries(Object.entries(artifacts).map(([role, artifact]) =>
        [role, { version: artifact.version, sha256: artifact.sha256 }])),
      steps, currentWrite: currentWriteResult, legacyBefore, legacyAfter,
      nativeHelper: {
        executed: process.platform === 'win32',
        sha256: Object.fromEntries(Object.entries(artifacts).map(([role, artifact]) =>
          [role, artifact.files.find((file) => file.path === 'bin/windows/PoolingSecurityHelper.exe').sha256])),
      },
      secondInstanceUnchanged: secondSnapshot.instanceId,
      limitations: [
        'Owned extracted packages, not npm dependency resolution or global-prefix shim validation.',
        'Managed hold launches, not real OS autostart registration or arbitrary old launchers.',
        'UI byte validation, not browser rendering; no unresolved-transaction downgrade.',
        'Native helper execution is Windows-only; a legacy audit-unavailable 403 is not a successful write.',
        'Caller-supplied artifact hashes, not independent source/provenance certification.',
      ],
    };
  });
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(await checkReplacement(replacementOptions(process.argv.slice(2))), null, 2));
}
