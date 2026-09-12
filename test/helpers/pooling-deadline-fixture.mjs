import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import http from 'node:http';
import workerThreads from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';
import { killBridge } from './kill-bridge.mjs';
import { PoolingCheckpoint, PoolingFixtureGuard, FIXTURE_DEADLOCK_MS } from './pooling-checkpoint.mjs';
import { PoolingConfigWriter } from '../../bin/pooling-writer.mjs';
import { PoolingFiles, recoverPoolingConfig } from '../../bin/pooling-files.mjs';

const port = 8875;
const hooks = new URL('./pooling-worker-hooks.mjs', import.meta.url).href;
const bridgePath = fileURLToPath(new URL('../../bin/mcp-bridge.mjs', import.meta.url));

class ExecutionClock {
  constructor() {
    this.value = new BigInt64Array(new SharedArrayBuffer(8));
    this.readTime = process.hrtime.bigint;
    this.setTimeout = global.setTimeout;
    this.clearTimeout = global.clearTimeout;
    this.pending = new Map();
    Atomics.store(this.value, 0, this.readTime());
    process.hrtime.bigint = () => Atomics.load(this.value, 0);
    global.setTimeout = (callback, milliseconds, ...args) => {
      const timer = {};
      this.pending.set(timer, {
        deadline: process.hrtime.bigint() + BigInt(Math.ceil(milliseconds)) * 1000000n,
        callback: () => callback(...args),
      });
      return timer;
    };
    global.clearTimeout = (timer) => {
      if (!this.pending.delete(timer)) this.clearTimeout(timer);
    };
  }

  advance(milliseconds, runTimers = true) {
    Atomics.add(this.value, 0, BigInt(milliseconds) * 1000000n);
    if (runTimers) this.runTimers();
  }

  runTimers() {
    for (const [timer, operation] of this.pending) {
      if (operation.deadline > process.hrtime.bigint()) continue;
      this.pending.delete(timer);
      operation.callback();
    }
  }

  restore() {
    process.hrtime.bigint = this.readTime;
    global.setTimeout = this.setTimeout;
    global.clearTimeout = this.clearTimeout;
    this.pending.clear();
  }
}

export class DeadlineFixture {
  constructor(t, stage, { controlledClock = false, guardMs = FIXTURE_DEADLOCK_MS } = {}) {
    this.directory = fs.mkdtempSync(join(tmpdir(), 'pooling-deadline-'));
    this.config = join(this.directory, 'servers.json');
    this.stage = stage;
    this.original = '{"alpha":{"command":"node"},"beta":{"command":"node"}}\n';
    fs.writeFileSync(this.config, this.original);
    fs.writeFileSync(join(this.directory, 'stage'), stage);
    this.revision = createHash('sha256').update(this.original).digest('hex');
    // Bound fixture deadlocks independently of the controlled operation clock.
    this.guard = new PoolingFixtureGuard(stage, guardMs);
    this.checkpoint = new PoolingCheckpoint(this.directory, stage,
      AbortSignal.any([t.signal, this.guard.signal]));
    this.clock = controlledClock ? new ExecutionClock() : undefined;
    const testClock = this.clock?.value.buffer;
    const recordWorkerError = (error) => this.record('worker-error', { message: error.stack });
    const workers = this.workers = new Set();
    this.Worker = workerThreads.Worker;
    workerThreads.Worker = class extends this.Worker {
      constructor(filename, options) {
        super(filename, {
          ...options, execArgv: ['--import', hooks],
          workerData: testClock ? { ...options.workerData, poolingTestClock: testClock } : options.workerData,
        });
        workers.add(this);
        this.once('exit', () => workers.delete(this));
        this.on('error', recordWorkerError);
      }
    };
    syncBuiltinESMExports();
    this.writer = new PoolingConfigWriter(this.config);
    for (const name of ['apply', 'undo', 'stageApply', 'stageUndo', 'commitBatch', 'rejectStage', 'close']) {
      const operation = this.writer[name].bind(this.writer);
      this.writer[name] = (...args) => this.guard.wait(operation(...args));
    }
    t.after(async () => {
      try {
        this.release();
        const outcomes = await Promise.allSettled([
          this.guard.wait(Promise.resolve().then(() => this.writer.close())),
          this.guard.wait(Promise.resolve().then(() => this.stopBridge())),
        ]);
        const failures = outcomes.filter((outcome) => outcome.status === 'rejected')
          .map((outcome) => outcome.reason);
        if (failures.length) {
          await Promise.all([...this.workers].map((worker) => worker.terminate()));
        }
        const events = this.events();
        t.diagnostic(`DEADLINE_PROOF ${JSON.stringify({
          stage,
          helpers: events.filter((event) => event.event === 'helper').length,
          commands: [...new Set(events.filter((event) => event.event === 'helper').map((event) => event.kind))],
          events: events.filter((event) => !['operation-start',
            'journal-saved', 'last-preflight'].includes(event.event)),
        })}`);
        fs.rmSync(this.directory, { recursive: true, force: true });
        if (failures.length) throw new AggregateError(failures, 'Fixture completion or teardown failed');
      } finally {
        this.guard.dispose();
        this.clock?.restore();
        workerThreads.Worker = this.Worker;
        syncBuiltinESMExports();
      }
    });
  }

  request(mode = 'pool') {
    return { name: 'alpha', mode, revision: this.revision };
  }

  limit(milliseconds) {
    return process.hrtime.bigint() + BigInt(milliseconds) * 1000000n;
  }

  release() {
    fs.writeFileSync(join(this.directory, 'release'), 'release');
  }

  abandon(controller) {
    this.record('caller-abandoned');
    controller.abort();
  }

  record(event, extra = {}) {
    fs.appendFileSync(join(this.directory, 'events.jsonl'),
      JSON.stringify({ event, at: Date.now(), ...extra }) + '\n');
  }

  disableHook() {
    fs.writeFileSync(join(this.directory, 'disable-hook'), 'disabled');
  }

  enableHook() {
    fs.unlinkSync(join(this.directory, 'disable-hook'));
  }

  async entered(operation) {
    await this.checkpoint.wait(operation);
    this.record('checkpoint-observed', { stage: this.stage });
  }

  events() {
    const path = join(this.directory, 'events.jsonl');
    return fs.existsSync(path) ? fs.readFileSync(path, 'utf8').trim().split('\n').map(JSON.parse) : [];
  }

  unchanged() {
    assert.equal(fs.readFileSync(this.config, 'utf8'), this.original);
    this.cleanDrafts();
  }

  cleanDrafts() {
    for (const name of ['servers.pending.json', 'servers.pending-next.json', 'servers.pending-old.json']) {
      assert.equal(fs.existsSync(join(this.directory, name)), false, name);
    }
    assert.equal(fs.existsSync(`${this.config}.bak`), false);
    this.boundedJournal();
  }

  boundedJournal() {
    const directory = `${this.config}.pooling-transaction`;
    if (!fs.existsSync(directory)) return;
    const names = fs.readdirSync(directory).filter((name) => name !== 'owner');
    assert.ok(names.length <= 2);
    for (const name of names) {
      assert.ok(name.startsWith('state-') && name.endsWith('.json'));
      assert.ok(fs.statSync(join(directory, name)).size <= 16384);
    }
  }

  pending() {
    assert.equal(fs.readFileSync(this.config, 'utf8'), this.original);
    const path = join(this.directory, 'servers.pending.json');
    const candidate = JSON.parse(fs.readFileSync(path, 'utf8'));
    assert.deepEqual(candidate, { alpha: { command: 'node', sharing: 'pool', minWarm: 1 },
      beta: { command: 'node' } });
    const staged = this.events().findLast((event) => event.event === 'stage-complete');
    const inspected = new PoolingFiles(this.config).inspect(path);
    // Check the native stage's returned descriptor, not a full source security
    // clone: supported owner normalization can change that fingerprint.
    assert.deepEqual(inspected, {
      identity: staged.identity, revision: staged.revision, security: staged.security, size: staged.size,
    });
    this.boundedJournal();
  }

  committed() {
    const current = JSON.parse(fs.readFileSync(this.config, 'utf8'));
    assert.deepEqual(current, { alpha: { command: 'node', sharing: 'pool', minWarm: 1 },
      beta: { command: 'node' } });
    assert.equal(fs.readFileSync(join(this.directory, 'servers.previous.json'), 'utf8'), this.original);
    this.cleanDrafts();
  }

  async recoverUnchanged() {
    await this.writer.close();
    await this.stopBridge();
    const result = recoverPoolingConfig(this.config);
    this.record('explicit-recovery', result);
    assert.ok(['none', 'discarded'].includes(result.outcome));
    this.unchanged();
  }

  async stopBridge() {
    if (!this.child) return;
    killBridge(this.child);
    await this.exited;
    this.child = undefined;
  }

  async bridge({ controlledClock = false } = {}) {
    if (controlledClock) fs.writeFileSync(join(this.directory, 'bridge-clock'), 'enabled');
    this.child = spawn(process.execPath, [
      '--import', hooks, bridgePath, '--port', String(port), '--config', this.config,
    ], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: { ...process.env, MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0',
        MCP_IDLE_TIMEOUT_MS: '0', MCP_HEALTH_INTERVAL_MS: '0' },
    });
    this.stderr = '';
    this.child.stderr.on('data', (bytes) => { this.stderr += bytes; });
    this.exited = once(this.child, 'exit');
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      try {
        await this.http('GET', '/api/status').promise;
        this.nonce = fs.readFileSync(join(this.directory, 'admin.nonce'), 'utf8').trim();
        return;
      } catch (error) {
        if (error.code !== 'ECONNREFUSED') throw error;
      }
      await delay(20);
    }
    throw new Error(`Bridge startup failed: ${this.stderr}`);
  }

  advanceBridgeClock(milliseconds) {
    fs.writeFileSync(join(this.directory, 'advance-clock'), String(milliseconds));
  }

  async stageForReload() {
    this.disableHook();
    const snapshot = (await this.http('GET', '/api/status').promise).body;
    const response = await this.http('POST', '/admin/servers/alpha/pooling',
      { mode: 'pool', minWarm: 1, revision: snapshot.prewarm.revision }).promise;
    assert.equal(response.status, 202);
    assert.equal(response.body.pending, true);
    assert.equal(response.body.revision, this.revision);
    assert.equal(response.body.snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
    assert.equal(response.body.snapshot.prewarm.batches.find((batch) => batch.id === response.body.batchId).status,
      'pending');
    this.pending();
    this.enableHook();
    return response.body;
  }

  http(method, path, body, bodyDelayMs = 0) {
    let request;
    const promise = new Promise((resolve, reject) => {
      request = http.request({ host: '127.0.0.1', port, path, method, agent: false,
        headers: { 'content-type': 'application/json', 'x-mcp-nonce': this.nonce ?? '',
          'x-mcp-pooling-batch': '1' } }, (response) => {
        let text = '';
        response.on('data', (bytes) => { text += bytes; });
        response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(text) }));
        response.on('error', reject);
      });
      request.on('error', reject);
      request.setTimeout(10000, () => request.destroy(new Error('Test HTTP deadline')));
      const send = () => request.end(body === undefined ? undefined : JSON.stringify(body));
      if (bodyDelayMs === -1) {
        request.flushHeaders();
      } else if (bodyDelayMs) {
        request.flushHeaders();
        setTimeout(send, bodyDelayMs);
      } else {
        send();
      }
    });
    return { promise: this.guard.wait(promise), request };
  }

  async settledLog() {
    const deadline = Date.now() + 4500;
    while (Date.now() < deadline) {
      if (this.stderr.includes('pooling action rejected')) return;
      await delay(10);
    }
    throw new Error('Bridge mutation did not settle');
  }

  async batchSettled(batchId) {
    const deadline = Date.now() + 4500;
    while (Date.now() < deadline) {
      const snapshot = (await this.http('GET', '/api/status').promise).body;
      const batch = snapshot.prewarm.batches.find((entry) => entry.id === batchId);
      if (['applied', 'failed'].includes(batch?.status)) return { snapshot, batch };
      await delay(10);
    }
    throw new Error('Bridge batch did not settle');
  }
}
