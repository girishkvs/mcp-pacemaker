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
import { PoolingConfigWriter } from '../../bin/pooling-writer.mjs';

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
  constructor(t, stage, { controlledClock = false } = {}) {
    this.directory = fs.mkdtempSync(join(tmpdir(), 'pooling-deadline-'));
    this.config = join(this.directory, 'servers.json');
    this.original = '{"alpha":{"command":"node"},"beta":{"command":"node"}}\n';
    fs.writeFileSync(this.config, this.original);
    fs.writeFileSync(join(this.directory, 'stage'), stage);
    this.revision = createHash('sha256').update(this.original).digest('hex');
    this.clock = controlledClock ? new ExecutionClock() : undefined;
    const testClock = this.clock?.value.buffer;
    this.Worker = workerThreads.Worker;
    workerThreads.Worker = class extends this.Worker {
      constructor(filename, options) {
        super(filename, {
          ...options, execArgv: ['--import', hooks],
          workerData: testClock ? { ...options.workerData, poolingTestClock: testClock } : options.workerData,
        });
      }
    };
    syncBuiltinESMExports();
    this.writer = new PoolingConfigWriter(this.config);
    t.after(async () => {
      try {
        this.release();
        await this.writer.close();
        if (this.child) {
          killBridge(this.child);
          await this.exited;
        }
        t.diagnostic(`DEADLINE_PROOF ${JSON.stringify({ stage, events: this.events() })}`);
        fs.rmSync(this.directory, { recursive: true, force: true });
      } finally {
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

  record(event) {
    fs.appendFileSync(join(this.directory, 'events.jsonl'), JSON.stringify({ event, at: Date.now() }) + '\n');
  }

  disableHook() {
    fs.writeFileSync(join(this.directory, 'disable-hook'), 'disabled');
  }

  async entered() {
    const deadline = Date.now() + 4000;
    while (Date.now() < deadline) {
      if (fs.existsSync(join(this.directory, 'entered'))) return;
      await delay(10);
    }
    throw new Error('Test stage was not reached');
  }

  events() {
    const path = join(this.directory, 'events.jsonl');
    return fs.existsSync(path) ? fs.readFileSync(path, 'utf8').trim().split('\n').map(JSON.parse) : [];
  }

  unchanged() {
    assert.equal(fs.readFileSync(this.config, 'utf8'), this.original);
    assert.equal(fs.readdirSync(this.directory).some((name) => name.startsWith('.pooling-')), false);
  }

  async bridge() {
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

  http(method, path, body, bodyDelayMs = 0) {
    let request;
    const promise = new Promise((resolve, reject) => {
      request = http.request({ host: '127.0.0.1', port, path, method, agent: false,
        headers: { 'content-type': 'application/json', 'x-mcp-nonce': this.nonce ?? '' } }, (response) => {
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
    return { promise, request };
  }

  async settledLog() {
    const deadline = Date.now() + 4500;
    while (Date.now() < deadline) {
      const settled = this.stderr.includes('pooling action rejected') ||
        this.stderr.includes('pooling pool applied') ||
        this.stderr.includes('pooling isolated applied') ||
        this.stderr.includes('pooling undo applied') ||
        this.stderr.includes('pooling commit settled');
      if (settled) return;
      await delay(10);
    }
    throw new Error('Bridge mutation did not settle');
  }
}
