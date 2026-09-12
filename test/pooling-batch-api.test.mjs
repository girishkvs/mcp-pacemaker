// This file owns port 8878.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { killBridge } from './helpers/kill-bridge.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PORT = 8878;

class BatchBridge {
  constructor(t) {
    this.dir = mkdtempSync(join(tmpdir(), 'pacemaker-batch-api-'));
    this.config = join(this.dir, 'servers.json');
    const definition = {
      command: process.execPath, args: [join(ROOT, 'test', 'fixtures', 'echo-mcp-server.mjs')],
      env: { PRIVATE_SENTINEL: 'batch-private-value' },
    };
    this.original = JSON.stringify({ alpha: definition, beta: definition }, null, 2) + '\n';
    writeFileSync(this.config, this.original);
    this.child = spawn(process.execPath, [join(ROOT, 'bin', 'mcp-bridge.mjs'),
      '--port', String(PORT), '--config', this.config], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: {
        ...process.env, MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0',
        MCP_IDLE_TIMEOUT_MS: '0', MCP_RESUME: '0', MCP_HEALTH_INTERVAL_MS: '0',
      },
    });
    this.stderr = '';
    this.child.stderr.on('data', (bytes) => { this.stderr = (this.stderr + bytes).slice(-4000); });
    this.exited = once(this.child, 'exit');
    t.after(async () => {
      killBridge(this.child);
      await this.exited;
      rmSync(this.dir, { recursive: true, force: true });
    });
  }

  async ready() {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      try {
        const result = await this.request('GET', '/api/status');
        assert.equal(result.status, 200);
        this.nonce = readFileSync(join(this.dir, 'admin.nonce'), 'utf8').trim();
        return;
      } catch (error) {
        if (error.cause?.code !== 'ECONNREFUSED') throw error;
        await delay(30);
      }
    }
    throw new Error(`Batch bridge did not start: ${this.stderr}`);
  }

  async request(method, path, body, headers = {}) {
    const response = await fetch(`http://127.0.0.1:${PORT}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(this.nonce ? { 'x-mcp-nonce': this.nonce } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const text = await response.text();
    return { status: response.status, text, body: JSON.parse(text) };
  }

  async snapshot() {
    return (await this.request('GET', '/api/status')).body;
  }

  async eventSnapshot() {
    const response = await fetch(`http://127.0.0.1:${PORT}/api/events`, {
      signal: AbortSignal.timeout(10000),
    });
    assert.equal(response.status, 200);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    try {
      while (!text.includes('\n\n')) {
        const { done, value } = await reader.read();
        assert.equal(done, false, 'SSE ended before its initial snapshot');
        text += decoder.decode(value, { stream: true });
      }
      const frame = text.slice(0, text.indexOf('\n\n'));
      assert.ok(frame.startsWith('data: '));
      return JSON.parse(frame.slice('data: '.length));
    } finally {
      await reader.cancel();
    }
  }

  async stage(name, minWarm) {
    const snapshot = await this.snapshot();
    return this.request('POST', `/admin/servers/${name}/pooling`, {
      revision: snapshot.prewarm.revision, mode: 'pool', minWarm,
    }, { 'x-mcp-pooling-batch': '1' });
  }

  async waitForStatus(id, status) {
    const deadline = Date.now() + 12000;
    do {
      const snapshot = await this.snapshot();
      const batch = snapshot.prewarm.batches?.find((item) => item.id === id);
      if (batch?.status === status) return { snapshot, batch };
      if (batch?.status === 'failed') throw new Error(batch.error);
      await delay(50);
    } while (Date.now() < deadline);
    throw new Error(`Batch did not reach ${status}`);
  }

  text() { return readFileSync(this.config, 'utf8'); }
}

test('batch API stages a complete copy and activates only after the five-second reload', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const before = await f.snapshot();
  const receipt = await f.stage('alpha', 2);
  assert.equal(receipt.status, 202, receipt.text);
  assert.equal(receipt.body.pending, true);
  assert.equal(receipt.body.revision, before.prewarm.revision);
  assert.ok(Number.isSafeInteger(before.snapshotVersion));
  assert.ok(before.snapshotVersion > 0);
  assert.ok(receipt.body.snapshot.snapshotVersion > before.snapshotVersion);
  const nextSnapshot = await f.snapshot();
  assert.ok(nextSnapshot.snapshotVersion > receipt.body.snapshot.snapshotVersion);
  assert.equal(f.text(), f.original);
  const pending = readFileSync(join(f.dir, 'servers.pending.json'), 'utf8');
  const expected = JSON.parse(f.original);
  expected.alpha.sharing = 'pool';
  expected.alpha.minWarm = 2;
  assert.deepEqual(JSON.parse(pending), expected);
  assert.equal(receipt.text.includes('batch-private-value'), false);
  assert.equal(receipt.body.snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
  await delay(1000);
  assert.equal(f.text(), f.original);
  const { snapshot } = await f.waitForStatus(receipt.body.batchId, 'applied');
  assert.deepEqual(JSON.parse(f.text()), expected);
  assert.equal(snapshot.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  assert.equal(readFileSync(join(f.dir, 'servers.previous.json'), 'utf8'), f.original);
});

test('a second server edit resets the delay and joins the same complete file batch', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const first = await f.stage('alpha', 2);
  assert.equal(first.status, 202, first.text);
  await delay(3000);
  const second = await f.stage('beta', 1);
  assert.equal(second.status, 202, second.text);
  assert.equal(second.body.batchId, first.body.batchId);
  await delay(3000);
  assert.equal(f.text(), f.original, 'The original first-edit deadline must not commit a later draft');
  const { snapshot, batch } = await f.waitForStatus(first.body.batchId, 'applied');
  assert.deepEqual(batch.changes.map((change) => change.name).sort(), ['alpha', 'beta']);
  assert.equal(snapshot.servers.find((server) => server.name === 'alpha').minWarm, 2);
  assert.equal(snapshot.servers.find((server) => server.name === 'beta').minWarm, 1);
  assert.equal(readFileSync(join(f.dir, 'servers.previous.json'), 'utf8'), f.original);
});

test('an older client cannot mistake a queued change for an immediate success', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const before = await f.snapshot();
  const result = await f.request('POST', '/admin/servers/alpha/pooling', {
    mode: 'pool', minWarm: 2, revision: before.prewarm.revision,
  });
  assert.ok(result.status >= 400, result.text);
  assert.equal(f.text(), f.original);
  assert.equal((await f.snapshot()).prewarm.batches?.some((batch) => batch.status === 'pending'), false);
});

test('Reload now flushes a staged batch without waiting for its timer', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const staged = await f.stage('alpha', 2);
  assert.equal(staged.status, 202, staged.text);
  const reloaded = await f.request('POST', '/admin/reload');
  assert.equal(reloaded.status, 200, reloaded.text);
  assert.equal(JSON.parse(f.text()).alpha.minWarm, 2);
  const { batch } = await f.waitForStatus(staged.body.batchId, 'applied');
  assert.equal(batch.status, 'applied');
  const previous = readFileSync(join(f.dir, 'servers.previous.json'), 'utf8');
  await delay(5200);
  assert.equal(readFileSync(join(f.dir, 'servers.previous.json'), 'utf8'), previous);
});

test('GET, SSE, accepted receipts and reload responses share one snapshot sequence', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const before = await f.snapshot();
  const firstEvent = await f.eventSnapshot();
  const staged = await f.stage('alpha', 2);
  assert.equal(staged.status, 202, staged.text);
  const accepted = staged.body.snapshot;
  const batch = accepted.prewarm.batches.find((record) => record.id === staged.body.batchId);
  assert.equal(accepted.prewarm.revision, staged.body.revision);
  assert.equal(batch.revision, staged.body.revision);
  assert.equal(batch.status, 'pending');
  const pendingEvent = await f.eventSnapshot();
  const reloaded = await f.request('POST', '/admin/reload');
  assert.equal(reloaded.status, 200, reloaded.text);
  const appliedEvent = await f.eventSnapshot();
  const after = await f.snapshot();
  const snapshots = [before, firstEvent, accepted, pendingEvent, reloaded.body.snapshot, appliedEvent, after];
  let previousVersion = 0;
  for (const snapshot of snapshots) {
    assert.equal(snapshot.instanceId, before.instanceId);
    assert.ok(Number.isSafeInteger(snapshot.snapshotVersion));
    assert.ok(snapshot.snapshotVersion > previousVersion);
    previousVersion = snapshot.snapshotVersion;
  }
  assert.equal(reloaded.body.snapshot.prewarm.batches.find((record) => record.id === batch.id).status, 'applied');
  assert.equal(batch.status, 'pending');
  assert.equal(accepted.prewarm.revision, before.prewarm.revision);
  assert.notEqual(after.prewarm.revision, before.prewarm.revision);
});

test('a pending batch can be cancelled without enabling any of its server changes', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const staged = await f.stage('alpha', 2);
  assert.equal(staged.status, 202, staged.text);
  const cancelled = await f.request('POST', '/admin/servers/alpha/pooling', {
    undoId: staged.body.undoId, revision: staged.body.revision,
  }, { 'x-mcp-pooling-batch': '1' });
  assert.equal(cancelled.status, 200, cancelled.text);
  assert.equal(cancelled.body.cancelled, true);
  await delay(5200);
  assert.equal(f.text(), f.original);
});

test('an external edit between staging and reload is not overwritten by the pending copy', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const staged = await f.stage('alpha', 2);
  assert.equal(staged.status, 202, staged.text);
  const edited = f.original + '\n';
  writeFileSync(f.config, edited);
  const reloaded = await f.request('POST', '/admin/reload');
  assert.ok(reloaded.status >= 400, reloaded.text);
  assert.equal(f.text(), edited);
  const batch = (await f.snapshot()).prewarm.batches.find((item) => item.id === staged.body.batchId);
  assert.equal(batch.status, 'failed');
  assert.equal(batch.commitState, 'not-committed');
});

test('reload validation returns safe structured 400 errors while read failures remain 500', async (t) => {
  const f = new BatchBridge(t);
  await f.ready();
  const before = await f.snapshot();
  const privateValue = 'reload-private-canary';
  const cases = [
    { text: `{"${privateValue}":`, code: 'INVALID_CONFIG_JSON', detail: 'invalid JSON' },
    { text: '[]', code: 'INVALID_CONFIG_ROOT', detail: 'top level' },
    { text: JSON.stringify({ [join(f.dir, privateValue)]: { args: [privateValue] } }),
      code: 'INVALID_SERVER_DEFINITION', detail: 'neither "command" nor "url"' },
  ];
  for (const entry of cases) {
    writeFileSync(f.config, entry.text);
    const result = await f.request('POST', '/admin/reload');
    assert.equal(result.status, 400, result.text);
    assert.equal(result.body.code, entry.code);
    assert.ok(result.body.error.includes(entry.detail));
    assert.equal(result.text.includes(privateValue), false);
    assert.equal(result.text.includes(f.dir), false);
    assert.equal(result.body.snapshot.prewarm.revision, before.prewarm.revision);
  }
  rmSync(f.config);
  const unreadable = await f.request('POST', '/admin/reload');
  assert.equal(unreadable.status, 500, unreadable.text);
  assert.equal(unreadable.body.code, 'CONFIG_READ_FAILED');
  assert.equal(unreadable.text.includes(f.config), false);
  assert.equal(unreadable.body.snapshot.prewarm.revision, before.prewarm.revision);
});
