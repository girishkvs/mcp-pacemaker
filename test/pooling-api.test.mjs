// This file owns port 8871.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { killBridge } from './helpers/kill-bridge.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const port = 8871;
const echo = { command: process.execPath, args: [join(root, 'test', 'fixtures', 'echo-mcp-server.mjs')] };

class PoolingBridge {
  constructor(t, alpha = echo) {
    this.dir = mkdtempSync(join(tmpdir(), 'pacemaker-pooling-api-'));
    this.config = join(this.dir, 'servers.json');
    this.original = JSON.stringify({ alpha, beta: { ...echo, env: { PRIVATE_SENTINEL: 'must-not-leak' } }, remote: { type: 'http', url: 'http://127.0.0.1:1' } }, null, 2) + '\n';
    writeFileSync(this.config, this.original);
    this.child = spawn(process.execPath, [join(root, 'bin', 'mcp-bridge.mjs'), '--port', String(port), '--config', this.config], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: { ...process.env, MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0', MCP_IDLE_TIMEOUT_MS: '0', MCP_HEALTH_INTERVAL_MS: '0' },
    });
    this.stderr = '';
    this.child.stderr.on('data', (chunk) => { this.stderr += chunk; });
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
        const response = await this.request('GET', '/status');
        if (response.status === 200) {
          this.nonce = readFileSync(join(this.dir, 'admin.nonce'), 'utf8').trim();
          return;
        }
      } catch (error) {
        if (error.code !== 'ECONNREFUSED') throw error;
      }
      await delay(30);
    }
    throw new Error(`Bridge failed to start: ${this.stderr}`);
  }

  request(method, path, body, headers = {}) {
    return new Promise((resolveRequest, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port, method, path, agent: false,
        headers: { 'content-type': 'application/json', ...headers } }, (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolveRequest({ status: res.statusCode, headers: res.headers, text }));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(10000, () => req.destroy(new Error('Pooling API request timed out')));
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }

  async snapshot() {
    return JSON.parse((await this.request('GET', '/api/status')).text);
  }

  async change(body, name = 'alpha', headers = {}) {
    return this.request('POST', `/admin/servers/${encodeURIComponent(name)}/pooling`, body,
      { 'x-mcp-nonce': this.nonce, 'x-mcp-pooling-batch': '1', ...headers });
  }

  async reload() {
    const response = await this.request('POST', '/admin/reload', undefined, { 'x-mcp-nonce': this.nonce });
    assert.equal(response.status, 200, response.text);
    return JSON.parse(response.text);
  }
}

test('prewarm snapshot covers stdio eligibility without exposing command or environment data', async (t) => {
  const bridge = new PoolingBridge(t);
  await bridge.ready();
  const snapshot = await bridge.snapshot();
  assert.match(snapshot.prewarm.revision, /^[a-f0-9]{64}$/);
  assert.equal(snapshot.prewarm.maxWarm, 32);
  assert.equal(snapshot.servers.find((server) => server.name === 'alpha').prewarming.eligible, true);
  assert.equal(snapshot.servers.find((server) => server.name === 'remote').prewarming.eligible, false);
  assert.doesNotMatch(JSON.stringify(snapshot), /must-not-leak|PRIVATE_SENTINEL|echo-mcp-server/);
});

test('one-click apply and undo preserve active sessions even when file watching is off', async (t) => {
  const bridge = new PoolingBridge(t);
  await bridge.ready();
  const init = await bridge.request('POST', '/alpha/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  const before = await bridge.snapshot();
  const pid = before.servers.find((server) => server.name === 'alpha').pids[0];
  const applied = await bridge.change({ mode: 'pool', minWarm: 1, revision: before.prewarm.revision });
  assert.equal(applied.status, 202, applied.text);
  const result = JSON.parse(applied.text);
  assert.ok(result.undoId);
  assert.equal(readFileSync(bridge.config, 'utf8'), bridge.original);
  await bridge.reload();
  const after = await bridge.snapshot();
  const alpha = after.servers.find((server) => server.name === 'alpha');
  assert.equal(alpha.sharing, 'pool');
  assert.equal(alpha.minWarm, 1);
  assert.deepEqual(alpha.pids, [pid], 'changing warm slots must not recycle the active child');
  const call = await bridge.request('POST', '/alpha/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' }, { 'mcp-session-id': init.headers['mcp-session-id'] });
  assert.ok(JSON.parse(call.text).result);
  const undone = await bridge.change({ undoId: result.undoId, revision: after.prewarm.revision });
  assert.equal(undone.status, 202, undone.text);
  await bridge.reload();
  assert.equal(readFileSync(bridge.config, 'utf8'), bridge.original);
  assert.equal((await bridge.snapshot()).servers.find((server) => server.name === 'alpha').sharing, 'isolated');
});

test('admin mutation rejects missing nonce, foreign Origin, oversized bodies and extra fields', async (t) => {
  const bridge = new PoolingBridge(t);
  await bridge.ready();
  const revision = (await bridge.snapshot()).prewarm.revision;
  const body = { mode: 'pool', minWarm: 1, revision };
  assert.equal((await bridge.change(body, 'alpha', { 'x-mcp-nonce': '' })).status, 401);
  assert.equal((await bridge.change(body, 'alpha', { origin: 'https://untrusted.example' })).status, 403);
  assert.equal((await bridge.change({ ...body, padding: 'x'.repeat(5000) })).status, 413);
  assert.equal((await bridge.change({ ...body, command: 'do-not-execute' })).status, 400);
  assert.equal(readFileSync(bridge.config, 'utf8'), bridge.original);
});

test('concurrent edits batch together but stale edits and Undo cannot overwrite newer configuration', async (t) => {
  const bridge = new PoolingBridge(t);
  await bridge.ready();
  const revision = (await bridge.snapshot()).prewarm.revision;
  const replies = await Promise.all([
    bridge.change({ mode: 'pool', minWarm: 1, revision }, 'alpha'),
    bridge.change({ mode: 'pool', minWarm: 1, revision }, 'beta'),
  ]);
  assert.deepEqual(replies.map((reply) => reply.status).sort(), [202, 202]);
  const success = JSON.parse(replies[0].text);
  assert.equal(JSON.parse(replies[1].text).batchId, success.batchId);
  const reloaded = await bridge.reload();
  const stale = await bridge.change({ mode: 'isolated', revision });
  assert.equal(stale.status, 409);
  const edited = readFileSync(bridge.config, 'utf8') + '\n';
  writeFileSync(bridge.config, edited);
  const undone = await bridge.change({ undoId: success.undoId,
    revision: reloaded.snapshot.prewarm.revision }, success.name);
  assert.equal(undone.status, 409);
  assert.equal(readFileSync(bridge.config, 'utf8'), edited);
});

test('invalid sizes and HTTP targets do not change configuration', async (t) => {
  const bridge = new PoolingBridge(t);
  await bridge.ready();
  const revision = (await bridge.snapshot()).prewarm.revision;
  for (const minWarm of [0, -1, 33, 1.5, null, '2']) {
    assert.equal((await bridge.change({ mode: 'pool', minWarm, revision })).status, 400);
  }
  assert.equal((await bridge.change({ mode: 'pool', minWarm: 1, revision }, 'remote')).status, 400);
  assert.equal(readFileSync(bridge.config, 'utf8'), bridge.original);
});

test('undoing Disable with a legacy negative target cannot spin the bridge', async (t) => {
  const bridge = new PoolingBridge(t, { ...echo, sharing: 'pool', minWarm: -1 });
  await bridge.ready();
  const revision = (await bridge.snapshot()).prewarm.revision;
  const disabled = await bridge.change({ mode: 'isolated', revision });
  assert.equal(disabled.status, 202, disabled.text);
  const change = JSON.parse(disabled.text);
  const reloaded = await bridge.reload();
  const undone = await bridge.change({ undoId: change.undoId, revision: reloaded.snapshot.prewarm.revision });
  assert.equal(undone.status, 202, undone.text);
  await bridge.reload();
  assert.equal(readFileSync(bridge.config, 'utf8'), bridge.original);
  assert.equal((await bridge.snapshot()).servers.find((server) => server.name === 'alpha').warm, 0);
});
