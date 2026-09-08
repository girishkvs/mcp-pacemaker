// This file owns port 8870; every bridge runs with its own disposable config.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { ServerMetrics } from '../bin/server-metrics.mjs';
import { killBridge } from './helpers/kill-bridge.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const port = 8870;
const echo = { command: process.execPath, args: [join(root, 'test', 'fixtures', 'echo-mcp-server.mjs')] };
const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };
const list = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

function request(method, path, body, headers = {}) {
  return new Promise((resolveRequest, reject) => {
    const req = http.request({
      hostname: '127.0.0.1', port, path, method, agent: false,
      headers: { 'content-type': 'application/json', ...headers },
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolveRequest({ status: res.statusCode, headers: res.headers, text }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(8000, () => req.destroy(new Error(`${method} ${path} timed out`)));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

async function eventually(read, predicate, message) {
  const deadline = Date.now() + 8000;
  let value;
  do {
    value = await read();
    if (predicate(value)) return value;
    await delay(30);
  } while (Date.now() < deadline);
  assert.fail(`${message}: ${JSON.stringify(value)}`);
}

async function boot(t, config) {
  const dir = mkdtempSync(join(tmpdir(), 'pacemaker-metrics-'));
  const cfg = join(dir, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [
    join(root, 'bin', 'mcp-bridge.mjs'), '--port', String(port), '--config', cfg,
  ], {
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...process.env, MCP_IDLE_TIMEOUT_MS: '0', MCP_RECYCLE_MINUTES: '0',
      MCP_HEALTH_INTERVAL_MS: '0', MCP_CONFIG_WATCH: '0',
      MCP_INIT_TIMEOUT_MS: '1000', MCP_REQUEST_TIMEOUT_MS: '1000',
    },
  });
  let output = '';
  child.stderr.on('data', (chunk) => { output += chunk; });
  const exited = once(child, 'exit');
  t.after(async () => {
    killBridge(child);
    await exited;
    rmSync(dir, { recursive: true, force: true });
  });
  await eventually(async () => {
    try {
      return (await request('GET', '/status')).status === 200;
    } catch (error) {
      if (error.code !== 'ECONNREFUSED') throw error;
      return false;
    }
  }, Boolean, 'bridge did not listen');
  const snapshot = async () => JSON.parse((await request('GET', '/api/status')).text);
  const metrics = async (name = 'echo') => (await snapshot()).servers.find((server) => server.name === name).spawn;
  return { snapshot, metrics, output: () => output, nonce: readFileSync(join(dir, 'admin.nonce'), 'utf8').trim() };
}

test('process totals outlive the bounded latency sample window', () => {
  const metrics = new ServerMetrics();
  for (let i = 1; i <= 75; i++) {
    metrics.attemptingSpawn('echo');
    metrics.spawned('echo');
    metrics.initialized('echo', i);
  }
  const snapshot = metrics.snapshot('echo');
  assert.equal(snapshot.total, 75);
  assert.equal(snapshot.attempts, 75);
  assert.equal(snapshot.samples, 50);
  assert.equal(snapshot.p50Ms, 51);
  assert.equal(snapshot.maxMs, 75);
  assert.equal(metrics.snapshot('unused').p50Ms, null);
});

test('a cold child is counted once, not once per request or sample', async (t) => {
  const bridge = await boot(t, { echo, remote: { type: 'http', url: 'http://127.0.0.1:1' } });
  const before = await bridge.snapshot();
  assert.equal(before.servers.find((server) => server.name === 'echo').spawn.total, 0);
  assert.equal(before.servers.find((server) => server.name === 'remote').spawn, null);
  assert.ok(before.instanceId);
  assert.ok(Number.isFinite(Date.parse(before.startedAt)));
  const init = await request('POST', '/echo/mcp', initialize);
  assert.ok(JSON.parse(init.text).result);
  const headers = { 'mcp-session-id': init.headers['mcp-session-id'] };
  for (let i = 0; i < 3; i++) {
    const reply = await request('POST', '/echo/mcp', list, headers);
    assert.ok(JSON.parse(reply.text).result);
  }
  const metrics = await bridge.metrics();
  assert.equal(metrics.total, 1);
  assert.equal(metrics.attempts, 1);
  assert.equal(metrics.samples, 1);
  assert.equal(metrics.sessionStarts, 1);
  assert.equal(metrics.sessionResumes, 0);
  assert.equal((await bridge.snapshot()).instanceId, before.instanceId);
});

test('warm starts and refills count, but adopting an existing child does not', async (t) => {
  const bridge = await boot(t, { echo: { ...echo, sharing: 'pool', minWarm: 1 } });
  await eventually(() => bridge.metrics(), (metrics) => metrics.total === 1, 'warm child did not start');
  const init = await request('POST', '/echo/mcp', initialize);
  assert.ok(JSON.parse(init.text).result);
  const metrics = await eventually(() => bridge.metrics(), (value) => value.total === 2, 'pool did not refill');
  assert.equal(metrics.attempts, 2);
  assert.equal(metrics.warmAdoptions, 1);
  assert.equal(metrics.sessionStarts, 1);
  assert.equal(metrics.samples, 0, 'warm idle time is not cold-start latency');
});

test('latency accounting does not crash on a tolerated null member in a legacy batch', async (t) => {
  // This peer tolerates the invalid member, isolating the bridge's post-response metrics path.
  const tolerant = {
    command: process.execPath,
    args: ['-e', `
      require('node:readline').createInterface({ input: process.stdin }).on('line', (line) => {
        const message = JSON.parse(line);
        if (message?.method === 'initialize') {
          process.stdout.write(JSON.stringify({
            jsonrpc: '2.0', id: message.id,
            result: { protocolVersion: '2025-03-26', capabilities: {}, serverInfo: { name: 'tolerant', version: '1' } }
          }) + '\\n');
        }
      });
    `],
  };
  const bridge = await boot(t, { echo: tolerant });
  const reply = await request('POST', '/echo/mcp', [null, initialize]);
  assert.equal(reply.status, 200);
  assert.ok(JSON.parse(reply.text).result);
  assert.equal((await bridge.metrics()).total, 1);
  assert.equal((await bridge.metrics()).samples, 1);
});

test('a recycled session replacement is counted as a spawn and a resume', async (t) => {
  const bridge = await boot(t, { echo });
  const init = await request('POST', '/echo/mcp', initialize);
  assert.ok(JSON.parse(init.text).result);
  const recycled = await request('POST', '/admin/recycle/echo', undefined, { 'x-mcp-nonce': bridge.nonce });
  assert.equal(recycled.status, 200);
  await eventually(bridge.snapshot, (snapshot) => snapshot.sessions === 0, 'old child did not exit');
  const reply = await request('POST', '/echo/mcp', list, { 'mcp-session-id': init.headers['mcp-session-id'] });
  assert.ok(JSON.parse(reply.text).result);
  const metrics = await bridge.metrics();
  assert.equal(metrics.total, 2);
  assert.equal(metrics.sessionStarts, 1);
  assert.equal(metrics.sessionResumes, 1);
});

test('a failed OS spawn is not counted as a started process', async (t) => {
  const bridge = await boot(t, { echo: { command: join(root, 'not-a-real-executable.exe') } });
  await request('POST', '/echo/mcp', initialize);
  const metrics = await bridge.metrics();
  assert.equal(metrics.attempts, 1);
  assert.equal(metrics.total, 0);
  assert.equal(metrics.failures, 1);
  assert.equal(metrics.samples, 0);
});

test('classic SSE children are included in process totals', async (t) => {
  const bridge = await boot(t, { echo });
  const req = http.get({ hostname: '127.0.0.1', port, path: '/echo/sse', agent: false });
  req.on('error', () => {});
  t.after(() => req.destroy());
  const [response] = await once(req, 'response');
  response.resume();
  const metrics = await eventually(() => bridge.metrics(), (value) => value.total === 1, 'classic child did not start');
  assert.equal(metrics.sessionStarts, 1);
  assert.equal(metrics.samples, 0);
  req.destroy();
});
