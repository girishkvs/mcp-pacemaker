// Regression test: a server that starts and then crashes must be reported.
//
// lastError was only set when the child failed to spawn (ENOENT). A server that launched and
// then exited non-zero — a wrapper resolved against the wrong working directory, for instance —
// left lastError empty, so /api/status and `doctor` looked healthy while every session died.
// That silence is actively misleading, so the exit code and the tail of stderr are recorded.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8814 and 8819.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const FIXTURE = resolve(__dirname, 'fixtures', 'crashing-mcp-server.mjs');
const PORT = 8814;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

const req2 = (port, method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

test('a server that starts then exits non-zero is reported with its stderr', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-crash-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ broken: { command: 'node', args: [FIXTURE] } }));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(PORT), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, MCP_INIT_TIMEOUT_MS: '4000' } });
  t.after(() => child.kill());

  for (let i = 0; i < 60; i++) {
    try { const s = await req('GET', '/status'); if (s.status === 200) break; } catch { /* wait */ }
    await sleep(100);
  }

  await req('POST', '/broken/mcp', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  });

  const nonce = readFileSync(join(tmp, 'admin.nonce'), 'utf8').trim();
  const status = await req('GET', '/api/status', { headers: { 'x-admin-nonce': nonce } });
  const server = JSON.parse(status.body).servers.find((s) => s.name === 'broken');

  assert.ok(server.lastError, 'a crashed server must not report a healthy status');
  assert.match(server.lastError, /exited code 1/);
  assert.match(server.lastError, /Cannot find module/, 'the reason from stderr should be included');
});

// taskkill /F reports exit code 1, so without distinguishing who killed the process every
// recycle, idle reap and session close would be reported as a crash. That noise is worse than
// no reporting: it buries the real failures.
test('a teardown the bridge initiated is not reported as a crash', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-kill-'));
  const cfg = join(tmp, 'servers.json');
  const HEALTHY = resolve(__dirname, 'fixtures', 'stubborn-mcp-server.mjs');
  writeFileSync(cfg, JSON.stringify({ fine: { command: 'node', args: [HEALTHY] } }));
  const child = spawn(process.execPath, [BRIDGE, '--port', '8819', '--config', cfg], { stdio: 'ignore' });
  t.after(() => child.kill());

  const at = (method, path, opts) => req2(8819, method, path, opts);
  for (let i = 0; i < 60; i++) {
    try { const s = await at('GET', '/status'); if (s.status === 200) break; } catch { /* wait */ }
    await sleep(100);
  }

  const init = await at('POST', '/fine/mcp', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established');

  const nonce = readFileSync(join(tmp, 'admin.nonce'), 'utf8').trim();
  await at('POST', '/admin/recycle/fine', { headers: { 'x-mcp-nonce': nonce } });
  await sleep(1500); // let the kill and the exit event land

  const status = await at('GET', '/api/status', { headers: { 'x-admin-nonce': nonce } });
  const server = JSON.parse(status.body).servers.find((s) => s.name === 'fine');
  assert.equal(server.lastError, undefined, `a recycle must not look like a crash, got: ${server.lastError}`);
});
