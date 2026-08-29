import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const FIXTURE = resolve(__dirname, 'fixtures', 'echo-mcp-server.mjs');
const PORT = 8793; // dedicated test port (not the default 8791)

let child;

function req(method, path, { headers = {}, body } = {}) {
  return new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (resp) => {
      let d = '';
      resp.on('data', (c) => (d += c));
      resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej);
    if (body) r.write(body);
    r.end();
  });
}

async function waitUp() {
  for (let i = 0; i < 50; i++) {
    try { const s = await req('GET', '/status'); if (s.status === 200) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('bridge did not start');
}

before(async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ echo: { command: process.execPath, args: [FIXTURE] } }));
  child = spawn(process.execPath, [BRIDGE, '--port', String(PORT), '--config', cfg], { stdio: 'ignore' });
  await waitUp();
});

after(() => { try { child.kill(); } catch { /* noop */ } });

test('GET /status lists configured servers', async () => {
  const s = await req('GET', '/status');
  assert.equal(s.status, 200);
  const j = JSON.parse(s.body);
  assert.equal(j.ok, true);
  assert.equal(j.service, 'mcp-pacemaker');
  assert.deepEqual(j.servers, ['echo']);
});

test('Streamable HTTP: initialize returns a session id + result, session is reusable', async () => {
  const r = await req('POST', '/echo/mcp', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  });
  assert.equal(r.status, 200);
  const sid = r.headers['mcp-session-id'];
  assert.ok(sid, 'expected Mcp-Session-Id header');
  assert.equal(JSON.parse(r.body).result.serverInfo.name, 'echo');

  const r2 = await req('POST', '/echo/mcp', {
    headers: { 'content-type': 'application/json', 'mcp-session-id': sid },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
  });
  assert.equal(r2.status, 200);
  assert.equal(JSON.parse(r2.body).result.tools[0].name, 'ping');
});

test('Streamable HTTP: POST without a session (non-initialize) is rejected', async () => {
  const r = await req('POST', '/echo/mcp', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list' }),
  });
  assert.equal(r.status, 404);
});

test('unknown server 404s', async () => {
  const r = await req('GET', '/nope/sse');
  assert.equal(r.status, 404);
});
