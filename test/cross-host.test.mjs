// Cross-host multi-agent test: three different MCP hosts (VS Code, Copilot CLI, Claude Code) open
// concurrent sessions on the SAME bridged server through ONE bridge; the bridge attributes each
// session to its host via clientInfo.name. Deterministic (echo fixture, no real CLIs) so it is
// CI-safe. The live claude+copilot cross-host connect is validated out-of-band (E2 live gate).
import { test } from 'node:test';
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
const PORT = 8807;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function req(method, path, { headers = {}, body } = {}) {
  return new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });
}
const initFor = (client) => req('POST', '/echo/mcp', {
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: client, version: '1.0.0' } } }),
});

test('cross-host: three hosts share one bridged server, each attributed by clientInfo', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ echo: { command: process.execPath, args: [FIXTURE] } }));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(PORT), '--config', cfg], { stdio: 'ignore' });
  t.after(() => { try { child.kill(); } catch { /* noop */ } });
  for (let i = 0; i < 60; i++) { try { if ((await req('GET', '/status')).status === 200) break; } catch { /* wait */ } await sleep(100); }

  const hosts = ['Visual Studio Code', 'GitHub Copilot', 'Claude Code'];
  const results = await Promise.all(hosts.map(initFor));
  for (const r of results) { assert.equal(r.status, 200); assert.ok(r.headers['mcp-session-id'], 'session id issued'); }
  const sids = results.map((r) => r.headers['mcp-session-id']);
  assert.equal(new Set(sids).size, 3, 'three distinct sessions');

  const snap = JSON.parse((await req('GET', '/api/status')).body);
  const echo = snap.servers.find((s) => s.name === 'echo');
  assert.equal(echo.sessions, 3, 'three concurrent sessions on one bridged server');
  for (const h of hosts) assert.ok(echo.clients.includes(h), `client "${h}" attributed on the shared server`);
  assert.equal(echo.pids.length, 3, 'isolated: one child process per session');
});
