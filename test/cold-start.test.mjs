// Regression test: a slow cold start must not be cut off by the steady-state request timeout.
//
// `initialize` is the request that pays for spawning the server, and a first run can be slow
// (a package manager fetching the server before it can answer). Sharing one timeout with
// ordinary calls meant those servers returned -32001 "upstream timeout" and looked broken,
// while raising the timeout for every call would turn a genuine hang into a long stall.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8812-8813.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { killBridge } from './helpers/kill-bridge.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const FIXTURE = resolve(__dirname, 'fixtures', 'stubborn-mcp-server.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (port, method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

async function bootBridge(port, config, env) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-slow-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, ...env } });
  for (let i = 0; i < 60; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) return child; } catch { /* wait */ }
    await sleep(100);
  }
  killBridge(child);
  throw new Error(`bridge on ${port} did not start`);
}

// Answers `initialize` well after the steady-state timeout, but well within the init timeout.
const slowDef = { command: 'node', args: [FIXTURE, '--init-delay', '2000'] };
const initBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
const rpc = { 'content-type': 'application/json' };

test('a slow initialize is allowed to finish rather than timing out', async (t) => {
  const port = 8812;
  const child = await bootBridge(port, { slow: slowDef },
    { MCP_REQUEST_TIMEOUT_MS: '500', MCP_INIT_TIMEOUT_MS: '20000' });
  t.after(() => killBridge(child));

  const r = await req(port, 'POST', '/slow/mcp', { headers: rpc, body: initBody });
  assert.equal(r.status, 200);
  const msg = JSON.parse((r.body.match(/data: (.*)/) || [null, r.body])[1]);
  assert.ok(!msg.error, `initialize should not time out, got ${JSON.stringify(msg.error)}`);
  assert.equal(msg.result.serverInfo.name, 'stubborn');
});

test('the longer budget applies only to initialize, not to ordinary calls', async (t) => {
  const port = 8813;
  // The fixture answers initialize immediately here, and never answers `tools/list`, so an
  // ordinary call must hit the short steady-state timeout instead of the init budget.
  const child = await bootBridge(port, { slow: { command: 'node', args: [FIXTURE] } },
    { MCP_REQUEST_TIMEOUT_MS: '1000', MCP_INIT_TIMEOUT_MS: '60000' });
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/slow/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established');

  const started = Date.now();
  const r = await req(port, 'POST', '/slow/mcp', {
    headers: { ...rpc, 'mcp-session-id': sid },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'never/answer' }),
  });
  const elapsed = Date.now() - started;
  const msg = JSON.parse((r.body.match(/data: (.*)/) || [null, r.body])[1]);
  assert.equal(msg.error?.code, -32001, 'unanswered call should time out');
  assert.ok(elapsed < 10000, `should use the short budget, took ${elapsed}ms`);
});
