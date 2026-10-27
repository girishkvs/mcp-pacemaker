// Regression tests: only requests from this machine may use the bridge.
//
// The bridge checked Host and Origin only on its admin and pooling routes. Every other route,
// including tool calls and the HTTP proxy that adds the owner's credentials, answered any web page
// the user had open: a cross-site `text/plain` POST ran a tool without a CORS preflight, and DNS
// rebinding let a page read the replies. The MCP spec requires servers to check Origin.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8885.
import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { killBridge } from './helpers/kill-bridge.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const ECHO = resolve(__dirname, 'fixtures', 'echo-mcp-server.mjs');
const PORT = 8885;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const INITIALIZE = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'origin-test', version: '0.0.0' } } });
const JSON_HEADERS = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };

let bridge;
let upstream;
let logFile;
const upstreamSeen = [];

// Resolves with the status as soon as the headers arrive, so an SSE stream the gate wrongly let
// through fails the assertion instead of hanging the test.
const statusOf = (method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers, agent: false }, (resp) => {
      res(resp.statusCode);
      resp.destroy();
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

before(async () => {
  upstream = http.createServer((rq, rs) => {
    upstreamSeen.push(rq.headers.authorization ?? null);
    rs.writeHead(200, { 'content-type': 'application/json' });
    rs.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-origin-'));
  const cfg = join(tmp, 'servers.json');
  logFile = join(tmp, 'bridge.log');
  writeFileSync(cfg, JSON.stringify({
    echo: { command: 'node', args: [ECHO] },
    remote: { type: 'http', url: `http://127.0.0.1:${upstream.address().port}/mcp`, headers: { Authorization: 'Bearer test-owner-token' } },
  }));
  bridge = spawn(process.execPath, [BRIDGE, '--port', String(PORT), '--config', cfg], { stdio: 'ignore' });
  for (let i = 0; i < 100; i++) {
    try { if (await statusOf('GET', '/status') === 200) return; } catch { /* wait */ }
    await sleep(100);
  }
  throw new Error('bridge did not start');
});

after(() => {
  killBridge(bridge);
  upstream?.close();
});

test('a request for another host name is refused on every route, and logged once', { timeout: 30000 }, async () => {
  const routes = [
    ['GET', '/status'],
    ['GET', '/api/status'],
    ['GET', '/ui'],
    ['GET', '/echo/sse'],
    ['GET', '/.well-known/oauth-protected-resource/remote'],
    ['POST', '/echo/mcp', INITIALIZE],
    ['POST', '/remote/mcp', INITIALIZE],
  ];
  for (const host of [`evil.example:${PORT}`, `127.0.0.1.nip.io:${PORT}`, `localhost.evil.example:${PORT}`, '127.0.0.1:99999']) {
    for (const [method, path, body] of routes) {
      const status = await statusOf(method, path, { headers: { ...JSON_HEADERS, host }, body });
      assert.equal(status, 403, `${method} ${path} with Host ${host}`);
    }
  }
  assert.deepEqual(upstreamSeen, [], 'nothing may reach the upstream, least of all with the owner\'s token');

  // A real rebinding page sends its own name as Origin too, so the Host check has to win.
  const rebound = { host: `evil.example:${PORT}`, origin: `http://evil.example:${PORT}` };
  assert.equal(await statusOf('POST', '/echo/mcp', { headers: { ...JSON_HEADERS, ...rebound }, body: INITIALIZE }), 403);

  const refusals = readFileSync(logFile, 'utf8').split('\n').filter((line) => line.includes(' refused '));
  assert.equal(refusals.length, 1, refusals.join('\n'));
  assert.match(refusals[0], /refused GET \/status from Host evil\.example:8885, Origin none: not a local request/);
});

test('a page from another site cannot call a tool or reach the proxy', { timeout: 30000 }, async () => {
  const batch = `[${INITIALIZE},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}]`;
  const pages = [
    { origin: 'https://evil.example' },
    { origin: 'null' },
    { origin: 'http://localhost.evil.example' },
    { host: `192.0.2.1:${PORT}`, origin: `http://192.0.2.2:${PORT}` },
  ];
  for (const page of pages) {
    const headers = { 'content-type': 'text/plain', ...page };
    assert.equal(await statusOf('POST', '/echo/mcp', { headers, body: batch }), 403, JSON.stringify(page));
    assert.equal(await statusOf('POST', '/remote/mcp', { headers, body: INITIALIZE }), 403, JSON.stringify(page));
  }
  assert.deepEqual(upstreamSeen, []);
});

test('a cross-site request without an Origin is refused, except opening the dashboard from a link', { timeout: 30000 }, async () => {
  const fetchedBy = (mode, dest) => ({ 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': mode, 'sec-fetch-dest': dest });
  assert.equal(await statusOf('GET', '/echo/sse', { headers: fetchedBy('no-cors', 'image') }), 403);
  assert.equal(await statusOf('GET', '/echo/sse', { headers: fetchedBy('navigate', 'document') }), 403);
  assert.equal(await statusOf('GET', '/remote/mcp', { headers: fetchedBy('navigate', 'document') }), 403);
  assert.equal(await statusOf('GET', '/ui', { headers: fetchedBy('navigate', 'iframe') }), 403);
  assert.equal(await statusOf('GET', '/ui', { headers: fetchedBy('navigate', 'document') }), 200);
  assert.notEqual(await statusOf('GET', '/ui/assets/missing.js', { headers: fetchedBy('navigate', 'document') }), 403);
  assert.equal(await statusOf('GET', '/uix', { headers: fetchedBy('navigate', 'document') }), 403);
  assert.deepEqual(upstreamSeen, []);
});

test('local clients still work', { timeout: 30000 }, async () => {
  // MCP clients send no Origin. The dashboard sends its own, and local tools on another port pass.
  const clients = [
    {},
    { host: `localhost:${PORT}` },
    { host: `[::1]:${PORT}` },
    { origin: `http://127.0.0.1:${PORT}` },
    { host: `192.0.2.1:${PORT}`, origin: `http://192.0.2.1:${PORT}` },
    { origin: 'http://localhost:6274' },
    { origin: 'http://[::1]:6274' },
  ];
  for (const client of clients) {
    const status = await statusOf('POST', '/echo/mcp', { headers: { ...JSON_HEADERS, ...client }, body: INITIALIZE });
    assert.equal(status, 200, JSON.stringify(client));
  }
  assert.equal(await statusOf('POST', '/remote/mcp', { headers: JSON_HEADERS, body: INITIALIZE }), 200);
  assert.deepEqual(upstreamSeen, ['Bearer test-owner-token']);
});
