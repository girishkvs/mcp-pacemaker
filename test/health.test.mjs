// Regression tests: a server's reported health must reflect what is happening now.
//
// `lastError` is sticky and only ever accumulates, so it cannot distinguish "failing right now"
// from "failed once last week", and it never clears on recovery. A server here 401'd on every
// call for hours while the dashboard showed nothing wrong. These tests pin the three states
// apart — ok, failing, and the deliberately separate unknown — and pin that a server nobody has
// called is never reported healthy.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8840-8849 and 8851-8853
// and 8874 (8850 belongs to tui.test.mjs).
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { once } from 'node:events';
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

async function boot(port, cfg, env) {
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, MCP_CONFIG_WATCH: '0', ...env } });
  for (let i = 0; i < 80; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) return child; } catch { /* wait */ }
    await sleep(100);
  }
  killBridge(child);
  throw new Error(`bridge on ${port} did not start`);
}

function makeConfig(servers) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-health-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(servers));
  return { tmp, cfg };
}

async function health(port, name) {
  const r = await req(port, 'GET', '/api/status');
  return JSON.parse(r.body).servers.find((s) => s.name === name).health;
}

// An upstream whose behaviour a test can flip mid-run, to model a credential going bad.
function fakeUpstream(handler) {
  const srv = http.createServer(handler);
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res({ srv, port: srv.address().port })));
}

const rpc = { 'content-type': 'application/json' };
const initBody = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'health-test', version: '1' } },
});

test('a server nobody has called is "unknown", never "ok"', async (t) => {
  const { cfg } = makeConfig({ idle: { command: 'node', args: [FIXTURE] } });
  const port = 8840;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const h = await health(port, 'idle');
  assert.equal(h.state, 'unknown', 'no evidence must not be reported as healthy');
  assert.equal(h.lastSuccessSec, null);
});

test('a working stdio server reports ok once it answers', async (t) => {
  const { cfg } = makeConfig({ good: { command: 'node', args: [FIXTURE] } });
  const port = 8841;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/good/mcp', { headers: rpc, body: initBody });
  const h = await health(port, 'good');
  assert.equal(h.state, 'ok');
  assert.equal(h.consecutiveFailures, 0);
  assert.ok(h.lastSuccessSec != null, 'a success time is recorded');
});

test('peer-defined errors using bridge numeric codes still prove the server answered', async (t) => {
  const { cfg, tmp } = makeConfig({ peer: { command: process.execPath, args: [FIXTURE], maxSessions: 1 } });
  const port = 8874;
  const child = await boot(port, cfg, { MCP_QUEUE_TIMEOUT_MS: '0' });
  const exited = once(child, 'exit');
  t.after(async () => {
    killBridge(child);
    await exited;
    rmSync(tmp, { recursive: true, force: true });
  });
  const initialized = await req(port, 'POST', '/peer/mcp', { headers: rpc, body: initBody });
  const sid = initialized.headers['mcp-session-id'];
  for (const code of [-32000, -32001]) {
    assert.equal((await req(port, 'POST', '/peer/mcp', { headers: rpc, body: initBody })).status, 503);
    assert.equal((await health(port, 'peer')).state, 'failing');
    const response = await req(port, 'POST', '/peer/mcp', {
      headers: { ...rpc, 'mcp-session-id': sid },
      body: JSON.stringify({ jsonrpc: '2.0', id: code, method: 'test/error',
        params: { code, data: { kind: 'SHARED_REQUEST_TIMEOUT' } } }),
    });
    assert.equal(JSON.parse(response.body).error.code, code);
    assert.equal((await health(port, 'peer')).state, 'ok');
  }
});

test('a server whose credential goes bad reports failing, and counts the failures', async (t) => {
  let reject = false;
  const { srv, port: upstream } = await fakeUpstream((rq, rs) => {
    if (reject) { rs.writeHead(401, { 'www-authenticate': 'Bearer realm="x"' }).end('nope'); return; }
    rs.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }));
  });
  t.after(() => srv.close());

  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp`, headers: { authorization: 'Bearer test-credential' } } });
  const port = 8842;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  assert.equal((await health(port, 'remote')).state, 'ok');

  // The credential expires. This is the case that stayed invisible for hours.
  reject = true;
  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  const bad = await health(port, 'remote');
  assert.equal(bad.state, 'failing');
  assert.equal(bad.consecutiveFailures, 2, 'consecutive failures are counted, not just the last one');
});

test('health clears when a server recovers', async (t) => {
  let reject = true;
  const { srv, port: upstream } = await fakeUpstream((rq, rs) => {
    if (reject) { rs.writeHead(500).end('boom'); return; }
    rs.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }));
  });
  t.after(() => srv.close());

  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp` } });
  const port = 8843;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  assert.equal((await health(port, 'remote')).state, 'failing');

  reject = false;
  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  const ok = await health(port, 'remote');
  assert.equal(ok.state, 'ok', 'a recovered server must stop reporting the old error');
  assert.equal(ok.consecutiveFailures, 0);

  const snap = await req(port, 'GET', '/api/status');
  assert.equal(JSON.parse(snap.body).servers.find((s) => s.name === 'remote').lastError, null, 'the stale error text is cleared too');
});

test('an upstream error the client caused is not blamed on the server', async (t) => {
  const { srv, port: upstream } = await fakeUpstream((rq, rs) => rs.writeHead(404).end('no such tool'));
  t.after(() => srv.close());

  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp` } });
  const port = 8844;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  const h = await health(port, 'remote');
  assert.equal(h.state, 'unknown', 'a 404 says nothing about server health either way');
  assert.equal(h.consecutiveFailures, 0);
});

test('a server named after one of the bridge\'s own routes is reported, not silently ignored', async (t) => {
  // `/api` is answered by the bridge before it consults the server table, so this server can
  // never be reached. Nothing in the request path can report that — only a config check can.
  const { cfg } = makeConfig({ api: { command: 'node', args: [FIXTURE] }, fine: { command: 'node', args: [FIXTURE] } });
  const port = 8846;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const r = await req(port, 'GET', '/api/doctor');
  const checks = JSON.parse(r.body).checks;
  const bad = checks.find((c) => c.name === 'api');
  assert.equal(bad.status, 'bad', 'the shadowed server is flagged');
  assert.match(bad.detail, /reserved/);
  assert.equal(checks.find((c) => c.name === 'fine').status, 'ok', 'and normal servers are unaffected');
});

const listBody = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' });

test('a 401 on a server the CLIENT authenticates is a handshake, not a failure', async (t) => {
  // enghub is auth:{type:none}: the client signs in, the bridge only relays the challenge. Every
  // handshake starts with a 401, and counting those flipped a healthy server to "failing" for the
  // few seconds of every sign-in — which is most of what the live dashboard was showing.
  const { srv, port: upstream } = await fakeUpstream((rq, rs) =>
    rs.writeHead(401, { 'www-authenticate': 'Bearer resource_metadata="https://up/x"' }).end('sign in'));
  t.after(() => srv.close());

  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp`, auth: { type: 'none' } } });
  const port = 8847;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  const h = await health(port, 'remote');
  assert.equal(h.state, 'unknown', 'a relayed challenge says nothing about health');
  assert.equal(h.consecutiveFailures, 0, 'handshakes are not counted as failures');
});

test('a 401 on a server the BRIDGE authenticates is still a real failure', async (t) => {
  const { srv, port: upstream } = await fakeUpstream((rq, rs) =>
    rs.writeHead(401, { 'www-authenticate': 'Bearer realm="x"' }).end('expired'));
  t.after(() => srv.close());

  // headers make the bridge the authenticating party, so a 401 is the bridge's problem.
  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp`, headers: { authorization: 'Bearer stale' } } });
  const port = 8848;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/remote', { headers: rpc, body: initBody });
  const h = await health(port, 'remote');
  assert.equal(h.state, 'failing', 'the credential the bridge supplied was rejected');
  assert.match((await req(port, 'GET', '/api/status')).body, /rejected the credential from the configured authorization header/);
});

test('the bridge refusing a session counts as a failure', async (t) => {
  // The most client-visible failure the bridge produces is its own 503. It was invisible to
  // health, so a server that could not be reached at all still reported as fine.
  const { cfg } = makeConfig({ capped: { command: 'node', args: [FIXTURE], maxSessions: 1 } });
  const port = 8849;
  const child = await boot(port, cfg, { MCP_QUEUE_TIMEOUT_MS: '0' });
  t.after(() => killBridge(child));

  const first = await req(port, 'POST', '/capped/mcp', { headers: rpc, body: initBody });
  assert.equal(first.status, 200);
  const second = await req(port, 'POST', '/capped/mcp', { headers: rpc, body: initBody });
  assert.equal(second.status, 503, 'the cap is enforced');

  const h = await health(port, 'capped');
  assert.equal(h.state, 'failing');
  assert.match((await req(port, 'GET', '/api/status')).body, /bridge refused a session/);
});

test('sessions counted against the cap are reported separately from the display total', async (t) => {
  // `sessions` sums both transports but `maxSessions` only governs the streamable pool, which is
  // how a card came to read "33/32" without the cap ever being breached.
  const { cfg } = makeConfig({ dual: { command: 'node', args: [FIXTURE] } });
  const port = 8853;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  await req(port, 'POST', '/dual/mcp', { headers: rpc, body: initBody });
  const s = JSON.parse((await req(port, 'GET', '/api/status')).body).servers.find((x) => x.name === 'dual');
  assert.equal(s.cappedSessions, 1, 'the streamable pool is reported on its own');
  assert.ok(s.cappedSessions <= s.sessions, 'and it never exceeds the display total');
});


test('a fresh restart is reported so a wedged client can be spotted', async (t) => {
  const { cfg } = makeConfig({ echo: { command: 'node', args: [FIXTURE] } });
  const port = 8852;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const snap = JSON.parse((await req(port, 'GET', '/api/status')).body);
  assert.ok(snap.restart, 'a recently started bridge reports its restart');
  assert.ok(snap.restart.sinceSec >= 0);
  assert.equal(typeof snap.restart.staleClients, 'number');
});

test('probing gives an idle server a verdict without any client traffic', async (t) => {
  let hits = 0;
  const { srv, port: upstream } = await fakeUpstream((rq, rs) => {
    hits++;
    rs.writeHead(401, { 'www-authenticate': 'Bearer realm="x"' }).end('expired');
  });
  t.after(() => srv.close());

  // The bridge holds the credential here, so a 401 really is the credential having expired —
  // which is the overnight case probing exists to catch.
  const { cfg } = makeConfig({ remote: { type: 'http', url: `http://127.0.0.1:${upstream}/mcp`, headers: { authorization: 'Bearer stale' } } });
  const port = 8845;
  const child = await boot(port, cfg, { MCP_HEALTH_INTERVAL_MS: '1000' });
  t.after(() => killBridge(child));

  // No client ever calls this server; the probe alone must surface the broken credential.
  let h = null;
  for (let i = 0; i < 60; i++) {
    await sleep(250);
    h = await health(port, 'remote');
    if (h.state === 'failing') break;
  }
  assert.equal(h.state, 'failing', 'the probe found the 401 with no client involved');
  assert.ok(hits > 0, 'the upstream was actually probed');
});
