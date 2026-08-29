// Bridge resource-control tests: keep-warm pool (sharing:'pool'), per-server maxSessions cap,
// and the opt-in idle reaper (MCP_IDLE_TIMEOUT_MS). Deterministic — uses local fixtures, no
// network. Each test boots its own bridge on a dedicated port (never 8791/8793/8798).
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
const STUBBORN = resolve(__dirname, 'fixtures', 'stubborn-mcp-server.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const reqTo = (port) => (method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

async function bootBridge(port, config, env = {}) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg], { stdio: 'ignore', env: { ...process.env, ...env } });
  const req = reqTo(port);
  for (let i = 0; i < 60; i++) { try { const s = await req('GET', '/status'); if (s.status === 200) return { child, req }; } catch { /* wait */ } await sleep(100); }
  child.kill(); throw new Error(`bridge on ${port} did not start`);
}

const echoDef = { command: process.execPath, args: [FIXTURE] };
const initBody = (id = 1) => JSON.stringify({ jsonrpc: '2.0', id, method: 'initialize', params: {} });
const status = async (req) => JSON.parse((await req('GET', '/api/status')).body);
const svc = (snap, name) => snap.servers.find((s) => s.name === name);

test('sharing:"pool" pre-warms a child before any client, then refills after handing one out', async (t) => {
  const { child, req } = await bootBridge(8801, { echo: { ...echoDef, sharing: 'pool', minWarm: 1 } });
  t.after(() => child.kill());
  await sleep(400);
  let s = svc(await status(req), 'echo');
  assert.equal(s.sharing, 'pool');
  assert.equal(s.warm, 1, 'pool pre-warms a child before any client');
  assert.equal(s.sessions, 0, 'no sessions before any client');

  const r = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).result.serverInfo.name, 'echo');
  await sleep(400);
  s = svc(await status(req), 'echo');
  assert.equal(s.sessions, 1, 'session adopted a warm child');
  assert.equal(s.warm, 1, 'pool refilled after handing out a warm child');
});

test('per-server maxSessions caps concurrent sessions with 503', async (t) => {
  // No queueing here: assert the cap itself still refuses rather than admitting extra sessions.
  const { child, req } = await bootBridge(8802, { echo: { ...echoDef, maxSessions: 1 } }, { MCP_QUEUE_TIMEOUT_MS: '0' });
  t.after(() => child.kill());
  const r1 = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody(1) });
  assert.equal(r1.status, 200, 'first session allowed');
  const r2 = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody(2) });
  assert.equal(r2.status, 503, 'second session over the cap is rejected');
  const s = svc(await status(req), 'echo');
  assert.equal(s.maxSessions, 1);
  assert.equal(s.sessions, 1, 'only one active session');
});

// A cap alone converts a burst into failed requests. Waiting briefly for a slot absorbs the
// burst without queueing without limit — past the wait it still refuses rather than piling up.
test('a request at the cap waits for a slot instead of failing immediately', async (t) => {
  const { child, req } = await bootBridge(8822, { echo: { ...echoDef, maxSessions: 1 } }, { MCP_QUEUE_TIMEOUT_MS: '8000' });
  t.after(() => child.kill());

  const first = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody(1) });
  assert.equal(first.status, 200, 'first session allowed');
  const sid = first.headers['mcp-session-id'];

  // Issue a second init while at the cap, then free the slot while it is still waiting.
  const queued = req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody(2) });
  await sleep(400);
  await req('DELETE', '/echo/mcp', { headers: { 'mcp-session-id': sid } });

  const r2 = await queued;
  assert.equal(r2.status, 200, 'the queued request should be admitted once a slot frees');
  assert.equal(svc(await status(req), 'echo').sessions, 1, 'still only one session at a time');
});

test('MCP_IDLE_TIMEOUT_MS reaps idle Streamable HTTP sessions', async (t) => {
  const { child, req } = await bootBridge(8803, { echo: echoDef }, { MCP_IDLE_TIMEOUT_MS: '700' });
  t.after(() => child.kill());
  const r = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  const sid = r.headers['mcp-session-id'];
  assert.ok(sid, 'session id issued');
  const before = svc(await status(req), 'echo');
  assert.equal(before.sessions, 1, 'one active session');
  await sleep(2200); // > timeout + reaper interval
  const reaped = svc(await status(req), 'echo');
  assert.equal(reaped.sessions, 0, 'idle session reaped');
  assert.deepEqual(reaped.pids, [], 'the server process is actually gone, not just untracked');

  // Reaping frees the process; it does not end the client's session. A client that comes back
  // is served transparently on the id it still holds, against a freshly started server.
  const r2 = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json', 'mcp-session-id': sid }, body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list' }) });
  assert.equal(r2.status, 200, 'a returning client must not be stranded by idle reaping');
  const after = svc(await status(req), 'echo');
  assert.equal(after.sessions, 1, 'the session is live again');
  assert.notDeepEqual(after.pids, before.pids, 'served by a new server process');
});

// A call that runs longer than the idle timeout must not have its server reaped underneath it.
// `lastActivity` is stamped when a request arrives, so the reaper used to see a session that had
// been "idle" for the entire duration of an active call, kill the child, and leave the caller
// waiting for a reply that could never arrive. This is also why the idle-reap test above was
// flaky: its resumed session paid for a fresh server spawn inside the request, and the reaper
// could fire before the answer came back.
test('a call slower than the idle timeout is not reaped while it is still running', async (t) => {
  const { child, req } = await bootBridge(
    8831,
    { slow: { command: process.execPath, args: [STUBBORN, '--call-delay', '1500'] } },
    { MCP_IDLE_TIMEOUT_MS: '600', MCP_REQUEST_TIMEOUT_MS: '6000' },
  );
  t.after(() => child.kill());

  const r = await req('POST', '/slow/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  const sid = r.headers['mcp-session-id'];
  assert.ok(sid, 'session id issued');

  const call = await req('POST', '/slow/mcp', {
    headers: { 'content-type': 'application/json', 'mcp-session-id': sid },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
  });
  assert.equal(call.status, 200);
  const payload = JSON.parse(call.body);
  assert.ok(payload.result, `an in-flight call must still be answered, got ${call.body}`);
  assert.equal(payload.result.tools[0].name, 'ping');

  const after = svc(await status(req), 'slow');
  assert.equal(after.sessions, 1, 'a session that just answered a request is not idle');
});

// A killed child's `exit` event can arrive long after the kill: `taskkill /F /T` takes about a
// second on Windows. If a client returns in that window its session is resumed onto a fresh
// child under the same id, and the late exit event then deleted that replacement — so the client
// was silently dropped by the very mechanism meant to keep it alive. This is what made the idle
// reap test above flaky. Detected here by process identity: if the stale exit tears the session
// down, the next call has to resume again onto a third child, so the pid changes.
test('a late exit from a reaped child does not delete the session that replaced it', async (t) => {
  const { child, req } = await bootBridge(8832, { echo: echoDef }, { MCP_IDLE_TIMEOUT_MS: '700' });
  t.after(() => child.kill());
  const r = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  const sid = r.headers['mcp-session-id'];
  assert.ok(sid, 'session id issued');

  // Catch the reap as it happens, so the resume below lands while taskkill is still running.
  let reaped = false;
  for (let i = 0; i < 400 && !reaped; i++) {
    if (svc(await status(req), 'echo').sessions === 0) reaped = true; else await sleep(10);
  }
  assert.ok(reaped, 'the idle session should have been reaped');

  const call = (id) => req('POST', '/echo/mcp', {
    headers: { 'content-type': 'application/json', 'mcp-session-id': sid },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list' }),
  });
  const r2 = await call(9);
  assert.equal(r2.status, 200, 'the returning client is served on the id it still holds');
  const resumedPid = svc(await status(req), 'echo').pids[0];
  assert.ok(resumedPid, 'the resumed session has a server process');

  // Keep the session in use past the point the reaped child's exit is delivered, so the idle
  // reaper cannot claim it and the only thing that can remove it is the stale exit.
  for (let i = 0; i < 8; i++) { await sleep(250); await call(10 + i); }

  const after = svc(await status(req), 'echo');
  assert.equal(after.sessions, 1, 'exactly one live session');
  assert.equal(after.pids[0], resumedPid, 'the resumed session survived the reaped child exiting, with no further respawn');
});
