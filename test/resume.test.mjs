// Regression tests: a client's session must survive the bridge restarting, and a recycle.
//
// Streamable HTTP session ids lived only in memory, so restarting the bridge (an upgrade, a
// crash, a reboot) made every live session 404. Clients surface that as
// "-32001: Session not found" rather than re-initializing, so the user sees dead MCP servers —
// the exact outage this project exists to prevent. Recycle had the same effect.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8815-8818, 8829, 8833.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync, existsSync, statSync } from 'node:fs';
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
    { stdio: 'ignore', env: { ...process.env, ...env } });
  for (let i = 0; i < 80; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) return child; } catch { /* wait */ }
    await sleep(100);
  }
  killBridge(child);
  throw new Error(`bridge on ${port} did not start`);
}

async function stop(child, port) {
  killBridge(child);
  for (let i = 0; i < 60; i++) {
    try { await req(port, 'GET', '/status'); } catch { return; }
    await sleep(100);
  }
}

function makeConfig() {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-resume-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ echo: { command: 'node', args: [FIXTURE] } }));
  return { tmp, cfg };
}

const rpc = { 'content-type': 'application/json' };
const initBody = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'resume-test', version: '1' } },
});
const listBody = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
const parse = (body) => JSON.parse((body.match(/data: (.*)/) || [null, body])[1]);

test('a session survives the bridge restarting', async (t) => {
  const { tmp, cfg } = makeConfig();
  const port = 8815;
  let child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established');

  // The bridge goes away entirely — an upgrade, a crash, a reboot.
  await stop(child, port);
  child = await boot(port, cfg);

  // Same session id the client has been holding all along.
  const after = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(after.status, 200, 'a client using its existing session id must not get a 404');
  const msg = parse(after.body);
  assert.ok(!msg.error, `expected a result, got ${JSON.stringify(msg.error)}`);
  assert.ok(Array.isArray(msg.result.tools), 'the resumed session serves real responses');
});

test('an explicit DELETE is final: the session does not come back', async (t) => {
  const { cfg } = makeConfig();
  const port = 8816;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  await req(port, 'DELETE', '/echo/mcp', { headers: { 'mcp-session-id': sid } });

  const after = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(after.status, 404, 'a deleted session must not be resurrected; spec requires 404 so the client re-initializes');
});

// MCP 2025-11-25 (and every session-bearing revision back to 2025-03-26), Streamable HTTP /
// Session Management: a server that has terminated a session MUST answer 404 for that id,
// because §4 makes "re-initialize on 404" a client MUST. 410 reads better to a human but strands
// a compliant client in undefined behaviour, which is the exact failure this bridge exists to
// avoid. This test exists to stop that "improvement" being made.
test('a terminated session is 404, never 410 — the spec makes 404 the recovery signal', async (t) => {
  const { cfg } = makeConfig();
  const port = 8818;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const known = init.headers['mcp-session-id'];
  await req(port, 'DELETE', '/echo/mcp', { headers: { 'mcp-session-id': known } });

  const gone = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': known }, body: listBody });
  const never = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': 'never-existed-0000' }, body: listBody });

  assert.equal(gone.status, 404, 'a session we know we terminated must still be 404');
  assert.equal(never.status, 404, 'an id we never issued is also 404');
  assert.notEqual(gone.body, never.body, 'the body must still tell an operator which case it is');
  assert.match(gone.body, /re-initialize/i, 'the known-gone body says what the client should do');
});

test('recycle is transparent: the client keeps using its session id', async (t) => {
  const { tmp, cfg } = makeConfig();
  const port = 8817;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];

  const nonce = readFileSync(join(dirname(cfg), 'admin.nonce'), 'utf8').trim();
  const rec = await req(port, 'POST', '/admin/recycle/echo', { headers: { 'x-mcp-nonce': nonce } });
  assert.equal(rec.status, 200, 'recycle accepted');

  // taskkill is asynchronous, so wait until the session is genuinely gone. Without this the
  // follow-up request can race the child's exit and pass without exercising the resume path.
  let gone = false;
  for (let i = 0; i < 60 && !gone; i++) {
    const st = await req(port, 'GET', '/api/status', { headers: { 'x-admin-nonce': nonce } });
    const echo = JSON.parse(st.body).servers.find((s) => s.name === 'echo');
    gone = !echo || echo.sessions === 0; // sessions is a count, not a list
    if (!gone) await sleep(100);
  }
  assert.ok(gone, 'recycle should have torn the session down');

  const after = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(after.status, 200, 'recycle must not strand the client');
  assert.ok(Array.isArray(parse(after.body).result.tools));
});

test('a scheduled recycle happens unprompted and stays invisible to the client', async (t) => {
  const { cfg } = makeConfig();
  const port = 8818;
  // A short period (fractional minutes are allowed) so the scheduler fires within the test.
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, MCP_RECYCLE_MINUTES: '0.02' } });
  t.after(() => killBridge(child));
  for (let i = 0; i < 80; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) break; } catch { /* wait */ }
    await sleep(100);
  }

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established');

  const nonce = readFileSync(join(dirname(cfg), 'admin.nonce'), 'utf8').trim();
  const echoStat = async () => {
    const st = await req(port, 'GET', '/api/status', { headers: { 'x-admin-nonce': nonce } });
    return JSON.parse(st.body).servers.find((s) => s.name === 'echo');
  };
  const firstPid = (await echoStat()).pids[0];
  assert.ok(firstPid, 'server running');

  // Nobody asks for this: the scheduler retires the process on its own.
  let recycled = false;
  for (let i = 0; i < 100 && !recycled; i++) {
    recycled = (await echoStat()).sessions === 0;
    if (!recycled) await sleep(200);
  }
  assert.ok(recycled, 'the scheduled recycle should tear the session down unprompted');

  // The client knows nothing about any of this and keeps working on its original id.
  const after = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(after.status, 200, 'a scheduled recycle must not strand the client');
  assert.ok(Array.isArray(parse(after.body).result.tools));
  assert.notEqual((await echoStat()).pids[0], firstPid, 'the server process should have been replaced');
});
// The retention window was only ever applied when sessions.json was read at startup. A
// long-running bridge therefore kept honouring records far older than the window it documents,
// and kept re-persisting them, so the file only ever grew. Observed on a live bridge: entries
// 45 hours old under a 24 hour TTL, still resumable.
test('a record past the retention window is not resumable, and is dropped from disk', async (t) => {
  const { tmp, cfg } = makeConfig();
  const port = 8833;
  // Reap the live session quickly, so the id can only come back through the resume path — which
  // is where the retention window has to be enforced.
  const child = await boot(port, cfg, { MCP_RESUME_TTL_MS: '2500', MCP_IDLE_TIMEOUT_MS: '400' });
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established');

  // Let the idle reaper take the live session, then confirm resume works inside the window.
  await sleep(1200);
  const inside = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(inside.status, 200, 'inside the window the id is still resumable');

  // Now age the record past the window, with the bridge still running the whole time.
  await sleep(3000);
  const outside = await req(port, 'POST', '/echo/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(outside.status, 404, 'an expired id must 404 so a spec-compliant client re-initializes');

  const onDisk = JSON.parse(readFileSync(join(tmp, 'sessions.json'), 'utf8'));
  assert.equal(Object.prototype.hasOwnProperty.call(onDisk, sid), false,
    'the expired record must be dropped from sessions.json, not re-persisted forever');
});

// The in-memory ring buffer behind /api/logs and the dashboard is the only history the bridge
// kept, and a single chatty client fills it in minutes — on a live setup a client reconnecting
// every 30s left about two minutes of history, far too little to explain something that
// happened overnight. stderr is no help either: the supervisor starts the bridge without
// redirecting it. So the log is also written next to the config, and rolled at a fixed size.
test('the bridge writes a durable log next to its config, and rolls it', async (t) => {
  const { tmp, cfg } = makeConfig();
  const port = 8829;
  const child = await boot(port, cfg, { MCP_LOG_MAX_BYTES: '2000' });
  t.after(() => killBridge(child));

  const logFile = join(tmp, 'bridge.log');
  for (let i = 0; i < 50 && !existsSync(logFile); i++) await sleep(100);
  assert.ok(existsSync(logFile), 'a log file must exist without any supervisor redirection');
  assert.match(readFileSync(logFile, 'utf8'), /listening on http/, 'startup is recorded');

  // Enough traffic to pass the roll threshold; each session start and exit logs a line.
  for (let i = 0; i < 12; i++) {
    const r = await req(port, 'POST', '/echo/mcp', { headers: rpc, body: initBody });
    const sid = r.headers['mcp-session-id'];
    if (sid) await req(port, 'DELETE', '/echo/mcp', { headers: { 'mcp-session-id': sid } });
  }
  for (let i = 0; i < 50 && !existsSync(logFile + '.1'); i++) await sleep(100);

  assert.ok(existsSync(logFile + '.1'), 'the log must roll rather than grow without bound');
  assert.ok(statSync(logFile).size < 20000, 'the active log is bounded after rolling');
});
