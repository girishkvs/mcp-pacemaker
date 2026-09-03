// Regression test for the Windows process-tree leak.
//
// On Windows a bare command name (npx/uvx/dnx/... and their .cmd shims) is spawned under a
// cmd.exe wrapper. child.kill() signals only that wrapper, so the real server process survives
// and is reparented — leaking a process on every recycle, idle reap, session close and shutdown.
// The bridge must tear down the whole tree instead.
//
// The bare-command path only exists on Windows; elsewhere the command is spawned directly, so
// this test asserts the same observable outcome (no surviving server process) on every platform.
//
// Liveness is observed through the fixture's heartbeat file rather than by pid or by process
// enumeration. The suite runs test files in parallel and pids get reused, so a pid liveness
// check produces false positives; enumerating every process was slow enough under load to be
// unreliable on its own.
import { test } from 'node:test';
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
const FIXTURE = resolve(__dirname, 'fixtures', 'stubborn-mcp-server.mjs');
const IS_WIN = process.platform === 'win32';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// agent:false disables socket pooling so these assertions never depend on keep-alive timing;
// keep-alive behaviour has its own test in keepalive.test.mjs.
const reqTo = (port) => (method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

async function bootBridge(port, config) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg], { stdio: 'ignore' });
  const req = reqTo(port);
  for (let i = 0; i < 60; i++) {
    try { const s = await req('GET', '/status'); if (s.status === 200) return { child, req, tmp }; } catch { /* wait */ }
    await sleep(100);
  }
  killBridge(child);
  throw new Error(`bridge on ${port} did not start`);
}

// A server defined by a BARE command, which is what triggers the cmd.exe wrapper on Windows.
// `node` resolves on PATH on every platform the CI matrix covers. The fixture deliberately
// survives stdin EOF, so an orphaned process stays observable.
const bareDef = (hb) => ({ command: 'node', args: [FIXTURE, '--heartbeat', hb] });
const initBody = (id = 1) => JSON.stringify({ jsonrpc: '2.0', id, method: 'initialize', params: {} });

// Liveness is measured by the fixture's heartbeat file rather than by enumerating processes.
// Process enumeration on Windows (Get-CimInstance over every process) took seconds under the
// parallel suite, swallowed its own errors, and was vulnerable to pid reuse. A heartbeat that
// stops advancing is a direct, cheap signal that the process is gone.
function beating(hbPath, windowMs = 500) {
  const read = () => { try { return readFileSync(hbPath, 'utf8'); } catch { return null; } };
  const first = read();
  if (first === null) return false;
  const deadline = Date.now() + windowMs;
  while (Date.now() < deadline) {
    if (read() !== first) return true;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50); // blocking 50ms pause
  }
  return false;
}

// The server starts behind a cmd.exe wrapper, so on a loaded machine its first heartbeat can
// take well over a second to appear. Poll rather than assuming a fixed startup delay.
async function awaitBeating(hbPath, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (beating(hbPath)) return true;
    await sleep(100);
  }
  return false;
}

async function assertNoSurvivors(hbPath, what) {
  // taskkill is asynchronous on Windows and can be slow when the suite is running in
  // parallel, so allow a generous window before declaring the process leaked.
  for (let i = 0; i < 40; i++) {
    if (!beating(hbPath)) return;
    await sleep(250);
  }
  assert.fail(`orphaned server process still heartbeating after ${what}`);
}

function cleanup(bridgeChild) {
  killBridge(bridgeChild);
}

test('recycle tears down the whole process tree of a bare-command server', async (t) => {
  const hb = join(mkdtempSync(join(tmpdir(), 'mcpka-hb-')), 'beat');
  const { child, req, tmp } = await bootBridge(8804, { echo: bareDef(hb) });
  t.after(() => cleanup(child));

  const r = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  assert.equal(r.status, 200, 'session established');
  assert.ok(await awaitBeating(hb), 'fixture process is running before recycle');

  const nonce = readFileSync(join(tmp, 'admin.nonce'), 'utf8').trim();
  const rec = await req('POST', '/admin/recycle/echo', { headers: { 'x-mcp-nonce': nonce } });
  assert.equal(rec.status, 200, 'recycle accepted');

  await assertNoSurvivors(hb, 'recycle');
});

test('DELETE of a Streamable HTTP session leaves no orphaned process', async (t) => {
  const hb = join(mkdtempSync(join(tmpdir(), 'mcpka-hb-')), 'beat');
  const { child, req } = await bootBridge(8805, { echo: bareDef(hb) });
  t.after(() => cleanup(child));

  const r = await req('POST', '/echo/mcp', { headers: { 'content-type': 'application/json' }, body: initBody() });
  const sid = r.headers['mcp-session-id'];
  assert.ok(sid, 'session id issued');
  assert.ok(await awaitBeating(hb), 'fixture process is running before DELETE');

  await req('DELETE', '/echo/mcp', { headers: { 'mcp-session-id': sid } });

  await assertNoSurvivors(hb, 'DELETE');
});
