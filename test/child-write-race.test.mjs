// Regression tests: a server that exits while the bridge is writing to it must not crash the
// bridge.
//
// The bridge wrote to a child's stdin with no 'error' listener on the pipe. A child that exited
// between that write and the bridge handling its exit, for example a server restarting
// mid-request, failed the write with EPIPE. The unhandled 'error' then took down the whole bridge
// and every session on it. In production the window is short, so a test preload widens it.
//
// The crash also left no trace in bridge.log, so the last test checks that a fatal error does.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8886-8888.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import http from 'node:http';
import { killBridge } from './helpers/kill-bridge.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const SERVER = resolve(__dirname, 'fixtures', 'exit-after-call-server.mjs');
const DELAY_CHILD_EXIT = pathToFileURL(resolve(__dirname, 'fixtures', 'delay-child-exit.mjs')).href;
const THROW_ON_TRIGGER = pathToFileURL(resolve(__dirname, 'fixtures', 'throw-on-trigger.mjs')).href;
const DELAYED_EXIT_ENV = { MCP_TEST_CHILD_EXIT_DELAY_MS: '2000' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (port, method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

async function startBridge(t, port, preload, env) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-race-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ race: { command: 'node', args: [SERVER] } }));
  const child = spawn(process.execPath, ['--import', preload, BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, ...env } });
  const exited = new Promise((res) => child.once('exit', (code) => res(code)));
  t.after(() => killBridge(child));
  for (let i = 0; i < 100; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) break; } catch { /* wait */ }
    await sleep(100);
  }
  return { child, exited, logFile: join(tmp, 'bridge.log') };
}

test('a Streamable HTTP request to a server that just exited fails without crashing the bridge', { timeout: 30000 }, async (t) => {
  const port = 8886;
  const { child, logFile } = await startBridge(t, port, DELAY_CHILD_EXIT, DELAYED_EXIT_ENV);
  const post = (body, sessionId) => req(port, 'POST', '/race/mcp', {
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(sessionId ? { 'mcp-session-id': sessionId } : {}) },
    body: JSON.stringify(body),
  });

  const init = await post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'race-test', version: '0.0.0' } } });
  const sessionId = init.headers['mcp-session-id'];
  assert.ok(sessionId, 'initialize should open a session');
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, sessionId);
  const call = await post({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'exit', arguments: {} } }, sessionId);
  assert.match(call.body, /exiting/);
  await sleep(500); // the server has exited; the bridge has not handled that yet

  const next = await post({ jsonrpc: '2.0', id: 3, method: 'tools/list' }, sessionId);
  assert.equal(next.status, 200);
  assert.match(JSON.parse(next.body).error.message, /server exited/);
  assert.equal(child.exitCode, null, 'the bridge must still be running');
  assert.equal((await req(port, 'GET', '/status')).status, 200);
  assert.match(readFileSync(logFile, 'utf8'), /\[race\] stdin write failed/);
});

test('a classic SSE message to a server that just exited does not crash the bridge', { timeout: 30000 }, async (t) => {
  const port = 8887;
  const { child, logFile } = await startBridge(t, port, DELAY_CHILD_EXIT, DELAYED_EXIT_ENV);
  let stream = '';
  const sse = http.get({ host: '127.0.0.1', port, path: '/race/sse', agent: false }, (resp) => {
    resp.setEncoding('utf8');
    resp.on('data', (chunk) => { stream += chunk; });
  });
  sse.on('error', () => { /* the stream ends with the bridge */ });
  t.after(() => sse.destroy());
  const streamMatch = async (pattern) => {
    for (let i = 0; i < 200 && !pattern.test(stream); i++) await sleep(50);
    assert.match(stream, pattern);
    return pattern.exec(stream);
  };
  const endpoint = new URL((await streamMatch(/event: endpoint\ndata: (\S+)\n\n/))[1]);
  const send = (body) => req(port, 'POST', endpoint.pathname + endpoint.search, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  assert.equal((await send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'exit', arguments: {} } })).status, 202);
  await streamMatch(/exiting/); // the 202 only means the bridge wrote the call; wait for the reply
  await sleep(500); // the server has exited; the bridge has not handled that yet
  assert.equal((await send({ jsonrpc: '2.0', id: 2, method: 'tools/list' })).status, 202);
  await sleep(300); // the failed write is reported asynchronously

  assert.equal(child.exitCode, null, 'the bridge must still be running');
  assert.equal((await req(port, 'GET', '/status')).status, 200);
  assert.match(readFileSync(logFile, 'utf8'), /\[race\] stdin write failed/);
});

test('a crash leaves its stack in bridge.log', { timeout: 30000 }, async (t) => {
  const trigger = join(mkdtempSync(join(tmpdir(), 'mcpka-fatal-')), 'throw-now');
  const { child, exited, logFile } = await startBridge(t, 8888, THROW_ON_TRIGGER, { MCP_TEST_THROW_FILE: trigger });
  assert.equal(child.exitCode, null, 'the bridge should be running before the crash is triggered');
  writeFileSync(trigger, '');

  assert.equal(await exited, 1, 'a crash must still end the process, so the supervisor restarts it');
  assert.match(readFileSync(logFile, 'utf8'), /fatal uncaughtException: Error: fatal-test-marker/);
});
