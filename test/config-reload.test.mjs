// Regression tests: editing servers.json must take effect without restarting the bridge.
//
// Before this, adding one server meant restarting the bridge, which killed the live sessions of
// every *other* server — so a config edit cost an outage proportional to how much you were
// already running. The reload is therefore a diff, and the assertions below are mostly about
// what it must NOT touch.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8834-8839.
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

function makeConfig(servers, prefix = 'mcpka-reload-') {
  const tmp = mkdtempSync(join(tmpdir(), prefix));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(servers));
  return { tmp, cfg };
}

const nonceFor = (tmp) => readFileSync(join(tmp, 'admin.nonce'), 'utf8').trim();
const reload = (port, tmp) => req(port, 'POST', '/admin/reload', { headers: { 'x-mcp-nonce': nonceFor(tmp) } });

async function snapshot(port) {
  const r = await req(port, 'GET', '/api/status');
  return Object.fromEntries(JSON.parse(r.body).servers.map((s) => [s.name, s]));
}

const rpc = { 'content-type': 'application/json' };
const initBody = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'reload-test', version: '1' } },
});
const listBody = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
const parse = (body) => JSON.parse((body.match(/data: (.*)/) || [null, body])[1]);

const server = (label) => ({ command: 'node', args: [FIXTURE, '--label', label] });

test('reloading leaves untouched servers and their live sessions alone', async (t) => {
  const { tmp, cfg } = makeConfig({ keep: server('keep'), edited: server('before') });
  const port = 8834;
  const child = await boot(port, cfg, { MCP_CONFIG_WATCH: '0' });
  t.after(() => killBridge(child));

  const init = await req(port, 'POST', '/keep/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established on the server we are not editing');
  const pidBefore = (await snapshot(port)).keep.pids[0];
  assert.ok(pidBefore, 'the untouched server has a live child');

  writeFileSync(cfg, JSON.stringify({ keep: server('keep'), edited: server('after') }));
  const r = await reload(port, tmp);
  assert.equal(r.status, 200);
  const j = JSON.parse(r.body);
  assert.deepEqual(j.changed, ['edited'], 'only the edited server is reported changed');
  assert.deepEqual(j.added, []);
  assert.deepEqual(j.removed, []);
  assert.equal(j.restarted, 0, 'no live session was disturbed — the only one belongs to an unedited server');

  // Session resume would hide a needless recycle from the client, so assert on the process
  // itself: an unrelated edit must not cost this server its child. Wait past killTree, which
  // takes about a second on Windows.
  await sleep(2000);
  const after = await req(port, 'POST', '/keep/mcp', { headers: { ...rpc, 'mcp-session-id': sid }, body: listBody });
  assert.equal(after.status, 200, 'the untouched session still works');
  assert.equal(parse(after.body).result.tools[0].name, 'ping');
  assert.equal((await snapshot(port)).keep.pids[0], pidBefore, 'and it is still the same process');
});

test('an edited server serves its new definition after reload', async (t) => {
  const { tmp, cfg } = makeConfig({ edited: server('before') });
  const port = 8835;
  const child = await boot(port, cfg, { MCP_CONFIG_WATCH: '0' });
  t.after(() => killBridge(child));

  const first = await req(port, 'POST', '/edited/mcp', { headers: rpc, body: initBody });
  assert.equal(parse(first.body).result.serverInfo.name, 'before');

  writeFileSync(cfg, JSON.stringify({ edited: server('after') }));
  assert.equal((await reload(port, tmp)).status, 200);

  const second = await req(port, 'POST', '/edited/mcp', { headers: rpc, body: initBody });
  assert.equal(parse(second.body).result.serverInfo.name, 'after', 'the new args are in force');
});

test('reload adds and removes servers', async (t) => {
  const { tmp, cfg } = makeConfig({ old: server('old') });
  const port = 8836;
  const child = await boot(port, cfg, { MCP_CONFIG_WATCH: '0' });
  t.after(() => killBridge(child));

  assert.equal((await req(port, 'POST', '/fresh/mcp', { headers: rpc, body: initBody })).status, 404, 'not configured yet');

  writeFileSync(cfg, JSON.stringify({ fresh: server('fresh') }));
  const j = JSON.parse((await reload(port, tmp)).body);
  assert.deepEqual(j.added, ['fresh']);
  assert.deepEqual(j.removed, ['old']);

  const added = await req(port, 'POST', '/fresh/mcp', { headers: rpc, body: initBody });
  assert.equal(added.status, 200, 'the added server is routable');
  assert.equal(parse(added.body).result.serverInfo.name, 'fresh');
  assert.equal((await req(port, 'POST', '/old/mcp', { headers: rpc, body: initBody })).status, 404, 'the removed server is gone');
});

test('a broken config is rejected and the running config keeps serving', async (t) => {
  const { tmp, cfg } = makeConfig({ good: server('good') });
  const port = 8837;
  const child = await boot(port, cfg, { MCP_CONFIG_WATCH: '0' });
  t.after(() => killBridge(child));

  // Exactly what a half-written editor save looks like on disk.
  writeFileSync(cfg, '{ "good": { "command": "node", ');
  const bad = await reload(port, tmp);
  assert.equal(bad.status, 400);
  assert.match(JSON.parse(bad.body).error, /invalid JSON/);

  let live = await req(port, 'POST', '/good/mcp', { headers: rpc, body: initBody });
  assert.equal(live.status, 200, 'still serving the last good config');
  assert.equal(parse(live.body).result.serverInfo.name, 'good');

  // Valid JSON, but a server definition that could never start.
  writeFileSync(cfg, JSON.stringify({ good: server('good'), broken: { args: ['x'] } }));
  const invalid = await reload(port, tmp);
  assert.equal(invalid.status, 400);
  assert.match(JSON.parse(invalid.body).error, /neither "command" nor "url"/);
  assert.equal((await req(port, 'POST', '/broken/mcp', { headers: rpc, body: initBody })).status, 404, 'rejected wholesale, not partially applied');

  live = await req(port, 'POST', '/good/mcp', { headers: rpc, body: initBody });
  assert.equal(live.status, 200, 'still serving the last good config');
});

test('saving servers.json reloads it without an admin call', async (t) => {
  const { cfg } = makeConfig({ watched: server('before') });
  const port = 8838;
  const child = await boot(port, cfg);
  t.after(() => killBridge(child));

  const first = await req(port, 'POST', '/watched/mcp', { headers: rpc, body: initBody });
  assert.equal(parse(first.body).result.serverInfo.name, 'before');

  writeFileSync(cfg, JSON.stringify({ watched: server('after') }));

  let name = null;
  for (let i = 0; i < 60; i++) {
    await sleep(100);
    const r = await req(port, 'POST', '/watched/mcp', { headers: rpc, body: initBody });
    name = parse(r.body).result.serverInfo.name;
    if (name === 'after') break;
  }
  assert.equal(name, 'after', 'the file watcher picked the edit up on its own');
});

test('MCP_CONFIG_WATCH=0 disables the watcher but leaves the admin endpoint working', async (t) => {
  const { tmp, cfg } = makeConfig({ watched: server('before') });
  const port = 8839;
  const child = await boot(port, cfg, { MCP_CONFIG_WATCH: '0' });
  t.after(() => killBridge(child));

  writeFileSync(cfg, JSON.stringify({ watched: server('after') }));
  await sleep(1500); // comfortably past the 300ms debounce

  const unwatched = await req(port, 'POST', '/watched/mcp', { headers: rpc, body: initBody });
  assert.equal(parse(unwatched.body).result.serverInfo.name, 'before', 'the edit was not picked up');

  assert.equal((await reload(port, tmp)).status, 200);
  const explicit = await req(port, 'POST', '/watched/mcp', { headers: rpc, body: initBody });
  assert.equal(parse(explicit.body).result.serverInfo.name, 'after', 'an explicit reload still works');
});
