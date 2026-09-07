// Regression tests for the keep-warm pool (`sharing: "pool"`).
//
// Both cases were found on the live bridge: `ev2` was configured `sharing: pool, minWarm: 1` and
// had been sitting at `warm: 0` for three hours, while `kusto` — same config — stayed full. The
// difference was only that kusto is taken often, and every take triggers a refill. A pooled
// server that goes quiet drained to empty and stayed there, silently degrading to a cold spawn
// per session, which is the exact thing pooling exists to prevent.
//
// Ports: see the allocation note in auth-token.test.mjs. This file owns 8862-8865.
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
const FIXTURE = resolve(__dirname, 'fixtures', 'pool-child.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (port, method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

// Captures the bridge's own log, because "did the pool refill" is a question about spawns over
// time, and a point-in-time `warm` reading cannot tell "refilled" from "never drained".
async function boot(port, config, env = {}) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-pool-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, ...env } });
  let logged = '';
  child.stderr.on('data', (c) => (logged += c));
  for (let i = 0; i < 80; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) return { child, log: () => logged }; } catch { /* wait */ }
    await sleep(100);
  }
  killBridge(child);
  throw new Error(`bridge on ${port} did not start`);
}

const rpc = { 'content-type': 'application/json' };
const initBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
const status = async (port) => JSON.parse((await req(port, 'GET', '/api/status')).body);

test('a warm child that dies on its own is replaced', async (t) => {
  const port = 8862;
  // Exits ~700ms after spawn, without ever being used: the pool drains through no fault of ours.
  const def = { command: 'node', args: [FIXTURE, '--exit-after', '700'], sharing: 'pool', minWarm: 1 };
  const { child, log } = await boot(port, { drainer: def });
  t.after(() => killBridge(child));

  // Long enough for the boot child to die and the backoff (1s after a first fast exit) to fire.
  await sleep(4000);

  const spawns = (log().match(/pre-warmed pool child/g) || []).length;
  assert.ok(spawns >= 2, `pool must refill after an unattended exit; only ${spawns} spawn(s) in 4s`);

  const s = await status(port);
  const drainer = s.servers.find((x) => x.name === 'drainer');
  assert.equal(drainer.sharing, 'pool', 'still a pool server');
});

test('a pooled session child that dies is counted as one failure, not two', async (t) => {
  const port = 8863;
  // A taken warm child keeps the exit handler `spawnWarm` attached *and* gains the one
  // `startStreamableChild` attaches. Both called noteExit, so every failing child of a pooled
  // server drove that server's health down twice as fast as an identical unpooled one.
  const def = { command: 'node', args: [FIXTURE], sharing: 'pool', minWarm: 1 };
  const { child } = await boot(port, { twice: def });
  t.after(() => killBridge(child));

  await sleep(600); // let the boot child land in the pool so the session adopts a warm one
  const init = await req(port, 'POST', '/twice/mcp', { headers: rpc, body: initBody });
  const sid = init.headers['mcp-session-id'];
  assert.ok(sid, 'session established on a warm child');

  // Not awaited: the child dies before answering, so this request only ends when the bridge's
  // own request timeout fires. The send is what matters.
  req(port, 'POST', '/twice/mcp', {
    headers: { ...rpc, 'mcp-session-id': sid },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'crash/now' }),
  }).catch(() => { /* the child dies mid-request; that is the point */ });

  let health;
  for (let i = 0; i < 40; i++) {
    health = (await status(port)).servers.find((x) => x.name === 'twice').health;
    if (health.consecutiveFailures > 0) break;
    await sleep(100);
  }
  assert.equal(health.consecutiveFailures, 1, `one dead child is one failure, saw ${health.consecutiveFailures}`);
});

// A real cold start is dominated by a package manager, and running several at once is how a
// shared npm/uv cache gets corrupted — 17 simultaneous `npx` invocations on the author's machine
// produced `npm error code ECOMPROMISED` and failed every one of those sessions. No server
// definition can fix that, so the bridge serializes cold spawns.
test('concurrent cold starts are serialized by the spawn gate', async (t) => {
  const port = 8864;
  const DELAY = 1200;
  const def = { command: 'node', args: [FIXTURE, '--startup-delay', String(DELAY)] };
  const { child } = await boot(port, { slow: def }, { MCP_MAX_CONCURRENT_SPAWNS: '2', MCP_INIT_TIMEOUT_MS: '60000' });
  t.after(() => killBridge(child));

  const started = Date.now();
  const all = await Promise.all([0, 1, 2, 3].map(() =>
    req(port, 'POST', '/slow/mcp', { headers: rpc, body: initBody })));
  const elapsed = Date.now() - started;

  assert.ok(all.every((r) => r.status === 200), 'every cold start still succeeds, just not at once');
  // 4 spawns, 2 at a time, each blocking for DELAY => at least two batches.
  assert.ok(elapsed >= DELAY * 2, `4 spawns at a gate of 2 must take >= 2 batches, took ${elapsed}ms`);
  assert.ok(elapsed < DELAY * 6, `serialization must not be pathological, took ${elapsed}ms`);
});

// Pooling costs a resident process per warm slot, so the bridge measures and recommends but does
// not decide. Turning it on unasked would spend someone's memory without their say-so.
test('a slow server is measured and recommended for pooling, but never pooled automatically', async (t) => {
  const port = 8865;
  const def = { command: 'node', args: [FIXTURE, '--startup-delay', '2400'] };
  const { child } = await boot(port, { pokey: def }, { MCP_MAX_CONCURRENT_SPAWNS: '4', MCP_INIT_TIMEOUT_MS: '60000' });
  t.after(() => killBridge(child));

  // Three samples: the advisory stays quiet until it has seen enough to be worth acting on.
  for (let i = 0; i < 3; i++) await req(port, 'POST', '/pokey/mcp', { headers: rpc, body: initBody });

  const s = (await status(port)).servers.find((x) => x.name === 'pokey');
  assert.ok(s.spawn, 'cold start cost must be measured, not guessed');
  assert.ok(s.spawn.p50Ms >= 2000, `p50 should reflect the real delay, got ${s.spawn.p50Ms}ms`);
  assert.ok(s.advice, 'a 2.4s cold start is worth telling the user about');
  assert.equal(s.advice.suggest.sharing, 'pool', 'the recommendation is to pool');
  assert.equal(s.sharing, 'isolated', 'but the bridge must not enable pooling on its own');
  assert.equal(s.warm, 0, 'and must not have pre-spawned anything');
});
