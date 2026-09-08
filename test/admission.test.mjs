// This file owns port 8872.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { killBridge } from './helpers/kill-bridge.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const base = 'http://127.0.0.1:8872';

test('queued cold starts reserve session capacity before waiting for the global spawn gate', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'pacemaker-admission-'));
  const config = join(dir, 'servers.json');
  const fixture = join(root, 'test', 'fixtures', 'pool-child.mjs');
  writeFileSync(config, JSON.stringify({
    blocker: { command: process.execPath, args: [fixture, '--startup-delay', '1800'], sharedPackageCache: true },
    target: { command: process.execPath, args: [fixture], sharedPackageCache: true, maxSessions: 1 },
  }));
  const child = spawn(process.execPath, [join(root, 'bin', 'mcp-bridge.mjs'), '--port', '8872', '--config', config], {
    stdio: 'ignore',
    env: {
      ...process.env, MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0', MCP_IDLE_TIMEOUT_MS: '0',
      MCP_MAX_CONCURRENT_SPAWNS: '1', MCP_SPAWN_GATE_WAIT_MS: '10000', MCP_QUEUE_TIMEOUT_MS: '0',
    },
  });
  const exited = once(child, 'exit');
  t.after(async () => {
    killBridge(child);
    await exited;
    rmSync(dir, { recursive: true, force: true });
  });
  const snapshot = async () => fetch(`${base}/api/status`).then((response) => response.json());
  const initialize = (name) => fetch(`${base}/${name}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    signal: AbortSignal.timeout(10000),
  });
  const deadline = Date.now() + 10000;
  while (true) {
    try {
      await snapshot();
      break;
    } catch (error) {
      if (error.cause?.code !== 'ECONNREFUSED' ||
          Date.now() >= deadline) throw error;
      await delay(30);
    }
  }
  const blocker = initialize('blocker');
  while (!(await snapshot()).servers.find((server) => server.name === 'blocker').sessions) {
    assert.ok(Date.now() < deadline, 'blocker did not acquire the spawn gate');
    await delay(20);
  }
  const replies = await Promise.all([initialize('target'), initialize('target')]);
  assert.equal((await blocker).status, 200);
  assert.deepEqual(replies.map((response) => response.status).sort(), [200, 503]);
  const target = (await snapshot()).servers.find((server) => server.name === 'target');
  assert.equal(target.sessions, 1);
  assert.equal(target.spawn.total, 1);
});
