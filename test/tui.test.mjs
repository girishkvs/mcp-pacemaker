// TUI (top.mjs) tests. Covers the pure port-resolution logic and the network read path the Ink
// UI depends on (fetchSnapshot / recycleServer). Ink rendering itself needs a TTY and is not
// exercised here.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { portFromState, fetchSnapshot, recycleServer } from '../bin/top.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const FIXTURE = resolve(__dirname, 'fixtures', 'echo-mcp-server.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('portFromState: list shape wins, legacy {port} fallback, else 8791', () => {
  assert.equal(portFromState({ hosts: [{ id: 'vscode', port: 8850 }, { id: 'codex', port: 8860 }] }), 8850);
  assert.equal(portFromState({ port: 8877 }), 8877);
  assert.equal(portFromState({ hosts: [] }), 8791);
  assert.equal(portFromState(null), 8791);
  assert.equal(portFromState({}), 8791);
});

test('fetchSnapshot / recycleServer return null against a dead port', async () => {
  assert.equal(await fetchSnapshot(8809), null);
  assert.equal(await recycleServer(8809, 'echo', 'x'), null);
});

test('fetchSnapshot reads a live bridge snapshot (the TUI read path)', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({ echo: { command: process.execPath, args: [FIXTURE] } }));
  const child = spawn(process.execPath, [BRIDGE, '--port', '8808', '--config', cfg], { stdio: 'ignore' });
  t.after(() => child.kill());
  let snap = null;
  for (let i = 0; i < 60 && !snap; i++) { snap = await fetchSnapshot(8808); if (!snap) await sleep(100); }
  assert.ok(snap, 'snapshot fetched');
  assert.ok(Array.isArray(snap.servers), 'snapshot has servers[]');
  assert.ok(snap.servers.some((s) => s.name === 'echo'), 'echo present in snapshot');
});
