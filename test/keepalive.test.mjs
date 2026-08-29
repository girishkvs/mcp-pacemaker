// Regression test: a pooled keep-alive connection must survive an idle gap.
//
// Node's HTTP server closes idle keep-alive sockets after 5s by default. A client that is busy
// (blocked event loop) across that window never processes the server's FIN, so the socket stays
// in its pool marked free; the next request writes to a dead socket and fails with ECONNRESET.
// MCP clients routinely idle longer than 5s between tool calls, so the server must hold sockets
// open well past that. The blocking loop below is what makes the failure deterministic.
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
const PORT = 8806;
const IDLE_MS = 6500; // longer than Node's 5s default keepAliveTimeout
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Blocks the event loop, so the server's FIN is not processed while we wait.
const blockEventLoop = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function get(agent, path) {
  return new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method: 'GET', agent }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, body: d }));
    });
    r.on('error', rej); r.end();
  });
}

test('a pooled keep-alive socket survives a busy client idling past the Node default', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-ka-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({}));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(PORT), '--config', cfg], { stdio: 'ignore' });
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  t.after(() => { agent.destroy(); child.kill(); });

  let up = false;
  for (let i = 0; i < 60; i++) {
    try { const s = await get(agent, '/status'); if (s.status === 200) { up = true; break; } } catch { /* wait */ }
    await sleep(100);
  }
  assert.ok(up, 'bridge started');

  blockEventLoop(IDLE_MS);

  // Reuses the pooled socket. With the server's default 5s keep-alive this rejects ECONNRESET.
  const second = await get(agent, '/status');
  assert.equal(second.status, 200, 'second request on the reused socket succeeds');
});
