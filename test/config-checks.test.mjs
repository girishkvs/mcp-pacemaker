// Regression tests for the silent cwd failure.
//
// A config imported from a host whose entries assumed a project root keeps its relative wrapper
// paths, but the bridge resolves those against its own base directory. The server then dies at
// spawn with MODULE_NOT_FOUND while `status` still lists it as configured, so the breakage is
// invisible until a client happens to call that server. This happened twice in production on a
// live 15-server config, both times unnoticed for hours.
//
// This file owns port 8830. The full allocation across the suite is listed at the top of
// test/auth-token.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import { checkServerPaths, relativePathArgs } from '../bin/config-checks.mjs';
import { killBridge } from './helpers/kill-bridge.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (port, method, path) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, body: d }));
    });
    r.on('error', rej); r.end();
  });

test('a relative script path that resolves nowhere is reported, not left silent', () => {
  const base = mkdtempSync(join(tmpdir(), 'mcpka-cwd-'));
  const c = checkServerPaths('wrapped', { command: 'node', args: ['.vscode/mcp/wrapped-server/index.js'] }, base);
  assert.equal(c?.status, 'bad', 'a wrapper path that does not exist under the base directory is a hard failure');
  assert.match(c.detail, /no "cwd" set/, 'the report must name the missing cwd, which is the actual fix');
});

test('the same path is accepted once cwd points at the directory it was written for', () => {
  const base = mkdtempSync(join(tmpdir(), 'mcpka-cwd-'));
  const proj = join(base, 'proj');
  mkdirSync(join(proj, 'wrap'), { recursive: true });
  writeFileSync(join(proj, 'wrap', 'index.js'), '');
  assert.equal(checkServerPaths('ok', { command: 'node', args: ['wrap/index.js'], cwd: 'proj' }, base), null);
});

test('a resolvable path with no cwd is a warning, because it depends on the base directory', () => {
  const base = mkdtempSync(join(tmpdir(), 'mcpka-cwd-'));
  mkdirSync(join(base, 'wrap'), { recursive: true });
  writeFileSync(join(base, 'wrap', 'index.js'), '');
  const c = checkServerPaths('fragile', { command: 'node', args: ['wrap/index.js'] }, base);
  assert.equal(c?.status, 'warn');
});

// The check must not cry wolf on the most common config shape in the wild, or it gets ignored.
test('package specs and flags passed to a runner are not mistaken for paths', () => {
  const args = ['-y', '--registry', 'https://registry.example/npm/', '@scope/some-mcp', 'an-arg'];
  assert.deepEqual(relativePathArgs({ args }), []);
  assert.equal(checkServerPaths('runner', { command: 'npx', args }, tmpdir()), null);
});

test('absolute paths and http servers are left alone', () => {
  const abs = process.platform === 'win32' ? 'C:\\tools\\server.js' : '/opt/tools/server.js';
  assert.deepEqual(relativePathArgs({ args: [abs] }), []);
  assert.equal(checkServerPaths('remote', { type: 'http', url: 'https://example.test/' }, tmpdir()), null);
});

test('the running bridge surfaces the broken path on /api/doctor', async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-doctor-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify({
    broken: { command: 'node', args: ['.vscode/mcp/gone/index.js'] },
    fine: { command: 'npx', args: ['-y', '@scope/pkg'] },
  }));
  const port = 8830;
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg], { stdio: 'ignore' });
  t.after(() => killBridge(child));
  let up = false;
  for (let i = 0; i < 60 && !up; i++) {
    try { up = (await req(port, 'GET', '/status')).status === 200; } catch { await sleep(100); }
  }
  assert.ok(up, 'bridge did not start');

  const doc = JSON.parse((await req(port, 'GET', '/api/doctor')).body);
  const broken = doc.checks.find((c) => c.name === 'broken');
  assert.equal(broken?.status, 'bad', 'the dashboard health page must show the unresolvable path');
  assert.equal(doc.checks.find((c) => c.name === 'fine')?.status, 'ok', 'a package spec must still read as healthy');
});
