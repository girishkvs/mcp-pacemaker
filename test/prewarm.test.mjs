import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { formatPrewarm, runPrewarm } from '../bin/prewarm.mjs';

async function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'pacemaker-prewarm-cli-'));
  const configPath = join(dir, 'servers.json');
  writeFileSync(join(dir, 'admin.nonce'), 'nonce-for-test');
  const posts = [];
  const snapshot = {
    service: 'mcp-pacemaker', instanceId: 'interval-a', startedAt: '2026-09-07T00:00:00.000Z',
    prewarm: { revision: 'revision-one', maxWarm: 32 },
    servers: [
      {
        name: 'alpha', type: 'stdio', sharing: 'isolated', warm: 0, minWarm: 0,
        spawn: { total: 91, samples: 50, p50Ms: 2800, p95Ms: 4500 },
        prewarming: { eligible: true, suggestedMinWarm: 3 },
      },
      {
        name: 'pooled', type: 'stdio', sharing: 'pool', warm: 2, minWarm: 2,
        spawn: { total: 2, samples: 0, p50Ms: null, p95Ms: null },
        prewarming: { eligible: true, suggestedMinWarm: 2 },
      },
      { name: 'remote', type: 'http', sharing: 'isolated', spawn: null },
      {
        name: 'multiplexed', type: 'stdio', sharing: 'shared', warm: 0, minWarm: 0,
        shared: { state: 'ready', members: 5, unresolved: 2, queued: 1 },
        spawn: { total: 1, samples: 1, p50Ms: 1800, p95Ms: 1800 },
        prewarming: { eligible: false, suggestedMinWarm: 0 },
      },
    ],
  };
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    if (request.method === 'GET') {
      response.end(JSON.stringify(snapshot));
      return;
    }
    let text = '';
    request.on('data', (chunk) => { text += chunk; });
    request.on('end', () => {
      const body = JSON.parse(text);
      posts.push({ path: request.url, body, nonce: request.headers['x-mcp-nonce'] });
      if (body.revision === 'stale') {
        response.writeHead(409).end(JSON.stringify({ error: 'Configuration changed; refresh before applying' }));
      } else {
        response.end(JSON.stringify({ ok: true, name: 'alpha', revision: 'revision-two', undoId: 'undo-one' }));
      }
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  snapshot.port = server.address().port;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolveClose) => server.close(resolveClose));
    rmSync(dir, { recursive: true, force: true });
  });
  const output = [];
  return {
    snapshot, posts, output, configPath,
    run: (options) => runPrewarm(options, { configPath, ports: [snapshot.port], write: (text) => output.push(text) }),
  };
}

test('prewarm view includes all stdio candidates and pooled servers without applying anything', async (t) => {
  const f = await fixture(t);
  await f.run({});
  assert.match(f.output[0], /alpha/);
  assert.match(f.output[0], /pooled/);
  assert.match(f.output[0], /multiplexed/);
  assert.match(f.output[0], /ready: 5 sessions, 2 pending, 1 queued/);
  assert.doesNotMatch(f.output[0], /remote/);
  assert.match(f.output[0], /91/);
  assert.equal(f.posts.length, 0);
  assert.match(formatPrewarm(f.snapshot), /STARTS/);
});

test('explicit CLI enable sends the shown size and revision with the admin nonce', async (t) => {
  const f = await fixture(t);
  await f.run({ enable: 'alpha' });
  assert.deepEqual(f.posts, [{
    path: '/admin/servers/alpha/pooling',
    body: { revision: 'revision-one', mode: 'pool', minWarm: 3 },
    nonce: 'nonce-for-test',
  }]);
  assert.match(f.output.join('\n'), /enabled 3 warm/);
  assert.match(f.output.join('\n'), /--undo undo-one/);
});

test('explicit CLI disable and undo do not invent or auto-apply recommendations', async (t) => {
  const f = await fixture(t);
  await f.run({ disable: 'pooled' });
  await f.run({ undo: 'undo-one', server: 'pooled' });
  assert.deepEqual(f.posts.map((post) => post.body), [
    { revision: 'revision-one', mode: 'isolated' },
    { revision: 'revision-one', undoId: 'undo-one' },
  ]);
});

test('generated Undo retains the explicitly selected config directory', async (t) => {
  const f = await fixture(t);
  await f.run({ enable: 'alpha', config: f.configPath });
  const undo = f.output.find((line) => line.startsWith('Undo:'));
  const quote = process.platform === 'win32' ? '"' : "'";
  assert.ok(undo.includes(`--config ${quote}${f.configPath}${quote}`));
  assert.ok(undo.includes(`--server ${quote}alpha${quote} --undo undo-one`));
});

test('Windows Undo commands preserve arguments in Command Prompt', { skip: process.platform !== 'win32' }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'pacemaker-undo-shell-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const capture = join(dir, 'args.json');
  writeFileSync(join(dir, 'cli.mjs'), "import fs from 'node:fs'; fs.writeFileSync(process.env.CAPTURE_ARGS, JSON.stringify(process.argv.slice(2)));\n");
  const module = join(dir, 'prewarm.mjs');
  writeFileSync(module, readFileSync(new URL('../bin/prewarm.mjs', import.meta.url)));
  const { formatUndoCommand: isolatedFormat } = await import(pathToFileURL(module));
  for (const [name, config] of [
    ['alpha', 'C:\\Config Dir\\servers.json'],
    ['special $name', 'C:\\Config %Dir%\\servers.json'],
  ]) {
    const command = isolatedFormat(12345, name, 'undo-one', config);
    const result = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `"${command}"`], {
      encoding: 'utf8',
      windowsVerbatimArguments: true,
      env: { ...process.env, CAPTURE_ARGS: capture, Dir: 'must-not-expand' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(readFileSync(capture, 'utf8')), [
      'prewarm', '--port', '12345', '--config', config, '--server', name, '--undo', 'undo-one',
    ]);
    const powershell = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(command, 'utf16le').toString('base64')], {
      encoding: 'utf8',
      env: { ...process.env, CAPTURE_ARGS: capture, Dir: 'must-not-expand' },
    });
    assert.equal(powershell.status, 0, powershell.stderr);
    assert.deepEqual(JSON.parse(readFileSync(capture, 'utf8')), [
      'prewarm', '--port', '12345', '--config', config, '--server', name, '--undo', 'undo-one',
    ]);
  }
});

test('invalid actions are rejected before an admin write', async (t) => {
  const f = await fixture(t);
  for (const options of [
    { enable: 'alpha', disable: 'alpha' },
    { count: '3' },
    { undo: 'undo-one' },
    { enable: 'alpha', count: '0' },
    { enable: 'alpha', count: '33' },
    { enable: 'alpha', count: '1.5' },
    { enable: 'remote' },
    { enable: 'multiplexed' },
    { enable: 'missing' },
  ]) {
    await assert.rejects(() => f.run(options));
  }
  assert.equal(f.posts.length, 0);
});

test('stale configuration errors are shown rather than reported as successful changes', async (t) => {
  const f = await fixture(t);
  f.snapshot.prewarm.revision = 'stale';
  await assert.rejects(() => f.run({ enable: 'alpha' }), /Configuration changed/);
  assert.equal(f.output.length, 0);
});

test('JSON view returns the same measured snapshot without mutations', async (t) => {
  const f = await fixture(t);
  await f.run({ json: true });
  assert.deepEqual(JSON.parse(f.output[0]), f.snapshot);
  assert.equal(f.posts.length, 0);
});
