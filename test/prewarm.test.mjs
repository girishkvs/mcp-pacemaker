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
  const batchHeaders = [];
  let responseBody = { ok: true, name: 'alpha', revision: 'revision-two', undoId: 'undo-one' };
  let responseStatus;
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
      batchHeaders.push(request.headers['x-mcp-pooling-batch']);
      if (body.revision === 'stale') {
        response.writeHead(409).end(JSON.stringify({ error: 'Configuration changed; refresh before applying' }));
      } else {
        response.statusCode = responseStatus ?? (responseBody.pending ? 202 : 200);
        response.end(JSON.stringify(responseBody));
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
    snapshot, posts, output, configPath, batchHeaders,
    setResponse: (value, status) => { responseBody = value; responseStatus = status; },
    pendingReceipt: (changes = [{ name: 'alpha', mode: 'pool', minWarm: 3 }]) => {
      snapshot.snapshotVersion = 2;
      snapshot.prewarm.batchDelayMs = 5000;
      snapshot.prewarm.batches = [{
        id: 'batch-one', status: 'pending', applyAt: Date.now() + 5000,
        revision: snapshot.prewarm.revision, changes,
      }];
      return {
        ok: true, name: 'alpha', pending: true, batchId: 'batch-one',
        revision: snapshot.prewarm.revision, undoId: 'batch-token',
        snapshot: structuredClone(snapshot),
      };
    },
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

test('batched enable reports staged settings and sends the batch protocol header', async (t) => {
  const f = await fixture(t);
  f.setResponse(f.pendingReceipt([
    { name: 'alpha', mode: 'pool', minWarm: 3 }, { name: 'pooled', mode: 'isolated' },
  ]));
  await f.run({ enable: 'alpha' });
  assert.deepEqual(f.batchHeaders, ['1']);
  assert.ok(f.output[0].includes('3 warm slot(s) staged'));
  assert.ok(f.output[0].includes('Pending reload'));
  assert.ok(f.output[0].includes('not active yet'));
  assert.equal(f.output[0].includes('enabled'), false);
  assert.ok(f.output[1].includes('entire batch: alpha, pooled'));
  assert.ok(f.output[1].includes('--undo batch-token'));
});

test('batched disable and restoration do not claim completed activation', async (t) => {
  const f = await fixture(t);
  f.setResponse(f.pendingReceipt([{ name: 'alpha', mode: 'isolated' }]));
  await f.run({ disable: 'alpha' });
  await f.run({ undo: 'batch-token', server: 'alpha' });
  const messages = f.output.filter((line) => line.includes('not active yet'));
  assert.equal(messages.length, 2);
  assert.ok(messages[0].includes('pre-warming disable staged'));
  assert.ok(messages[1].includes('previous batch configuration staged'));
});

test('cancelling a pending batch is reported separately from an applied undo', async (t) => {
  const f = await fixture(t);
  f.setResponse({ ok: true, name: 'alpha', cancelled: true, revision: 'revision-one', snapshot: f.snapshot });
  await f.run({ undo: 'batch-token', server: 'alpha' });
  assert.deepEqual(f.output, ['alpha: pending batch cancelled. Active settings were not changed.']);
});

test('prewarm table keeps active values and separately reports pending, applying and failed batches', async (t) => {
  const f = await fixture(t);
  f.snapshot.prewarm.batches = [
    { id: 'pending', status: 'pending', applyAt: Date.now() + 5000,
      changes: [{ name: 'alpha', mode: 'pool', minWarm: 3 }] },
    { id: 'applying', status: 'applying', applyAt: null,
      changes: [{ name: 'pooled', mode: 'isolated' }] },
    { id: 'failed', status: 'failed', applyAt: null, error: 'Config changed.',
      changes: [{ name: 'alpha', mode: 'isolated' }] },
  ];
  const text = formatPrewarm(f.snapshot);
  assert.ok(text.includes('isolated'));
  assert.ok(text.includes('Pending batch (reload in'));
  assert.ok(text.includes('Active settings above have not changed.'));
  assert.ok(text.includes('Applying batch: pooled: pre-warming off.'));
  assert.ok(text.includes('Batch failed (alpha: pre-warming off): Config changed.'));
  assert.equal(f.posts.length, 0);
});

test('JSON stage result preserves the pending receipt without inventing applied state', async (t) => {
  const f = await fixture(t);
  const receipt = f.pendingReceipt();
  f.setResponse(receipt);
  await f.run({ enable: 'alpha', json: true });
  assert.deepEqual(JSON.parse(f.output[0]), receipt);
});

test('a later successful batch does not leave an old failure in the current CLI view', async (t) => {
  const f = await fixture(t);
  f.snapshot.prewarm.batches = [
    { id: 'new', status: 'applied', applyAt: null,
      changes: [{ name: 'alpha', mode: 'pool', minWarm: 3 }] },
    { id: 'old', status: 'failed', applyAt: null, error: 'Old failure.',
      changes: [{ name: 'alpha', mode: 'pool', minWarm: 1 }] },
  ];
  assert.equal(formatPrewarm(f.snapshot).includes('Old failure.'), false);
});

test('an unreadable pending receipt is not reported as a successful queued change', async (t) => {
  const f = await fixture(t);
  f.setResponse({ ok: true, pending: true, name: 'alpha' });
  await assert.rejects(() => f.run({ enable: 'alpha' }),
    (error) => error.message.includes('receipt'));
  assert.deepEqual(f.output, []);
});

test('the audit inheritance notice is informational and does not block a queued save', async (t) => {
  const f = await fixture(t);
  const notice = 'File saves inherit audit rules from the containing folder. Custom per-file audit rules may not carry forward.';
  f.snapshot.prewarm.saveWarning = notice;
  f.setResponse(f.pendingReceipt());
  await f.run({ enable: 'alpha' });
  assert.equal(f.posts.length, 1);
  assert.equal(f.output[0], `File save notice: ${notice}`);
  assert.ok(f.output[1].includes('not active yet'));
  assert.ok(formatPrewarm(f.snapshot).includes(`File save notice: ${notice}`));
});

test('JSON output retains the save notice in the snapshot without adding non-JSON lines', async (t) => {
  const f = await fixture(t);
  f.snapshot.prewarm.saveWarning = 'Directory-inherited auditing is used.';
  const receipt = f.pendingReceipt();
  f.setResponse(receipt);
  await f.run({ enable: 'alpha', json: true });
  assert.equal(f.output.length, 1);
  assert.deepEqual(JSON.parse(f.output[0]), receipt);
});

for (const [label, change] of [
  ['missing pending marker', (receipt) => { delete receipt.pending; }],
  ['missing private token', (receipt) => { delete receipt.undoId; }],
  ['missing matching summary', (receipt) => { receipt.snapshot.prewarm.batches = []; }],
  ['missing snapshot', (receipt) => { delete receipt.snapshot; }],
  ['wrong batch id', (receipt) => { receipt.batchId = 'another-batch'; }],
  ['wrong server', (receipt) => { receipt.name = 'another-server'; }],
  ['missing snapshot ordering', (receipt) => { delete receipt.snapshot.snapshotVersion; }],
  ['invalid countdown', (receipt) => { receipt.snapshot.prewarm.batches[0].applyAt = 'later'; }],
  ['invalid requested settings', (receipt) => { receipt.snapshot.prewarm.batches[0].changes[0].minWarm = -1; }],
]) {
  test(`HTTP status: malformed 202 with ${label} is not reported as enabled or queued`, async (t) => {
    const f = await fixture(t);
    const receipt = f.pendingReceipt();
    change(receipt);
    f.setResponse(receipt, 202);
    await assert.rejects(() => f.run({ enable: 'alpha' }));
    assert.deepEqual(f.output, []);
  });
}

test('HTTP status: a pending body on HTTP 200 is rejected instead of changing protocol meanings', async (t) => {
  const f = await fixture(t);
  f.setResponse(f.pendingReceipt(), 200);
  await assert.rejects(() => f.run({ enable: 'alpha' }));
  assert.deepEqual(f.output, []);
});

test('HTTP status: an unsupported success status cannot claim activation', async (t) => {
  const f = await fixture(t);
  f.setResponse({ ok: true, name: 'alpha', revision: 'revision-two' }, 201);
  await assert.rejects(() => f.run({ enable: 'alpha' }));
  assert.deepEqual(f.output, []);
});

test('restored target: a pooled preimage without minWarm is a valid pending Undo', async (t) => {
  const f = await fixture(t);
  f.setResponse(f.pendingReceipt([{ name: 'alpha', mode: 'pool' }]));
  await f.run({ undo: 'previous-batch-token', server: 'alpha' });
  assert.ok(f.output[0].includes('previous batch configuration staged'));
  assert.ok(f.output[0].includes('not active yet'));
  assert.equal(f.output.join('\n').includes('undefined'), false);
});

test('restored target: a merged receipt can include a restored automatic target on another server', async (t) => {
  const f = await fixture(t);
  f.setResponse(f.pendingReceipt([
    { name: 'alpha', mode: 'pool', minWarm: 3 },
    { name: 'pooled', mode: 'pool' },
  ]));
  await f.run({ enable: 'alpha' });
  assert.ok(f.output[0].includes('3 warm slot(s) staged'));
  assert.ok(f.output[1].includes('alpha, pooled'));
});

test('restored target: the pending view does not invent a numeric target for an omitted setting', async (t) => {
  const f = await fixture(t);
  f.pendingReceipt([{ name: 'alpha', mode: 'pool' }]);
  const text = formatPrewarm(f.snapshot);
  assert.ok(text.includes('alpha: pooling with configured target'));
  assert.equal(text.includes('undefined warm'), false);
});
