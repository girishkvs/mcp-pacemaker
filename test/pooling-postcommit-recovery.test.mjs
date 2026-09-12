// Integration listeners use port 0; no fixed test port is reserved by this file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { PoolingConfigStore, recoverPoolingConfig } from '../bin/pooling-config.mjs';
import { PoolingFiles, hashBytes } from '../bin/pooling-files.mjs';
import { PoolingExecution, POOLING_BUDGET_MS } from '../bin/pooling-execution.mjs';
import { PostCommitFault } from './fixtures/pooling-postcommit-fault.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const BRIDGE = fileURLToPath(new URL('./fixtures/pooling-postcommit-bridge.mjs', import.meta.url));
const PRELOAD = new URL('./fixtures/pooling-postcommit-preload.mjs', import.meta.url).href;

class Fixture {
  constructor(t) {
    this.t = t;
    this.dir = fs.mkdtempSync(join(tmpdir(), 'pooling-postcommit-'));
    this.path = join(this.dir, 'servers.json');
    this.original = Buffer.from(JSON.stringify({
      alpha: { command: process.execPath, args: [join(ROOT, 'test/fixtures/echo-mcp-server.mjs')] },
      beta: { command: process.execPath, args: [join(ROOT, 'test/fixtures/echo-mcp-server.mjs')] },
    }) + '\r\n');
    fs.writeFileSync(this.path, this.original, { mode: 0o600 });
    this.files = new PoolingFiles(this.path);
    this.store = new PoolingConfigStore(this.path);
    this.children = [];
    t.after(async () => {
      this.fault?.restore();
      this.store.close();
      for (const entry of this.children) await this.stop(entry);
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  stage(name = 'alpha', minWarm = 2) {
    return this.store.stageApply({ name, mode: 'pool', minWarm, revision: this.store.revision() });
  }

  commit(receipt, execution) {
    return this.store.commitBatch({ batchId: receipt.batchId, generation: receipt.generation }, execution);
  }

  record() {
    const records = fs.readdirSync(this.files.directory).filter((name) => name.startsWith('state-'));
    records.sort((a, b) => Number(a.split('-')[1].split('.')[0]) - Number(b.split('-')[1].split('.')[0]));
    const path = join(this.files.directory, records.at(-1));
    return { path, value: JSON.parse(fs.readFileSync(path, 'utf8')) };
  }

  rewriteRecord(change) {
    const record = this.record();
    change(record.value);
    record.value.checksum = hashBytes(Buffer.from(JSON.stringify(record.value.state)));
    fs.writeFileSync(record.path, JSON.stringify(record.value));
  }

  rejects(action, code, state) {
    assert.throws(action, (error) => {
      assert.equal(error.code, code);
      if (state) assert.equal(error.commitState, state);
      assert.equal(error.message.includes(this.dir), false);
      return true;
    });
  }

  failedUndo(realExpiry = false) {
    const enabled = this.stage();
    this.commit(enabled);
    this.enabled = this.files.inspect(this.path);
    const undo = this.store.stageUndo({
      name: 'alpha', undoId: enabled.undoId, revision: this.store.revision(),
    });
    this.draft = this.files.inspect(this.files.paths.pending);
    this.fault = new PostCommitFault(this.path, { realExpiry });
    this.fault.install();
    const execution = new PoolingExecution(process.hrtime.bigint() + BigInt(POOLING_BUDGET_MS) * 1000000n);
    try {
      this.rejects(() => this.commit(undo, execution), 'IO_ERROR', 'unknown');
    } finally {
      this.fault.restore();
    }
    assert.ok(this.fault.placed);
    if (realExpiry) {
      assert.ok(this.fault.expiredAfterPlacement);
      assert.ok(this.fault.helperResults.length >= 2);
      assert.ok(this.fault.helperResults.every((item) => item.timeoutMs === 1 &&
        item.errorCode === 'ETIMEDOUT'));
    }
    assert.equal(this.store.pendingSummary(), null);
    assert.ok(fs.readFileSync(this.path).equals(this.original));
    this.rejects(() => this.store.stageUndo({
      name: 'alpha', undoId: enabled.undoId, revision: this.store.revision(),
    }), 'UNDO_CONFLICT');
    this.rejects(() => this.stage('beta'), 'RECOVERY_REQUIRED');
    this.rejects(() => recoverPoolingConfig(this.path), 'STORE_BUSY');
    this.t.diagnostic(JSON.stringify({
      phaseAfterFailure: this.record().value.state.phase, failedOperationState: 'unknown',
      originalBytesPlaced: true, realExpiry, helperResults: this.fault.helperResults,
    }));
    this.store.close();
    return undo;
  }

  verifyRecovered() {
    const active = this.files.inspect(this.path);
    const previous = this.files.inspect(this.files.paths.previous);
    assert.ok(JSON.stringify(active) === JSON.stringify(this.draft), 'Active ownership/content/security changed');
    assert.ok(JSON.stringify(previous) === JSON.stringify(this.enabled), 'Previous ownership/content/security changed');
    assert.ok(fs.readFileSync(this.path).equals(this.original));
    assert.equal(fs.existsSync(this.files.paths.pending), false);
    assert.equal(this.record().value.state.phase, 'idle');
  }

  fingerprint() {
    const entries = {};
    for (const path of [this.path, ...Object.values(this.files.paths), this.record().path]) {
      if (!fs.existsSync(path)) {
        entries[path] = null;
        continue;
      }
      const stat = fs.statSync(path);
      entries[path] = {
        identity: `${stat.dev}:${stat.ino}`, content: hashBytes(fs.readFileSync(path)),
      };
    }
    return hashBytes(Buffer.from(JSON.stringify(entries)));
  }

  async start({ fault = false, realExpiry = false } = {}) {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !key.startsWith('MCP_') && !['NODE_OPTIONS', 'NODE_PATH'].includes(key)));
    Object.assign(env, {
      MCP_RESUME: '0', MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0',
      MCP_IDLE_TIMEOUT_MS: '0', MCP_HEALTH_INTERVAL_MS: '0', MCP_LOG_MAX_BYTES: '0',
      MCP_TEST_POSTCOMMIT_EXPIRY: realExpiry ? '1' : '0',
    });
    const args = [...(fault ? ['--import', PRELOAD] : []), BRIDGE,
      '--config', this.path, '--host', '127.0.0.1', '--port', '0'];
    const child = spawn(process.execPath, args, {
      cwd: this.dir, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.stdout.resume();
    child.stderr.resume();
    const entry = { child, exit: once(child, 'exit'), evidence: [] };
    this.children.push(entry);
    child.on('message', (message) => {
      if (message.postcommitTestEvidence) entry.evidence.push(message);
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Owned bridge startup watchdog expired')), 15000);
      child.on('message', (message) => {
        if (message.startupFailure) {
          clearTimeout(timer);
          reject(new Error(`Owned startup refused: ${message.startupFailure}`));
        } else if (message.ready) {
          clearTimeout(timer);
          entry.port = message.port;
          resolve();
        }
      });
      child.once('exit', () => {
        clearTimeout(timer);
        reject(new Error('Owned bridge exited before startup'));
      });
    });
    this.bridge = entry;
    this.nonce = fs.readFileSync(join(this.dir, 'admin.nonce'), 'utf8').trim();
    return this.status();
  }

  async stop(entry = this.bridge) {
    if (!entry) return;
    if (entry.child.exitCode === null &&
        entry.child.signalCode === null &&
        entry.child.connected) entry.child.send({ shutdown: true });
    await entry.exit;
  }

  async request(path, body, headers = {}) {
    const response = await fetch(`http://127.0.0.1:${this.bridge.port}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', 'x-mcp-nonce': this.nonce,
        'x-mcp-pooling-batch': '1', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10000),
    });
    return { status: response.status, body: await response.json(), headers: response.headers };
  }

  async status() {
    const result = await this.request('/api/status');
    assert.equal(result.status, 200);
    return result.body;
  }

  async stageHttp(body) {
    const result = await this.request('/admin/servers/alpha/pooling', body);
    assert.equal(result.status, 202);
    return result.body;
  }
}

test('staging and Undo retain the caller default owner and exact access security', {
  skip: process.platform !== 'win32',
}, (t) => {
  const f = new Fixture(t);
  const before = f.files.inspect(f.path);
  const pending = f.stage();
  const draft = f.files.inspect(f.files.paths.pending);
  assert.ok(draft.security === before.security, 'Staging changed fresh default-owner access security');
  assert.ok(draft.identity !== before.identity);
  f.commit(pending);
  assert.ok(f.files.inspect(f.path).security === before.security);
  const undo = f.store.stageUndo({
    name: 'alpha', undoId: pending.undoId, revision: f.store.revision(),
  });
  f.commit(undo);
  assert.ok(f.files.inspect(f.path).security === before.security);
  assert.ok(fs.readFileSync(f.path).equals(f.original));
});

test('default-owner retention cannot bypass denied source WRITE_DATA', {
  skip: process.platform !== 'win32',
}, (t) => {
  const f = new Fixture(t);
  const setup = spawnSync('pwsh.exe', ['-NoProfile', '-File',
    join(ROOT, 'test/fixtures/pooling-deny-default-owner-write.ps1'), '-Path', f.path], {
    windowsHide: true, encoding: 'utf8', timeout: 10000,
  });
  assert.equal(setup.status, 0, 'Owned default-owner denial fixture setup failed');
  const before = f.files.inspect(f.path);
  f.rejects(() => f.stage(), 'ACCESS_DENIED');
  assert.ok(JSON.stringify(f.files.inspect(f.path)) === JSON.stringify(before));
  assert.ok(fs.readFileSync(f.path).equals(f.original));
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  assert.equal(f.store.pendingSummary(), null);
});

test('real post-placement verification expiry remains recoverable with a fresh execution', {
  skip: process.platform !== 'win32',
}, (t) => {
  const f = new Fixture(t);
  f.failedUndo(true);
  const recovered = recoverPoolingConfig(f.path);
  assert.equal(recovered.outcome, 'committed');
  f.verifyRecovered();
  assert.equal(recoverPoolingConfig(f.path).outcome, 'none');
  f.store = new PoolingConfigStore(f.path);
  const next = f.stage('beta', 3);
  assert.equal(f.commit(next).commitState, 'committed');
  assert.equal(JSON.parse(fs.readFileSync(f.path, 'utf8')).beta.minWarm, 3);
});

test('startup verifies a transient post-placement failure before loading and permits the next write', async (t) => {
  const f = new Fixture(t);
  f.failedUndo();
  const snapshot = await f.start();
  f.verifyRecovered();
  assert.equal(snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
  const pending = await f.stageHttp({ mode: 'pool', minWarm: 3, revision: snapshot.prewarm.revision });
  assert.equal((await f.request('/admin/reload', {})).status, 200);
  const after = await f.status();
  assert.equal(after.prewarm.batches.find((batch) => batch.id === pending.batchId).status, 'applied');
  assert.equal(after.servers.find((server) => server.name === 'alpha').minWarm, 3);
});

test('HTTP post-placement expiry stays failed and reconciled; restart keeps the placed bytes', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const f = new Fixture(t);
  let snapshot = await f.start({ fault: true, realExpiry: true });
  const initialized = await f.request('/alpha/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(initialized.status, 200);
  const session = initialized.headers.get('mcp-session-id');
  snapshot = await f.status();
  const activePid = snapshot.servers.find((server) => server.name === 'alpha').pids[0];
  const enabled = await f.stageHttp({ mode: 'pool', minWarm: 2, revision: snapshot.prewarm.revision });
  assert.equal((await f.request('/admin/reload', {})).status, 200);
  snapshot = await f.status();
  f.enabled = f.files.inspect(f.path);
  const undo = await f.stageHttp({ undoId: enabled.undoId, revision: snapshot.prewarm.revision });
  f.draft = f.files.inspect(f.files.paths.pending);
  const failed = await f.request('/admin/reload', {});
  assert.equal(failed.status, 504);
  const deadline = Date.now() + 10000;
  while (!f.bridge.evidence.length) {
    assert.ok(Date.now() < deadline, 'Writer did not deliver its bounded late outcome');
    await delay(25);
  }
  const evidence = f.bridge.evidence[0];
  assert.equal(evidence.code, 'IO_ERROR');
  assert.equal(evidence.commitState, 'unknown');
  assert.equal(evidence.expiredAfterPlacement, true);
  assert.ok(evidence.helperResults.every((item) => item.timeoutMs === 1 && item.errorCode === 'ETIMEDOUT'));
  snapshot = await f.status();
  const batch = snapshot.prewarm.batches.find((item) => item.id === undo.batchId);
  assert.equal(batch.status, 'failed');
  assert.equal(batch.commitState, 'committed');
  assert.equal(batch.revision, hashBytes(f.original));
  assert.equal(snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
  assert.ok(snapshot.servers.find((server) => server.name === 'alpha').pids.includes(activePid));
  assert.equal((await f.request('/alpha/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { 'mcp-session-id': session })).status, 200);
  t.diagnostic(JSON.stringify({
    publicStatus: batch.status, publicCommitState: batch.commitState,
    writerCode: evidence.code, writerCommitState: evidence.commitState,
    phaseAfterFailure: f.record().value.state.phase, activeSessionPreserved: true,
  }));
  await f.stop();
  await f.start();
  f.verifyRecovered();
});

for (const change of [
  'active-content', 'active-same-bytes-replaced', 'previous-content', 'previous-same-bytes-replaced',
  'active-security', 'previous-security', 'missing-active', 'missing-previous',
  'pending-contender', 'next-contender', 'old-contender', 'previous-extra-link',
  'corrupt-checksum', 'malformed-journal', 'generic-failed-journal',
]) {
  test(`post-placement recovery rejects ${change} without modifying transaction data`, (t) => {
    const f = new Fixture(t);
    f.failedUndo();
    const target = change.startsWith('previous') || change === 'missing-previous'
      ? f.files.paths.previous : f.path;
    if (change.endsWith('-content')) {
      fs.appendFileSync(target, '\n');
    } else if (change.endsWith('-same-bytes-replaced')) {
      const bytes = fs.readFileSync(target);
      fs.renameSync(target, join(f.dir, 'retained-owned-object.json'));
      fs.writeFileSync(target, bytes, { mode: 0o600 });
    } else if (change.endsWith('-security')) {
      if (process.platform === 'win32') {
        const account = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
        const deny = spawnSync('icacls.exe', [target, '/deny', `${account}:(WD)`], { encoding: 'utf8' });
        assert.equal(deny.status, 0, 'Owned synthetic write-denial setup failed');
      } else {
        fs.chmodSync(target, 0o400);
      }
    } else if (change.startsWith('missing-')) {
      fs.renameSync(target, join(f.dir, 'retained-owned-object.json'));
    } else if (change.endsWith('-contender')) {
      const role = change.split('-')[0];
      fs.writeFileSync(f.files.paths[role], f.original, { mode: 0o600 });
    } else if (change === 'previous-extra-link') {
      fs.linkSync(target, join(f.dir, 'unaccounted-link.json'));
    } else if (change === 'corrupt-checksum') {
      const record = f.record();
      record.value.checksum = '0'.repeat(64);
      fs.writeFileSync(record.path, JSON.stringify(record.value));
    } else if (change === 'malformed-journal') {
      fs.writeFileSync(f.record().path, '{}');
    } else {
      f.rewriteRecord((value) => { value.state.phase = 'failed'; });
    }
    const before = f.fingerprint();
    f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
    assert.equal(f.fingerprint(), before);
    f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
    assert.equal(f.fingerprint(), before);
  });
}
