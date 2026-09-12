import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { killBridge } from '../helpers/kill-bridge.mjs';
import { ROOT, isolatedEnvironment, ownedDirectory, removeOwnedDirectory } from '../../tools/compatibility/fixtures.mjs';

export async function waitFor(read, predicate, label) {
  const deadline = Date.now() + 20000;
  do {
    const value = await read();
    if (predicate(value)) return value;
    await delay(50);
  } while (Date.now() < deadline);
  throw new Error(`Timed out: ${label}`);
}

export function assertSnapshot(snapshot, version) {
  assert.equal(snapshot.service, 'mcp-pacemaker');
  assert.equal(snapshot.version, version);
  assert.ok(snapshot.instanceId);
  assert.ok(snapshot.prewarm.revision);
  assert.ok(snapshot.servers.some((server) => server.name === 'alpha'));
}

export function assertImmediate(body, version) {
  assert.equal(body.ok, true);
  assert.equal(body.name, 'alpha');
  assert.notEqual(body.pending, true);
  assert.ok(body.revision);
  assert.ok(body.undoId);
  assertSnapshot(body.snapshot, version);
}

export function assertPending(body) {
  assertImmediate({ ...body, pending: false }, '2.0.0');
  assert.equal(body.pending, true);
  assert.ok(body.batchId);
  assert.ok(Number.isSafeInteger(body.snapshot.snapshotVersion));
  assert.ok(body.snapshot.snapshotVersion > 0);
  assert.equal(body.snapshot.prewarm.revision, body.revision);
  const batch = body.snapshot.prewarm.batches.find((item) => item.id === body.batchId);
  assert.equal(batch.status, 'pending');
  assert.equal(batch.revision, body.revision);
  assert.ok(Number.isFinite(batch.applyAt));
  assert.ok(batch.changes.some((change) => change.name === 'alpha'));
}

export class CompatibilityBridge {
  constructor() {
    this.owned = ownedDirectory();
    this.dir = this.owned.dir;
    this.env = isolatedEnvironment(this.dir);
    this.config = join(this.dir, 'servers.json');
    const definition = {
      command: process.execPath,
      args: [join(ROOT, 'test', 'fixtures', 'pool-child.mjs'), '--startup-delay', '150'],
      env: { COMPAT_SENTINEL: 'preserve-unrelated-config' },
    };
    this.original = JSON.stringify({ alpha: definition, beta: definition }, null, 2) + '\n';
    writeFileSync(this.config, this.original);
    this.logs = [];
  }

  async start(root, version) {
    assert.equal(this.running, undefined);
    if (!this.port) {
      const probe = createServer();
      probe.listen(0, '127.0.0.1');
      await once(probe, 'listening');
      this.port = probe.address().port;
      await new Promise((resolveClose, reject) => probe.close((error) => error ? reject(error) : resolveClose()));
      this.base = `http://127.0.0.1:${this.port}`;
    }
    const child = spawn(process.execPath, [
      join(root, 'bin', 'mcp-bridge.mjs'), '--host', '127.0.0.1',
      '--port', String(this.port), '--config', this.config,
    ], { cwd: this.dir, env: this.env, stdio: ['ignore', 'pipe', 'pipe'] });
    const running = { child, version, stdout: '', stderr: '', closed: false };
    this.running = running;
    this.logs.push(running);
    child.stdout.on('data', (bytes) => { running.stdout += bytes; });
    child.stderr.on('data', (bytes) => { running.stderr += bytes; });
    child.once('error', (error) => { running.error = error; });
    running.exit = new Promise((resolveExit) => child.once('close', (code, signal) => {
      running.closed = true;
      resolveExit({ code, signal });
    }));
    const snapshot = await waitFor(async () => {
      if (running.error) throw running.error;
      assert.equal(running.closed, false, `Bridge exited before startup\n${running.stderr}`);
      try { return await this.snapshot(); }
      catch (error) {
        if (error.cause?.code !== 'ECONNREFUSED') throw error;
        return null;
      }
    }, Boolean, `bridge ${version} startup`);
    assertSnapshot(snapshot, version);
    this.nonce = readFileSync(join(this.dir, 'admin.nonce'), 'utf8').trim();
    return snapshot;
  }

  async stop() {
    if (!this.running) return;
    const running = this.running;
    if (!running.closed) killBridge(running.child);
    await running.exit;
    this.running = undefined;
  }

  async request(method, path, body, headers = {}) {
    const response = await fetch(this.base + path, {
      method, headers: { 'content-type': 'application/json', 'x-mcp-nonce': this.nonce ?? '', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const text = await response.text();
    return {
      status: response.status, text,
      body: response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : undefined,
      headers: response.headers,
    };
  }

  async snapshot() {
    const response = await this.request('GET', '/api/status');
    assert.equal(response.status, 200, response.text);
    return response.body;
  }

  async mutation(body, batch = true) {
    const snapshot = await this.snapshot();
    return this.request('POST', '/admin/servers/alpha/pooling', {
      revision: snapshot.prewarm.revision, ...body,
    }, batch ? { 'x-mcp-pooling-batch': '1' } : {});
  }

  async seedAdvice() {
    for (let index = 0; index < 3; index++) {
      const initialized = await this.request('POST', '/alpha/mcp', {
        jsonrpc: '2.0', id: index + 1, method: 'initialize', params: {},
      });
      assert.equal(initialized.status, 200, initialized.text);
      assert.ok(initialized.body.result);
      const closed = await this.request('DELETE', '/alpha/mcp', undefined, {
        'mcp-session-id': initialized.headers.get('mcp-session-id'),
      });
      assert.ok(closed.status >= 200 && closed.status < 300, closed.text);
    }
    await waitFor(() => this.snapshot(),
      (snapshot) => snapshot.servers.find((server) => server.name === 'alpha').prewarming.eligible,
      'real cold starts produce pre-warming advice');
  }

  async cli(root, args, expectedCode = 0, command = 'prewarm') {
    const child = spawn(process.execPath, [
      join(root, 'bin', 'cli.mjs'), command, '--port', String(this.port), '--config', this.config, ...args,
    ], { cwd: this.dir, env: this.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (bytes) => { stdout += bytes; });
    child.stderr.on('data', (bytes) => { stderr += bytes; });
    const timeout = setTimeout(() => killBridge(child), 20000);
    try {
      const [code] = await once(child, 'close');
      this.logs.push({ version: `CLI: ${args.join(' ')}`, stdout, stderr });
      assert.equal(code, expectedCode, `CLI exit ${code}\n${stdout}\n${stderr}`);
      return { stdout, stderr };
    } finally {
      clearTimeout(timeout);
    }
  }

  async applied(id) {
    return waitFor(() => this.snapshot(), (snapshot) => {
      const batch = snapshot.prewarm.batches.find((item) => item.id === id);
      assert.notEqual(batch?.status, 'failed', JSON.stringify(batch));
      return batch?.status === 'applied';
    }, `batch ${id} applies`);
  }

  async assertUnchanged() {
    assert.equal(this.text(), this.original);
    const snapshot = await this.snapshot();
    assert.equal(snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
    assert.equal((snapshot.prewarm.batches ?? []).some((batch) => ['pending', 'applying'].includes(batch.status)), false);
  }

  text() {
    return readFileSync(this.config, 'utf8');
  }

  assertEnabled() {
    const expected = JSON.parse(this.original);
    expected.alpha.sharing = 'pool';
    expected.alpha.minWarm = 1;
    assert.deepEqual(JSON.parse(this.text()), expected);
  }

  async run(t, action) {
    let failed = false;
    try { await action(this); }
    catch (error) {
      failed = true;
      for (const log of this.logs) t.diagnostic(`${log.version}\n${log.stdout}\n${log.stderr}`);
      throw error;
    } finally {
      try {
        await this.stop();
        removeOwnedDirectory(this.owned);
      } catch (error) {
        if (!failed) throw error;
        t.diagnostic(`Cleanup also failed: ${error.stack}`);
      }
    }
  }
}
