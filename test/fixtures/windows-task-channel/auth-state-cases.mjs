import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, fork } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fixtureRoot = fileURLToPath(new URL('../../../', import.meta.url));
const sourceRoot = process.env.MCP_TASK_CHANNEL_TEST_MODULE
  ? dirname(dirname(process.env.MCP_TASK_CHANNEL_TEST_MODULE)) : fixtureRoot;
const output = process.env.MCP_TASK_CHANNEL_TEST_EVIDENCE;
const windows = { skip: process.platform !== 'win32', timeout: 60000 };
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

class Case {
  constructor(t) {
    this.root = mkdtempSync(join(tmpdir(), 'mcp-auth-state-owned-'));
    this.records = [];
    this.events = [];
    this.waiters = [];
    this.pending = new Map();
    this.acks = [];
    this.receipt = { test: t.name, sourceRoot, root: this.root };
    t.after(() => this.cleanup());
    this.save('start', this.receipt);
  }

  save(name, value) {
    if (!output) return;
    writeFileSync(join(output, `${basename(this.root)}-${name}.json`), JSON.stringify(value, null, 2) + '\n');
  }

  record(identity) {
    if (!identity) return;
    this.records.push(identity);
    this.save('identities', this.records);
  }

  inspect(identity, stop = false) {
    const args = ['-NoProfile', '-NonInteractive', '-File',
      join(fixtureRoot, 'test/fixtures/windows-process-lifetime/identity.ps1'), '-ProcessId', String(identity.pid)];
    if (identity.creationTime) args.push('-CreationTicks', String(BigInt(identity.creationTime) + 504911232000000000n));
    if (stop) args.push('-StopOwned');
    const call = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    assert.equal(call.status, 0, call.stderr);
    return JSON.parse(call.stdout);
  }

  async wait(check, milliseconds = 10000) {
    const end = Date.now() + milliseconds;
    while (Date.now() < end) {
      const value = check();
      if (value) return value;
      if (this.exited) throw new Error(`Guard exited: ${JSON.stringify(this.events)}`);
      await delay(20);
    }
    throw new Error('Owned condition deadline');
  }

  async start(prepeer = false) {
    const pack = join(this.root, 'pack');
    const build = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File',
      join(here, 'build-auth-barrier.ps1'), '-SourceRoot', sourceRoot, '-Destination', pack],
    { encoding: 'utf8', windowsHide: true, timeout: 120000 });
    this.receipt.build = { code: build.status, stdout: build.stdout, stderr: build.stderr };
    assert.equal(build.status, 0, build.stderr);
    const { queryCliCallerContext } = await import(pathToFileURL(join(pack, 'bin/windows-task-channel.mjs')).href);
    const caller = await queryCliCallerContext();
    this.record(caller.guardIdentity);
    const helper = join(pack, 'bin/windows-task-channel/TaskChannelGuard.exe');
    this.receipt.variantSha256 = hash(helper);
    this.guard = spawn(helper, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.guard.stdin.on('error', () => {});
    this.guard.stdout.setEncoding('utf8');
    let buffer = '';
    this.guard.stdout.on('data', text => {
      buffer += text;
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const value = JSON.parse(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
        this.events.push(value);
        if (value.type === 'started') this.record(value.guardIdentity);
        if (value.type === 'authorized') {
          this.acks.push(value.id);
          this.pending.get(value.id)?.resolve(value);
          this.pending.delete(value.id);
        }
        if (value.type === 'failed') this.reject(new Error(value.reason));
      }
    });
    this.guard.stderr.resume();
    this.exit = new Promise(resolve => this.guard.once('close', (code, signal) => {
      this.exited = { code, signal };
      this.reject(new Error(`guard-exit-${code}`));
      resolve(this.exited);
    }));
    const scriptPath = join(this.root, 'worker.mjs');
    copyFileSync(join(here, 'read-state-worker.mjs'), scriptPath);
    const operationId = randomUUID();
    this.guard.stdin.write(JSON.stringify({
      action: 'serve', operationId, targetSid: caller.identity.ownerSid, sessionId: caller.identity.sessionId,
      manifestParent: this.root, document: { opaque: 'owned-barrier' },
      bootstrap: { nodePath: process.execPath, nodeSha256: hash(process.execPath),
        scriptPath, scriptSha256: hash(scriptPath) },
      handshakeTimeoutMs: 15000, lifetimeMs: 45000,
    }) + '\n');
    const ready = await this.wait(() => this.events.find(event => event.type === 'ready'), 15000);
    if (!prepeer) {
      this.worker = fork(scriptPath, ['--manifest', ready.manifestPath, '--operation', operationId,
        '--controller-root', this.root], { execPath: process.execPath, execArgv: [],
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
      this.worker.stdout.resume();
      this.worker.stderr.resume();
      const initial = this.inspect({ pid: this.worker.pid });
      this.workerIdentity = { pid: this.worker.pid, creationTime: initial.creationFileTime };
      this.record(this.workerIdentity);
      await this.wait(() => this.events.find(event => event.type === 'worker'), 15000);
    }
    return this;
  }

  reject(error) {
    for (const value of this.pending.values()) value.reject(error);
    this.pending.clear();
  }

  authorize(id = 1) {
    const promise = new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
    promise.catch(() => {});
    this.guard.stdin.write(JSON.stringify({ action: 'authorize', id }) + '\n');
    return promise;
  }

  async entered() {
    await this.wait(() => existsSync(join(this.root, 'auth-entered.json')));
    this.receipt.barrierEntered = true;
  }

  async readState() {
    const file = join(this.root, 'peer-read-state.json');
    await this.wait(() => existsSync(file));
    this.receipt.peerReadBeforeRelease = JSON.parse(readFileSync(file));
    return this.receipt.peerReadBeforeRelease;
  }

  release() {
    writeFileSync(join(this.root, 'auth-release'), 'owned-release');
  }

  raw(bytes) {
    this.worker.send({ action: 'raw', base64: bytes.toString('base64') });
  }

  async cleanup() {
    const errors = [];
    if (existsSync(this.root)) this.release();
    if (this.guard?.stdin.writable) this.guard.stdin.end();
    if (this.exit) await Promise.race([this.exit, delay(6500)]);
    if (this.worker?.connected) this.worker.send({ action: 'exit' });
    await delay(200);
    const seen = new Set(), cleanup = [];
    for (const identity of this.records) {
      const key = `${identity.pid}:${identity.creationTime}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try {
        let state = this.inspect(identity);
        if (!state.gone) state = this.inspect(identity, true);
        assert.equal(state.gone, true);
        cleanup.push({ identity, final: state });
      } catch (error) { errors.push(error.message); }
    }
    this.receipt.events = this.events;
    this.receipt.acknowledgements = this.acks;
    this.receipt.exit = this.exited;
    this.receipt.cleanup = cleanup;
    this.receipt.errors = errors;
    this.save('receipt', this.receipt);
    this.save('cleanup', { cleanup, errors, exits: this.exited ? [this.exited] : [] });
    if (!errors.length) rmSync(this.root, { recursive: true, force: true });
    this.save('removed', { removed: !existsSync(this.root) });
    assert.deepEqual(errors, []);
  }
}

for (const [name, bytes] of [
  ['invalid UTF8', Buffer.from([255, 10])],
  ['invalid JSON', Buffer.from('invalid\n')],
  ['nonobject', Buffer.from('[]\n')],
]) {
  test(`task channel rejects completed ${name} before authorization acknowledgement`, windows, async t => {
    const fixture = await new Case(t).start();
    const authorization = fixture.authorize().then(() => ({ accepted: true }), error => ({ accepted: false, reason: error.message }));
    await fixture.entered();
    fixture.raw(bytes);
    const state = await fixture.readState();
    assert.equal(state.completed, true);
    assert.equal(state.faulted, true);
    fixture.release();
    const result = await authorization;
    fixture.receipt.authorization = result;
    assert.equal(result.accepted, false);
    assert.deepEqual(fixture.acks, []);
    assert.equal(fixture.inspect(fixture.workerIdentity).gone, false);
  });
}

for (const action of ['exit', 'disconnect']) {
  test(`task channel refuses authorization when peer ${action} occurs during token observation`, windows, async t => {
    const fixture = await new Case(t).start();
    fixture.release();
    const started = Date.now();
    await fixture.authorize();
    fixture.receipt.priorAuthorizationMs = Date.now() - started;
    assert.equal(fixture.inspect(fixture.workerIdentity).gone, false);
    assert.deepEqual(fixture.acks, [1]);
    rmSync(join(fixture.root, 'auth-release'));
    rmSync(join(fixture.root, 'auth-entered.json'));
    const authorization = fixture.authorize(2).then(
      () => ({ accepted: true }),
      error => ({ accepted: false, reason: error.message }),
    );
    await fixture.entered();
    assert.deepEqual(fixture.acks, [1]);
    const workerExit = new Promise(resolve => fixture.worker.once('exit', resolve));
    fixture.worker.send({ action });
    assert.equal((await fixture.readState()).completed, true);
    if (action === 'exit') await workerExit;
    fixture.receipt.peerGoneBeforeRelease = fixture.inspect(fixture.workerIdentity).gone;
    assert.equal(fixture.receipt.peerGoneBeforeRelease, action === 'exit');
    assert.deepEqual(fixture.acks, [1]);
    fixture.release();
    const result = await authorization;
    fixture.receipt.authorization = result;
    assert.equal(result.accepted, false);
    assert.match(result.reason, /PEER_EXITED|CHANNEL_DISCONNECTED/);
    assert.deepEqual(fixture.acks, [1]);
    assert.equal((await fixture.exit).code, 3);
  });
}

for (const phase of ['prepeer', 'postpeer']) {
  for (const action of ['close', 'EOF']) {
    test(`task channel ${phase} ${action} cancels blocked authorization`, windows, async t => {
      const fixture = await new Case(t).start(phase === 'prepeer');
      const authorization = fixture.authorize().then(() => ({ accepted: true }), error => ({ accepted: false, reason: error.message }));
      await fixture.entered();
      const start = Date.now();
      if (action === 'close') fixture.guard.stdin.write('{"action":"close"}\n');
      else fixture.guard.stdin.end();
      await delay(1500);
      fixture.receipt.cancelElapsedMs = Date.now() - start;
      fixture.receipt.exitedBeforeBarrierRelease = Boolean(fixture.exited);
      assert.equal(Boolean(fixture.exited), true);
      const result = await authorization;
      fixture.receipt.authorization = result;
      assert.equal(result.accepted, false);
      assert.deepEqual(fixture.acks, []);
      if (fixture.worker) assert.equal(fixture.inspect(fixture.workerIdentity).gone, false);
    });
  }

}

test('task channel preserves valid opaque frames and FIFO commands across authorization', windows, async t => {
  const fixture = await new Case(t).start();
  const first = fixture.authorize();
  await fixture.entered();
  const frame = { payload: 'eyJvcGFxdWUiOnRydWV9', sequence: 'worker-owned-not-native-command' };
  fixture.raw(Buffer.from(JSON.stringify(frame) + '\n'));
  assert.equal((await fixture.readState()).faulted, false);
  const second = fixture.authorize(2);
  fixture.release();
  await first;
  await second;
  assert.deepEqual(fixture.acks, [1, 2]);
  const received = await fixture.wait(() => fixture.events.find(event => event.type === 'frame'));
  assert.deepEqual(received.frame, frame);
  fixture.raw(Buffer.from('{"payload":"second"}\n'));
  await fixture.wait(() => fixture.events.filter(event => event.type === 'frame').length === 2);
  assert.deepEqual(fixture.events.filter(event => event.type === 'frame').map(event => event.frame), [frame, { payload: 'second' }]);
});

for (const action of ['close', 'EOF']) {
  test(`task channel ${action} stays observable behind a queued authorization`, windows, async t => {
    const fixture = await new Case(t).start();
    const first = fixture.authorize().then(() => true, () => false);
    await fixture.entered();
    const second = fixture.authorize(2).then(() => true, () => false);
    if (action === 'close') fixture.guard.stdin.write('{"action":"close"}\n');
    else fixture.guard.stdin.end();
    await delay(1500);
    assert.ok(fixture.exited);
    assert.equal(await first, false);
    assert.equal(await second, false);
    assert.deepEqual(fixture.acks, []);
    assert.equal(fixture.inspect(fixture.workerIdentity).gone, false);
  });
}

for (const fault of ['duplicate sequence', 'queue overflow']) {
  test(`task channel refuses ${fault} while authorization is blocked`, windows, async t => {
    const fixture = await new Case(t).start();
    const first = fixture.authorize().then(() => true, () => false);
    await fixture.entered();
    if (fault === 'duplicate sequence') fixture.guard.stdin.write('{"action":"authorize","id":1}\n');
    else {
      for (let id = 2; id <= 34; id++) fixture.guard.stdin.write(JSON.stringify({ action: 'authorize', id }) + '\n');
    }
    await delay(1500);
    assert.ok(fixture.exited);
    assert.equal(await first, false);
    assert.deepEqual(fixture.acks, []);
    assert.equal(fixture.inspect(fixture.workerIdentity).gone, false);
  });
}
