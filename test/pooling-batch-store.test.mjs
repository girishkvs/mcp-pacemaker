import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import childProcess from 'node:child_process';
import {
  PoolingConfigStore, PoolingConfigError, recoverPoolingConfig, hasPoolingTransaction,
  MAX_UNDO_ENTRIES, MAX_UNDO_BYTES, MAX_CONFIG_BYTES, POOLING_SAVE_WARNING,
} from '../bin/pooling-config.mjs';
import { PoolingFiles, MAX_TRANSACTION_BYTES } from '../bin/pooling-files.mjs';
import { PoolingExecution } from '../bin/pooling-execution.mjs';

const BEFORE = '{\r\n  "alpha": {"command":"node","env":{"TOKEN":"private-canary"}},\r\n  "beta": {"command":"node"},\r\n  "other": {"command":"node"}\r\n}\r\n';
const CHILD = fileURLToPath(new URL('./fixtures/pooling-batch-crash.mjs', import.meta.url));

class Fixture {
  constructor(t, text = BEFORE, filename = 'servers.json') {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'mcp-batch-store-'));
    this.path = join(this.dir, filename);
    this.before = text;
    fs.writeFileSync(this.path, text, { mode: 0o600 });
    this.files = new PoolingFiles(this.path);
    this.store = new PoolingConfigStore(this.path);
    t.after(() => {
      this.store.close();
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  stage(name = 'alpha', minWarm = 2) {
    return this.store.stageApply({ name, mode: 'pool', minWarm, revision: this.store.revision() });
  }

  commit(receipt, execution) {
    return this.store.commitBatch({ batchId: receipt.batchId, generation: receipt.generation }, execution);
  }

  undo(receipt, name = 'alpha', revision = this.store.revision()) {
    return this.store.stageUndo({ name, undoId: receipt.undoId, revision });
  }

  text(path = this.path) { return fs.readFileSync(path, 'utf8'); }

  rejects(action, code, commitState) {
    assert.throws(action, (error) => {
      assert.ok(error instanceof PoolingConfigError);
      assert.equal(error.code, code);
      if (commitState) assert.equal(error.commitState, commitState);
      assert.equal(error.message.includes('private-canary'), false);
      assert.equal(error.message.includes(this.dir), false);
      return true;
    });
  }

  inspect(path = this.path) { return this.files.inspect(path); }

  async crashed(point, t) {
    const child = childProcess.spawn(process.execPath, [CHILD, this.path, point], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited;
    });
    await new Promise((resolve, reject) => {
      let output = '';
      let errors = '';
      const timer = setTimeout(() => reject(new Error(`Crash checkpoint timeout: ${errors}`)), 15000);
      child.stdout.on('data', (bytes) => {
        output += bytes;
        if (output.includes('CHECKPOINT\n')) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.stderr.on('data', (bytes) => { errors += bytes; });
      child.once('exit', () => {
        clearTimeout(timer);
        reject(new Error(`Child exited before crash checkpoint: ${errors}`));
      });
    });
    child.kill('SIGKILL');
    const exit = await exited;
    assert.ok(exit.code !== 0 || exit.signal !== null);
  }

  recoverChild() {
    const result = childProcess.spawnSync(process.execPath, [CHILD, this.path, 'recover'], {
      encoding: 'utf8', windowsHide: true, timeout: 15000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.stderr, '');
    return { status: result.status, value: JSON.parse(result.stdout) };
  }
}

test('complete pending copies merge server edits with a stable batch/token and new generation', (t) => {
  const f = new Fixture(t);
  const before = f.inspect();
  const first = f.stage();
  assert.equal(first.revision, before.revision);
  assert.equal(f.text(), BEFORE);
  assert.equal(f.text(f.files.paths.pending).includes('"TOKEN":"private-canary"'), true);
  const pendingBefore = f.inspect(f.files.paths.pending);
  const second = f.stage('beta', 3);
  assert.equal(second.batchId, first.batchId);
  assert.equal(second.undoId, first.undoId);
  assert.notEqual(second.generation, first.generation);
  assert.notEqual(f.inspect(f.files.paths.pending).identity, pendingBefore.identity);
  assert.equal(f.text(), BEFORE);
  assert.deepEqual(second.changes, [
    { name: 'alpha', mode: 'pool', minWarm: 2 }, { name: 'beta', mode: 'pool', minWarm: 3 },
  ]);
  assert.equal(JSON.stringify(second).includes('private-canary'), false);
  assert.equal(JSON.stringify(f.store.pendingSummary()).includes(first.undoId), false);
  const candidate = f.inspect(f.files.paths.pending);
  f.rejects(() => f.commit(first), 'BATCH_CONFLICT', 'not-committed');
  const result = f.commit(second);
  assert.equal(result.commitState, 'committed');
  assert.deepEqual(f.inspect(), candidate);
  assert.deepEqual(f.inspect(f.files.paths.previous), before);
  assert.equal(f.store.pendingSummary(), null);
});

test('invalid and no-op updates leave the accepted draft, receipt generation and active file unchanged', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const draft = f.inspect(f.files.paths.pending);
  f.rejects(() => f.stage('beta', 0), 'INVALID_REQUEST');
  const noop = f.stage();
  assert.equal(noop.pending, true);
  assert.equal(noop.accepted, false);
  assert.equal(noop.generation, first.generation);
  assert.equal(noop.revision, first.revision);
  assert.deepEqual(f.inspect(f.files.paths.pending), draft);
  assert.equal(f.store.pendingSummary().generation, first.generation);
  assert.equal(f.text(), BEFORE);
  f.commit(first);
});

test('an accepted edit back toward the active state still updates the existing draft', (t) => {
  const f = new Fixture(t, '{"alpha":{"command":"node","sharing":"isolated"},"beta":{"command":"node"}}');
  const first = f.stage();
  const reverted = f.store.stageApply({ name: 'alpha', mode: 'isolated', revision: first.revision });
  assert.equal(reverted.pending, true);
  assert.equal(reverted.batchId, first.batchId);
  assert.notEqual(reverted.generation, first.generation);
  assert.equal(f.text(f.files.paths.pending), f.before);
  const second = f.stage('beta');
  f.commit(second);
  assert.equal(JSON.parse(f.text()).alpha.sharing, 'isolated');
  assert.equal(JSON.parse(f.text()).beta.sharing, 'pool');
});

test('pending Undo through any included server cancels the whole batch only', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  f.stage('beta');
  f.rejects(() => f.undo(first, 'other'), 'UNDO_CONFLICT');
  const cancelled = f.undo(first, 'beta');
  assert.deepEqual(cancelled, { ok: true, cancelled: true, batchId: first.batchId, revision: first.revision });
  assert.equal(f.text(), BEFORE);
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  f.rejects(() => f.undo(first), 'UNDO_CONFLICT');
});

test('committed Undo stages the full preimage, reserves the token and consumes it only after commit', (t) => {
  const f = new Fixture(t);
  const receipt = f.stage();
  const last = f.stage('beta');
  f.commit(last);
  const committedText = f.text();
  const restore = f.undo(receipt, 'beta');
  assert.notEqual(restore.batchId, receipt.batchId);
  assert.notEqual(restore.undoId, receipt.undoId);
  assert.equal(f.text(), committedText);
  assert.equal(f.text(f.files.paths.pending), BEFORE);
  f.rejects(() => f.undo(receipt), 'UNDO_CONFLICT');
  f.undo(restore);
  const retry = f.undo(receipt);
  f.commit(retry);
  assert.equal(f.text(), BEFORE);
  f.rejects(() => f.undo(receipt), 'UNDO_CONFLICT');
  const redo = f.undo(retry, 'beta');
  f.commit(redo);
  assert.equal(f.text(), committedText);
});

test('a committed Undo never discards unrelated pending changes', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  f.commit(first);
  const pending = f.stage('beta');
  const draft = f.text(f.files.paths.pending);
  f.rejects(() => f.undo(first), 'PENDING_CONFLICT');
  assert.equal(f.store.pendingSummary().generation, pending.generation);
  assert.equal(f.text(f.files.paths.pending), draft);
  f.undo(pending, 'beta');
  const restoration = f.undo(first);
  f.commit(restoration);
  assert.equal(f.text(), BEFORE);
});

test('precommit expiry restores the reserved original Undo without entering a move', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  f.commit(first);
  const restoration = f.undo(first);
  const expired = new PoolingExecution(process.hrtime.bigint() - 1n);
  f.rejects(() => f.commit(restoration, expired), 'WRITER_DEADLINE', 'not-committed');
  const retry = f.undo(first);
  f.commit(retry);
  assert.equal(f.text(), BEFORE);
});

test('staging respects its helper budget without claiming commit; commit uses a fresh execution', (t) => {
  const f = new Fixture(t);
  const stagedExecution = new PoolingExecution(process.hrtime.bigint() + 9000000000n);
  const begin = t.mock.method(stagedExecution, 'beginCommit', () => { throw new Error('Stage must not commit'); });
  if (process.platform === 'win32') {
    const original = childProcess.spawnSync;
    t.mock.method(childProcess, 'spawnSync', (command, args, options) => {
      assert.ok(options.timeout > 0);
      assert.ok(options.timeout <= 9000);
      return original(command, args, options);
    });
  }
  const receipt = f.store.stageApply({ name: 'alpha', mode: 'pool', revision: f.store.revision() }, stagedExecution);
  assert.equal(begin.mock.callCount(), 0);
  stagedExecution.cancel(true);
  const fresh = new PoolingExecution(process.hrtime.bigint() + 9000000000n);
  let entered = false;
  const originalBegin = fresh.beginCommit.bind(fresh);
  t.mock.method(fresh, 'beginCommit', () => { originalBegin(); entered = true; });
  const move = PoolingFiles.prototype.move;
  t.mock.method(PoolingFiles.prototype, 'move', function (...args) {
    assert.equal(entered, true);
    return move.apply(this, args);
  });
  assert.equal(f.commit(receipt, fresh).commitState, 'committed');
});

test('cancellation during draft publication retains the prior native draft for a fresh execution', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const draft = f.inspect(f.files.paths.pending);
  const execution = new PoolingExecution(process.hrtime.bigint() + 9000000000n);
  const move = PoolingFiles.prototype.move;
  const mock = t.mock.method(PoolingFiles.prototype, 'move', function (source, ...args) {
    const result = move.call(this, source, ...args);
    if (source === this.paths.next) execution.cancel();
    return result;
  });
  f.rejects(() => f.store.stageApply({
    name: 'beta', mode: 'pool', revision: f.store.revision(),
  }, execution), 'WRITER_CANCELLED');
  mock.mock.restore();
  assert.equal(f.store.pendingSummary().generation, first.generation);
  assert.equal(f.text(), BEFORE);
  assert.deepEqual(f.inspect(f.files.paths.old), draft);
  f.commit(first);
  assert.equal(JSON.parse(f.text()).beta.sharing, undefined);
});

test('cancelled update after secure creation journals its unaccepted copy without losing the earlier draft', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const draft = f.inspect(f.files.paths.pending);
  const execution = new PoolingExecution(process.hrtime.bigint() + 9000000000n);
  const stage = PoolingFiles.prototype.stage;
  const mock = t.mock.method(PoolingFiles.prototype, 'stage', function (...args) {
    const result = stage.apply(this, args);
    execution.cancel();
    return result;
  });
  f.rejects(() => f.store.stageApply({
    name: 'beta', mode: 'pool', revision: f.store.revision(),
  }, execution), 'WRITER_CANCELLED');
  mock.mock.restore();
  assert.deepEqual(f.inspect(f.files.paths.pending), draft);
  assert.equal(f.store.pendingSummary().generation, first.generation);
  f.commit(first);
  assert.equal(JSON.parse(f.text()).beta.sharing, undefined);
  assert.equal(fs.existsSync(f.files.paths.next), false);
});

test('source content and same-byte object replacement conflict before active placement', (t) => {
  for (const sameBytes of [false, true]) {
    const f = new Fixture(t);
    const pending = f.stage();
    const edited = sameBytes ? BEFORE : BEFORE + '\n';
    const replacement = join(f.dir, 'editor.json');
    fs.writeFileSync(replacement, edited);
    fs.renameSync(replacement, f.path);
    const object = f.inspect();
    f.rejects(() => f.commit(pending), 'REVISION_CONFLICT', 'not-committed');
    assert.deepEqual(f.inspect(), object);
    assert.equal(f.text(), edited);
    assert.equal(fs.existsSync(f.files.paths.previous), false);
  }
});

test('external draft mutation is never activated or blindly deleted', (t) => {
  const f = new Fixture(t);
  const pending = f.stage();
  fs.writeFileSync(f.files.paths.pending, '{"alpha":{"command":"private-canary"}}');
  const contender = f.inspect(f.files.paths.pending);
  f.rejects(() => f.commit(pending), 'REVISION_CONFLICT', 'not-committed');
  assert.equal(f.text(), BEFORE);
  assert.deepEqual(f.inspect(f.files.paths.pending), contender);
  f.store.close();
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(f.files.paths.pending), contender);
});

test('repeated requests cannot bypass a rejected journal load or commit past it', (t) => {
  const f = new Fixture(t);
  fs.mkdirSync(f.files.directory, { mode: 0o700 });
  const path = join(f.files.directory, 'state-7.json');
  fs.writeFileSync(path, '{}', { mode: 0o600 });
  const active = f.inspect();
  const rejected = f.files.metadata(path);
  f.rejects(() => f.stage(), 'RECOVERY_REQUIRED');
  f.rejects(() => f.stage('beta'), 'RECOVERY_REQUIRED');
  f.rejects(() => f.stage(), 'RECOVERY_REQUIRED');
  assert.throws(() => f.store.commitBatch({ batchId: 'unaccepted', generation: 1 }), (error) => {
    assert.ok(error instanceof PoolingConfigError);
    assert.equal(error.commitState, 'not-committed');
    return true;
  });
  assert.deepEqual(f.inspect(), active);
  assert.deepEqual(f.files.metadata(path), rejected);
  assert.equal(f.text(), BEFORE);
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  assert.equal(fs.existsSync(f.files.paths.previous), false);
  assert.deepEqual(fs.readdirSync(f.files.directory).sort(), ['owner', 'state-7.json']);
  f.store.close();
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.files.metadata(path), rejected);
  assert.deepEqual(f.inspect(), active);
});

test('existing unowned pending and previous destinations are never overwritten', (t) => {
  for (const destination of ['pending', 'previous']) {
    const f = new Fixture(t);
    let receipt;
    if (destination === 'previous') receipt = f.stage();
    const path = f.files.paths[destination];
    fs.writeFileSync(path, 'private-canary');
    const contender = f.inspect(path);
    if (receipt) f.rejects(() => f.commit(receipt), 'REVISION_CONFLICT', 'not-committed');
    else f.rejects(() => f.stage(), 'RECOVERY_REQUIRED');
    assert.deepEqual(f.inspect(path), contender);
    assert.equal(f.text(), BEFORE);
  }
});

test('owned previous is rotated only after exact identity/content/security verification', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  f.commit(first);
  const second = f.stage('beta');
  fs.writeFileSync(f.files.paths.previous, 'external-previous');
  const previous = f.inspect(f.files.paths.previous);
  const active = f.inspect();
  f.rejects(() => f.commit(second), 'REVISION_CONFLICT', 'not-committed');
  assert.deepEqual(f.inspect(), active);
  assert.deepEqual(f.inspect(f.files.paths.previous), previous);
});

test('a failed update before publication preserves the original accepted draft', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const original = PoolingFiles.prototype.stage;
  const mock = t.mock.method(PoolingFiles.prototype, 'stage', () => { throw new Error('private-canary'); });
  f.rejects(() => f.stage('beta'), 'IO_ERROR');
  mock.mock.restore();
  assert.equal(PoolingFiles.prototype.stage, original);
  assert.equal(f.store.pendingSummary().generation, first.generation);
  f.commit(first);
  assert.equal(JSON.parse(f.text()).beta.sharing, undefined);
});

test('failed draft publication rolls back to the previous accepted native draft', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const draft = f.inspect(f.files.paths.pending);
  const move = PoolingFiles.prototype.move;
  let failed = false;
  t.mock.method(PoolingFiles.prototype, 'move', function (source, destination, ...args) {
    if (!failed && source === this.paths.next) {
      failed = true;
      throw new Error('private-canary');
    }
    return move.call(this, source, destination, ...args);
  });
  f.rejects(() => f.stage('beta'), 'IO_ERROR');
  assert.equal(failed, true);
  assert.deepEqual(f.inspect(f.files.paths.pending), draft);
  assert.equal(f.store.pendingSummary().generation, first.generation);
  f.commit(first);
});

test('second-move contender is retained; entered failure is unknown and not auto-retried', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const original = f.inspect();
  const candidate = f.inspect(f.files.paths.pending);
  const move = PoolingFiles.prototype.move;
  let contender;
  t.mock.method(PoolingFiles.prototype, 'move', function (source, destination, ...args) {
    if (destination === this.active) {
      fs.writeFileSync(this.active, 'external-contender');
      contender = this.inspect(this.active);
    }
    return move.call(this, source, destination, ...args);
  });
  f.rejects(() => f.commit(first), process.platform === 'win32' ? 'REVISION_CONFLICT' : 'IO_ERROR', 'unknown');
  assert.deepEqual(f.inspect(), contender);
  assert.deepEqual(f.inspect(f.files.paths.previous), original);
  assert.deepEqual(f.inspect(f.files.paths.pending), candidate);
  f.store.close();
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(), contender);
});

test('post-placement helper failure is classified committed, never not-committed', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  const move = PoolingFiles.prototype.move;
  t.mock.method(PoolingFiles.prototype, 'move', function (source, destination, ...args) {
    const result = move.call(this, source, destination, ...args);
    if (destination === this.active) throw new Error('private-canary');
    return result;
  });
  f.rejects(() => f.commit(first), 'IO_ERROR', 'committed');
  assert.equal(JSON.parse(f.text()).alpha.sharing, 'pool');
});

test('committed restoration failure does not claim its original Undo token is unused', (t) => {
  const f = new Fixture(t);
  const first = f.stage();
  f.commit(first);
  const restoration = f.undo(first);
  const move = PoolingFiles.prototype.move;
  t.mock.method(PoolingFiles.prototype, 'move', function (source, destination, ...args) {
    const result = move.call(this, source, destination, ...args);
    if (destination === this.active) throw new Error('private-canary');
    return result;
  });
  f.rejects(() => f.commit(restoration), 'IO_ERROR', 'committed');
  assert.equal(f.text(), BEFORE);
  f.rejects(() => f.undo(first), 'UNDO_CONFLICT');
});

test('a failed helper that leaves an unverified candidate never grants cleanup ownership', (t) => {
  const f = new Fixture(t);
  const stage = PoolingFiles.prototype.stage;
  t.mock.method(PoolingFiles.prototype, 'stage', function (...args) {
    stage.apply(this, args);
    throw new Error('private-canary');
  });
  f.rejects(() => f.stage(), 'IO_ERROR');
  const candidate = f.inspect(f.files.paths.pending);
  assert.equal(f.text(), BEFORE);
  f.store.close();
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(f.files.paths.pending), candidate);
});

test('source WRITE_DATA denial is not bypassed using writable parent replacement rights', (t) => {
  const f = new Fixture(t);
  if (process.platform === 'win32') {
    const account = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
    const deny = childProcess.spawnSync('icacls.exe', [f.path, '/deny', `${account}:(WD)`], { encoding: 'utf8' });
    assert.equal(deny.status, 0, deny.stderr);
    try {
      const original = f.inspect();
      f.rejects(() => f.stage(), 'ACCESS_DENIED');
      assert.deepEqual(f.inspect(), original);
      assert.equal(fs.existsSync(f.files.paths.pending), false);
    } finally {
      const restore = childProcess.spawnSync('icacls.exe', [f.path, '/remove:d', account], { encoding: 'utf8' });
      assert.equal(restore.status, 0, restore.stderr);
    }
  } else {
    fs.chmodSync(f.path, 0o400);
    f.rejects(() => f.stage(), process.getuid() === 0 ? 'ACCESS_DENIED' : 'IO_ERROR');
    assert.equal(fs.existsSync(f.files.paths.pending), false);
  }
  assert.equal(f.text(), BEFORE);
});

test('source DACL changes after staging conflict before the active move', {
  skip: process.platform !== 'win32',
}, (t) => {
  const f = new Fixture(t);
  const receipt = f.stage();
  const account = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
  const deny = childProcess.spawnSync('icacls.exe', [f.path, '/deny', `${account}:(WD)`], { encoding: 'utf8' });
  assert.equal(deny.status, 0, deny.stderr);
  try {
    const changed = f.inspect();
    f.rejects(() => f.commit(receipt), 'REVISION_CONFLICT', 'not-committed');
    assert.deepEqual(f.inspect(), changed);
    assert.equal(f.text(), BEFORE);
  } finally {
    const restore = childProcess.spawnSync('icacls.exe', [f.path, '/remove:d', account], { encoding: 'utf8' });
    assert.equal(restore.status, 0, restore.stderr);
  }
});

test('exclusive live ownership blocks a second store and startup recovery', (t) => {
  const f = new Fixture(t);
  f.stage();
  const other = new PoolingConfigStore(f.path);
  try {
    f.rejects(() => other.stageApply({ name: 'beta', mode: 'pool', revision: f.store.revision() }), 'STORE_BUSY');
    f.rejects(() => recoverPoolingConfig(f.path), 'STORE_BUSY');
  } finally { other.close(); }
  assert.equal(f.text(), BEFORE);
});

test('close never commits pending work; startup drops it without replay, including custom filenames', (t) => {
  const f = new Fixture(t, BEFORE, 'custom settings.配置.json');
  assert.equal(hasPoolingTransaction(f.path), false);
  f.stage();
  assert.equal(hasPoolingTransaction(f.path), true);
  f.store.close();
  assert.equal(f.text(), BEFORE);
  assert.equal(fs.existsSync(f.files.paths.pending), true);
  assert.deepEqual(recoverPoolingConfig(f.path), { outcome: 'discarded', commitState: 'not-committed' });
  assert.equal(f.text(), BEFORE);
  assert.equal(fs.existsSync(f.files.paths.pending), false);
});

test('journals are bounded metadata only and corrupt records fail closed', (t) => {
  const f = new Fixture(t);
  for (let index = 0; index < 40; index++) f.stage('alpha', index % 2 + 1);
  const names = fs.readdirSync(f.files.directory).filter((name) => name !== 'owner');
  assert.equal(names.length, 1);
  const path = join(f.files.directory, names[0]);
  const bytes = fs.readFileSync(path);
  assert.ok(bytes.length <= MAX_TRANSACTION_BYTES);
  const text = bytes.toString('utf8');
  for (const secret of ['private-canary', 'command', f.dir, 'undoId']) assert.equal(text.includes(secret), false);
  const pending = f.inspect(f.files.paths.pending);
  f.store.close();
  fs.writeFileSync(path, '{"private-canary"');
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(f.files.paths.pending), pending);
  assert.equal(f.text(), BEFORE);
});

test('oversized journal records fail closed before data-file recovery', (t) => {
  const f = new Fixture(t);
  f.stage();
  const name = fs.readdirSync(f.files.directory).find((entry) => entry.startsWith('state-'));
  const pending = f.inspect(f.files.paths.pending);
  f.store.close();
  fs.writeFileSync(join(f.files.directory, name), 'x'.repeat(MAX_TRANSACTION_BYTES + 1));
  f.rejects(() => recoverPoolingConfig(f.path), 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(f.files.paths.pending), pending);
  assert.equal(f.text(), BEFORE);
});

for (const limit of ['count', 'bytes']) {
  test(`whole-batch Undo retention is bounded by ${limit}`, (t) => {
    const size = MAX_CONFIG_BYTES - 1024;
    const before = limit === 'bytes'
      ? JSON.stringify({ alpha: { command: 'node', env: { PADDING: 'x'.repeat(size) } } })
      : BEFORE;
    const f = new Fixture(t, before);
    const first = f.stage();
    f.commit(first);
    const activeAtFirst = f.text();
    const count = limit === 'count' ? MAX_UNDO_ENTRIES : Math.floor(MAX_UNDO_BYTES / Buffer.byteLength(before)) + 1;
    for (let index = 0; index < count; index++) {
      const receipt = f.stage('alpha', index % 2 + 3);
      f.commit(receipt);
    }
    fs.writeFileSync(f.path, activeAtFirst);
    f.rejects(() => f.undo(first), 'UNDO_CONFLICT');
  });
}

test('audit inheritance notice is nonblocking and does not claim custom auditing was detected', () => {
  assert.equal(POOLING_SAVE_WARNING,
    'New config copies inherit folder auditing. Custom per-file audit rules may not carry forward.');
});

for (const point of ['pending', 'before-first', 'between', 'after-second', 'complete', 'first-link', 'second-link']) {
  test(`actual process death at ${point} has bounded validated startup recovery`, {
    skip: process.platform === 'win32' && point.endsWith('-link'),
  }, async (t) => {
    const f = new Fixture(t);
    const original = f.inspect();
    await f.crashed(point, t);
    const candidate = point === 'complete' || point === 'after-second'
      ? f.inspect() : f.files.inspect(f.files.paths.pending, undefined, 2);
    const result = f.recoverChild();
    assert.equal(result.status, 0, JSON.stringify(result.value));
    if (point === 'pending') {
      assert.equal(result.value.outcome, 'discarded');
      assert.deepEqual(f.inspect(), original);
      assert.equal(fs.existsSync(f.files.paths.pending), false);
    } else {
      assert.ok(['none', 'committed'].includes(result.value.outcome));
      assert.deepEqual(f.inspect(), candidate);
      assert.deepEqual(f.inspect(f.files.paths.previous), original);
      assert.equal(JSON.parse(f.text()).alpha.minWarm, 2);
    }
    assert.equal(f.recoverChild().status, 0);
  });
}

test('actual crash recovery refuses an active contender without rollback or clobber', async (t) => {
  const f = new Fixture(t);
  const original = f.inspect();
  await f.crashed('between', t);
  const pending = f.inspect(f.files.paths.pending);
  fs.writeFileSync(f.path, 'external-contender');
  const contender = f.inspect();
  const recovered = f.recoverChild();
  assert.equal(recovered.status, 1);
  assert.equal(recovered.value.code, 'RECOVERY_REQUIRED');
  assert.deepEqual(f.inspect(), contender);
  assert.deepEqual(f.inspect(f.files.paths.previous), original);
  assert.deepEqual(f.inspect(f.files.paths.pending), pending);
});

for (const point of ['update-between', 'update-after']) {
  test(`actual crash during ${point} discards both unentered drafts without changing active`, async (t) => {
    const f = new Fixture(t);
    const original = f.inspect();
    await f.crashed(point, t);
    const recovered = f.recoverChild();
    assert.equal(recovered.status, 0, JSON.stringify(recovered.value));
    assert.equal(recovered.value.outcome, 'discarded');
    assert.deepEqual(f.inspect(), original);
    for (const key of ['pending', 'old', 'next']) assert.equal(fs.existsSync(f.files.paths[key]), false);
  });
}
