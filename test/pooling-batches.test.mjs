import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PoolingBatches } from '../bin/pooling-batches.mjs';
import { recoverPoolingConfig } from '../bin/pooling-files.mjs';

class Fixture {
  constructor(t) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'pooling-coordinator-'));
    this.path = join(this.dir, 'custom settings.配置.json');
    this.original = '{"alpha":{"command":"node"},"beta":{"command":"node"}}\r\n';
    fs.writeFileSync(this.path, this.original);
    this.memory = this.original;
    this.errors = [];
    this.reloads = 0;
    this.snapshotVersion = 0;
    this.batches = new PoolingBatches({
      configPath: this.path, revision: () => this.revision(),
      captureSnapshot: () => this.snapshot(),
      reload: () => {
        const bytes = fs.readFileSync(this.path, 'utf8');
        JSON.parse(bytes);
        this.memory = bytes;
        this.reloads++;
        return { ok: true, added: [], removed: [], changed: ['alpha'], restarted: 0 };
      },
      notify: () => this.onNotify?.(),
      onError: (error) => this.errors.push(error.code),
    });
    t.after(async () => {
      await this.batches.close();
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  revision() { return createHash('sha256').update(this.memory).digest('hex'); }
  snapshot() {
    return {
      snapshotVersion: ++this.snapshotVersion,
      prewarm: { revision: this.revision(), ...this.batches.snapshot() },
    };
  }
  stage(name = 'alpha', mode = 'pool', minWarm = 1) {
    return this.batches.stage({ name, mode, revision: this.revision(),
      ...(mode === 'pool' ? { minWarm } : {}) });
  }
  undo(receipt, name = 'alpha') {
    return this.batches.stage({ name, undoId: receipt.undoId, revision: this.revision() });
  }
  summary(id) { return this.batches.snapshot().batches.find((batch) => batch.id === id); }
}

test('coordinator merges private receipts while publishing only active values and bounded summaries', async (t) => {
  const f = new Fixture(t);
  const first = await f.stage();
  const second = await f.stage('beta', 'pool', 2);
  assert.equal(first.batchId, second.batchId);
  assert.equal(first.undoId, second.undoId);
  for (const field of ['generation', 'draftRevision', 'changes', 'accepted']) {
    assert.equal(Object.hasOwn(second, field), false);
  }
  assert.equal(f.memory, f.original);
  assert.equal(f.summary(first.batchId).status, 'pending');
  assert.equal(JSON.stringify(f.batches.snapshot()).includes(first.undoId), false);
  await f.batches.reloadNow();
  assert.equal(f.summary(first.batchId).status, 'applied');
  assert.equal(f.summary(first.batchId).revision, f.revision());
  assert.equal(f.summary(first.batchId).applyAt, null);
  assert.equal(JSON.parse(f.memory).alpha.minWarm, 1);
  assert.equal(JSON.parse(f.memory).beta.minWarm, 2);
  assert.equal(f.reloads, 1);
});

test('stage snapshots capture the accepted record and active base before a queued reload', async (t) => {
  const f = new Fixture(t);
  const baseRevision = f.revision();
  f.onNotify = () => {
    f.onNotify = undefined;
    fs.writeFileSync(f.path, f.original + '\n');
  };
  const staged = f.stage().then((receipt) => ({
    ...receipt, snapshot: receipt.snapshot ?? f.snapshot(),
  }));
  const reload = f.batches.reloadSaved('queued external edit');
  const receipt = await staged;
  await reload;
  assert.notEqual(f.revision(), baseRevision);
  assert.equal(receipt.revision, baseRevision);
  assert.equal(receipt.snapshot.prewarm.revision, baseRevision);
  const batch = receipt.snapshot.prewarm.batches.find((record) => record.id === receipt.batchId);
  assert.equal(batch.status, 'pending');
  assert.equal(batch.revision, baseRevision);
  assert.deepEqual(batch.changes, [{ name: 'alpha', mode: 'pool', minWarm: 1 }]);
  assert.ok(Number.isSafeInteger(receipt.snapshot.snapshotVersion));
  assert.ok(receipt.snapshot.snapshotVersion > 0);
});

test('captured batch summaries stay unchanged after merging and applying', async (t) => {
  const f = new Fixture(t);
  const first = await f.stage();
  const snapshot = first.snapshot ?? f.snapshot();
  const captured = structuredClone(snapshot);
  await f.stage('beta', 'pool', 2);
  assert.deepEqual(snapshot, captured);
  const publicSummary = f.summary(first.batchId);
  publicSummary.status = 'cancelled';
  publicSummary.changes[0].minWarm = 31;
  assert.equal(f.summary(first.batchId).status, 'pending');
  assert.equal(f.summary(first.batchId).changes[0].minWarm, 1);
  await f.batches.reloadNow();
  assert.equal(f.summary(first.batchId).status, 'applied');
  assert.deepEqual(snapshot, captured);
});

test('invalid updates and already-pending no-ops do not reset the accepted deadline', async (t) => {
  const f = new Fixture(t);
  const first = await f.stage();
  const applyAt = f.summary(first.batchId).applyAt;
  await assert.rejects(f.stage('beta', 'pool', 0), { code: 'INVALID_REQUEST' });
  const repeated = await f.stage();
  assert.equal(repeated.pending, true);
  assert.equal(repeated.batchId, first.batchId);
  assert.ok(Math.abs(f.summary(first.batchId).applyAt - applyAt) <= 20);
  const activeNoop = await f.stage('beta', 'isolated');
  assert.equal(activeNoop.pending, undefined);
  assert.equal(f.memory, f.original);
  await f.undo(first);
  assert.equal(f.summary(first.batchId).status, 'cancelled');
});

test('batch Undo restores all included servers and cancellation retains the original committed token', async (t) => {
  const f = new Fixture(t);
  const first = await f.stage();
  await f.stage('beta');
  await f.batches.reloadNow();
  const saved = f.memory;
  const restoration = await f.undo(first, 'beta');
  assert.equal(f.memory, saved);
  assert.equal(f.summary(restoration.batchId).changes.length, 2);
  await f.undo(restoration, 'beta');
  assert.equal(f.memory, saved);
  const retry = await f.undo(first);
  await f.batches.reloadNow();
  assert.equal(f.summary(retry.batchId).status, 'applied');
  assert.equal(f.memory, f.original);
});

test('watcher reload does not flush a pending batch or overwrite an external active edit', async (t) => {
  const f = new Fixture(t);
  const receipt = await f.stage();
  fs.writeFileSync(f.path, f.original + '\n');
  await f.batches.reloadSaved('external edit');
  assert.equal(f.memory, f.original + '\n');
  assert.equal(f.summary(receipt.batchId).status, 'pending');
  await assert.rejects(f.batches.reloadNow(), { code: 'REVISION_CONFLICT', commitState: 'not-committed' });
  assert.equal(f.summary(receipt.batchId).status, 'failed');
  assert.equal(f.summary(receipt.batchId).commitState, 'not-committed');
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original + '\n');
});

test('coordinator queue remains bounded before requests enter the worker', async (t) => {
  const f = new Fixture(t);
  const started = performance.now();
  const outcomes = await Promise.allSettled(Array.from({ length: 17 }, () => f.stage('alpha', 'isolated')));
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 16);
  assert.equal(outcomes.filter((result) => result.reason?.code === 'WRITER_BUSY').length, 1);
  assert.ok(performance.now() - started < 10000);
  assert.equal(f.batches.snapshot().batches.length, 0);
  assert.equal(f.memory, f.original);
});

test('shutdown never starts the pending commit and startup discards it without replay', async (t) => {
  const f = new Fixture(t);
  await f.stage();
  await f.batches.close();
  assert.equal(f.reloads, 0);
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
  assert.deepEqual(recoverPoolingConfig(f.path), { outcome: 'discarded', commitState: 'not-committed' });
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
  await assert.rejects(f.stage(), { code: 'WRITER_CLOSED' });
});
