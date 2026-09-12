import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import workerThreads from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';
import { setTimeout as delay } from 'node:timers/promises';
import { PoolingConfigWriter } from '../bin/pooling-writer.mjs';
import { PoolingFiles } from '../bin/pooling-files.mjs';
import { PoolingBatches } from '../bin/pooling-batches.mjs';

class Fixture {
  constructor(t) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'pooling-publication-'));
    this.path = join(this.dir, 'servers.json');
    this.original = '{"alpha":{"command":"node"},"beta":{"command":"node"}}\n';
    this.memory = this.original;
    fs.writeFileSync(this.path, this.original);
    this.files = new PoolingFiles(this.path);
    const fixture = this;
    const OriginalWorker = workerThreads.Worker;
    workerThreads.Worker = class extends OriginalWorker {
      constructor(url, options) {
        super(url, { ...options,
          execArgv: ['--import', new URL('./fixtures/pooling-stage-publication.mjs', import.meta.url).href],
        });
        this.on('message', (message) => {
          if (fixture.abortOnReply &&
              message.result?.pending) fixture.controller.abort();
          if (fixture.abortOnCancelReply &&
              message.result?.cancelled) fixture.controller.abort();
        });
      }
    };
    syncBuiltinESMExports();
    this.writer = new PoolingConfigWriter(this.path);
    this.batches = new PoolingBatches({
      configPath: this.path,
      revision: () => createHash('sha256').update(this.memory).digest('hex'),
      reload: () => {
        this.memory = fs.readFileSync(this.path, 'utf8');
        return { ok: true };
      },
      notify: () => {},
      onError: () => {},
    });
    t.after(async () => {
      this.flag('release-cancellation');
      await this.batches.close();
      await this.writer.close();
      workerThreads.Worker = OriginalWorker;
      syncBuiltinESMExports();
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  revision() { return createHash('sha256').update(fs.readFileSync(this.path)).digest('hex'); }
  request(name) { return { name, mode: 'pool', minWarm: 1, revision: this.revision() }; }
  cancelPublication() { fs.writeFileSync(join(this.dir, 'cancel-publication'), 'cancel'); }
  allowPublication() { fs.unlinkSync(join(this.dir, 'cancel-publication')); }
  commit(receipt) {
    return this.writer.commitBatch({ batchId: receipt.batchId, generation: receipt.generation });
  }
  flag(name) { fs.writeFileSync(join(this.dir, name), name); }
  summary(id) { return this.batches.snapshot().batches.find((batch) => batch.id === id); }
  stage(name) { return this.batches.stage(this.request(name)); }
  cancel(receipt, options = {}) {
    return this.batches.stage({
      name: 'alpha', undoId: receipt.undoId, revision: this.revision(),
    }, options);
  }
  async waitFor(predicate) {
    const deadline = Date.now() + 4000;
    while (!predicate()) {
      assert.ok(Date.now() < deadline, 'Cancellation checkpoint was not reached');
      await delay(10);
    }
  }
  cancellationCount() {
    return fs.readFileSync(join(this.dir, 'completed-cancellations'), 'utf8').split('\n').filter(Boolean).length;
  }
  async verifyNextBatch(receipt) {
    const second = await this.stage('beta');
    assert.notEqual(second.batchId, receipt.batchId);
    await this.batches.reloadNow();
    assert.equal(this.summary(receipt.batchId).status, 'cancelled');
    assert.equal(this.summary(receipt.batchId).applyAt, null);
    assert.equal(this.summary(second.batchId).status, 'applied');
    assert.equal(JSON.parse(this.memory).alpha.sharing, undefined);
    assert.equal(JSON.parse(this.memory).beta.minWarm, 1);
    assert.equal(this.cancellationCount(), 1);
  }
}

test('a cancelled first publication cannot be merged into a later accepted batch', async (t) => {
  const f = new Fixture(t);
  f.cancelPublication();
  await assert.rejects(f.writer.stageApply(f.request('beta')), { code: 'WRITER_CANCELLED' });
  f.allowPublication();
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
  await f.commit(await f.writer.stageApply(f.request('alpha')));
  const active = JSON.parse(fs.readFileSync(f.path, 'utf8'));
  assert.equal(active.alpha.sharing, 'pool');
  assert.equal(active.beta.sharing, undefined);
});

test('a cancelled update restores the exact previously accepted draft and generation', async (t) => {
  const f = new Fixture(t);
  const accepted = await f.writer.stageApply(f.request('alpha'));
  const descriptor = f.files.inspect(f.files.paths.pending);
  f.cancelPublication();
  await assert.rejects(f.writer.stageApply(f.request('beta')), { code: 'WRITER_CANCELLED' });
  f.allowPublication();
  assert.deepEqual(f.files.inspect(f.files.paths.pending), descriptor);
  await f.commit(accepted);
  assert.equal(JSON.parse(fs.readFileSync(f.path, 'utf8')).beta.sharing, undefined);
});

test('abandoned restoration publication releases the original Undo reservation', async (t) => {
  const f = new Fixture(t);
  const applied = await f.writer.apply(f.request('alpha'));
  const request = { name: 'alpha', undoId: applied.undoId, revision: applied.revision };
  f.cancelPublication();
  await assert.rejects(f.writer.stageUndo(request), { code: 'WRITER_CANCELLED' });
  f.allowPublication();
  await f.commit(await f.writer.stageUndo(request));
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
});

test('abort observed after worker completion but before receipt restores the earlier draft', async (t) => {
  const f = new Fixture(t);
  const accepted = await f.writer.stageApply(f.request('alpha'));
  const descriptor = f.files.inspect(f.files.paths.pending);
  f.controller = new AbortController();
  f.abortOnReply = true;
  await assert.rejects(f.writer.stageApply(f.request('beta'), { signal: f.controller.signal }),
    { code: 'WRITER_CANCELLED' });
  f.abortOnReply = false;
  assert.deepEqual(f.files.inspect(f.files.paths.pending), descriptor);
  await f.commit(accepted);
  assert.equal(JSON.parse(fs.readFileSync(f.path, 'utf8')).beta.sharing, undefined);
});

test('completed cancellation is reconciled when execution completion rejects its acknowledgement', async (t) => {
  const f = new Fixture(t);
  const receipt = await f.stage('alpha');
  const active = f.files.inspect(f.path);
  f.flag('cancel-cancellation');
  await assert.rejects(f.cancel(receipt), { code: 'WRITER_CANCELLED' });
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  assert.deepEqual(f.files.inspect(f.path), active);
  assert.equal(f.summary(receipt.batchId).status, 'cancelled');
  await f.verifyNextBatch(receipt);
});

test('completed cancellation is reconciled after the caller has already abandoned the request', async (t) => {
  const f = new Fixture(t);
  const receipt = await f.stage('alpha');
  f.flag('hold-cancellation');
  const controller = new AbortController();
  const cancelled = assert.rejects(f.cancel(receipt, { signal: controller.signal }), { code: 'WRITER_CANCELLED' });
  await f.waitFor(() => fs.existsSync(join(f.dir, 'cancellation-completed')));
  controller.abort();
  await cancelled;
  assert.equal(fs.existsSync(f.files.paths.pending), false);
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
  const next = f.verifyNextBatch(receipt);
  f.flag('release-cancellation');
  await next;
});

test('completed cancellation is reconciled when the caller aborts before receiving its worker reply', async (t) => {
  const f = new Fixture(t);
  const receipt = await f.stage('alpha');
  f.controller = new AbortController();
  f.abortOnCancelReply = true;
  await assert.rejects(f.cancel(receipt, { signal: f.controller.signal }), { code: 'WRITER_CANCELLED' });
  f.abortOnCancelReply = false;
  assert.equal(f.summary(receipt.batchId).status, 'cancelled');
  await f.verifyNextBatch(receipt);
});

test('completed cancellation of a restoration retains the original committed Undo token', async (t) => {
  const f = new Fixture(t);
  const original = await f.stage('alpha');
  await f.batches.reloadNow();
  const restoration = await f.cancel(original);
  f.flag('cancel-cancellation');
  await assert.rejects(f.cancel(restoration), { code: 'WRITER_CANCELLED' });
  assert.equal(f.summary(restoration.batchId).status, 'cancelled');
  const retried = await f.cancel(original);
  await f.batches.reloadNow();
  assert.equal(f.summary(retried.batchId).status, 'applied');
  assert.equal(f.memory, f.original);
  assert.equal(f.cancellationCount(), 1);
});

test('an abandoned cancel that never runs leaves the accepted batch and draft unchanged', async (t) => {
  const f = new Fixture(t);
  const receipt = await f.stage('alpha');
  const pending = f.files.inspect(f.files.paths.pending);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(f.cancel(receipt, { signal: controller.signal }), { code: 'WRITER_CANCELLED' });
  assert.equal(f.summary(receipt.batchId).status, 'pending');
  assert.ok(Number.isFinite(f.summary(receipt.batchId).applyAt));
  assert.deepEqual(f.files.inspect(f.files.paths.pending), pending);
  assert.equal(fs.existsSync(join(f.dir, 'completed-cancellations')), false);
  await f.batches.reloadNow();
  assert.equal(f.summary(receipt.batchId).status, 'applied');
  assert.equal(JSON.parse(f.memory).alpha.minWarm, 1);
});
