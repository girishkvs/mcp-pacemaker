import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PoolingConfigWriter } from '../bin/pooling-writer.mjs';

class Fixture {
  constructor(t) {
    this.directory = mkdtempSync(join(tmpdir(), 'pooling-writer-'));
    this.path = join(this.directory, 'servers.json');
    this.original = '{"alpha":{"command":"node"},"beta":{"command":"node"}}\n';
    this.revision = createHash('sha256').update(this.original).digest('hex');
    writeFileSync(this.path, this.original);
    this.writer = new PoolingConfigWriter(this.path);
    t.after(async () => {
      await this.writer.close();
      rmSync(this.directory, { recursive: true, force: true });
    });
  }

  apply(name = 'alpha') {
    return this.writer.apply({ name, mode: 'pool', minWarm: 1, revision: this.revision });
  }
}

test('pooling writes leave the caller event loop responsive and retain Undo in the worker', async (t) => {
  const fixture = new Fixture(t);
  let timerRan = false;
  const timer = setTimeout(() => { timerRan = true; }, 0);
  t.after(() => clearTimeout(timer));
  const applied = await fixture.apply();
  assert.equal(timerRan, true, 'blocking config operations must not run on the caller thread');
  assert.equal(applied.ok, true);
  assert.equal(JSON.parse(readFileSync(fixture.path, 'utf8')).alpha.sharing, 'pool');
  const undone = await fixture.writer.undo({ name: 'alpha', undoId: applied.undoId, revision: applied.revision });
  assert.equal(undone.ok, true);
  assert.equal(readFileSync(fixture.path, 'utf8'), fixture.original);
});

test('the worker serializes same-revision writes with one winner', async (t) => {
  const fixture = new Fixture(t);
  const results = await Promise.allSettled([fixture.apply('alpha'), fixture.apply('beta')]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const failure = results.find((result) => result.status === 'rejected').reason;
  assert.equal(failure.statusCode, 409);
  assert.equal(failure.code, 'REVISION_CONFLICT');
});

test('close drains accepted work and refuses new work', async (t) => {
  const fixture = new Fixture(t);
  const applying = fixture.apply();
  const closing = fixture.writer.close();
  assert.equal((await applying).ok, true);
  await closing;
  await assert.rejects(() => fixture.apply(), { code: 'WRITER_CLOSED', statusCode: 503 });
  await fixture.writer.close();
});

test('pooling queue admission is bounded', async (t) => {
  const fixture = new Fixture(t);
  const results = await Promise.allSettled(Array.from({ length: 17 }, () => fixture.writer.apply({})));
  assert.equal(results.filter((result) => result.reason?.code === 'WRITER_BUSY').length, 1);
  assert.equal(results.filter((result) => result.reason?.code === 'INVALID_REQUEST').length, 16);
  assert.equal(readFileSync(fixture.path, 'utf8'), fixture.original);
});

test('worker startup failures reject pending work without leaking internal details', async () => {
  const writer = new PoolingConfigWriter('invalid\0private-path');
  try {
    await assert.rejects(() => writer.apply({}), (error) => {
      assert.equal(error.code, 'WRITER_FAILED');
      assert.equal(error.message.includes('private-path'), false);
      return true;
    });
    await assert.rejects(() => writer.apply({}), { code: 'WRITER_FAILED' });
  } finally {
    await writer.close();
  }
});
