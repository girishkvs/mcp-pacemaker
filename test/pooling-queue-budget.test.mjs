import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DeadlineFixture as Fixture } from './helpers/pooling-deadline-fixture.mjs';
import { POOLING_BUDGET_MS } from '../bin/pooling-execution.mjs';

test('admitted no-op queue settles within the existing 10-second client budget', async (t) => {
  const fixture = new Fixture(t, 'queue-budget', { pauseWorker: true });
  const started = performance.now();
  const requests = Array.from({ length: 17 }, () => fixture.writer.apply(fixture.request('isolated')));
  const settled = Promise.allSettled(requests);
  fixture.release();
  const results = await settled;
  const elapsedMs = performance.now() - started;
  const counts = {
    fulfilled: results.filter((result) => result.status === 'fulfilled').length,
    expired: results.filter((result) => result.reason?.code === 'WRITER_DEADLINE').length,
    busy: results.filter((result) => result.reason?.code === 'WRITER_BUSY').length,
  };
  t.diagnostic(`QUEUE_WALL_BUDGET ${JSON.stringify({
    counts, elapsedMs, codes: results.map((result) => result.reason?.code ?? 'OK'),
  })}`);
  assert.equal(counts.busy, 1);
  assert.equal(counts.fulfilled + counts.expired, 16);
  assert.ok(elapsedMs < 10000, 'All admitted requests must settle within the client budget');
  await fixture.writer.close();
  fixture.unchanged();
  assert.equal(fs.existsSync(`${fixture.config}.bak`), false);
  assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
});

for (const scenario of [
  { costMs: 500, fulfilled: 16, expired: 0, completed: 16 },
  { costMs: 600, fulfilled: 14, expired: 2, completed: 15 },
]) {
  test(`no-op queue shares the request budget with ${scenario.costMs} ms operation phases`, async (t) => {
    const fixture = new Fixture(t, 'queue-budget', {
      controlledClock: true, operationCostMs: scenario.costMs, pauseWorker: true,
    });
    assert.equal(POOLING_BUDGET_MS, 9000);
    const deadline = fixture.limit(POOLING_BUDGET_MS);
    const started = process.hrtime.bigint();
    const wallStarted = performance.now();
    const acceptedMs = [];
    let timerTicks = 0;
    const timer = setInterval(() => { timerTicks++; }, 10);
    t.after(() => clearInterval(timer));
    const requests = Array.from({ length: 17 }, async () => {
      const result = await fixture.writer.apply(fixture.request('isolated'), { deadline });
      acceptedMs.push(Number(process.hrtime.bigint() - started) / 1e6);
      return result;
    });
    // All 17 admissions happen before service begins. Each real store operation
    // then consumes a known logical cost, independent of native startup latency.
    const settled = Promise.allSettled(requests);
    fixture.release();
    const results = await settled;
    await fixture.writer.close();
    const counts = {
      fulfilled: results.filter((result) => result.status === 'fulfilled').length,
      expired: results.filter((result) => result.reason?.code === 'WRITER_DEADLINE').length,
      busy: results.filter((result) => result.reason?.code === 'WRITER_BUSY').length,
    };
    t.diagnostic(`QUEUE_BUDGET ${JSON.stringify({
      ...scenario, counts, acceptedMs, timerTicks, limitMs: POOLING_BUDGET_MS,
      wallMs: performance.now() - wallStarted,
    })}`);
    assert.deepEqual(counts, { fulfilled: scenario.fulfilled, expired: scenario.expired, busy: 1 });
    const events = fixture.events();
    assert.equal(events.filter((event) => event.event === 'operation-finished').length, scenario.completed);
    if (process.platform === 'win32') {
      assert.equal(events.filter((event) => event.event === 'helper').length, scenario.completed);
      assert.equal(events.filter((event) =>
        event.event === 'helper-return' && event.realHelperCompleted).length, scenario.completed);
    }
    assert.equal(events.some((event) => event.event === 'config-committed'), false);
    fixture.unchanged();
    assert.equal(fs.existsSync(`${fixture.config}.bak`), false);
    assert.ok(timerTicks > 0);
    assert.ok(Math.max(...acceptedMs) < 10000);
    assert.equal(Number(process.hrtime.bigint() - started) / 1e6, scenario.completed * scenario.costMs);
  });
}
