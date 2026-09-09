// This file owns port 8875. Fault hooks run only in its disposable workers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { DeadlineFixture as Fixture } from './helpers/pooling-deadline-fixture.mjs';

const windows = { skip: process.platform !== 'win32' };

test('queued expiry skips the mutation, never replays, and preserves the active request', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const first = fixture.writer.apply(fixture.request('isolated'));
  await fixture.entered();
  const second = fixture.writer.apply(fixture.request(), { deadline: fixture.limit(200) });
  const results = await Promise.allSettled([first, second]);
  await fixture.writer.close();
  fixture.unchanged();
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[1].reason?.code, 'WRITER_DEADLINE');
  assert.equal(fixture.events().filter((event) => event.event === 'helper').length, 1);
  assert.equal(fixture.events().find((event) => event.event === 'helper').executable, 'PoolingSecurityHelper.exe');
  assert.equal(fixture.events().find((event) => event.event === 'helper').shell, false);
  assert.equal(fixture.events().find((event) => event.event === 'helper-return').realHelperCompleted, true);
});

test('a slow helper uses the remaining total deadline and cannot commit after timeout', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const result = await Promise.allSettled([
    fixture.writer.apply(fixture.request(), { deadline: fixture.limit(500) }),
  ]);
  await fixture.writer.close();
  fixture.unchanged();
  assert.equal(result[0].reason?.code, 'WRITER_DEADLINE');
  const events = fixture.events();
  assert.equal(events.find((event) => event.event === 'helper-return').error, 'ETIMEDOUT');
  assert.ok(events.find((event) => event.event === 'helper').timeout <= 500);
  assert.equal(fs.existsSync(`${fixture.config}.bak`), false);
});

for (const stage of ['copy-start', 'copy-complete', 'data-flushed', 'backup-published', 'last-preflight']) {
  const options = stage.startsWith('copy-') ? windows : {};
  test(`abort at ${stage} wins before config commit and cleans staging`, options, async (t) => {
    const fixture = new Fixture(t, stage);
    const controller = new AbortController();
    const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { signal: controller.signal })]);
    await fixture.entered();
    fixture.abandon(controller);
    fixture.release();
    const [outcome] = await result;
    await fixture.writer.close();
    fixture.unchanged();
    assert.equal(outcome.reason?.code, 'WRITER_CANCELLED');
    assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
    if (stage === 'copy-start' ||
        stage === 'copy-complete') {
      assert.equal(fixture.events().some((event) => event.event === 'staging-data-write'), false);
    }
  });
}

test('expired queued entries keep their admission slots until acknowledged', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const first = fixture.writer.apply(fixture.request('isolated'));
  await fixture.entered();
  const queued = await Promise.allSettled(Array.from({ length: 15 }, () =>
    fixture.writer.apply(fixture.request('isolated'), { deadline: fixture.limit(100) })));
  const extra = await Promise.allSettled([fixture.writer.apply(fixture.request('isolated'))]);
  assert.equal(extra[0].reason?.code, 'WRITER_BUSY');
  assert.equal(queued.filter((result) => result.reason?.code === 'WRITER_DEADLINE').length, 15);
  await first;
  await fixture.writer.close();
  fixture.unchanged();
});

test('abandoned undo retains the token for an explicit later undo', windows, async (t) => {
  const fixture = new Fixture(t, 'copy-complete');
  fixture.disableHook();
  const applied = await fixture.writer.apply(fixture.request());
  fs.unlinkSync(join(fixture.directory, 'disable-hook'));
  const controller = new AbortController();
  const request = { name: 'alpha', undoId: applied.undoId, revision: applied.revision };
  const result = Promise.allSettled([fixture.writer.undo(request, { signal: controller.signal })]);
  await fixture.entered();
  fixture.abandon(controller);
  fixture.release();
  const [outcome] = await result;
  assert.equal(outcome.reason?.code, 'WRITER_CANCELLED');
  const undone = await fixture.writer.undo(request);
  assert.equal(undone.ok, true);
  await fixture.writer.close();
  fixture.unchanged();
});

test('commit already entered is outcome-unknown, not cancellation, and is not replayed', async (t) => {
  const fixture = new Fixture(t, 'commit-entered');
  const controller = new AbortController();
  let lateSettlements = 0;
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    signal: controller.signal,
    onLateSettlement: () => { lateSettlements++; },
  })]);
  await fixture.entered();
  fixture.abandon(controller);
  fixture.release();
  const [outcome] = await result;
  await fixture.writer.close();
  assert.equal(outcome.reason?.code, 'WRITER_OUTCOME_UNKNOWN');
  assert.equal(lateSettlements, 1);
  assert.equal(JSON.parse(fs.readFileSync(fixture.config, 'utf8')).alpha.sharing, 'pool');
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

test('HTTP disconnect before commit prevents a later disk mutation with watch disabled', windows, async (t) => {
  const fixture = new Fixture(t, 'copy-complete');
  await fixture.bridge();
  const snapshot = (await fixture.http('GET', '/api/status').promise).body;
  const operation = fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'pool', minWarm: 1, revision: snapshot.prewarm.revision });
  const result = Promise.allSettled([operation.promise]);
  await fixture.entered();
  fixture.record('caller-abandoned');
  operation.request.destroy(new Error('Test caller abandonment'));
  await result;
  await delay(50);
  fixture.release();
  await fixture.settledLog();
  fixture.disableHook();
  const barrier = await fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'isolated', revision: fixture.revision }).promise;
  assert.equal(barrier.status, 200);
  fixture.unchanged();
  assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
});

test('HTTP disconnect after commit entry still reconciles disk and runtime without replay', async (t) => {
  const fixture = new Fixture(t, 'commit-entered');
  await fixture.bridge();
  const snapshot = (await fixture.http('GET', '/api/status').promise).body;
  const operation = fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'pool', minWarm: 1, revision: snapshot.prewarm.revision });
  const result = Promise.allSettled([operation.promise]);
  await fixture.entered();
  fixture.record('caller-abandoned');
  operation.request.destroy(new Error('Test caller abandonment'));
  await result;
  await delay(50);
  fixture.release();
  await fixture.settledLog();
  let current;
  const deadline = Date.now() + 4000;
  do {
    current = (await fixture.http('GET', '/api/status').promise).body;
    if (current.servers.find((server) => server.name === 'alpha').sharing === 'pool') break;
    await delay(10);
  } while (Date.now() < deadline);
  assert.equal(current.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

for (const stage of ['last-preflight', 'commit-entered']) {
  test(`absolute deadline at ${stage} distinguishes prevented from already-started commit`, async (t) => {
    const fixture = new Fixture(t, stage, { controlledClock: true });
    const deadline = fixture.limit(1500);
    const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { deadline })]);
    await fixture.entered();
    fixture.clock.advance(1540);
    fixture.record('deadline-passed');
    fixture.release();
    const [outcome] = await result;
    await fixture.writer.close();
    if (stage === 'last-preflight') {
      fixture.unchanged();
      assert.equal(outcome.reason?.code, 'WRITER_DEADLINE');
    } else {
      assert.equal(outcome.reason?.code, 'WRITER_OUTCOME_UNKNOWN');
      assert.equal(JSON.parse(fs.readFileSync(fixture.config, 'utf8')).alpha.sharing, 'pool');
      const events = fixture.events();
      assert.ok(events.find((event) => event.event === 'config-committed').at >=
        events.find((event) => event.event === 'deadline-passed').at);
    }
  });
}

test('HTTP operation budget includes body reception, not only worker execution', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  await fixture.bridge();
  const started = performance.now();
  const response = await fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'pool', minWarm: 1, revision: fixture.revision }, 8500).promise;
  const elapsedMs = performance.now() - started;
  assert.equal(response.status, 504);
  assert.ok(elapsedMs < 10000);
  fixture.disableHook();
  const barrier = await fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'isolated', revision: fixture.revision }).promise;
  assert.equal(barrier.status, 200);
  fixture.unchanged();
  t.diagnostic(`HTTP_DEADLINE ${JSON.stringify({ elapsedMs, status: response.status })}`);
});

test('HTTP body that never ends is rejected without creating a writer operation', async (t) => {
  const fixture = new Fixture(t, 'copy-complete');
  await fixture.bridge();
  const started = performance.now();
  const operation = fixture.http('POST', '/admin/servers/alpha/pooling', {}, -1);
  const result = await operation.promise;
  operation.request.destroy();
  assert.equal(result.status, 408);
  assert.ok(performance.now() - started < 10000);
  fixture.unchanged();
  assert.equal(fixture.events().length, 0);
});

test('cancellation during a native helper does not write staging data later', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const controller = new AbortController();
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { signal: controller.signal })]);
  await fixture.entered();
  fixture.abandon(controller);
  assert.equal((await result)[0].reason?.code, 'WRITER_CANCELLED');
  await fixture.writer.close();
  fixture.unchanged();
  assert.equal(fixture.events().filter((event) => event.event === 'helper').length, 1);
  assert.equal(fixture.events().some((event) => event.event === 'staging-data-write'), false);
});

test('a cleanup failure after cancellation is reported by the late-settlement callback', async (t) => {
  const fixture = new Fixture(t, 'data-flushed');
  fs.writeFileSync(join(fixture.directory, 'fail-cleanup'), 'fail');
  const controller = new AbortController();
  const late = [];
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    signal: controller.signal, onLateSettlement: (result) => late.push(result),
  })]);
  await fixture.entered();
  fixture.abandon(controller);
  fixture.release();
  assert.equal((await result)[0].reason?.code, 'WRITER_CANCELLED');
  await fixture.writer.close();
  assert.equal(fs.readFileSync(fixture.config, 'utf8'), fixture.original);
  assert.equal(late.length, 1);
  assert.equal(late[0].error.code, 'IO_ERROR');
  assert.equal(late[0].committed, false);
  assert.equal(fs.readdirSync(fixture.directory).filter((name) => name.startsWith('.pooling-')).length, 2);
});

test('late worker completion stays visible even when the caller timer runs after completion', async (t) => {
  const fixture = new Fixture(t, 'commit-entered', { controlledClock: true });
  fs.writeFileSync(join(fixture.directory, 'delay-commit-after-release'), 'delay');
  const late = [];
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    deadline: fixture.limit(1500), onLateSettlement: (result) => late.push(result),
  })]);
  await fixture.entered();
  fixture.release();
  fixture.clock.advance(1700, false);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2300);
  fixture.clock.runTimers();
  const [outcome] = await result;
  await fixture.writer.close();
  assert.equal(outcome.reason?.code, 'WRITER_DEADLINE_COMMITTED');
  assert.equal(late.length, 1);
  assert.equal(late[0].committed, true);
  assert.equal(late[0].error.code, 'WRITER_DEADLINE_COMMITTED');
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

for (const scenario of [
  { stage: 'worker-exit-before-commit', saved: false, afterTimeout: false },
  { stage: 'worker-exit-after-rename', saved: true, afterTimeout: false },
  { stage: 'worker-exit-after-completion', saved: true, afterTimeout: false },
  { stage: 'worker-exit-after-rename', saved: true, afterTimeout: true },
]) {
  test(`worker exit: ${scenario.stage}, ${scenario.afterTimeout ? 'after' : 'before'} timeout`, async (t) => {
    const fixture = new Fixture(t, scenario.stage);
    await fixture.bridge();
    const body = { mode: 'pool', minWarm: 1, revision: fixture.revision };
    const started = performance.now();
    const operation = fixture.http('POST', '/admin/servers/alpha/pooling',
      body, scenario.afterTimeout ? 6000 : 0);
    if (scenario.afterTimeout) await delay(6000);
    await fixture.entered();
    let response;
    if (scenario.afterTimeout) {
      response = await operation.promise;
      fixture.record('timeout-response-received');
      fixture.release();
    } else {
      fixture.release();
      response = await operation.promise;
    }
    const responseMs = performance.now() - started;
    if (scenario.afterTimeout) {
      const deadline = Date.now() + 4000;
      while (!fixture.stderr.split('\n').some((line) => line.includes('pooling operation settled'))) {
        if (Date.now() >= deadline) throw new Error('Worker failure did not reach the settlement callback');
        await delay(10);
      }
    }
    const snapshot = (await fixture.http('GET', '/api/status').promise).body;
    const sharing = snapshot.servers.find((server) => server.name === 'alpha').sharing;
    const reloadCount = fixture.stderr.split('\n')
      .filter((line) => line.includes('config reloaded (pooling commit settled')).length;
    const commitCount = fixture.events().filter((event) => event.event === 'config-committed').length;
    t.diagnostic(`WORKER_EXIT_PROOF ${JSON.stringify({
      ...scenario, responseMs, status: response.status, error: response.body.error,
      runtimeSharing: sharing, reloadCount, commitCount,
    })}`);
    assert.equal(response.status, scenario.afterTimeout ? 504 : 500);
    assert.ok(responseMs < 10000);
    assert.equal(reloadCount, scenario.saved ? 1 : 0);
    assert.equal(sharing, scenario.saved ? 'pool' : 'isolated');
    assert.equal(commitCount, scenario.saved ? 1 : 0);
    if (scenario.saved) {
      const outcome = scenario.afterTimeout ? 'Its outcome is not yet known.' : 'Its outcome is unknown.';
      assert.ok(response.body.error.includes(outcome));
      assert.ok(response.body.error.includes('Do not replay'));
      assert.ok(fixture.stderr.split('\n').some((line) =>
        line.includes('pooling operation settled') && line.includes('WRITER_OUTCOME_UNKNOWN')));
      assert.equal(JSON.parse(fs.readFileSync(fixture.config, 'utf8')).alpha.sharing, 'pool');
    } else {
      assert.ok(response.body.error.includes('Pooling writer stopped'));
      assert.equal(response.body.error.toLowerCase().includes('outcome'), false);
      fixture.unchanged();
    }
    const helpers = fixture.events().filter((event) => event.event === 'helper').length;
    const next = await fixture.http('POST', '/admin/servers/alpha/pooling', {
      mode: scenario.saved ? 'isolated' : 'pool', revision: snapshot.prewarm.revision,
    }).promise;
    assert.equal(next.status, 500);
    assert.ok(next.body.error.includes('Pooling writer stopped'));
    assert.equal(fixture.events().filter((event) => event.event === 'helper').length, helpers);
    assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, commitCount);
    assert.equal(fixture.stderr.split('\n')
      .filter((line) => line.includes('config reloaded (pooling commit settled')).length, reloadCount);
    if (!scenario.saved) fixture.unchanged();
  });
}
