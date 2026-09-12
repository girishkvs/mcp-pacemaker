// This file owns port 8875. Fault hooks run only in its disposable workers.
import { test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import childProcess, { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { DeadlineFixture as Fixture } from './helpers/pooling-deadline-fixture.mjs';
import { PoolingCheckpoint, FIXTURE_DEADLOCK_MS } from './helpers/pooling-checkpoint.mjs';
import { PoolingFiles } from '../bin/pooling-files.mjs';
import { PoolingExecution } from '../bin/pooling-execution.mjs';

const test = (name, options, callback) => typeof options === 'function'
  ? nodeTest(name, { timeout: FIXTURE_DEADLOCK_MS }, options)
  : nodeTest(name, { timeout: FIXTURE_DEADLOCK_MS, ...options }, callback);

const windows = { skip: process.platform !== 'win32' };

for (const mode of ['completion', 'teardown']) {
  test(`fixture guard bounds stalled ${mode} after a successful checkpoint`, () => {
    const child = fileURLToPath(new URL('./fixtures/pooling-fixture-guard.mjs', import.meta.url));
    const result = spawnSync(process.execPath, [child, mode], { encoding: 'utf8', timeout: 5000 });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /Fixture deadlock guard expired/);
  });
}

test('phase checkpoint accepts a signal recorded before the wait', async (t) => {
  const fixture = new Fixture(t, 'commit-completed');
  fs.writeFileSync(join(fixture.directory, 'entered'), fixture.stage);
  await fixture.entered(Promise.resolve());
});

test('phase checkpoint observes a subsequently published signal', async (t) => {
  const fixture = new Fixture(t, 'commit-completed');
  const entered = fixture.entered(new Promise(() => {}));
  fs.writeFileSync(join(fixture.directory, 'entered-next'), fixture.stage);
  setImmediate(() => fs.renameSync(join(fixture.directory, 'entered-next'),
    join(fixture.directory, 'entered')));
  await entered;
});

test('phase checkpoint rejects an operation completed before the selected phase', async (t) => {
  const fixture = new Fixture(t, 'commit-completed');
  await assert.rejects(fixture.entered(Promise.resolve()),
    /Operation completed before checkpoint commit-completed/);
});

test('phase checkpoint propagates an operation failure before the selected phase', async (t) => {
  const fixture = new Fixture(t, 'commit-completed');
  const failure = new Error('Controlled worker failure');
  await assert.rejects(fixture.entered(Promise.reject(failure)), (error) => error === failure);
});

test('phase checkpoint refuses the wrong worker phase', async (t) => {
  const fixture = new Fixture(t, 'commit-completed');
  fs.writeFileSync(join(fixture.directory, 'entered'), 'last-preflight');
  await assert.rejects(fixture.entered(new Promise(() => {})),
    /Expected checkpoint commit-completed, received last-preflight/);
});

test('phase checkpoint has an independent fixture deadlock guard', async (t) => {
  const fixture = new Fixture(t, 'commit-completed', { controlledClock: true });
  const controller = new AbortController();
  const checkpoint = new PoolingCheckpoint(fixture.directory, fixture.stage, controller.signal);
  const entered = checkpoint.wait(new Promise(() => {}));
  const failure = new Error('Controlled fixture deadline');
  controller.abort(failure);
  await assert.rejects(entered, (error) => error === failure);
});

test('phase setup waits for readiness without consuming the controlled operation deadline', windows, async (t) => {
  const fixture = new Fixture(t, 'commit-completed', { controlledClock: true });
  fs.writeFileSync(join(fixture.directory, 'helper-setup-delay'), '4500');
  const result = Promise.allSettled([
    fixture.writer.apply(fixture.request(), { deadline: fixture.limit(1500) }),
  ]);
  await fixture.entered(result);
  const events = fixture.events();
  const ready = events.find((event) => event.event === 'hooks-ready');
  const held = events.find((event) => event.event === 'phase-held');
  assert.ok(held.at - ready.at >= 4500);
  assert.equal(held.tick, ready.tick);
  fixture.clock.advance(1540);
  fixture.release();
  const [outcome] = await result;
  await fixture.writer.close();
  assert.equal(outcome.reason?.code, 'WRITER_OUTCOME_UNKNOWN');
  assert.equal(fixture.events().find((event) => event.event === 'operation-result').completedLate, true);
  fixture.committed();
});

test('requests received during active placement form the next batch without losing accepted settings', async (t) => {
  const fixture = new Fixture(t, 'active-placed');
  await fixture.bridge();
  const first = await fixture.stageForReload();
  const before = (await fixture.http('GET', '/api/status').promise).body;
  const reload = fixture.http('POST', '/admin/reload').promise;
  await fixture.entered(reload);
  const applying = (await fixture.http('GET', '/api/status').promise).body;
  assert.equal(applying.prewarm.batches.find((batch) => batch.id === first.batchId).status, 'applying');
  const next = fixture.http('POST', '/admin/servers/beta/pooling', {
    mode: 'pool', minWarm: 2, revision: before.prewarm.revision,
  }).promise;
  await delay(50);
  fixture.release();
  assert.equal((await reload).status, 200);
  const staged = await next;
  assert.equal(staged.status, 202);
  assert.notEqual(staged.body.batchId, first.batchId);
  assert.equal(staged.body.snapshot.servers.find((server) => server.name === 'beta').sharing, 'isolated');
  const secondReload = await fixture.http('POST', '/admin/reload').promise;
  assert.equal(secondReload.status, 200);
  const current = secondReload.body.snapshot;
  assert.equal(current.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  assert.equal(current.servers.find((server) => server.name === 'beta').minWarm, 2);
  assert.ok(current.snapshotVersion > staged.body.snapshot.snapshotVersion);
});

test('queued expiry skips the mutation, never replays, and preserves the active request', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const first = fixture.writer.stageApply(fixture.request());
  await fixture.entered(first);
  const second = fixture.writer.stageApply({ ...fixture.request(), name: 'beta' },
    { deadline: fixture.limit(200) });
  const results = await Promise.allSettled([first, second]);
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[0].value.pending, true);
  assert.equal(results[1].reason?.code, 'WRITER_DEADLINE');
  fixture.pending();
  const staged = results[0].value;
  await fixture.writer.commitBatch({ batchId: staged.batchId, generation: staged.generation });
  await fixture.writer.close();
  fixture.committed();
  assert.equal(fixture.events().filter((event) => event.event === 'helper' && event.slow).length, 1);
  assert.equal(fixture.events().find((event) => event.event === 'helper').executable, 'PoolingSecurityHelper.exe');
  assert.equal(fixture.events().find((event) => event.event === 'helper').shell, false);
  assert.equal(fixture.events().find((event) => event.event === 'helper-return').realHelperCompleted, true);
  assert.equal(fixture.events().filter((event) => event.event === 'stage-complete').length, 1);
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
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

// Old copy-start/copy-complete/data-flushed/backup-published hooks now cover
// stage entry, native stage return, draft publication, and commit preparation.
// Stage return includes the actual native write+flush; it is not an empty copy.
for (const stage of ['stage-start', 'stage-complete', 'draft-published', 'commit-prepared', 'last-preflight']) {
  const options = stage.startsWith('stage-') ? windows : {};
  test(`abort at ${stage} prevents activation and permits bounded draft recovery`, options, async (t) => {
    const fixture = new Fixture(t, stage);
    const controller = new AbortController();
    const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { signal: controller.signal })]);
    await fixture.entered(result);
    fixture.abandon(controller);
    fixture.release();
    const [outcome] = await result;
    await fixture.writer.close();
    assert.equal(fs.readFileSync(fixture.config, 'utf8'), fixture.original);
    assert.equal(outcome.reason?.code, 'WRITER_CANCELLED');
    assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
    assert.equal(fixture.events().filter((event) =>
      event.event === 'phase-held' && event.phase === stage).length, 1);
    if (stage === 'stage-start') {
      assert.equal(fixture.events().some((event) => event.event === 'stage-complete'), false);
      assert.equal(fixture.events().some((event) => event.event === 'helper' && event.kind === 'stage'), false);
      fixture.unchanged();
    } else {
      const completed = fixture.events().find((event) => event.event === 'stage-complete');
      assert.equal(completed.bytesMatch, true);
      fixture.pending();
    }
    await fixture.recoverUnchanged();
    assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
  });
}

test('expired queued entries keep their admission slots until acknowledged', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const first = fixture.writer.stageApply(fixture.request());
  await fixture.entered(first);
  const queued = await Promise.allSettled(Array.from({ length: 15 }, () =>
    fixture.writer.stageApply({ ...fixture.request(), name: 'beta' }, { deadline: fixture.limit(100) })));
  const extra = await Promise.allSettled([fixture.writer.stageApply(fixture.request())]);
  assert.equal(extra[0].reason?.code, 'WRITER_BUSY');
  assert.equal(queued.filter((result) => result.reason?.code === 'WRITER_DEADLINE').length, 15);
  const staged = await first;
  assert.equal(staged.pending, true);
  fixture.pending();
  await fixture.writer.commitBatch({ batchId: staged.batchId, generation: staged.generation });
  await fixture.writer.close();
  fixture.committed();
  assert.equal(fixture.events().filter((event) => event.event === 'stage-complete').length, 1);
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

test('abandoned undo retains the token for an explicit later undo', windows, async (t) => {
  const fixture = new Fixture(t, 'stage-complete');
  fixture.disableHook();
  const applied = await fixture.writer.apply(fixture.request());
  fixture.enableHook();
  const controller = new AbortController();
  const request = { name: 'alpha', undoId: applied.undoId, revision: applied.revision };
  const result = Promise.allSettled([fixture.writer.stageUndo(request, { signal: controller.signal })]);
  await fixture.entered(result);
  fixture.abandon(controller);
  fixture.release();
  const [outcome] = await result;
  assert.equal(outcome.reason?.code, 'WRITER_CANCELLED');
  const staged = await fixture.writer.stageUndo(request);
  assert.equal(staged.pending, true);
  const undone = await fixture.writer.commitBatch({ batchId: staged.batchId, generation: staged.generation });
  assert.equal(undone.ok, true);
  const reused = await Promise.allSettled([fixture.writer.stageUndo(request)]);
  assert.equal(reused[0].reason?.code, 'UNDO_CONFLICT');
  await fixture.writer.close();
  fixture.unchanged();
});

test('real active placement is outcome-unknown on cancellation and is not replayed', async (t) => {
  const fixture = new Fixture(t, 'active-placed');
  const controller = new AbortController();
  let lateSettlements = 0;
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    signal: controller.signal,
    onLateSettlement: () => { lateSettlements++; },
  })]);
  await fixture.entered(result);
  fixture.committed();
  fixture.abandon(controller);
  fixture.release();
  const [outcome] = await result;
  await fixture.writer.close();
  assert.equal(outcome.reason?.code, 'WRITER_OUTCOME_UNKNOWN');
  assert.equal(lateSettlements, 1);
  assert.equal(JSON.parse(fs.readFileSync(fixture.config, 'utf8')).alpha.sharing, 'pool');
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

test('HTTP staging disconnect prevents activation and retains only a recoverable draft with watch disabled', windows, async (t) => {
  const fixture = new Fixture(t, 'stage-complete');
  await fixture.bridge();
  const snapshot = (await fixture.http('GET', '/api/status').promise).body;
  const operation = fixture.http('POST', '/admin/servers/alpha/pooling',
    { mode: 'pool', minWarm: 1, revision: snapshot.prewarm.revision });
  const result = Promise.allSettled([operation.promise]);
  await fixture.entered(result);
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
  fixture.pending();
  assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
  const reloaded = await fixture.http('POST', '/admin/reload').promise;
  assert.equal(reloaded.status, 200);
  assert.equal(reloaded.body.snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
  assert.equal(reloaded.body.snapshot.prewarm.batches.length, 0);
  await fixture.recoverUnchanged();
});

test('HTTP reload disconnect after real active placement reconciles runtime without replay', async (t) => {
  const fixture = new Fixture(t, 'active-placed');
  await fixture.bridge();
  const staged = await fixture.stageForReload();
  const operation = fixture.http('POST', '/admin/reload');
  const result = Promise.allSettled([operation.promise]);
  await fixture.entered(result);
  fixture.record('caller-abandoned');
  operation.request.destroy(new Error('Test caller abandonment'));
  await result;
  await delay(50);
  fixture.release();
  const { snapshot: current, batch } = await fixture.batchSettled(staged.batchId);
  assert.equal(batch.status, 'applied');
  assert.equal(current.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  fixture.committed();
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
  const barrier = await fixture.http('POST', '/admin/reload').promise;
  assert.equal(barrier.status, 200);
  assert.equal(barrier.body.unchanged, true);
  assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, 1);
});

test('controlled deadline reaches last-preflight after a slow native stage', windows, async (t) => {
  const fixture = new Fixture(t, 'last-preflight', { controlledClock: true });
  fs.writeFileSync(join(fixture.directory, 'helper-stage-delay'), '2000');
  const result = Promise.allSettled([
    fixture.writer.apply(fixture.request(), { deadline: fixture.limit(1500) }),
  ]);
  await fixture.entered(result);
  const events = fixture.events();
  const started = events.find((event) => event.event === 'stage-start');
  const completed = events.find((event) => event.event === 'stage-complete');
  const call = events.find((event) => event.event === 'helper' && event.kind === 'stage');
  const native = events.find((event) => event.event === 'helper-return' && event.kind === 'stage');
  assert.equal(call.timeout, 1500);
  assert.equal(call.wallTimeout, 10000);
  assert.equal(native.status, 0);
  assert.equal(native.error, undefined);
  assert.equal(native.realHelperCompleted, true);
  assert.ok(native.elapsedMs >= 2000);
  assert.equal(started.tick, completed.tick);
  assert.equal(BigInt(started.deadline) - BigInt(started.tick), 1500000000n);
  assert.equal(completed.bytesMatch, true);
  fixture.clock.advance(1540);
  fixture.release();
  assert.equal((await result)[0].reason?.code, 'WRITER_DEADLINE');
  await fixture.writer.close();
  fixture.pending();
  await fixture.recoverUnchanged();
  assert.equal(fixture.events().some((event) => event.event === 'config-committed'), false);
});

test('real deadline still times out a slow native stage before activation', windows, (t) => {
  const fixture = new Fixture(t, 'last-preflight');
  const files = new PoolingFiles(fixture.config);
  // Source setup is outside this budget: exercise the real native timeout even
  // when worker startup or the initial inspection is slow.
  const descriptor = files.inspect(fixture.config);
  const slowHelper = fileURLToPath(new URL('./helpers/pooling-slow-helper.mjs', import.meta.url));
  const nativeSpawn = childProcess.spawnSync;
  let returned;
  let timeout;
  childProcess.spawnSync = (command, args, options) => {
    assert.equal(args[0], 'stage');
    timeout = options.timeout;
    returned = nativeSpawn(process.execPath, [slowHelper, fixture.directory, command, 'stage', '2000'], options);
    fixture.record('helper-return', {
      kind: 'stage', timeout, error: returned.error?.code, status: returned.status,
      signal: returned.signal, stderr: returned.stderr?.slice(0, 1024),
    });
    return returned;
  };
  try {
    const execution = new PoolingExecution(fixture.limit(1500));
    assert.throws(() => files.stage(files.paths.pending, fixture.config, descriptor,
      Buffer.from(fixture.original), execution), { code: 'WRITER_DEADLINE' });
  } finally {
    childProcess.spawnSync = nativeSpawn;
  }
  assert.ok(timeout > 0 &&
    timeout <= 1500);
  assert.equal(returned.error?.code, 'ETIMEDOUT');
  assert.equal(returned.status, null);
  assert.equal(returned.stderr.includes('TEST_REAL_HELPER_COMPLETED'), false);
  fixture.unchanged();
});

for (const stage of ['last-preflight', 'commit-completed']) {
  test(`absolute deadline at ${stage} distinguishes prevented activation from a real committed result`, async (t) => {
    const fixture = new Fixture(t, stage, { controlledClock: true });
    const deadline = fixture.limit(1500);
    const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { deadline })]);
    await fixture.entered(result);
    fixture.clock.advance(1540);
    fixture.record('deadline-passed');
    fixture.release();
    const [outcome] = await result;
    await fixture.writer.close();
    if (stage === 'last-preflight') {
      fixture.pending();
      assert.equal(outcome.reason?.code, 'WRITER_DEADLINE');
      await fixture.recoverUnchanged();
    } else {
      assert.equal(outcome.reason?.code, 'WRITER_OUTCOME_UNKNOWN');
      fixture.committed();
      const events = fixture.events();
      // Real placement precedes expiry; delayed completion must not report cancellation.
      assert.ok(events.find((event) => event.event === 'config-committed').at <=
        events.find((event) => event.event === 'deadline-passed').at);
      assert.equal(events.find((event) => event.event === 'operation-result').completedLate, true);
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
  const fixture = new Fixture(t, 'stage-complete');
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

test('cancellation during native inspection never starts the secure staging helper', windows, async (t) => {
  const fixture = new Fixture(t, 'slow-helper');
  const controller = new AbortController();
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), { signal: controller.signal })]);
  await fixture.entered(result);
  fixture.abandon(controller);
  assert.equal((await result)[0].reason?.code, 'WRITER_CANCELLED');
  await fixture.writer.close();
  fixture.unchanged();
  assert.equal(fixture.events().filter((event) => event.event === 'helper').length, 1);
  assert.equal(fixture.events().some((event) => event.event === 'stage-start'), false);
  assert.equal(fixture.events().some((event) => event.event === 'helper' && event.kind === 'stage'), false);
});

test('a cleanup failure after cancellation is reported by the late-settlement callback', async (t) => {
  const fixture = new Fixture(t, 'stage-complete');
  fs.writeFileSync(join(fixture.directory, 'fail-cleanup'), 'fail');
  const controller = new AbortController();
  const late = [];
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    signal: controller.signal, onLateSettlement: (result) => late.push(result),
  })]);
  await fixture.entered(result);
  fixture.abandon(controller);
  fixture.release();
  assert.equal((await result)[0].reason?.code, 'WRITER_CANCELLED');
  assert.equal(fs.readFileSync(fixture.config, 'utf8'), fixture.original);
  // The batch store refuses uncertain cleanup rather than deleting by filename.
  await fixture.writer.close();
  assert.equal(late.length, 1);
  assert.equal(late[0].error.code, 'RECOVERY_REQUIRED');
  assert.equal(late[0].committed, false);
  assert.equal(fixture.events().filter((event) => event.event === 'cleanup-refused').length, 1);
  fixture.pending();
  assert.equal(fs.existsSync(join(fixture.directory, 'servers.pending-next.json')), false);
  assert.equal(fs.existsSync(join(fixture.directory, 'servers.pending-old.json')), false);
  assert.equal(fs.existsSync(join(fixture.directory, 'servers.previous.json')), false);
});

test('late worker completion stays visible even when the caller timer runs after completion', async (t) => {
  const fixture = new Fixture(t, 'commit-completed', { controlledClock: true });
  fs.writeFileSync(join(fixture.directory, 'delay-commit-after-release'), 'delay');
  const late = [];
  const result = Promise.allSettled([fixture.writer.apply(fixture.request(), {
    deadline: fixture.limit(1500), onLateSettlement: (result) => late.push(result),
  })]);
  await fixture.entered(result);
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
  { stage: 'worker-exit-after-placement', saved: true, afterTimeout: false },
  { stage: 'worker-exit-after-completion', saved: true, afterTimeout: false },
  { stage: 'worker-exit-after-placement', saved: true, afterTimeout: true },
]) {
  test(`worker exit: ${scenario.stage}, ${scenario.afterTimeout ? 'after' : 'before'} timeout`, async (t) => {
    const fixture = new Fixture(t, scenario.stage);
    await fixture.bridge({ controlledClock: scenario.afterTimeout });
    const staged = await fixture.stageForReload();
    const started = performance.now();
    const operation = fixture.http('POST', '/admin/reload');
    await fixture.entered(operation.promise);
    let response;
    if (scenario.afterTimeout) {
      fixture.committed();
      fixture.advanceBridgeClock(9100);
      response = await operation.promise;
      fixture.record('timeout-response-received');
      fixture.release();
    } else {
      fixture.release();
      response = await operation.promise;
    }
    const responseMs = performance.now() - started;
    const deadline = Date.now() + 4000;
    while (!fixture.events().some((event) => event.event === 'worker-exit')) {
      if (Date.now() >= deadline) throw new Error('Worker did not exit at the selected phase');
      await delay(10);
    }
    const { snapshot, batch } = await fixture.batchSettled(staged.batchId);
    const sharing = snapshot.servers.find((server) => server.name === 'alpha').sharing;
    const reloadCount = fixture.stderr.split('\n')
      .filter((line) => line.includes('config reloaded (pooling commit reconciliation')).length;
    const commitCount = fixture.events().filter((event) => event.event === 'config-committed').length;
    t.diagnostic(`WORKER_EXIT_PROOF ${JSON.stringify({
      ...scenario, responseMs, status: response.status, error: response.body.error,
      runtimeSharing: sharing, reloadCount, commitCount, batch,
    })}`);
    assert.equal(response.status, scenario.afterTimeout ? 504 : 500);
    assert.ok(responseMs < 10000);
    assert.equal(reloadCount, scenario.saved ? 1 : 0);
    assert.equal(sharing, scenario.saved ? 'pool' : 'isolated');
    assert.equal(commitCount, scenario.saved ? 1 : 0);
    assert.equal(batch.status, 'failed');
    assert.equal(batch.commitState, scenario.saved ? 'committed' : 'not-committed');
    const exit = fixture.events().find((event) => event.event === 'worker-exit');
    assert.equal(exit.method, 'commitBatch');
    assert.equal(BigInt(exit.tick) >= BigInt(exit.deadline), scenario.afterTimeout);
    if (scenario.saved) {
      const outcome = scenario.afterTimeout ? 'Its outcome is not yet known.' : 'Its outcome is unknown.';
      assert.ok(response.body.error.includes(outcome));
      assert.ok(response.body.error.includes('Do not replay'));
      assert.ok(batch.error.includes('Do not replay'));
      const placement = fixture.events().find((event) => event.event === 'config-committed');
      assert.equal(placement.bytesMatch, true);
      assert.ok(BigInt(placement.tick) < BigInt(placement.deadline));
      fixture.committed();
    } else {
      assert.ok(response.body.error.includes('Pooling writer stopped'));
      assert.equal(response.body.error.toLowerCase().includes('outcome'), false);
      fixture.pending();
    }
    const helpers = fixture.events().filter((event) => event.event === 'helper').length;
    const next = await fixture.http('POST', '/admin/servers/alpha/pooling', {
      mode: scenario.saved ? 'isolated' : 'pool', revision: snapshot.prewarm.revision,
    }).promise;
    assert.equal(next.status, 500);
    assert.ok(next.body.error.includes('Pooling writer stopped'));
    const latched = (await fixture.http('GET', '/api/status').promise).body.prewarm.batches
      .find((entry) => entry.id === staged.batchId);
    assert.equal(latched.status, 'failed');
    assert.equal(latched.commitState, scenario.saved ? 'committed' : 'not-committed');
    if (scenario.saved) assert.ok(latched.error.includes('Pooling writer stopped after config commit started'));
    assert.equal(fixture.events().filter((event) => event.event === 'helper').length, helpers);
    assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, commitCount);
    assert.equal(fixture.stderr.split('\n')
      .filter((line) => line.includes('config reloaded (pooling commit reconciliation')).length, reloadCount);
    const reloaded = await fixture.http('POST', '/admin/reload').promise;
    assert.equal(reloaded.status, 200);
    assert.equal(reloaded.body.unchanged, true);
    assert.equal(reloaded.body.snapshot.prewarm.batches.find((entry) => entry.id === staged.batchId).status, 'failed');
    assert.equal(fixture.events().filter((event) => event.event === 'config-committed').length, commitCount);
    if (!scenario.saved) await fixture.recoverUnchanged();
  });
}
