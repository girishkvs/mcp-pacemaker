import assert from 'node:assert/strict';
import test from 'node:test';
import { UiHookHarness } from './helpers/ui-hook-harness.mjs';

test('older SSE cannot permanently discard an accepted private batch receipt', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(3, 'r0', [ui.batch()])), 202);
  await ui.frame(ui.snapshot(2, 'r0'));
  await ui.frame(ui.snapshot(4, 'r1', [ui.batch('applied', 'r1')]));

  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.equal(ui.current.actions.unavailable.length, 0);
  assert.equal(ui.current.actions.states.alpha.status, 'applied');
  assert.equal(ui.current.actions.batchAction(ui.current.actions.batches[0]).reason, undefined);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r1');
});

test('same-version and older SSE frames cannot replace active values', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(3, 'r1'));
  await ui.frame(ui.snapshot(3, 'r0'));
  await ui.frame(ui.snapshot(2, 'r0'));

  assert.equal(ui.current.channel.data.snapshotVersion, 3);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r1');
  assert.equal(ui.current.channel.data.servers[0].sharing, 'pool');
});

test('delayed HTTP reread cannot replace a newer SSE snapshot or expire its receipt', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  const reread = await ui.begin('reread');
  await ui.frame(ui.snapshot(4, 'r1', [ui.batch('applied', 'r1')]));
  await ui.respond(reread, ui.snapshot(3, 'r0'));

  assert.equal(reread.request.url, '/api/status');
  assert.equal(ui.current.channel.data.snapshotVersion, 4);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r1');
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.equal(ui.current.actions.unavailable.length, 0);
});

test('delayed HTTP reload cannot regress active revision r2 to r1', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const reload = await ui.begin('reloadNow');
  await ui.frame(ui.snapshot(2, 'r1'));
  await ui.frame(ui.snapshot(4, 'r2'));
  await ui.respond(reload, { ok: true, snapshot: ui.snapshot(3, 'r1') });

  assert.equal(reload.request.url, '/admin/reload');
  assert.equal(reload.request.options.method, 'POST');
  assert.equal(ui.current.channel.data.snapshotVersion, 4);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r2');
  assert.equal(ui.requests.length, 1);
});

test('reload failure follow-up GET also uses the shared ordering guard', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const reload = await ui.begin('reloadNow');
  await ui.respondWithoutFinishing(reload.request, { ok: false, error: 'reload test failure' }, 500);
  const followup = { request: ui.requests.at(-1), done: reload.done };
  assert.equal(followup.request.url, '/api/status');
  await ui.frame(ui.snapshot(4, 'r2'));
  await ui.respond(followup, ui.snapshot(3, 'r1'));

  assert.equal(ui.current.channel.data.snapshotVersion, 4);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r2');
  assert.ok(ui.current.actions.batchError.includes('reload test failure'));
});

test('a restarted instance resets its counter without accepting late SSE or HTTP from the retired instance', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(8, 'r1'));
  const reread = await ui.begin('reread');
  await ui.frame(ui.snapshot(1, 'r2', [], 'bridge-b'));
  await ui.frame(ui.snapshot(9, 'r0'));
  await ui.respond(reread, ui.snapshot(10, 'r0'));

  assert.equal(ui.current.channel.data.instanceId, 'bridge-b');
  assert.equal(ui.current.channel.data.snapshotVersion, 1);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r2');
  assert.equal(ui.current.actions.instanceChanged, true);
  assert.equal(ui.requests.length, 1);
});

test('a delayed stage receipt keeps its token and settles against the newer already-published snapshot', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.frame(ui.snapshot(3, 'r1', [ui.batch('applied', 'r1')]));
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);

  assert.equal(ui.current.channel.data.snapshotVersion, 3);
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.equal(ui.current.actions.states.alpha.status, 'applied');
  assert.equal(ui.current.actions.states.alpha.revision, 'r1');
  assert.equal(ui.current.actions.unavailable.length, 0);
});

test('a same-version HTTP receipt still supplies its private token after SSE published that snapshot', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  const accepted = ui.snapshot(2, 'r0', [ui.batch()]);
  await ui.frame(accepted);
  await ui.respond(stage, ui.receipt(accepted), 202);

  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.equal(ui.current.actions.states.alpha.status, 'pending');
  assert.equal(ui.current.actions.batchAction(ui.current.actions.batches[0]).reason, undefined);
  assert.ok(!JSON.stringify(ui.current.channel.data).includes('private-test-token'));
});

test('a newer HTTP snapshot can legitimately restore an earlier content revision', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const reload = await ui.begin('reloadNow');
  await ui.frame(ui.snapshot(2, 'r1'));
  await ui.respond(reload, { ok: true, snapshot: ui.snapshot(3, 'r0') });

  assert.equal(ui.current.channel.data.snapshotVersion, 3);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r0');
  assert.equal(ui.current.channel.data.servers[0].sharing, 'isolated');
});

test('invalid SSE ordering fields are visible errors and cannot discard a valid receipt', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  for (const version of [undefined, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '3']) {
    await ui.frame(ui.snapshot(version, 'r0'));
    assert.equal(ui.current.channel.data.snapshotVersion, 2);
    assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
    assert.ok(ui.current.channel.error.includes('ordering information'));
  }
  const noInstance = ui.snapshot(3, 'r0');
  delete noInstance.instanceId;
  await ui.frame(noInstance);
  assert.equal(ui.current.channel.data.snapshotVersion, 2);
  assert.equal(ui.current.actions.unavailable.length, 0);
  assert.ok(ui.renderBatchStatus().includes('Snapshot update rejected:'));
});

test('a malformed 202 cannot be treated as activation or as a usable receipt', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(0, 'r0', [ui.batch()])), 202);

  assert.equal(stage.request.options.headers['x-mcp-pooling-batch'], '1');
  assert.equal(ui.current.channel.data.snapshotVersion, 1);
  assert.equal(ui.current.actions.states.alpha.undoId, undefined);
  assert.equal(ui.current.actions.states.alpha.message, undefined);
  assert.ok(ui.current.actions.states.alpha.error.includes('no usable receipt'));
  assert.equal(ui.requests.length, 1);
});

test('a genuinely newer missing summary expires its receipt and requires explicit rereading', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  await ui.frame(ui.snapshot(40, 'r1'));

  assert.equal(ui.current.actions.unavailable.length, 1);
  assert.equal(ui.current.actions.editable, false);
  assert.equal(ui.current.actions.states.alpha.undoId, undefined);
  const reread = await ui.begin('reread');
  await ui.respond(reread, ui.snapshot(41, 'r1'));
  assert.equal(ui.current.actions.needsReread, false);
  assert.equal(ui.current.actions.editable, true);
  assert.equal(ui.requests.length, 2);
});

test('legacy HTTP 200 immediate results remain supported without snapshotVersion', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  const legacy = ui.snapshot(undefined, 'r0');
  delete legacy.prewarm.batches;
  await ui.start(legacy);
  const stage = await ui.begin('apply', 'alpha', 1);
  const applied = ui.snapshot(undefined, 'r1');
  delete applied.prewarm.batches;
  await ui.respond(stage, { ok: true, name: 'alpha', revision: 'r1', undoId: 'legacy-token', snapshot: applied });

  assert.equal(ui.current.channel.data.prewarm.revision, 'r1');
  assert.equal(ui.current.actions.states.alpha.message, 'Enabled 1 warm slot.');
  assert.equal(ui.current.actions.states.alpha.undoId, 'legacy-token');
});

for (const outcome of ['cancelled', 'not-committed', 'committed', 'unknown', 'missing']) {
  test(`ordered restoration settlement preserves the ${outcome} Undo rule`, async (t) => {
    const ui = new UiHookHarness();
    t.after(() => ui.close());
    await ui.start(ui.snapshot(1, 'r0'));
    const stage = await ui.begin('apply', 'alpha', 1);
    await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
    const original = ui.batch('applied', 'r1');
    await ui.frame(ui.snapshot(3, 'r1', [original]));
    const undo = await ui.begin('undoBatch', 'batch-a', 'undo');
    const restoration = ui.batch('pending', 'r1', 'batch-b');
    restoration.changes = [{ name: 'alpha', mode: 'isolated' }];
    await ui.respond(undo, ui.receipt(ui.snapshot(4, 'r1', [restoration, original]), 'batch-b', 'restore-token'), 202);
    const settled = {
      ...restoration,
      applyAt: null,
      status: outcome === 'cancelled' ? 'cancelled' : 'failed',
      error: outcome === 'cancelled' ? undefined : 'test restoration failure',
    };
    if (outcome !== 'cancelled' &&
        outcome !== 'missing') settled.commitState = outcome;
    await ui.frame(ui.snapshot(6, 'r1', [settled, original]));
    await ui.frame(ui.snapshot(5, 'r1', [restoration, original]));

    const mayRestore = outcome === 'cancelled' || outcome === 'not-committed';
    assert.equal(ui.current.actions.batchAction(original).available, mayRestore);
    assert.equal(ui.current.actions.needsReread, !mayRestore);
    assert.equal(ui.current.channel.data.snapshotVersion, 6);
    if (!mayRestore) {
      const reread = await ui.begin('reread');
      await ui.respond(reread, ui.snapshot(7, 'r1', [settled, original]));
      assert.equal(ui.current.actions.needsReread, false);
      assert.equal(ui.current.actions.batchAction(original).available, false);
    }
  });
}

test('the audit-inheritance notice renders before staging without blocking configuration actions', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  const initial = ui.snapshot(1, 'r0');
  initial.prewarm.saveWarning = 'File saves inherit audit rules from the containing folder. Custom per-file audit rules may not carry forward.';
  await ui.start(initial);
  const html = ui.renderBatchStatus();

  assert.ok(html.includes(initial.prewarm.saveWarning));
  assert.ok(html.includes('role="note"'));
  assert.equal(ui.current.actions.editable, true);
  assert.equal(ui.current.actions.batchError, undefined);
  assert.equal(ui.requests.length, 0);
});

test('SSE and HTTP delivered within one React turn use the same synchronous ordering guard', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  const reload = await ui.begin('reloadNow');
  const newer = ui.snapshot(5, 'r2', [ui.batch('applied', 'r2')]);
  newer.servers[0].minWarm = 2;
  await ui.respond(reload, { ok: true, snapshot: ui.snapshot(4, 'r1') }, 200, newer);

  assert.equal(ui.current.channel.data.snapshotVersion, 5);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r2');
  assert.equal(ui.current.channel.data.servers[0].minWarm, 2);
  assert.equal(ui.current.actions.states.alpha.status, 'applied');
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.equal(ui.current.actions.unavailable.length, 0);
});

test('a stale reread cannot acknowledge an unknown commit outcome', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  const failed = { ...ui.batch('failed', 'r1'), commitState: 'unknown', error: 'commit outcome unknown' };
  await ui.frame(ui.snapshot(3, 'r1', [failed]));
  const reread = await ui.begin('reread');
  await ui.frame(ui.snapshot(5, 'r2', [{ ...failed, revision: 'r2' }]));
  await ui.respond(reread, ui.snapshot(4, 'r1', [failed]));

  assert.equal(ui.current.channel.data.prewarm.revision, 'r2');
  assert.equal(ui.current.actions.needsReread, true);
  assert.equal(ui.current.actions.editable, false);
  assert.ok(ui.current.actions.batchError.includes('Rollback is not confirmed'));
  assert.equal(ui.requests.length, 2);
});

test('whole-batch Undo accepts an omitted pool target and renders configured target until applied', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  const initial = ui.snapshot(1, 'r0');
  Object.assign(initial.servers[0], { sharing: 'pool', minWarm: 2 });
  await ui.start(initial);
  const stage = await ui.begin('apply', 'alpha', null);
  const disabling = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'isolated' }] };
  const queued = { ...initial, snapshotVersion: 2, prewarm: { ...initial.prewarm, batches: [disabling] } };
  await ui.respond(stage, ui.receipt(queued), 202);
  const original = { ...disabling, status: 'applied', revision: 'r1', applyAt: null };
  const disabled = ui.snapshot(3, 'r1', [original]);
  Object.assign(disabled.servers[0], { sharing: 'isolated', minWarm: 0 });
  await ui.frame(disabled);

  const undo = await ui.begin('undoBatch', original.id, 'undo');
  assert.deepEqual(JSON.parse(undo.request.options.body), { undoId: 'private-test-token', revision: 'r1' });
  const restoration = {
    ...ui.batch('pending', 'r1', 'restoration'),
    changes: [{ name: 'alpha', mode: 'pool' }],
  };
  const pending = { ...disabled, snapshotVersion: 4, prewarm: { ...disabled.prewarm, batches: [restoration, original] } };
  await ui.respond(undo, ui.receipt(pending, restoration.id, 'restore-token'), 202);

  assert.deepEqual(ui.current.actions.states.alpha.requested, { name: 'alpha', mode: 'pool' });
  assert.equal(ui.current.actions.states.alpha.undoId, 'restore-token');
  assert.equal(ui.current.actions.states.alpha.status, 'pending');
  assert.equal(ui.current.channel.data.servers[0].sharing, 'isolated');
  for (const html of [ui.renderBatchStatus(), ui.renderPoolingControls('alpha')]) {
    assert.ok(html.includes('pooling with configured target'));
    assert.ok(!html.includes('undefined warm'));
    assert.ok(!html.includes('1 warm slots'));
  }
  assert.equal(Object.hasOwn(ui.current.actions.pending[0].changes[0], 'minWarm'), false);

  const applying = { ...restoration, status: 'applying', applyAt: null };
  await ui.frame({ ...pending, snapshotVersion: 5, prewarm: { ...pending.prewarm, batches: [applying, original] } });
  assert.equal(ui.current.actions.states.alpha.status, 'applying');
  assert.ok(ui.renderPoolingControls('alpha').includes('pooling with configured target'));
  const applied = { ...restoration, status: 'applied', applyAt: null, revision: 'r0' };
  const restored = ui.snapshot(6, 'r0', [applied, original]);
  Object.assign(restored.servers[0], { sharing: 'pool', minWarm: 2 });
  await ui.frame(restored);
  assert.equal(ui.current.actions.states.alpha.status, 'applied');
  assert.equal(ui.current.channel.data.servers[0].minWarm, 2);
  assert.equal(ui.current.actions.batchAction(applied).reason, undefined);
  assert.equal(ui.requests.length, 2);
});

test('an accepted merged batch preserves omitted and explicit targets with whole-batch controls', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  const restoring = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'pool' }] };
  const initial = ui.snapshot(1, 'r0', [restoring]);
  initial.servers.push({ ...initial.servers[0], name: 'beta' });
  await ui.start(initial);
  const stage = await ui.begin('apply', 'beta', 3);
  assert.deepEqual(JSON.parse(stage.request.options.body), { mode: 'pool', minWarm: 3, revision: 'r0' });
  const merged = { ...restoring, changes: [...restoring.changes, { name: 'beta', mode: 'pool', minWarm: 3 }] };
  const accepted = { ...initial, snapshotVersion: 2, prewarm: { ...initial.prewarm, batches: [merged] } };
  await ui.respond(stage, { ...ui.receipt(accepted), name: 'beta' }, 202);

  assert.deepEqual(ui.current.actions.states.alpha.requested, { name: 'alpha', mode: 'pool' });
  assert.deepEqual(ui.current.actions.states.beta.requested, { name: 'beta', mode: 'pool', minWarm: 3 });
  assert.equal(Object.hasOwn(ui.current.actions.pending[0].changes[0], 'minWarm'), false);
  assert.ok(ui.renderBatchStatus().includes('alpha: pooling with configured target'));
  assert.ok(ui.renderBatchStatus().includes('beta: pool, 3 warm slots'));
  assert.ok(ui.renderBatchStatus().includes('Whole batch — 2 servers: alpha, beta.'));
  assert.ok(ui.renderPoolingControls('alpha').includes('pooling with configured target'));
  assert.ok(ui.renderPoolingControls('beta').includes('pre-warming with 3 warm slots'));
  assert.equal(ui.current.actions.batchAction(merged).reason, undefined);
  assert.equal(ui.current.channel.data.servers[1].sharing, 'isolated');
  assert.ok(!JSON.stringify(ui.current.channel.data).includes('private-test-token'));
  assert.equal(ui.requests.length, 1);
});

for (const minWarm of [1, 4]) {
  test(`an explicit pool target at the advertised boundary ${minWarm} is accepted`, async (t) => {
    const ui = new UiHookHarness();
    t.after(() => ui.close());
    await ui.start(ui.snapshot(1, 'r0'));
    const stage = await ui.begin('apply', 'alpha', minWarm);
    const batch = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'pool', minWarm }] };
    await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [batch])), 202);

    assert.equal(ui.current.actions.states.alpha.requested.minWarm, minWarm);
    assert.ok(ui.renderBatchStatus().includes(`alpha: pool, ${minWarm} warm slots`));
    assert.ok(!ui.renderBatchStatus().includes('pooling with configured target'));
  });
}

for (const minWarm of [-1, 0, 1.5, 5, '2', null, true, Number.MAX_SAFE_INTEGER + 1]) {
  test(`HTTP 202 rejects invalid explicit target ${JSON.stringify(minWarm)} anywhere in a merged batch`, async (t) => {
    const ui = new UiHookHarness();
    t.after(() => ui.close());
    const initial = ui.snapshot(1, 'r0');
    initial.servers.push({ ...initial.servers[0], name: 'beta' });
    await ui.start(initial);
    const stage = await ui.begin('apply', 'alpha', 1);
    const batch = {
      ...ui.batch(),
      changes: [{ name: 'alpha', mode: 'pool', minWarm: 1 }, { name: 'beta', mode: 'pool', minWarm }],
    };
    const invalid = { ...initial, snapshotVersion: 2, prewarm: { ...initial.prewarm, batches: [batch] } };
    await ui.respond(stage, ui.receipt(invalid), 202);

    assert.equal(ui.current.channel.data.snapshotVersion, 1);
    assert.equal(ui.current.actions.states.alpha.undoId, undefined);
    assert.equal(ui.current.actions.states.alpha.message, undefined);
    assert.ok(ui.current.actions.states.alpha.error.includes('invalid pooling target'));
    assert.equal(ui.current.actions.pending.length, 0);
    assert.equal(ui.current.channel.data.servers[0].lastError, null);
    assert.equal(ui.requests.length, 1);
  });
}

test('invalid SSE targets cannot replace active values or discard a receipt, and do not advance ordering', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  const invalid = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'pool', minWarm: -1 }] };
  await ui.frame(ui.snapshot(3, 'r1', [invalid]));

  assert.equal(ui.current.channel.data.snapshotVersion, 2);
  assert.equal(ui.current.channel.data.prewarm.revision, 'r0');
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.ok(ui.current.channel.error.includes('invalid pooling target'));
  assert.ok(ui.renderBatchStatus().includes('Snapshot update rejected:'));
  await ui.frame(ui.snapshot(3, 'r0', [ui.batch()]));
  assert.equal(ui.current.channel.data.snapshotVersion, 3);
  assert.equal(ui.current.channel.error, undefined);
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
});

test('an invalid explicit target in a reread response preserves the accepted snapshot and receipt', async (t) => {
  const ui = new UiHookHarness();
  t.after(() => ui.close());
  await ui.start(ui.snapshot(1, 'r0'));
  const stage = await ui.begin('apply', 'alpha', 1);
  await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [ui.batch()])), 202);
  const reread = await ui.begin('reread');
  const invalid = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'pool', minWarm: null }] };
  await ui.respond(reread, ui.snapshot(3, 'r1', [invalid]));

  assert.equal(ui.current.channel.data.snapshotVersion, 2);
  assert.equal(ui.current.actions.states.alpha.undoId, 'private-test-token');
  assert.ok(ui.current.actions.batchError.includes('invalid pooling target'));
  assert.equal(ui.current.actions.readMessage, undefined);
  assert.equal(ui.requests.length, 2);
});

for (const minWarm of [-1, 1]) {
  test(`an isolated batch change cannot carry an explicit target ${minWarm}`, async (t) => {
    const ui = new UiHookHarness();
    t.after(() => ui.close());
    await ui.start(ui.snapshot(1, 'r0'));
    const stage = await ui.begin('apply', 'alpha', null);
    const batch = { ...ui.batch(), changes: [{ name: 'alpha', mode: 'isolated', minWarm }] };
    await ui.respond(stage, ui.receipt(ui.snapshot(2, 'r0', [batch])), 202);

    assert.equal(ui.current.channel.data.snapshotVersion, 1);
    assert.equal(ui.current.actions.states.alpha.undoId, undefined);
    assert.ok(ui.current.actions.states.alpha.error.includes('invalid pooling target'));
    assert.equal(ui.requests.length, 1);
  });
}
