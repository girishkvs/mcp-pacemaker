import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadFixtures } from '../../tools/compatibility/fixtures.mjs';
import { CompatibilityBridge, assertImmediate, assertPending } from './bridge.mjs';
import { assertWritableDowngrade } from './downgrade.mjs';

const fixtures = loadFixtures();

test('actual 1.3.0 write capability survives a settled 2.0.0 roundtrip under unchanged authority',
  { timeout: 120000 }, async (t) => {
    await assertWritableDowngrade(t, fixtures);
  });

test('2.0.0 CLI and API -> real 1.3.0: immediate 200 enable and Undo', { timeout: 90000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.legacy, '1.3.0');
    await bridge.seedAdvice();
    const enabled = JSON.parse((await bridge.cli(fixtures.candidate,
      ['--enable', 'alpha', '--count', '1', '--json'])).stdout);
    assertImmediate(enabled, '1.3.0');
    bridge.assertEnabled();
    const undone = await bridge.cli(fixtures.candidate, ['--server', 'alpha', '--undo', enabled.undoId]);
    assert.match(undone.stdout, /restored previous pooling settings/);
    await bridge.assertUnchanged();

    const apiEnabled = await bridge.mutation({ mode: 'pool', minWarm: 1 });
    assert.equal(apiEnabled.status, 200, apiEnabled.text);
    assertImmediate(apiEnabled.body, '1.3.0');
    bridge.assertEnabled();
    const apiUndo = await bridge.mutation({ undoId: apiEnabled.body.undoId });
    assert.equal(apiUndo.status, 200, apiUndo.text);
    assert.equal(apiUndo.body.ok, true);
    await bridge.assertUnchanged();
  });
});

test('1.3.0 CLI and API -> real 2.0.0: fresh nonce, protocol 409, no write', { timeout: 90000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, '2.0.0');
    await bridge.seedAdvice();
    const rejected = await bridge.cli(fixtures.legacy, ['--enable', 'alpha', '--count', '1'], 1);
    assert.match(rejected.stdout + rejected.stderr, /Reload the dashboard or update the CLI/);
    const response = await bridge.mutation({ mode: 'pool', minWarm: 1 }, false);
    assert.equal(response.status, 409, response.text);
    assert.match(response.body.error, /Reload the dashboard or update the CLI/);
    await bridge.assertUnchanged();
    assert.deepEqual((await bridge.snapshot()).prewarm.batches, []);
  });
});

test('packed 2.0.0 CLI -> real 2.0.0: queued save, Cancel, apply and whole-batch Undo', { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, '2.0.0');
    await bridge.seedAdvice();
    const enable = async () => JSON.parse((await bridge.cli(fixtures.candidate,
      ['--enable', 'alpha', '--count', '1', '--json'])).stdout);
    const undo = async (receipt) => JSON.parse((await bridge.cli(fixtures.candidate,
      ['--server', 'alpha', '--undo', receipt.undoId, '--json'])).stdout);
    const first = await enable();
    assertPending(first);
    assert.equal(bridge.text(), bridge.original);
    const cancelled = await undo(first);
    assert.equal(cancelled.ok, true);
    assert.equal(cancelled.cancelled, true);
    await bridge.assertUnchanged();

    const second = await enable();
    assertPending(second);
    assert.equal(bridge.text(), bridge.original);
    await bridge.applied(second.batchId);
    bridge.assertEnabled();
    const restored = await undo(second);
    assertPending(restored);
    bridge.assertEnabled();
    await bridge.applied(restored.batchId);
    await bridge.assertUnchanged();
  });
});

test('safe 1.3.0 -> packed 2.0.0 -> 1.3.0 restarts preserve active config bytes', { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    const old = await bridge.start(fixtures.legacy, '1.3.0');
    await bridge.seedAdvice();
    const enabled = await bridge.mutation({ mode: 'pool', minWarm: 1 }, false);
    assert.equal(enabled.status, 200, enabled.text);
    const pooledBytes = bridge.text();
    await bridge.stop();
    const current = await bridge.start(fixtures.candidate, '2.0.0');
    assert.notEqual(current.instanceId, old.instanceId);
    assert.equal(bridge.text(), pooledBytes);

    const disabled = await bridge.mutation({ mode: 'isolated' });
    assert.equal(disabled.status, 202, disabled.text);
    assertPending(disabled.body);
    await bridge.applied(disabled.body.batchId);
    const restore = await bridge.mutation({ undoId: disabled.body.undoId });
    assert.equal(restore.status, 202, restore.text);
    await bridge.applied(restore.body.batchId);
    assert.equal(bridge.text(), pooledBytes);
    // Downgrade only after every accepted transaction has settled.
    await bridge.stop();
    const downgraded = await bridge.start(fixtures.legacy, '1.3.0');
    assert.notEqual(downgraded.instanceId, current.instanceId);
    assert.equal(bridge.text(), pooledBytes);
    bridge.assertEnabled();
    assert.equal(downgraded.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  });
});
