import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { test } from 'node:test';
import { loadFixtures } from '../../tools/compatibility/fixtures.mjs';
import { CompatibilityBridge, assertImmediate, assertPending } from './bridge.mjs';
import { assertWritableDowngrade, legacyScope, AUDIT_UNAVAILABLE } from './downgrade.mjs';

const fixtures = loadFixtures();
const { legacyVersion, candidateVersion } = fixtures;

// Reading a SACL needs SeSecurityPrivilege, which only administrators hold, so the ordinary
// Windows lane always reports partial audit visibility and the release refuses pooling writes.
// Linux and macOS have no audit scope and exercise the full write path. Declaring the expected
// value keeps a lane from silently swapping branches and reporting green under the other name.
const EXPECTED_SCOPE = process.platform === 'win32' ? 'P' : 'posix';
const assertLaneScope = (scope) => assert.equal(scope, EXPECTED_SCOPE,
  `Unexpected legacy audit visibility ${scope} for this lane`);

test(`actual ${legacyVersion} write capability survives a settled ${candidateVersion} roundtrip under unchanged authority`,
  { timeout: 120000 }, async (t) => {
    await assertWritableDowngrade(t, fixtures);
  });

test(`${candidateVersion} CLI and API -> real ${legacyVersion}: immediate 200 enable and Undo`, {
  skip: EXPECTED_SCOPE === 'P' && 'the release refuses pooling writes without readable audit policy',
  timeout: 90000,
}, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.legacy, legacyVersion);
    await bridge.seedAdvice();
    assertLaneScope(await legacyScope(bridge, fixtures.legacy));
    const enabled = JSON.parse((await bridge.cli(fixtures.candidate,
      ['--enable', 'alpha', '--count', '1', '--json'])).stdout);
    assertImmediate(enabled, legacyVersion);
    bridge.assertEnabled();
    const undone = await bridge.cli(fixtures.candidate, ['--server', 'alpha', '--undo', enabled.undoId]);
    assert.match(undone.stdout, /restored previous pooling settings/);
    await bridge.assertUnchanged();

    const apiEnabled = await bridge.mutation({ mode: 'pool', minWarm: 1 });
    assert.equal(apiEnabled.status, 200, apiEnabled.text);
    assertImmediate(apiEnabled.body, legacyVersion);
    bridge.assertEnabled();
    const apiUndo = await bridge.mutation({ undoId: apiEnabled.body.undoId });
    assert.equal(apiUndo.status, 200, apiUndo.text);
    assert.equal(apiUndo.body.ok, true);
    await bridge.assertUnchanged();
  });
});

test(`${candidateVersion} CLI and API -> real ${legacyVersion}: refused without readable audit policy`, {
  skip: EXPECTED_SCOPE !== 'P' && 'this lane can read audit policy, so the release accepts the write',
  timeout: 90000,
}, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.legacy, legacyVersion);
    await bridge.seedAdvice();
    assertLaneScope(await legacyScope(bridge, fixtures.legacy));
    const refused = await bridge.cli(fixtures.candidate,
      ['--enable', 'alpha', '--count', '1', '--json'], 1);
    assert.match(refused.stdout + refused.stderr, /readable audit policy/);
    await bridge.assertUnchanged();
    const api = await bridge.mutation({ mode: 'pool', minWarm: 1 }, false);
    assert.equal(api.status, 403, api.text);
    assert.deepEqual(api.body, { error: AUDIT_UNAVAILABLE });
    await bridge.assertUnchanged();
  });
});

test(`${legacyVersion} CLI and API -> real ${candidateVersion}: fresh nonce, protocol 409, no write`, { timeout: 90000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, candidateVersion);
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

test(`${candidateVersion} CLI -> real ${candidateVersion}: queued save, Cancel, apply and whole-batch Undo`, { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, candidateVersion);
    await bridge.seedAdvice();
    const enable = async () => JSON.parse((await bridge.cli(fixtures.candidate,
      ['--enable', 'alpha', '--count', '1', '--json'])).stdout);
    const undo = async (receipt) => JSON.parse((await bridge.cli(fixtures.candidate,
      ['--server', 'alpha', '--undo', receipt.undoId, '--json'])).stdout);
    const first = await enable();
    assertPending(first, candidateVersion);
    assert.equal(bridge.text(), bridge.original);
    const cancelled = await undo(first);
    assert.equal(cancelled.ok, true);
    assert.equal(cancelled.cancelled, true);
    await bridge.assertUnchanged();

    const second = await enable();
    assertPending(second, candidateVersion);
    assert.equal(bridge.text(), bridge.original);
    await bridge.applied(second.batchId);
    bridge.assertEnabled();
    const restored = await undo(second);
    assertPending(restored, candidateVersion);
    bridge.assertEnabled();
    await bridge.applied(restored.batchId);
    await bridge.assertUnchanged();
  });
});

test(`safe ${legacyVersion} -> ${candidateVersion} -> ${legacyVersion} restarts preserve active config bytes`, { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    // Seed pooled state before starting, the way assertWritableDowngrade does, so no external
    // write races a live bridge. Where the release cannot write it, the refusal has its own test.
    const scope = await legacyScope(bridge, fixtures.legacy);
    assertLaneScope(scope);
    if (scope === 'P') {
      const seeded = JSON.parse(bridge.original);
      seeded.alpha.sharing = 'pool';
      seeded.alpha.minWarm = 1;
      writeFileSync(bridge.config, JSON.stringify(seeded, null, 2) + '\n');
    }
    const old = await bridge.start(fixtures.legacy, legacyVersion);
    await bridge.seedAdvice();
    if (scope !== 'P') {
      const enabled = await bridge.mutation({ mode: 'pool', minWarm: 1 }, false);
      assert.equal(enabled.status, 200, enabled.text);
    }
    const pooledBytes = bridge.text();
    await bridge.stop();
    const current = await bridge.start(fixtures.candidate, candidateVersion);
    assert.notEqual(current.instanceId, old.instanceId);
    assert.equal(bridge.text(), pooledBytes);

    const disabled = await bridge.mutation({ mode: 'isolated' });
    assert.equal(disabled.status, 202, disabled.text);
    assertPending(disabled.body, candidateVersion);
    await bridge.applied(disabled.body.batchId);
    const restore = await bridge.mutation({ undoId: disabled.body.undoId });
    assert.equal(restore.status, 202, restore.text);
    await bridge.applied(restore.body.batchId);
    assert.equal(bridge.text(), pooledBytes);
    // Downgrade only after every accepted transaction has settled.
    await bridge.stop();
    const downgraded = await bridge.start(fixtures.legacy, legacyVersion);
    assert.notEqual(downgraded.instanceId, current.instanceId);
    assert.equal(bridge.text(), pooledBytes);
    bridge.assertEnabled();
    assert.equal(downgraded.servers.find((server) => server.name === 'alpha').sharing, 'pool');
  });
});
