import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { run } from '../../tools/compatibility/fixtures.mjs';
import { CompatibilityBridge, assertImmediate, assertPending, assertSnapshot } from './bridge.mjs';

const AUDIT_UNAVAILABLE = 'Automatic pooling edits require readable audit policy so security can be preserved. No config data was written.';

async function callerAuthority(env) {
  const identity = process.platform === 'win32'
    ? await run('whoami.exe', ['/all', '/fo', 'csv'], { env, timeout: 10000 })
    : JSON.stringify({
      uid: process.getuid(), euid: process.geteuid(),
      gid: process.getgid(), egid: process.getegid(), groups: process.getgroups().sort(),
    });
  return createHash('sha256').update(identity).digest('hex');
}

function fileState(path) {
  const stat = lstatSync(path, { bigint: true });
  return Object.fromEntries(['dev', 'ino', 'birthtimeNs', 'mtimeNs', 'size', 'mode', 'uid', 'gid']
    .map((name) => [name, String(stat[name])]));
}

async function legacyScope(bridge, legacy) {
  if (process.platform !== 'win32') return 'posix';
  const output = await run(join(legacy, 'bin', 'windows', 'PoolingSecurityHelper.exe'), ['inspect'], {
    env: { ...bridge.env, MCP_POOL_SOURCE: bridge.config }, timeout: 10000,
  });
  assert.match(output.trim(), /^[FP]:/, 'The actual 1.3.0 helper must report its audit visibility');
  return output.trim()[0];
}

export async function assertWritableDowngrade(t, fixtures) {
  await new CompatibilityBridge().run(t, async (bridge) => {
    // Use the token's default owner and inherited security, without ACL/token changes.
    const initial = JSON.parse(bridge.original);
    initial.alpha.sharing = 'pool';
    initial.alpha.minWarm = 1;
    const pooledBytes = JSON.stringify(initial, null, 2) + '\n';
    writeFileSync(bridge.config, pooledBytes);
    const authority = await callerAuthority(bridge.env);
    t.diagnostic(`Unchanged inherited caller authority SHA-256: ${authority}`);
    t.diagnostic('Caller-context hashes do not directly measure the individual bridge tokens.');
    const checkAuthority = async () => {
      assert.equal(await callerAuthority(bridge.env), authority, 'Caller authority changed during the downgrade test');
    };
    const legacyWriteAndUndo = async (phase, baseline) => {
      await checkAuthority();
      const scope = await legacyScope(bridge, fixtures.legacy);
      t.diagnostic(`${phase}: actual 1.3.0 audit scope ${scope}`);
      if (baseline) assert.equal(scope, baseline.scope, 'Legacy audit visibility changed after 2.0.0');
      const snapshot = await bridge.snapshot();
      const identity = fileState(bridge.config);
      const disabled = await bridge.mutation({ mode: 'isolated' }, false);
      const expectedStatus = baseline?.status ?? (scope === 'P' ? 403 : 200);
      assert.equal(disabled.status, expectedStatus, `${phase}: ${disabled.text}`);
      if (expectedStatus === 403) {
        assert.equal(process.platform, 'win32');
        assert.equal(scope, 'P');
        assert.deepEqual(disabled.body, { error: AUDIT_UNAVAILABLE });
        assert.equal(bridge.text(), pooledBytes);
        assert.deepEqual(fileState(bridge.config), identity);
        assert.equal((await bridge.snapshot()).prewarm.revision, snapshot.prewarm.revision);
        t.diagnostic(`${phase}: known legacy SECURITY_UNAVAILABLE refusal; bytes and identity unchanged`);
      } else {
        assertImmediate(disabled.body, '1.3.0');
        assert.equal(disabled.body.snapshot.servers.find((server) => server.name === 'alpha').sharing, 'isolated');
        const restored = await bridge.mutation({ undoId: disabled.body.undoId }, false);
        assert.equal(restored.status, 200, `${phase} Undo: ${restored.text}`);
        assert.equal(restored.body.ok, true);
        assertSnapshot(restored.body.snapshot, '1.3.0');
        assert.equal(bridge.text(), pooledBytes);
        bridge.assertEnabled();
        t.diagnostic(`${phase}: actual 1.3.0 write and Undo supported`);
      }
      await checkAuthority();
      return { status: disabled.status, scope };
    };

    const old = await bridge.start(fixtures.legacy, '1.3.0');
    const baseline = await legacyWriteAndUndo('before 2.0.0');
    await bridge.stop();
    await checkAuthority();
    const current = await bridge.start(fixtures.candidate, '2.0.0');
    assert.notEqual(current.instanceId, old.instanceId);
    assert.equal(bridge.text(), pooledBytes);

    const disabled = await bridge.mutation({ mode: 'isolated' });
    assert.equal(disabled.status, 202, disabled.text);
    assertPending(disabled.body);
    await bridge.applied(disabled.body.batchId);
    assert.equal(JSON.parse(bridge.text()).alpha.sharing, 'isolated');
    const restored = await bridge.mutation({ undoId: disabled.body.undoId });
    assert.equal(restored.status, 202, restored.text);
    assertPending(restored.body);
    const settled = await bridge.applied(restored.body.batchId);
    assert.equal(settled.prewarm.batches.some((batch) => ['pending', 'applying'].includes(batch.status)), false);
    assert.equal(bridge.text(), pooledBytes);

    await bridge.stop();
    await checkAuthority();
    const downgraded = await bridge.start(fixtures.legacy, '1.3.0');
    assert.notEqual(downgraded.instanceId, current.instanceId);
    assert.equal(bridge.text(), pooledBytes);
    await legacyWriteAndUndo('after settled 2.0.0 and downgrade', baseline);
  });
}
