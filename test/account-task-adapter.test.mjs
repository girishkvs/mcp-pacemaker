import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const windows = { skip: process.platform !== 'win32' };
function run(name) {
  return JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File',
    fileURLToPath(new URL('./fixtures/account-task-com.ps1', import.meta.url)),
    '-Adapter', fileURLToPath(new URL('../autostart/windows/account-task.ps1', import.meta.url)), '-Case', name,
  ], { encoding: 'utf8', windowsHide: true, timeout: 15000 }));
}
for (const name of ['bootstrap', 'hold', 'repoint', 'release', 'restore']) {
  test(`account task production adapter preserves original account and full descriptor during modeled ${name}`, windows, () => {
    const result = run(name);
    assert.equal(result.succeeded, true, result.error);
    assert.equal(result.securityUnchanged, true);
    assert.equal(result.ownerPreserved, true);
    assert.equal(result.principalPreserved, true);
    assert.equal(result.securitySetterCalled, false);
    assert.equal(result.flags, 52);
    if (name === 'restore') assert.equal(result.xmlRestored, true);
  });
}
for (const name of ['acl-drift', 'owner-drift', 'disabled', 'no-demand', 'wrong-principal']) {
  test(`account task production adapter refuses modeled ${name} before mutation or launch`, windows, () => {
    const result = run(name);
    assert.equal(result.succeeded, false);
    assert.equal(result.mutationDelta, 0);
    assert.equal(result.runCalls, 0);
    assert.equal(result.securityUnchanged, true);
  });
}
test('account task RunEx success is only correlation and never readiness proof', windows, () => {
  const result = run('launch');
  assert.equal(result.succeeded, true);
  assert.equal(result.runCalls, 1);
  assert.equal(result.launchNotReadiness, true);
  assert.equal(result.principalPreserved, true);
});
