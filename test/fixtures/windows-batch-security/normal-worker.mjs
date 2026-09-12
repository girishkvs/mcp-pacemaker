import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { NativeFixture, originalBytes, editedBytes } from './driver.mjs';

const [root, helper] = process.argv.slice(2);
const run = (name) => new NativeFixture(helper, join(root, name));
let currentCase = 'token';
try {
  const identity = spawnSync('whoami.exe', ['/groups', '/fo', 'csv', '/nh'], { encoding: 'utf8' });
  const privileges = spawnSync('whoami.exe', ['/priv', '/fo', 'csv', '/nh'], { encoding: 'utf8' });
  assert.equal(identity.status, 0);
  assert.equal(privileges.status, 0);
  const medium = identity.stdout.includes('"S-1-16-8192"');
  const securityPrivilegeAbsent = !privileges.stdout.includes('"SeSecurityPrivilege"');
  assert.equal(medium, true);
  assert.equal(securityPrivilegeAbsent, true);

  for (const name of [
    'inherited', 'protected', 'audit', 'low', 'medium', 'creator-allowed', 'deny-other',
    'audit-protected', 'label-mask3', 'label-mask5', 'label-mask7',
  ]) {
    currentCase = name;
    const value = run(name);
    const source = value.inspect();
    const candidate = value.success(value.stage(source), editedBytes);
    if (name === 'creator-allowed') {
      assert.notEqual(candidate.security, source.security);
    } else {
      assert.equal(candidate.security, source.security);
    }
    assert.deepEqual(value.success(value.move(value.source, value.previous, source)), source);
    assert.deepEqual(value.success(value.move(value.candidate, value.source, candidate)), candidate);
    assert.deepEqual(fs.readFileSync(value.previous), originalBytes);
  }

  for (const name of [
    'high', 'readonly', 'creator-refused', 'owner-rights', 'creator-special', 'callback', 'resource-policy',
  ]) {
    currentCase = name;
    const value = run(name);
    const fallback = { identity: 'unused', revision: '0'.repeat(64), security: '0'.repeat(64) };
    const unsupported = ['high', 'callback', 'resource-policy'].includes(name);
    if (unsupported) value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
    const descriptor = unsupported ? fallback : value.inspect();
    const result = value.stage(descriptor);
    const policy = ['owner-rights', 'creator-special', 'callback', 'resource-policy'].includes(name);
    value.failure(result, 1, policy ? 'PoolingPolicyException' : 'Win32Exception', policy ? undefined : 5);
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
    assert.equal(fs.existsSync(value.candidate), false);
    assert.equal(fs.existsSync(value.previous), false);
    if (!unsupported) assert.deepEqual(value.inspect(), descriptor);
  }

  const mismatch = run('inheritance-mismatch');
  currentCase = 'inheritance-mismatch';
  const before = mismatch.inspect();
  const destination = join(root, 'different-parent', 'candidate.json');
  mismatch.failure(mismatch.stage(before, editedBytes, destination), 1, 'PoolingPolicyException');
  assert.equal(fs.statSync(destination).size, 0);
  assert.deepEqual(mismatch.inspect(), before);
  assert.deepEqual(fs.readFileSync(mismatch.source), originalBytes);

  fs.writeFileSync(join(root, 'normal-result.json'), JSON.stringify({
    medium, securityPrivilegeAbsent, nodeVersion: process.version, cases: 19,
  }), { flag: 'wx' });
} catch (error) {
  fs.writeFileSync(join(root, 'normal-failure.json'), JSON.stringify({
    case: currentCase, type: error.name, message: error.message, stack: error.stack,
  }), { flag: 'wx' });
  process.exitCode = 1;
}
