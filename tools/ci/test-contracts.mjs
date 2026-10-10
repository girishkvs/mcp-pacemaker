import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { AUDIT_COMMAND_TIMEOUT_MS, auditArguments } from '../npm-publication/local-audit-report.mjs';

export const SOURCE_PLATFORMS = Object.freeze(['linux', 'win32', 'darwin']);
export const SOURCE_NODES = Object.freeze([20, 22, 24]);
// These files drive the real Windows task channel, which binds an interactive logon session and a
// per-user Task Scheduler registration. A provisioned CI account signs in with a password logon and
// has no interactive session, so they stay in the session lane and are required from an ordinary
// interactive Windows environment instead. Every other registered file runs in both lanes.
export const SESSION_REQUIRED_TESTS = Object.freeze([
  'test/account-recovery.test.mjs',
  'test/account-upgrade.test.mjs',
  'test/task-controller.test.mjs',
  'test/windows-task-channel.test.mjs',
]);

export function nodeTestArguments(script) {
  assert.equal(typeof script, 'string', 'Missing declared test command');
  const words = script.trim().split(/\s+/);
  assert.deepEqual(words.splice(0, 2), ['node', '--test'], 'Only explicit Node test commands are supported');
  // These suites start real bridges, supervisors, native helpers and npm, so the registered
  // command may bound how many files run at once. The bound is part of the declared contract.
  const bounded = /^--test-concurrency=([1-9][0-9]?)$/.test(words[0] ?? '') ? words.shift() : null;
  assert.ok(words.length > 0, 'Empty test contract');
  for (const file of words) {
    assert.match(file, /^test\/[\w./-]+\.test\.mjs$/, 'Test contract contains an unsupported argument');
    assert.ok(file.split('/').every(part => part !== '' && part !== '.' && part !== '..'));
  }
  assert.equal(new Set(words).size, words.length, 'Duplicate test contract member');
  return ['--test', ...(bounded ? [bounded] : []), ...words];
}

export function testContract(root, name, platform = process.platform) {
  assert.ok(SOURCE_PLATFORMS.includes(platform), 'Unsupported test platform');
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  if (name === 'audit') {
    assert.equal(platform, 'win32', 'The privileged Windows audit is not a portable test');
    return { name, role: 'privileged-fixture', platform, args: auditArguments(), session: false,
      timeoutMs: AUDIT_COMMAND_TIMEOUT_MS };
  }
  if (name === 'service-context') {
    return { name, role: 'user-runtime', platform, args: [], session: true, checkOnly: true };
  }
  const script = { source: 'test', compatibility: 'test:compat', browser: 'test:compat:browser' }[name];
  assert.ok(script ?? name === 'source-ordinary', 'Unknown test contract');
  const args = nodeTestArguments(pkg.scripts[script ?? 'test']);
  if (name === 'source' ||
      name === 'source-ordinary') {
    // Non-recursive by design: test/compat/* belongs to the separate compatibility contract.
    const actual = readdirSync(join(root, 'test')).filter(file => file.endsWith('.test.mjs'))
      .map(file => `test/${file}`).sort();
    assert.deepEqual(args.filter(value => value.startsWith('test/')).sort(), actual,
      'Source contract does not cover the complete registered suite');
  }
  if (name === 'source-ordinary') {
    assert.equal(platform, 'win32', 'The ordinary-account lane exists only for Windows');
    const files = args.filter(value => value.startsWith('test/'));
    for (const file of SESSION_REQUIRED_TESTS) {
      assert.ok(files.includes(file), `Session lane names an unregistered file: ${file}`);
    }
    const selected = files.filter(file => !SESSION_REQUIRED_TESTS.includes(file));
    // Compared against the registered files on disk, not against this lane's own input, so a
    // file that stops being selected here is caught rather than cancelling out of both sides.
    const registered = readdirSync(join(root, 'test')).filter(file => file.endsWith('.test.mjs'))
      .map(file => `test/${file}`).filter(file => !SESSION_REQUIRED_TESTS.includes(file)).sort();
    assert.deepEqual(selected.slice().sort(), registered,
      'The ordinary lane must run every registered file except the session-required ones');
    return { name, role: 'user-runtime', platform, session: false,
      args: [...args.filter(value => !value.startsWith('test/')), ...selected],
      timeoutMs: 60 * 60 * 1000 };
  }
  return { name, role: 'user-runtime', platform, args, session: name === 'source' && platform === 'win32',
    timeoutMs: (name === 'source' ? 60 : 45) * 60 * 1000 };
}

export function qualificationPlan(root) {
  const matrix = SOURCE_PLATFORMS.flatMap(platform => SOURCE_NODES.flatMap(node =>
    ['source', 'compatibility', ...(platform === 'win32' ? ['source-ordinary', 'audit'] : [])].map(name =>
      ({ ...testContract(root, name, platform), node }))));
  return [...matrix, { ...testContract(root, 'browser', 'linux'), node: 22 }];
}
