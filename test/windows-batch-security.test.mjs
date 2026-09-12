import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NativeFixture, originalBytes, editedBytes, expected,
} from './fixtures/windows-batch-security/driver.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HELPER = join(ROOT, 'bin', 'windows', 'PoolingSecurityHelper.exe');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'windows-batch-security');
const WINDOWS = { skip: process.platform !== 'win32' };

function fixture(t) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'mcp native batch \u03bb '));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const value = new NativeFixture(HELPER, directory);
  fs.writeFileSync(value.source, originalBytes);
  return value;
}

test('inspect-access returns a stable held-object descriptor and content revision', WINDOWS, (t) => {
  const value = fixture(t);
  const first = value.inspect();
  assert.deepEqual(value.inspect(), first);
  fs.writeFileSync(value.source, editedBytes);
  const changed = value.inspect();
  assert.equal(changed.identity, first.identity);
  assert.equal(changed.security, first.security);
  assert.notEqual(changed.revision, first.revision);
});

test('stage creates a complete candidate and no-replace moves retain both objects', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const candidate = value.success(value.stage(source), editedBytes);
  assert.notEqual(candidate.identity, source.identity);
  assert.deepEqual(value.inspect(), source);
  assert.deepEqual(value.inspect(value.candidate), candidate);
  assert.deepEqual(value.success(value.move(value.source, value.previous, source)), source);
  assert.equal(fs.existsSync(value.source), false);
  assert.deepEqual(value.inspect(value.previous), source);
  assert.deepEqual(value.success(value.move(value.candidate, value.source, candidate)), candidate);
  assert.deepEqual(value.inspect(), candidate);
  assert.deepEqual(fs.readFileSync(value.previous), originalBytes);
});

for (const field of ['identity', 'revision', 'security']) {
  test(`stage and move refuse stale ${field} without any byte/security change`, WINDOWS, (t) => {
    const value = fixture(t);
    const before = value.inspect();
    const stale = { ...before, [field]: field === 'identity' ? 'stale' : '0'.repeat(64) };
    value.failure(value.stage(stale), 3, 'PoolingConflictException');
    value.failure(value.move(value.source, value.previous, stale), 3, 'PoolingConflictException');
    assert.equal(fs.existsSync(value.candidate), false);
    assert.equal(fs.existsSync(value.previous), false);
    assert.deepEqual(value.inspect(), before);
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  });
}

test('CREATE_NEW collision and no-replace collision preserve existing candidate/previous', WINDOWS, (t) => {
  const value = fixture(t);
  fs.writeFileSync(value.candidate, 'external candidate');
  fs.writeFileSync(value.previous, 'external previous');
  const before = value.inspect();
  const candidate = value.inspect(value.candidate);
  const previous = value.inspect(value.previous);
  value.failure(value.stage(before), 3, 'Win32Exception', 80);
  value.failure(value.move(value.source, value.previous, before), 3, 'Win32Exception', 183);
  assert.deepEqual(value.inspect(), before);
  assert.deepEqual(value.inspect(value.candidate), candidate);
  assert.deepEqual(value.inspect(value.previous), previous);
});

test('a contender after the first move cannot be overwritten by candidate placement', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const candidate = value.success(value.stage(source), editedBytes);
  value.success(value.move(value.source, value.previous, source));
  fs.writeFileSync(value.source, 'external active');
  const contender = value.inspect();
  value.failure(value.move(value.candidate, value.source, candidate), 3, 'Win32Exception', 183);
  assert.deepEqual(value.inspect(), contender);
  assert.deepEqual(value.inspect(value.previous), source);
  assert.deepEqual(value.inspect(value.candidate), candidate);
});

test('bounded strict UTF8 requests and base64 refuse malformed input without creating files', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const inputs = [
    Buffer.from([0xff]),
    Buffer.alloc(1400001, 0x20),
    Buffer.from('{'),
    {},
    { expected: expected(before) },
    { expected: { ...expected(before), extra: 'x' }, bytes: '' },
    { expected: expected(before), bytes: '!!!!' },
    { expected: expected(before), bytes: 'YQ==\n' },
    { expected: expected(before), bytes: Buffer.from([0xff]).toString('base64') },
    { expected: expected(before), bytes: Buffer.alloc(1048577).toString('base64') },
  ];
  for (const input of inputs) {
    const result = value.run('stage', value.source, value.candidate, input);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(result.stderr.startsWith('MCPERR type='));
    assert.equal(fs.existsSync(value.candidate), false);
    assert.deepEqual(value.inspect(), before);
  }
});

test('single-link and 1MiB bounds apply to inspect, stage, and move', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const link = join(value.directory, 'hard-link.json');
  fs.linkSync(value.source, link);
  for (const result of [
    value.run('inspect-access'),
    value.stage(before),
    value.move(value.source, value.previous, before),
  ]) {
    value.failure(result, 1, 'PoolingPolicyException');
  }
  assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  assert.deepEqual(fs.readFileSync(link), originalBytes);
  fs.unlinkSync(link);
  fs.writeFileSync(value.source, Buffer.alloc(1048577, 0x20));
  value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
  value.failure(value.stage(before), 1, 'PoolingPolicyException');
  value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
  assert.equal(fs.statSync(value.source).size, 1048577);
  assert.equal(fs.existsSync(value.candidate), false);
  assert.equal(fs.existsSync(value.previous), false);
  fs.writeFileSync(value.source, Buffer.alloc(1048576, 0x20));
  const maximum = value.inspect();
  value.success(value.stage(maximum, Buffer.alloc(1048576, 0x20)), Buffer.alloc(1048576, 0x20));
});

test('existing data writer blocks staging without a candidate or source mutation', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const writer = fs.openSync(value.source, 'r+');
  try {
    value.failure(value.stage(source), 1, 'Win32Exception', 32);
    assert.equal(fs.existsSync(value.candidate), false);
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  } finally {
    fs.closeSync(writer);
  }
  assert.deepEqual(value.inspect(), source);
});

test('read-only attributes refuse staging without using parent replacement rights', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  fs.chmodSync(value.source, 0o444);
  try {
    value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
    value.failure(value.stage(before), 1, 'Win32Exception', 5);
    value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
    assert.equal(fs.existsSync(value.candidate), false);
    assert.equal(fs.existsSync(value.previous), false);
  } finally {
    fs.chmodSync(value.source, 0o600);
  }
  assert.deepEqual(value.inspect(), before);
});

test('final-component file reparse points never expose or mutate their target', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const target = join(value.directory, 'target.json');
  fs.renameSync(value.source, target);
  try {
    fs.symlinkSync(target, value.source, 'file');
  } catch (error) {
    if (error.code === 'EPERM') {
      t.skip('TEST-SETUP symbolic-link creation is not permitted by this token');
      return;
    }
    throw error;
  }
  value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
  value.failure(value.stage(before), 1, 'PoolingPolicyException');
  value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
  assert.equal(fs.lstatSync(value.source).isSymbolicLink(), true);
  assert.deepEqual(value.inspect(target), before);
  assert.deepEqual(fs.readFileSync(target), originalBytes);
  assert.equal(fs.existsSync(value.candidate), false);
  assert.equal(fs.existsSync(value.previous), false);
});

test('TEST-SETUP full audit oracle verifies ordinary-token staging and retained original policy', WINDOWS, (t) => {
  const directory = fs.mkdtempSync(join(tmpdir(), 'mcp-batch-audit-oracle-'));
  const shell = join(process.env.WINDIR, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  t.after(() => {
    const readonly = join(directory, 'readonly', 'active.json');
    if (fs.existsSync(readonly)) {
      const cleanup = spawnSync(shell, [
        '-NoProfile', '-NonInteractive', '-Command', '[IO.File]::Delete($env:MCP_TEST_READONLY)',
      ], {
        encoding: 'utf8', windowsHide: true, timeout: 10000,
        env: { ...process.env, MCP_TEST_READONLY: readonly },
      });
      assert.equal(cleanup.status, 0, cleanup.stderr);
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const result = spawnSync(shell, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', join(FIXTURES, 'oracle.ps1'),
    '-Root', directory, '-Helper', HELPER, '-Node', process.execPath,
  ], { encoding: 'utf8', windowsHide: true, timeout: 30000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  if (report.unavailable) {
    t.skip(report.unavailable);
    return;
  }
  assert.equal(report.normal.medium, true);
  assert.equal(report.normal.securityPrivilegeAbsent, true);
  assert.equal(report.normal.nodeVersion, process.version);
  assert.equal(report.normal.cases, 19);
  assert.equal(report.audit.sourceExplicit, 1);
  assert.equal(report.audit.sourceInherited, 1);
  assert.equal(report.audit.candidateExplicit, 0);
  assert.equal(report.audit.candidateInherited, 1);
  assert.equal(report.audit.previousExact, true);
  assert.equal(report.securityVerified, true);
});
