import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLegacyAccess } from '../bin/legacy-installation.mjs';
import { fixLegacyAccess } from '../bin/legacy-access.mjs';
import { planUpgrade } from '../bin/managed-upgrade.mjs';
import { LegacyUpgradeFixture } from './helpers/legacy-upgrade-fixture.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 120000 };
const functions = fileURLToPath(new URL('./fixtures/legacy-access-functions.ps1', import.meta.url));
const FILE_WRITE_DATA = 0x2;
const DELETE = 0x10000;
const WRITE_DAC = 0x40000;
const FULL_CONTROL = 0x1F01FF;
const OWNED_PORT = 41731;
const RUN_AS = 'S-1-5-21-1-2-3-1001';
// The real descriptor Task Scheduler creates when 1.3's register-task.ps1 runs from an elevated
// terminal: Administrators own the task and the run-as user can only read it.
const ELEVATED_TASK = 'O:BAG:{U}D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)(A;;FR;;;{U})';
// The same registration from a normal terminal.
const NORMAL_TASK = 'O:{U}G:{U}D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;{U})(A;;FR;;;{U})';

function runFunctions(mode, request) {
  return JSON.parse(execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', functions, '-Mode', mode], {
    input: JSON.stringify(request), encoding: 'utf8', windowsHide: true, timeout: 60000,
  }));
}

function accessReport(registration, missing, { fixable, elevated = false } = {}) {
  return {
    protocol: 1, elevated, runtimeSidMatches: true,
    evaluated: elevated ? 'ordinary-context-of-elevated-token' : 'current-token',
    task: { name: registration.name, path: registration.path, ownerName: 'BUILTIN\\Administrators' },
    cli: { path: 'C:\\legacy\\bin\\cli.mjs', directory: 'C:\\legacy\\bin', ownerName: 'BUILTIN\\Administrators' },
    missing, fixable: fixable ?? missing.filter(id => ['task-write', 'cli-owner'].includes(id)),
    expected: { taskSddl: 'O:BAG:BAD:(A;;FR;;;WD)', xmlSha256: registration.xmlSha256, cliSddl: 'O:BAG:BAD:(A;;FA;;;BA)' },
  };
}

const registration = { name: 'McpPacemaker-41731', path: '\\McpPacemaker-41731', xmlSha256: 'a'.repeat(64) };

test('a certain legacy access gap names each item and the one-time administrator fix', () => {
  assert.throws(() => assertLegacyAccess(accessReport(registration, ['task-write', 'cli-owner']), registration), error => {
    assert.equal(error.code, 'LEGACY_ACCESS_MISSING');
    assert.match(error.message, /Nothing was changed/);
    assert.match(error.message, /Task \\McpPacemaker-41731 \(owner BUILTIN\\Administrators\): your account can only read it\./);
    assert.match(error.message, /C:\\legacy\\bin\\cli\.mjs \(owner BUILTIN\\Administrators\)/);
    assert.match(error.message, /Run this once from an administrator terminal\. It will only give your account full control of task \\McpPacemaker-41731 and make your account the owner of C:\\legacy\\bin\\cli\.mjs:/);
    assert.match(error.message, /\n {2}mcp-pacemaker upgrade --fix-legacy-access\n/);
    assert.match(error.message, /again from a normal \(non-administrator\) terminal/);
    return true;
  });
});

test('access guidance names this administrator terminal and leaves manual gaps to an administrator', () => {
  assert.throws(() => assertLegacyAccess(accessReport(registration, ['task-write'], { elevated: true }), registration),
    /Run this once from this administrator terminal/);
  assert.throws(() => assertLegacyAccess(accessReport(registration, ['cli-delete']), registration), error => {
    assert.match(error.message, /your account cannot rename it/);
    assert.match(error.message, /an administrator must grant them/);
    assert.doesNotMatch(error.message, /\n {2}mcp-pacemaker upgrade --fix-legacy-access\n/);
    return true;
  });
});

test('complete access passes and an unbound access report refuses', () => {
  assert.equal(assertLegacyAccess(accessReport(registration, []), registration), undefined);
  const unbound = [
    { ...accessReport(registration, []), expected: { xmlSha256: 'b'.repeat(64) } },
    { ...accessReport(registration, []), task: { path: '\\Other' } },
    accessReport(registration, ['unknown-gap'], { fixable: [] }),
    accessReport(registration, ['cli-write'], { fixable: ['cli-write'] }),
    accessReport(registration, [], { fixable: ['task-write'] }),
  ];
  for (const report of unbound) {
    assert.throws(() => assertLegacyAccess(report, registration), /did not match the selected registration/);
  }
});

test('access rights count only allow entries that apply to the runtime user', windows, () => {
  const rights = runFunctions('rights', {
    cases: {
      elevatedTask: ELEVATED_TASK,
      normalTask: NORMAL_TASK,
      fixedTask: 'O:BAG:{U}D:AI(A;;FA;;;{U})(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)',
      administratorsFile: 'O:BAG:{U}D:(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1301bf;;;AU)(A;ID;0x1200a9;;;BU)',
      userOwnedFile: 'O:{U}G:{U}D:(A;ID;0x1301bf;;;AU)',
      ownerRights: 'O:{U}G:{U}D:(A;;FR;;;S-1-3-4)(A;;0x1301bf;;;AU)',
      genericAll: 'O:BAG:BAD:(A;;GA;;;{U})',
      inheritOnly: 'O:BAG:BAD:(A;OICIIO;FA;;;{U})',
      nullDacl: 'O:BAG:BAD:NO_ACCESS_CONTROL',
      denyIgnored: 'O:BAG:BAD:(D;;FA;;;WD)(A;;FA;;;{U})',
      unrelatedOnly: `O:BAG:BAD:(A;;FA;;;${RUN_AS})`,
    },
  });
  const has = (name, bits) => (rights[name] & bits) === bits;
  assert.equal(has('elevatedTask', FILE_WRITE_DATA), false, 'Administrators entries do not apply to the ordinary context.');
  assert.equal(has('normalTask', FILE_WRITE_DATA), true);
  assert.equal(has('fixedTask', FILE_WRITE_DATA), true);
  assert.equal(has('administratorsFile', FILE_WRITE_DATA | DELETE), true);
  assert.equal(has('administratorsFile', WRITE_DAC), false);
  assert.equal(has('userOwnedFile', WRITE_DAC), true, 'An owner implicitly holds WRITE_DAC.');
  assert.equal(has('ownerRights', WRITE_DAC), false, 'OWNER RIGHTS replaces implicit owner rights.');
  assert.equal(has('genericAll', FULL_CONTROL), true);
  assert.equal(has('inheritOnly', FILE_WRITE_DATA), false);
  assert.equal(has('nullDacl', FULL_CONTROL), true);
  assert.equal(has('denyIgnored', FILE_WRITE_DATA), true, 'A deny entry cannot create a certain gap.');
  assert.equal(rights.unrelatedOnly, 0);
});

test('task access fix replaces only the runtime user entry and verifies nothing else moved', windows, () => {
  const replaced = runFunctions('grant', {
    initial: ELEVATED_TASK,
    drifts: {
      owner: 'O:{U}G:{U}D:AI(A;;FA;;;{U})(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)',
      removedEntry: 'O:BAG:{U}D:AI(A;;FA;;;{U})(A;ID;0x1f019f;;;BA)(A;ID;FA;;;BA)',
      addedEntry: 'O:BAG:{U}D:AI(A;;FA;;;{U})(A;;FA;;;WD)(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)',
      audit: 'O:BAG:{U}D:AI(A;;FA;;;{U})(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)S:(AU;SA;FW;;;WD)',
    },
  });
  assert.equal(replaced.after, 'O:BAG:{U}D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)(A;;FA;;;{U})');
  assert.equal(replaced.flags, 0x10, 'Task Scheduler must not add its own principal entry.');
  assert.deepEqual(replaced.reads, [7], 'Only owner, group and DACL are read and written; audit and label data are untouched.');
  assert.equal(replaced.checks.actual, 'accepted');
  for (const drift of ['owner', 'removedEntry', 'addedEntry', 'audit']) assert.match(replaced.checks[drift], /LEGACY_ACCESS_DRIFT/, drift);
  const inserted = runFunctions('grant', { initial: 'O:BAG:{U}D:(A;ID;0x1f019f;;;BA)(A;ID;FA;;;BA)', drifts: {} });
  assert.equal(inserted.after, 'O:BAG:{U}D:(A;;FA;;;{U})(A;ID;0x1f019f;;;BA)(A;ID;FA;;;BA)');
  assert.equal(inserted.checks.actual, 'accepted');
});

test('access report binds the CLI file to the selected launcher root', windows, () => {
  const directory = realpathSync.native(mkdtempSync(join(tmpdir(), 'legacy access ')));
  try {
    const root = join(directory, 'legacy package');
    mkdirSync(join(root, 'autostart', 'windows'), { recursive: true });
    mkdirSync(join(root, 'bin'));
    writeFileSync(join(root, 'autostart', 'windows', 'launcher.vbs'), 'WScript.Quit 0\r\n');
    writeFileSync(join(root, 'bin', 'cli.mjs'), '// owned\n');
    writeFileSync(join(directory, 'cli.mjs'), '// foreign\n');
    const launcher = join(root, 'autostart', 'windows', 'launcher.vbs');
    const elevated = runFunctions('report', { launcher, taskSddl: ELEVATED_TASK, cli: join(root, 'bin', 'cli.mjs') });
    assert.deepEqual(elevated.missing, ['task-write']);
    assert.deepEqual(elevated.fixable, ['task-write']);
    assert.equal(elevated.runtimeSidMatches, true);
    assert.equal(elevated.boundToTask, true);
    assert.equal(elevated.mutations, 0);
    const normal = runFunctions('report', { launcher, taskSddl: NORMAL_TASK, cli: join(root, 'bin', 'cli.mjs') });
    assert.deepEqual(normal.missing, []);
    const foreign = runFunctions('report', { launcher, taskSddl: NORMAL_TASK, cli: join(directory, 'cli.mjs') });
    assert.match(foreign.error, /does not belong to the selected legacy registration/);
    execFileSync(process.env.ComSpec, ['/d', '/c', 'mklink', '/H', join(directory, 'second-link.mjs'), join(root, 'bin', 'cli.mjs')],
      { windowsHide: true, stdio: 'ignore' });
    const linked = runFunctions('report', { launcher, taskSddl: NORMAL_TASK, cli: join(root, 'bin', 'cli.mjs') });
    assert.match(linked.error, /must be one regular file without links/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

function accessTask(fixture, reports, { grant } = {}) {
  const calls = { access: [], grant: [] };
  const task = fixture.task;
  task.access = (port, cliPath) => {
    calls.access.push({ port, cliPath });
    const next = reports.length > 1 ? reports.shift() : reports[0];
    return accessReport(fixture.originalTask, next.missing, next);
  };
  task.grantAccess = (port, cliPath, expected) => {
    calls.grant.push({ port, cliPath, expected });
    if (grant) return grant();
    return { protocol: 1, changed: ['task-write', 'cli-owner'], before: expected, after: { ...expected, taskSddl: 'O:BAG:BAD:(A;;FA;;;WD)' }, missing: [] };
  };
  return { task, calls };
}

test('a certain access gap refuses legacy planning before process capture or download', windows, async () => {
  const fixture = new LegacyUpgradeFixture();
  try {
    fixture.registerOwned(OWNED_PORT, RUN_AS);
    const { task, calls } = accessTask(fixture, [{ missing: ['task-write', 'cli-owner'] }]);
    let captured = 0;
    const processes = { prepareLegacyProcesses: async () => { captured++; throw new Error('capture reached'); } };
    await assert.rejects(planUpgrade({ to: '2.0.3' }, { home: fixture.home, legacy: { task, processes } }),
      /cannot make the changes this upgrade needs[\s\S]*upgrade --fix-legacy-access/);
    assert.equal(captured, 0);
    assert.deepEqual(calls.access, [{ port: OWNED_PORT, cliPath: join(fixture.root, 'bin', 'cli.mjs') }]);
    assert.deepEqual(task.read().actions, ['fixture-registered']);
    assert.equal(existsSync(join(fixture.home, 'managed')), false);
    const complete = accessTask(fixture, [{ missing: [] }]);
    await assert.rejects(planUpgrade({ to: '2.0.3' }, { home: fixture.home, legacy: { task: complete.task, processes } }),
      /capture reached/);
    assert.equal(captured, 1);
  } finally { await fixture.cleanup(); }
});

test('fix-legacy-access is elevated only, bound to the inspected state and journaled', windows, async () => {
  const fixture = new LegacyUpgradeFixture({ taskOwner: 'builtin-administrators' });
  const now = () => new Date('2026-10-15T01:02:03.000Z');
  const quiet = () => {};
  try {
    fixture.registerOwned(OWNED_PORT, RUN_AS);
    const journals = () => existsSync(join(fixture.home, 'legacy-upgrade'))
      ? readdirSync(join(fixture.home, 'legacy-upgrade')).filter(name => name.startsWith('access-')) : [];
    const ordinary = accessTask(fixture, [{ missing: ['task-write'] }]);
    await assert.rejects(fixLegacyAccess({ home: fixture.home, yes: true, task: ordinary.task, log: quiet }),
      /from an administrator terminal/);
    const unchanged = accessTask(fixture, [{ missing: [] }]);
    assert.equal((await fixLegacyAccess({ home: fixture.home, task: unchanged.task, log: quiet })).status, 'unchanged');
    const manual = accessTask(fixture, [{ missing: ['task-write', 'cli-delete'], elevated: true }]);
    await assert.rejects(fixLegacyAccess({ home: fixture.home, yes: true, task: manual.task, log: quiet }),
      /need an administrator to change them by hand[\s\S]*cannot rename it/);
    const planned = accessTask(fixture, [{ missing: ['task-write', 'cli-owner'], elevated: true }]);
    const plan = await fixLegacyAccess({ home: fixture.home, plan: true, task: planned.task, log: quiet });
    assert.deepEqual({ status: plan.status, changes: plan.changes }, { status: 'planned', changes: ['task-write', 'cli-owner'] });
    const unconfirmed = accessTask(fixture, [{ missing: ['task-write'], elevated: true }]);
    await assert.rejects(fixLegacyAccess({ home: fixture.home, task: unconfirmed.task, log: quiet }), /interactive confirmation or --yes/);
    const declined = await fixLegacyAccess({
      home: fixture.home, interactive: true, confirm: async () => false, task: unconfirmed.task, log: quiet,
    });
    assert.equal(declined.status, 'cancelled');
    for (const flow of [ordinary, unchanged, manual, planned, unconfirmed]) assert.deepEqual(flow.calls.grant, []);
    assert.deepEqual(journals(), []);

    const fixed = accessTask(fixture, [{ missing: ['task-write', 'cli-owner'], elevated: true }, { missing: [], elevated: true }]);
    const result = await fixLegacyAccess({ home: fixture.home, yes: true, task: fixed.task, log: quiet, now });
    assert.equal(result.status, 'fixed');
    assert.deepEqual(result.changed, ['task-write', 'cli-owner']);
    assert.equal(fixed.calls.grant.length, 1);
    assert.equal(fixed.calls.grant[0].expected.xmlSha256, fixture.originalTask.xmlSha256);
    const journal = JSON.parse(readFileSync(result.journal, 'utf8'));
    assert.equal(journal.kind, 'legacy-access-fix');
    assert.deepEqual(journal.changes, ['task-write', 'cli-owner']);
    assert.equal(journal.before.xmlSha256, fixture.originalTask.xmlSha256);
    assert.ok(journal.after);
    assert.deepEqual(fixture.task.read().actions, ['fixture-registered'], 'The access fix never edits the registration itself.');

    const failing = accessTask(fixture, [{ missing: ['task-write', 'cli-owner'], elevated: true }], {
      grant: () => { throw Object.assign(new Error('LEGACY_ACCESS_UNVERIFIED: owned failure'), { changed: ['task-write'] }); },
    });
    const later = () => new Date('2026-10-15T01:02:04.000Z');
    await assert.rejects(fixLegacyAccess({ home: fixture.home, yes: true, task: failing.task, log: quiet, now: later }),
      /owned failure\nRecorded before-state: /);
    const failed = JSON.parse(readFileSync(join(fixture.home, 'legacy-upgrade', 'access-2026-10-15T01-02-04.000Z.json'), 'utf8'));
    assert.deepEqual({ failed: failed.failed, changed: failed.changed }, { failed: 'LEGACY_ACCESS_UNVERIFIED: owned failure', changed: ['task-write'] });

    const stuck = accessTask(fixture, [{ missing: ['task-write'], elevated: true }, { missing: ['task-write'], elevated: true }]);
    const last = () => new Date('2026-10-15T01:02:05.000Z');
    await assert.rejects(fixLegacyAccess({ home: fixture.home, yes: true, task: stuck.task, log: quiet, now: last }),
      /Access is still missing after the fix: task-write\. Recorded before-state: /);
    assert.equal(stuck.calls.grant.length, 1);
  } finally { await fixture.cleanup(); }
});
