import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLegacyRegistration } from '../bin/legacy-installation.mjs';
import { WindowsLegacyTaskAdapter } from '../bin/legacy-task.mjs';
import { LegacyUpgrader } from '../bin/legacy-upgrade.mjs';
import './fixtures/upgrade-caller-guard-cases.mjs';

const windows = { skip: process.platform !== 'win32' };
const adapter = fileURLToPath(new URL('../autostart/windows/legacy-task.ps1', import.meta.url));
const fixture = fileURLToPath(new URL('./fixtures/legacy-task-com.ps1', import.meta.url));
const restorationFixture = fileURLToPath(new URL('./fixtures/legacy-restoration-xml.ps1', import.meta.url));

test('task adapter retains exact raw precondition despite normalized restoration equivalence', windows, () => {
  const result = JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File', fixture, '-Adapter', adapter,
    '-Operation', 'hold', '-TaskOwner', 'builtin-administrators', '-StoredDefaultsElided',
    '-EchoResourceSecurity', '-StaleXmlRevision'],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 }));
  assert.equal(result.succeeded, false);
  assert.equal(result.mutations, 0);
  assert.equal(result.securityUnchanged, true);
  assert.match(result.error, /Selected task identity changed/);
});

function runAdapter(scenario, operation = 'hold', launcher, taskOwner = 'current-user', runAs = 'current-user', unrelatedArguments = 'none', nullWorkingDirectory = false, storedDefaultsElided = false, postWriteDrift = 'none', echoResourceSecurity = false, postWriteSecurityDrift = 'none') {
  const args = ['-NoProfile', '-File', fixture, '-Adapter', adapter, '-Scenario', scenario, '-Operation', operation];
  args.push('-TaskOwner', taskOwner, '-RunAs', runAs, '-UnrelatedArguments', unrelatedArguments);
  if (launcher) args.push('-Launcher', launcher);
  if (nullWorkingDirectory) args.push('-NullWorkingDirectory');
  if (storedDefaultsElided) args.push('-StoredDefaultsElided');
  args.push('-PostWriteDrift', postWriteDrift);
  if (echoResourceSecurity) args.push('-EchoResourceSecurity');
  args.push('-PostWriteSecurityDrift', postWriteSecurityDrift);
  return JSON.parse(execFileSync('pwsh', args, { encoding: 'utf8', windowsHide: true, timeout: 15000 }));
}

test('real task adapter normalizes an absent COM working directory without changing task XML', windows, () => {
  const result = runAdapter('none', 'start', undefined, 'current-user', 'current-user', 'none', true);
  assert.equal(result.succeeded, true, result.error);
  assert.equal(result.inspectedWorkingDirectory, '');
  assert.equal(result.xmlUnchanged, true);
  assert.equal(result.securityUnchanged, true);
  assert.equal(result.principalUnchanged, true);
});

for (const unrelatedArguments of ['null', 'empty']) {
  test(`real task adapter ignores unrelated exec task with ${unrelatedArguments} arguments`, windows, () => {
    const result = runAdapter('none', 'hold', undefined, 'current-user', 'current-user', unrelatedArguments);
    assert.equal(result.succeeded, true, result.error);
    assert.equal(result.mutations, 1);
    assert.equal(result.securityUnchanged, true);
    assert.equal(result.principalUnchanged, true);
    assert.equal(result.securitySetterCalled, false);
  });
}

for (const taskOwner of ['current-user', 'builtin-administrators']) {
  const scenarios = ['acl', 'owner', 'audit', 'integrity', 'audit-denied', 'missing'];
  if (taskOwner === 'builtin-administrators') scenarios.push('owner-current');
  for (const scenario of scenarios) {
    test(`real task adapter refuses ${scenario} change for ${taskOwner} owner with unchanged XML and run-as identity`, windows, () => {
      const result = runAdapter(scenario, 'hold', undefined, taskOwner);
      assert.equal(result.succeeded, false);
      assert.equal(result.mutations, 0);
      assert.equal(result.xmlUnchanged, true);
      assert.equal(result.principalUnchanged, true);
      assert.equal(result.securityUnchanged, true);
      assert.ok(result.securityReads.every(value => value === 31));
      assert.ok(result.securityReads.length >= 2);
    });
  }
}

for (const taskOwner of ['current-user', 'builtin-administrators']) {
  for (const operation of ['hold', 'enable', 'start', 'repoint', 'restore']) {
    test(`real task adapter preserves ${taskOwner} owner DACL audit and integrity across ${operation}`, windows, () => {
      const directory = mkdtempSync(join(tmpdir(), 'legacy-task-security-'));
      const launcher = join(directory, 'launcher.vbs');
      writeFileSync(launcher, "' owned fixture\n");
      try {
        const result = runAdapter('none', operation, launcher, taskOwner);
        assert.equal(result.succeeded, true, result.error);
        assert.equal(result.securityUnchanged, true);
        assert.equal(result.securitySetterCalled, false);
        assert.equal(result.ownerIsBuiltinAdministrators, taskOwner === 'builtin-administrators');
        assert.equal(result.runAsIsCurrentUser, true);
        assert.ok(result.securityReads.length >= 3);
        assert.ok(result.securityReads.every(value => value === 31));
        if (['repoint', 'restore'].includes(operation)) {
          assert.equal(result.descriptorPreservedByUpdate, true);
          assert.equal(result.sddlArgumentWasNull, true);
          assert.equal(result.candidateDescriptorCleared, true);
          assert.equal(result.registrationFlags & 4, 4, 'Update existing registration only.');
          assert.equal(result.registrationFlags & 16, 16, 'Do not add/remove a principal ACE.');
          assert.equal(result.registrationFlags & 2, 0, 'Never create an absent task.');
        }
      } finally { rmSync(directory, { recursive: true }); }
    });
  }
}

for (const taskOwner of ['unrelated-user', 'misleading-label']) {
  test(`real task adapter refuses ${taskOwner} ownership without changing security`, windows, () => {
    const result = runAdapter('none', 'hold', undefined, taskOwner);
    assert.equal(result.succeeded, false);
    assert.equal(result.mutations, 0);
    assert.equal(result.securityUnchanged, true);
    assert.equal(result.principalUnchanged, true);
  });
}

test('Administrators task ownership never authorizes a different run-as user', windows, () => {
  const result = runAdapter('none', 'hold', undefined, 'builtin-administrators', 'unrelated-user');
  assert.equal(result.succeeded, false);
  assert.equal(result.mutations, 0);
  assert.equal(result.securityUnchanged, true);
  assert.equal(result.principalUnchanged, true);
});

for (const operation of ['hold', 'enable', 'start', 'repoint', 'restore']) {
  for (const drift of ['none', 'action', 'principal', 'enabled', 'trigger', 'settings']) {
    test(`task adapter normalized post-write ${operation} ${drift === 'none' ? 'accepts omitted defaults' : `refuses ${drift} drift`}`, windows, () => {
      const directory = mkdtempSync(join(tmpdir(), 'legacy-task-xml-'));
      const launcher = join(directory, 'launcher.vbs');
      writeFileSync(launcher, "' owned model\n");
      try {
        const result = runAdapter('none', operation, launcher, 'builtin-administrators',
          'current-user', 'none', false, true, drift);
        assert.equal(result.succeeded, drift === 'none', result.error);
        assert.equal(result.mutations, 1);
        assert.equal(result.securityUnchanged, true);
        assert.equal(result.securitySetterCalled, false);
        assert.ok(result.securityReads.every(value => value === 31));
        if (drift !== 'none') assert.match(result.error, /Registration changed beyond the requested scoped edit/);
      } finally { rmSync(directory, { recursive: true }); }
    });
  }
}

for (const operation of ['repoint', 'restore']) {
  for (const drift of ['none', 'action', 'principal', 'enabled', 'trigger', 'settings', 'embedded-security', 'resource-owner',
    'resource-group', 'resource-acl', 'resource-audit', 'resource-integrity']) {
    test(`task adapter embedded descriptor echo ${operation} ${drift === 'none' ? 'preserves resource security' : `refuses ${drift}`}`, windows, () => {
      const directory = mkdtempSync(join(tmpdir(), 'legacy-task-sd-echo-'));
      const launcher = join(directory, 'launcher.vbs');
      writeFileSync(launcher, "' owned model\n");
      const resourceDrift = drift.startsWith('resource-');
      try {
        const result = runAdapter('none', operation, launcher, 'builtin-administrators',
          'current-user', 'none', false, true, resourceDrift ? 'none' : drift, true,
          resourceDrift ? drift.slice('resource-'.length) : 'none');
        assert.equal(result.succeeded, drift === 'none', result.error);
        assert.equal(result.mutations, 1);
        assert.equal(result.securitySetterCalled, false);
        assert.equal(result.descriptorPreservedByUpdate, true);
        assert.equal(result.sddlArgumentWasNull, true);
        assert.equal(result.candidateDescriptorCleared, true);
        assert.ok(result.securityReads.every(value => value === 31));
        if (resourceDrift) assert.match(result.error, /TASK_SECURITY_CHANGED/);
        else {
          assert.equal(result.securityUnchanged, true);
          if (drift !== 'none') assert.match(result.error, /Registration changed beyond the requested scoped edit/);
        }
      } finally { rmSync(directory, { recursive: true }); }
    });
  }
}

test('planning accepts only current-user or canonical builtin Administrators owner identity', windows, () => {
  const directory = mkdtempSync(join(tmpdir(), 'legacy-owner-policy-'));
  const launcher = join(directory, 'autostart', 'windows', 'launcher.vbs');
  mkdirSync(join(directory, 'autostart', 'windows'), { recursive: true });
  writeFileSync(launcher, "' owned fixture\n");
  const userSid = 'S-1-5-21-1-2-3-1000';
  const hash = text => createHash('sha256').update(text).digest('hex');
  const xml = '<Task>owned model</Task>';
  const record = {
    name: 'McpPacemaker-32190', path: '\\McpPacemaker-32190', enabled: true,
    userSid, currentUserSid: userSid, logonType: 3, runLevel: 0, xml, xmlSha256: hash(xml),
    actions: [{ type: 0, path: 'wscript.exe', arguments: `"${launcher}" 32190`, workingDirectory: '' }],
    triggers: [{ type: 9, userSid, enabled: true, stateChange: 0 }, { type: 11, userSid, enabled: true, stateChange: 8 }],
    settings: {
      multipleInstances: 2, restartCount: 3, restartInterval: 'PT1M', executionTimeLimit: 'PT0S',
      startWhenAvailable: true, disallowStartIfOnBatteries: false, stopIfGoingOnBatteries: false,
    },
  };
  const setOwner = ownerSid => {
    const sddl = `O:${ownerSid}G:${userSid}D:P(A;;FA;;;${userSid})S:(ML;;NW;;;ME)`;
    record.security = {
      protocol: 1, information: 31, complete: true, ownerSid, groupSid: userSid,
      controlFlags: 36884, sddl, sha256: hash(sddl),
    };
  };
  try {
    for (const ownerSid of [userSid, 'S-1-5-32-544']) {
      setOwner(ownerSid);
      assert.equal(parseLegacyRegistration([record], 32190).root, directory);
    }
    for (const ownerSid of ['S-1-5-21-1-2-3-1001', 'Administrator', 'BUILTIN\\Administrators',
      'S-1-5-32-0544', 'S-1-5-32-544 ', 's-1-5-32-544']) {
      setOwner(ownerSid);
      record.ownerLabel = 'Administrator';
      assert.throws(() => parseLegacyRegistration([record], 32190), /TASK_SECURITY_UNVERIFIED/);
    }
    setOwner('S-1-5-32-544');
    record.userSid = 'S-1-5-21-1-2-3-1001';
    assert.throws(() => parseLegacyRegistration([record], 32190), /run-as/);
  } finally { rmSync(directory, { recursive: true }); }
});

for (const kind of ['normalized', 'action', 'principal', 'logon', 'runlevel', 'enabled', 'trigger', 'settings',
  'metadata', 'malformed', 'duplicate', 'duplicate-registration', 'wrong-namespace', 'nested', 'dtd']) {
  test(`legacy restoration-only XML comparison ${kind}`, windows, () => {
    const pair = JSON.parse(execFileSync('pwsh', ['-NoProfile', '-File', restorationFixture, '-Case', kind],
      { encoding: 'utf8', windowsHide: true, timeout: 15000 }));
    const hash = text => createHash('sha256').update(text).digest('hex');
    const original = {
      name: 'McpPacemaker-32190', path: '\\McpPacemaker-32190', userSid: pair.sid, currentUserSid: pair.sid,
      enabled: true, logonType: 3, runLevel: 0, security: pair.security,
      xml: pair.originalXml, xmlSha256: hash(pair.originalXml),
    };
    const actual = { ...original, xml: pair.actualXml, xmlSha256: hash(pair.actualXml) };
    const verify = () => new LegacyUpgrader().assertRestoredTask(32190, actual, original);
    if (kind === 'normalized') {
      assert.notEqual(actual.xml, original.xml);
      verify();
      assert.equal(actual.xml, pair.actualXml);
      assert.equal(original.xml, pair.originalXml);
      for (const field of ['name', 'path', 'userSid', 'currentUserSid', 'enabled', 'logonType', 'runLevel']) {
        const changed = { ...actual, [field]: 'changed' };
        assert.throws(() => new WindowsLegacyTaskAdapter().assertRestored(32190, changed, original), /fields, security or raw XML identity/);
      }
      for (const field of ['ownerSid', 'groupSid', 'sddl', 'sha256', 'controlFlags', 'complete', 'information']) {
        const changed = { ...actual, security: { ...actual.security, [field]: 'changed' } };
        assert.throws(() => new WindowsLegacyTaskAdapter().assertRestored(32190, changed, original), /fields, security or raw XML identity/);
      }
      assert.throws(() => new WindowsLegacyTaskAdapter().assertRestored(32190, { ...actual, xmlSha256: '0'.repeat(64) }, original), /raw XML identity/);
      assert.throws(() => new WindowsLegacyTaskAdapter().assertRestored(32190, actual, { ...original, xmlSha256: '0'.repeat(64) }), /raw XML identity/);
      const invalidEqual = { ...original, xmlSha256: '0'.repeat(64) };
      assert.throws(() => new LegacyUpgrader().assertRestoredTask(32190, invalidEqual, invalidEqual), /raw XML identity/);
    } else assert.throws(verify);
  });
}
