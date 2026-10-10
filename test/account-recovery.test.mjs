import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInstance, durableJson, readManagedJson } from '../bin/managed-state.mjs';
import { runAccountController } from '../bin/account-upgrade-controller.mjs';
import { executeAccountUpgrade } from '../bin/account-upgrade-worker.mjs';
import { operationDigest, taskRevision } from '../bin/task-transaction-protocol.mjs';
import { ownedPackageSelection } from './helpers/managed-package.mjs';

const sid = 'S-1-5-21-1-2-3-1000';
const windows = { skip: process.platform !== 'win32' };

class RecoveryMetadataFixture {
  constructor() {
    this.directory = realpathSync.native(mkdtempSync(join(tmpdir(), 'account recovery metadata ')));
    this.root = join(this.directory, 'package');
    for (const path of ['bin', 'supervisor']) mkdirSync(join(this.root, path), { recursive: true });
    writeFileSync(join(this.root, 'package.json'), JSON.stringify({ name: 'mcp-pacemaker', version: '2.0.3' }));
    for (const path of ['bin/mcp-bridge.mjs', 'supervisor/supervise.mjs']) writeFileSync(join(this.root, path), '// Inert owned metadata fixture.\n');
    writeFileSync(join(this.root, 'bin/upgrade-capability.json'), '{"protocol":1}\n');
    this.config = join(this.directory, 'servers.json');
    writeFileSync(this.config, '{}\n');
    this.operationId = randomUUID();
    this.operation = join(this.directory, this.operationId);
    mkdirSync(this.operation);
    this.reference = { manifestPath: join(this.operation, 'manifest.json'), operationId: this.operationId,
      taskPath: '\\OwnedRecoveryTask', targetSid: sid };
    this.instance = createInstance({
      directory: join(this.directory, 'instance'), root: this.root, config: this.config, port: 32192,
      selection: ownedPackageSelection(this.root), controllerOperation: this.reference,
    });
    this.initialRecord = readManagedJson(join(this.instance.directory, 'instance.json'));
    this.record = { path: this.reference.taskPath, name: 'OwnedRecoveryTask', userSid: sid, currentUserSid: sid,
      logonType: 3, runLevel: 0, enabled: true, xml: '<Task>owned</Task>',
      security: { ownerSid: sid, sddl: 'owned complete descriptor', sha256: 'bound-owner-dacl-sacl-label' } };
    this.mutations = 0;
    this.channelCalls = 0;
    this.api = {
      queryTaskChannelCaller: async () => ({ actorFacts: { ownerSid: sid, elevated: false } }),
      inspectTrustedCodeRoot: async path => { assert.equal(path, this.operation); },
      createTaskChannel: async () => { this.channelCalls++; throw new Error('Settled recovery must not bootstrap another worker.'); },
    };
    this.task = {
      inspect: async () => ({ record: this.record, allowDemandStart: true, profilePath: this.directory }),
      bootstrap: async () => { this.mutations++; throw new Error('No task mutation expected.'); },
    };
  }
  prepare(phase) {
    durableJson(join(this.instance.directory, 'instance.json'), { ...this.initialRecord, controllerOperation: this.reference });
    this.binding = {
      protocol: 1, operationId: this.operationId, manifestPath: this.reference.manifestPath,
      taskPath: this.reference.taskPath, targetSid: sid, sessionId: 2, destination: this.instance.directory,
      root: this.root, config: this.config, port: this.instance.port, from: '1.3.0', to: '2.0.3',
      kind: 'legacy', registry: null, originalTaskRevision: taskRevision(this.record),
    };
    this.manifest = { protocol: 1, operationId: this.operationId, targetSid: sid, sessionId: 2,
      document: { binding: this.binding, digest: operationDigest(this.binding) } };
    this.prior = { protocol: 1, binding: this.binding, original: this.record, current: this.record, phase: 'completed' };
    this.journal = {
      protocol: 1, instanceId: this.instance.id,
      binding: { config: this.config, cwd: this.instance.cwd, node: this.instance.node, port: this.instance.port },
      previous: null, target: this.instance.active, recovery: this.instance.active, phase,
      legacy: { protocol: 1, acknowledged: 'restart-with-uncertain-http-and-partial-tree-v1', root: this.root },
    };
    this.save();
  }
  save() {
    durableJson(this.reference.manifestPath, this.manifest);
    durableJson(join(this.operation, 'controller-journal.json'), this.prior);
    durableJson(join(this.instance.directory, 'journal.json'), this.journal);
  }
  recover() {
    return runAccountController(this.root, {
      explicit: true, targetSid: sid, instance: this.instance.directory, args: ['upgrade', '--recover'],
    }, { channelApi: this.api, task: this.task, confirm: async () => true, report: () => {} });
  }
  cleanup() { rmSync(this.directory, { recursive: true }); }
}

test('review16 initial instance identity contains the protected operation before publication or HOLD', () => {
  const fixture = new RecoveryMetadataFixture();
  try { assert.deepEqual(fixture.initialRecord.controllerOperation, fixture.reference); }
  finally { fixture.cleanup(); }
});

for (const phase of ['committed', 'rolled-back', 'aborted', 'legacy-rolled-back', 'legacy-aborted']) {
  test(`review17 settled ${phase} recovery is read-only and repeatable without bootstrap`, windows, async () => {
    const fixture = new RecoveryMetadataFixture();
    try {
      fixture.prepare(phase);
      const before = readFileSync(join(fixture.instance.directory, 'instance.json'));
      assert.equal((await fixture.recover()).status, phase);
      assert.equal((await fixture.recover()).status, phase);
      assert.equal(fixture.channelCalls, 0);
      assert.equal(fixture.mutations, 0);
      assert.deepEqual(readFileSync(join(fixture.instance.directory, 'instance.json')), before);
    } finally { fixture.cleanup(); }
  });
}

for (const field of ['operationId', 'targetSid', 'taskPath', 'config', 'port', 'digest']) {
  test(`review16 inconsistent protected operation ${field} refuses before bootstrap`, windows, async () => {
    const fixture = new RecoveryMetadataFixture();
    try {
      fixture.prepare('committed');
      if (field === 'operationId') {
        durableJson(join(fixture.instance.directory, 'instance.json'), {
          ...fixture.initialRecord, controllerOperation: { ...fixture.reference, operationId: randomUUID() },
        });
      } else if (field === 'digest') fixture.manifest.document.digest = '0'.repeat(64);
      else if (field === 'targetSid') fixture.manifest.targetSid = 'S-1-5-21-1-2-3-1001';
      else if (field === 'taskPath') fixture.manifest.document.binding = { ...fixture.binding, taskPath: '\\OtherTask' };
      else fixture.prior.binding = { ...fixture.binding, [field]: field === 'port' ? 32193 : join(fixture.directory, 'other.json') };
      fixture.save();
      await assert.rejects(fixture.recover(), /binding|operation|disagree|scope/i);
      assert.equal(fixture.channelCalls, 0);
      assert.equal(fixture.mutations, 0);
    } finally { fixture.cleanup(); }
  });
}

test('review17 terminal runtime with unresolved task outcome refuses without rewriting the task', windows, async () => {
  const fixture = new RecoveryMetadataFixture();
  try {
    fixture.prepare('legacy-aborted');
    fixture.prior.phase = 'uncertain';
    fixture.save();
    await assert.rejects(fixture.recover(), /unresolved/);
    assert.equal(fixture.channelCalls, 0);
    assert.equal(fixture.mutations, 0);
  } finally { fixture.cleanup(); }
});

test('review17 recovery approval hashes bounded selection identity rather than the entire package inventory', async () => {
  const fixture = new RecoveryMetadataFixture();
  const cwd = process.cwd();
  try {
    fixture.prepare('legacy-held');
    fixture.journal.target.files = Array.from({ length: 129 }, (_, i) => ({
      path: `owned-${i}.mjs`, sha256: '0'.repeat(64),
    }));
    durableJson(join(fixture.instance.directory, 'active.json'), fixture.journal.target);
    fixture.save();
    let asked = false;
    const result = await executeAccountUpgrade({
      binding: { ...fixture.binding, home: fixture.directory, recover: true },
      call: async (verb, body) => {
        assert.equal(verb, 'PLAN');
        assert.match(body.digest, /^[a-f0-9]{64}$/);
        asked = true;
        return { approved: false };
      },
    });
    assert.equal(asked, true);
    assert.equal(result.status, 'cancelled');
  } finally { process.chdir(cwd); fixture.cleanup(); }
});
