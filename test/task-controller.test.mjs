import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { managementScope, authorizeTaskActor } from '../bin/task-scope.mjs';
import {
  canonicalJson, ControllerSignatures, operationDigest, taskRevision, validateTaskRequest, verifyTargetSession, WorkerSignatures,
} from '../bin/task-transaction-protocol.mjs';
import { TaskOnlyController } from '../bin/task-only-controller.mjs';
import { accountUpgradeOptions, runAccountController } from '../bin/account-upgrade-controller.mjs';
import { AccountTaskAdapter } from '../bin/account-task-adapter.mjs';
import { AccountWorkerSession } from '../bin/account-worker-session.mjs';
import { verifyCliSelectionTrust } from '../bin/cli-dispatch.mjs';
import { readManagedJson } from '../bin/managed-state.mjs';

const current = 'S-1-5-21-1-2-3-1000';
const other = 'S-1-5-21-1-2-3-1001';
const peer = { pid: 101, creationTime: '134359472611830204', ownerSid: current, sessionId: 2 };
const targetSession = { sessionId: 2, ownerSid: current, state: 'active', logonTime: '134350000000000000',
  observedAt: '2026-10-08T00:00:00.000Z', source: 'wts-account-sid-snapshot', atomicRunExBinding: false };
const facts = { ownerSid: current, elevated: false, enabledAdministrator: false,
  restricted: false, appContainer: false, guardThreadImpersonating: false, parentThreadImpersonation: 'observed-none' };
const cliContext = {
  proofScope: 'cli-effective-context-snapshot', ordinaryEligible: true, reason: 'ordinary-owned-model',
  identity: { ...peer, pid: process.pid }, actorFacts: facts, helperExit: { code: 0, signal: null },
  observation: { method: 'pss-threads-held-token-query', threadCount: 3, completeStableThreadSet: true,
    primaryStable: true, atomicFutureProtection: false, processAccess: '0x101400', captureFlags: '0x80', threadContextFlags: 0 },
};

test('account scope defaults current-user and never infers all-users from elevation or a path', () => {
  assert.equal(managementScope(['upgrade', '--to', '2.0.3']).explicit, false);
  assert.equal(managementScope(['--instance', 'owned', 'status']).explicit, false);
  assert.equal(authorizeTaskActor({ ...facts, elevated: true, enabledAdministrator: true }, current), 'current-user');
  for (const args of [
    ['upgrade', '--all-users'], ['upgrade', '--all-users=true'],
    ['upgrade', '--user', other], ['upgrade', '--task', '\\McpPacemaker-8791'],
    ['upgrade', '--user', 'Administrator', '--task', '\\McpPacemaker-8791'],
    ['upgrade', '--user', other, '--task', '\\McpPacemaker-8791', '--instance', 'owned'],
    ['upgrade', '--user', other, '--user', current, '--task', '\\McpPacemaker-8791'],
    ['upgrade', '--user', other, '--task', '\\..\\other'],
  ]) assert.throws(() => managementScope(args));
  const scope = managementScope(['--user=' + other, 'upgrade', '--task=\\McpPacemaker-8791', '--to', '2.0.3']);
  assert.equal(scope.targetSid, other);
  assert.equal(scope.taskPath, '\\McpPacemaker-8791');
  assert.deepEqual(scope.args, ['upgrade', '--to', '2.0.3']);
  assert.equal(managementScope(['upgrade', '--', '--user', other]).explicit, false);
  assert.equal(managementScope(['upgrade', '--to', '--', '--user', other]).explicit, false);
});

for (const [name, selector, options] of [
  ['SxS automatic port', ['--task', '\\OwnedTask'], ['--to', '2.0.3', '--sxs']],
  ['SxS explicit port', ['--task', '\\OwnedTask'], ['--to', '2.0.3', '--sxs', '--port', '32191']],
  ['SxS equals flag', ['--task', '\\OwnedTask'], ['--to=2.0.3', '--sxs=true']],
  ['normal explicit port', ['--task', '\\OwnedTask'], ['--to', '2.0.3', '--port', '32191']],
  ['equals port', ['--instance=owned'], ['--to=2.0.3', '--port=32191']],
  ['bare repair', ['--task', '\\OwnedTask'], []],
  ['self guidance', ['--task', '\\OwnedTask'], ['--self']],
  ['self with target', ['--task', '\\OwnedTask'], ['--self', '--to', '2.0.3']],
  ['recover through task selector', ['--task', '\\OwnedTask'], ['--recover']],
  ['recover with target', ['--instance', 'owned'], ['--recover', '--to', '2.0.3']],
  ['recover with registry override', ['--instance', 'owned'], ['--recover', '--registry', 'https://owned.invalid/']],
  ['recover with plan', ['--instance', 'owned'], ['--recover', '--plan']],
  ['recover unattended', ['--instance', 'owned'], ['--recover', '--yes']],
  ['both selectors', ['--task', '\\OwnedTask', '--instance', 'owned'], ['--to', '2.0.3']],
  ['all-users conversion', ['--task', '\\OwnedTask'], ['--to', '2.0.3', '--all-users']],
  ['configuration override', ['--task', '\\OwnedTask'], ['--to', '2.0.3', '--config', 'other.json']],
]) {
  test(`account option matrix refuses ${name} before native or task discovery`, { skip: process.platform !== 'win32' }, async () => {
    let touched = false;
    await assert.rejects(async () => {
      const scope = managementScope(['--user', current, ...selector, 'upgrade', ...options]);
      await runAccountController('unused-root', scope, {
        channelApi: { queryTaskChannelCaller: async () => { touched = true; throw new Error('Native discovery must not run.'); } },
        task: { inspect: async () => { touched = true; throw new Error('Task discovery must not run.'); } },
      });
    });
    assert.equal(touched, false);
  });
}

test('account option matrix preserves equals and separate instance selectors with explicit supported modes', () => {
  for (const args of [
    ['--user', current, '--instance=owned', 'upgrade', '--to=2.0.3', '--plan'],
    ['upgrade', '--to', '2.0.3', '--user', current, '--instance', 'owned', '--plan'],
  ]) {
    const scope = managementScope(args);
    assert.equal(scope.instance, 'owned');
    assert.equal(scope.targetSid, current);
    assert.deepEqual(accountUpgradeOptions(scope.args), { instance: 'owned', to: '2.0.3', plan: true });
  }
  const recovery = managementScope(['--user', current, 'upgrade', '--recover', '--instance=owned']);
  assert.deepEqual(accountUpgradeOptions(recovery.args), { recover: true, instance: 'owned' });
  const task = managementScope(['upgrade', '--user=' + current, '--task=\\OwnedTask',
    '--to=2.0.3', '--plan', '--yes', '--registry=https://owned.invalid/', '--controller-root=owned store']);
  assert.equal(task.taskPath, '\\OwnedTask');
  assert.deepEqual(accountUpgradeOptions(task.args), {
    to: '2.0.3', plan: true, yes: true, registry: 'https://owned.invalid/', 'controller-root': 'owned store',
  });
});

test('account invocation cannot discard a disagreeing parsed instance option', { skip: process.platform !== 'win32' }, async () => {
  await assert.rejects(runAccountController('unused-root', {
    targetSid: current, instance: 'first', args: ['upgrade', '--to', '2.0.3', '--instance', 'second'],
  }, {
    channelApi: { queryTaskChannelCaller: async () => assert.fail('No discovery before selector agreement.') },
  }), /selector disagrees/);
});

test('ordinary current-user repair guidance SxS and recovery arguments remain unchanged', () => {
  for (const args of [
    ['upgrade'], ['upgrade', '--self'], ['upgrade', '--to', '2.0.3', '--sxs'],
    ['upgrade', '--to', '2.0.3', '--sxs', '--port', '32191'],
    ['upgrade', '--recover', '--instance', 'owned', '--yes'],
  ]) {
    const scope = managementScope(args);
    assert.equal(scope.explicit, false);
    assert.deepEqual(scope.args, args);
  }
});

test('cross-user controller authorization requires every actual token fact, not a saved admin label', () => {
  const valid = { ...facts, elevated: true, enabledAdministrator: true };
  assert.equal(authorizeTaskActor(valid, other), 'explicit-other-user');
  for (const mutation of [
    { elevated: false }, { enabledAdministrator: false }, { restricted: true }, { appContainer: true },
    { parentThreadImpersonation: 'unverified' }, { parentThreadImpersonation: 'observed' }, { guardThreadImpersonating: true },
  ]) assert.throws(() => authorizeTaskActor({ ...valid, ...mutation, savedAdministrator: true }, other));
  assert.throws(() => authorizeTaskActor(facts, other));
});

test('domain-separated signatures bind operation, challenge, OS peer, sequence and exact request', () => {
  const controller = new ControllerSignatures();
  const operationId = randomUUID();
  const digest = operationDigest({ operationId, targetSid: current });
  const worker = new WorkerSignatures({ publicKey: controller.publicKey, operationId, digest, identity: peer, targetSession });
  const request = worker.request('HELLO', { challenge: worker.challenge, identity: peer });
  const args = { operationId, digest, challenge: worker.challenge, peer, targetSession, sequence: 0,
    request, stateDigest: digest, body: { ok: true } };
  const response = controller.response(args);
  for (const mutation of [
    { operationId: randomUUID() }, { digest: '0'.repeat(64) }, { challenge: '0'.repeat(64) },
    { peer: { ...peer, pid: 102 } }, { peer: { ...peer, ownerSid: other } },
    { sequence: 1 }, { body: { ok: false } }, { requestDigest: '0'.repeat(64) },
    { targetSession: { ...targetSession, ownerSid: other } },
  ]) assert.throws(() => worker.accept({ ...response, ...mutation }, request));
  const otherKey = new ControllerSignatures();
  assert.throws(() => worker.accept(otherKey.response(args), request));
  assert.deepEqual(worker.accept(response, request), { ok: true });
  assert.throws(() => worker.accept(response, request), /authentication/);
  assert.notEqual(operationDigest(['a', 'bc']), operationDigest(['ab', 'c']));
  assert.throws(() => canonicalJson(JSON.parse('{"__proto__":{}}')));
});

test('fixed task frames reject worker-selected executables, tasks, principals and replay', () => {
  const operationId = randomUUID();
  const digest = operationDigest({ operationId });
  const request = { protocol: 1, operationId, sequence: 1, stateDigest: digest, verb: 'REPOINT', body: null };
  validateTaskRequest(request, operationId, 1, digest);
  for (const mutation of [
    { taskPath: '\\unrelated' }, { body: { launcher: 'evil.exe' } }, { body: { principal: other } },
    { sequence: 0 }, { stateDigest: '0'.repeat(64) }, { verb: 'KILL' }, { verb: 'EXEC' },
    { operationId: randomUUID() },
  ]) assert.throws(() => validateTaskRequest({ ...request, ...mutation }, operationId, 1, digest));
});

class ControllerFixture {
  constructor(binding = {}) {
    this.binding = { operationId: randomUUID(), targetSid: current, sessionId: 2,
      destination: 'owned-instance', launcher: 'owned-launcher', port: 32191, from: '1.3.0', to: '2.0.3',
      bootstrapTask: { nodePath: 'trusted-node', arguments: 'sealed-args', cwd: 'trusted-root' }, ...binding };
    this.original = { path: '\\OwnedTask', userSid: current, currentUserSid: current, logonType: 3, runLevel: 0,
      enabled: true, xml: 'original', security: { ownerSid: 'S-1-5-32-544', sddl: 'unchanged', sha256: 'full-sd' } };
    this.record = structuredClone(this.original);
    this.calls = [];
    const set = phase => {
      this.calls.push(phase);
      this.record = { ...this.record, xml: phase };
      return structuredClone(this.record);
    };
    this.task = {
      inspect: async () => ({ record: structuredClone(this.record) }),
      bootstrap: async (...args) => { assert.deepEqual(args[2], this.binding.bootstrapTask); return set('bootstrap'); },
      hold: async () => set('held'),
      repoint: async (...args) => { assert.equal(args[2], this.binding.launcher); return set('selected'); },
      release: async () => set('released'),
      restore: async () => { this.calls.push('restore'); this.record = structuredClone(this.original); return this.record; },
      launch: async () => ({ requested: true, instanceGuid: 'correlation-only', readinessProven: false }),
    };
    this.channel = { targetSession, workerSession: targetSession,
      authorize: async () => ({ actorFacts: facts, targetSession }), close: async () => {} };
    this.signatures = new ControllerSignatures();
    this.controller = new TaskOnlyController({
      binding: this.binding, original: this.original, task: this.task, channel: this.channel,
      signatures: this.signatures, confirm: async () => true,
    });
    this.worker = new WorkerSignatures({ publicKey: this.signatures.publicKey, operationId: this.binding.operationId,
      digest: operationDigest(this.binding), identity: peer, targetSession });
  }
  async request(verb, body) {
    const request = this.worker.request(verb, body);
    const response = await this.controller.accept({ peer, frame: request });
    return this.worker.accept(response, request);
  }
  async ready() {
    await this.controller.mutate('bootstrap', 'bootstrap');
    this.controller.peer = peer;
    await this.request('HELLO', { challenge: this.worker.challenge, identity: peer });
    await this.request('PLAN', { digest: operationDigest({ owned: true }), summary: 'Owned plan' });
  }
  declineFlow() {
    let request;
    let step = 0;
    this.channel.awaitWorker = async () => peer;
    this.channel.receive = async () => {
      const requests = [
        ['HELLO', { challenge: this.worker.challenge, identity: peer }],
        ['PLAN', { digest: operationDigest({ owned: true }), summary: 'Owned plan' }],
      ];
      assert.ok(step < requests.length, 'Decline must not request staging, hold or stop.');
      const [verb, body] = requests[step++];
      request = this.worker.request(verb, body);
      return { peer, frame: request };
    };
    this.channel.send = async response => {
      const body = this.worker.accept(response, request);
      if (request.verb === 'PLAN') assert.equal(body.approved, false);
    };
    this.controller.confirm = async () => false;
  }
}

test('review15 declined second approval restores exact pre-bootstrap revision without approving runtime work', async () => {
  const fixture = new ControllerFixture();
  fixture.record = { ...fixture.original, xml: 'exact pre-bootstrap recovery revision' };
  fixture.controller.initial = structuredClone(fixture.record);
  fixture.controller.current = structuredClone(fixture.record);
  fixture.task.restore = async (expected, original) => {
    assert.deepEqual(expected, fixture.record);
    fixture.calls.push('restore');
    fixture.record = structuredClone(original);
    return fixture.record;
  };
  fixture.declineFlow();
  const result = await fixture.controller.run();
  assert.equal(result.status, 'cancelled');
  assert.equal(fixture.controller.phase, 'cancelled');
  assert.deepEqual(fixture.record, fixture.controller.initial);
  assert.deepEqual(fixture.record.security, fixture.original.security);
  assert.deepEqual(fixture.calls, ['bootstrap', 'restore']);
});

for (const failure of ['reauthorization', 'restoration', 'wrong-restored-revision']) {
  test(`review15 declined approval retains uncertainty on ${failure} failure`, async () => {
    const fixture = new ControllerFixture();
    fixture.declineFlow();
    let restoreAttempted = false;
    if (failure === 'reauthorization') {
      fixture.controller.confirm = async () => {
        fixture.channel.authorize = async () => { throw new Error('owned reauthorization failure'); };
        return false;
      };
    } else if (failure === 'restoration') {
      fixture.task.restore = async () => { restoreAttempted = true; throw new Error('owned restoration failure'); };
    } else fixture.task.restore = async () => {
      restoreAttempted = true;
      return { ...fixture.original, xml: 'wrong restored revision' };
    };
    await assert.rejects(fixture.controller.run());
    assert.equal(fixture.controller.phase, 'uncertain');
    assert.equal(fixture.controller.approvedPlan, undefined);
    assert.equal(restoreAttempted, failure !== 'reauthorization');
    assert.ok(!fixture.calls.includes('selected'));
  });
}

test('controller-only failed decline restoration preserves initial evidence and advertises manual recovery only', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'controller-only-recovery-'));
  const destination = join(directory, 'absent-managed-instance');
  const fixture = new ControllerFixture({
    destination, manifestPath: join(directory, 'manifest.json'), taskPath: '\\OwnedTask',
  });
  fixture.controller.journalPath = join(directory, 'controller-journal.json');
  fixture.declineFlow();
  fixture.task.restore = async () => { throw new Error('Owned full-SD restoration denied'); };
  try {
    await assert.rejects(fixture.controller.run(), error => {
      assert.match(error.message, /Manual verified restoration/);
      assert.match(error.message, /no controller-operation-only recovery command/);
      assert.match(error.message, /without a published instance, --instance cannot recover/);
      assert.match(error.message, /--task --recover is unsupported/);
      assert.ok(error.message.includes(JSON.stringify(directory)));
      return true;
    });
    const journal = readManagedJson(fixture.controller.journalPath);
    assert.equal(journal.phase, 'uncertain');
    assert.deepEqual(journal.initial, fixture.original);
    assert.deepEqual(journal.initial.security, fixture.original.security);
    assert.equal(existsSync(destination), false);
    assert.deepEqual(fixture.calls, ['bootstrap']);
  } finally { rmSync(directory, { recursive: true }); }
});

test('task controller uses only sealed variants and preserves builtin-admin ownership through rollback', async () => {
  const fixture = new ControllerFixture();
  await fixture.ready();
  await fixture.request('HOLD', null);
  await fixture.request('REPOINT', null);
  await fixture.request('ENABLE', null);
  await fixture.request('HOLD', null);
  await fixture.request('RESTORE', null);
  assert.deepEqual(fixture.record, fixture.original);
  assert.deepEqual(fixture.calls, ['bootstrap', 'selected', 'released', 'held', 'restore']);
});

test('ACL-only drift rejects task RPC before any further mutation', async () => {
  const fixture = new ControllerFixture();
  await fixture.ready();
  fixture.record.security = { ...fixture.record.security, sha256: 'changed' };
  const calls = fixture.calls.length;
  await assert.rejects(fixture.request('HOLD', null), /revision|security/);
  assert.equal(fixture.calls.length, calls);
});

test('task API S_OK without an authenticated worker cannot authorize stop or managed selection', async () => {
  const fixture = new ControllerFixture();
  fixture.channel.awaitWorker = async () => { throw new Error('No actual worker'); };
  await assert.rejects(fixture.controller.run(), /No actual worker/);
  assert.deepEqual(fixture.calls, ['bootstrap', 'restore']);
  assert.equal(fixture.controller.phase, 'restored-bootstrap');
});

test('controller account refusal occurs before task discovery or target-code execution', { skip: process.platform !== 'win32' }, async () => {
  let touched = false;
  await assert.rejects(runAccountController('trusted-root', {
    explicit: true, targetSid: other, taskPath: '\\OtherTask', args: ['upgrade', '--to', '2.0.3'],
  }, {
    channelApi: { queryTaskChannelCaller: async () => ({ actorFacts: facts }) },
    task: { inspect: () => { touched = true; throw new Error('must not inspect'); } },
  }), /already-elevated/);
  assert.equal(touched, false);
});

test('same XML cannot conceal a task descriptor revision change', () => {
  const fixture = new ControllerFixture();
  assert.notEqual(taskRevision(fixture.original),
    taskRevision({ ...fixture.original, security: { ...fixture.original.security, sha256: 'changed' } }));
});

test('untrusted caller code root is refused before target metadata discovery or execution', { skip: process.platform !== 'win32' }, async () => {
  let taskRead = false;
  const actor = { ...facts, elevated: true, enabledAdministrator: true };
  await assert.rejects(runAccountController('target-writable-root', {
    targetSid: other, taskPath: '\\OwnedTask', args: ['upgrade', '--to=2.0.3'],
  }, {
    channelApi: {
      queryTaskChannelCaller: async () => ({ actorFacts: actor }),
      inspectTrustedCodeRoot: async root => {
        assert.equal(root, 'target-writable-root');
        throw new Error('Untrusted writer can redirect the controller code root.');
      },
    },
    task: { inspect: async () => { taskRead = true; } },
  }), /Untrusted writer/);
  assert.equal(taskRead, false);
});

test('elevated task adapter uses fixed own scripts and strips target executable environment overrides', { skip: process.platform !== 'win32' }, () => {
  const previous = Object.fromEntries(['NODE_OPTIONS', 'NODE_PATH', 'npm_execpath', 'MCP_PACEMAKER_CLI_CONTEXT',
    'COR_ENABLE_PROFILING', 'COR_PROFILER_PATH', 'CORECLR_PROFILER', 'CORECLR_PROFILER_PATH_64',
    'DOTNET_STARTUP_HOOKS', 'COMPlus_ReadyToRun']
    .map(key => [key, process.env[key]]));
  for (const key of Object.keys(previous)) process.env[key] = 'owned-redirection-sentinel';
  let called = false;
  try {
    const adapter = new AccountTaskAdapter({
      taskPath: '\\SealedTask', targetSid: current, powershell: process.execPath,
      run: (file, args, options) => {
        called = true;
        assert.equal(file, process.execPath);
        assert.ok(args.includes('-NoProfile'));
        assert.ok(args[args.indexOf('-File') + 1].endsWith('account-task.ps1'));
        for (const key of Object.keys(previous)) assert.equal(options.env[key], undefined);
        const input = JSON.parse(options.input);
        assert.equal(input.taskPath, '\\SealedTask');
        assert.equal(input.targetSid, current);
        return '{}';
      },
    });
    adapter.call('inspect', { taskPath: '\\AttackerTask', targetSid: other });
    assert.equal(called, true);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('authenticated worker disconnect leaves phase-specific uncertainty without privileged cleanup', async () => {
  const fixture = new ControllerFixture();
  let request;
  let step = 0;
  fixture.channel.awaitWorker = async () => peer;
  fixture.channel.receive = async () => {
    const cases = [
      ['HELLO', { challenge: fixture.worker.challenge, identity: peer }],
      ['PLAN', { digest: operationDigest({ owned: true }), summary: 'Owned plan' }],
      ['HOLD', null],
    ];
    if (step === cases.length) throw new Error('Owned peer disconnected');
    const [verb, body] = cases[step++];
    request = fixture.worker.request(verb, body);
    return { peer, frame: request };
  };
  fixture.channel.send = async response => { fixture.worker.accept(response, request); };
  await assert.rejects(fixture.controller.run(), /disconnected/);
  assert.equal(fixture.controller.phase, 'uncertain');
  assert.deepEqual(fixture.calls, ['bootstrap']);
});

for (const [name, mutation] of [
  ['missing', null],
  ['wrong owner', { ...targetSession, ownerSid: other }],
  ['wrong session', { ...targetSession, sessionId: 3 }],
  ['changed generation', { ...targetSession, logonTime: '134350000000000001' }],
  ['logged out', { ...targetSession, state: 'listen' }],
  ['unsupported authority', { ...targetSession, source: 'saved-profile' }],
  ['claimed reservation', { ...targetSession, atomicRunExBinding: true }],
]) {
  test(`worker refuses correctly signed ${name} session facts without advancing its transcript`, () => {
    const fixture = new ControllerFixture();
    const request = fixture.worker.request('INSPECT');
    const response = fixture.signatures.response({
      operationId: fixture.binding.operationId, digest: fixture.worker.digest, challenge: fixture.worker.challenge,
      peer, targetSession: mutation, sequence: 0, request, stateDigest: fixture.worker.digest, body: {},
    });
    assert.throws(() => fixture.worker.accept(response, request), /session eligibility/);
    assert.equal(fixture.worker.sequence, 0);
  });
}

test('session eligibility allows disconnected but logged-on without claiming atomic RunEx ownership', () => {
  const value = { ...targetSession, state: 'disconnected' };
  assert.equal(verifyTargetSession(value, targetSession), value);
});

test('approval wait rechecks session generation before authorizing original-user staging', async () => {
  const fixture = new ControllerFixture();
  await fixture.controller.mutate('bootstrap', 'bootstrap');
  fixture.controller.peer = peer;
  await fixture.request('HELLO', { challenge: fixture.worker.challenge, identity: peer });
  fixture.controller.confirm = async () => {
    fixture.channel.authorize = async () => ({
      actorFacts: facts, targetSession: { ...targetSession, logonTime: '134350000000000001' },
    });
    return true;
  };
  await assert.rejects(fixture.request('PLAN', { digest: operationDigest({ owned: true }), summary: 'Owned plan' }), /session eligibility/);
  assert.equal(fixture.controller.phase, 'authenticated');
  assert.deepEqual(fixture.calls, ['bootstrap']);
});

for (const workerSession of [undefined, { ...targetSession, logonTime: '134350000000000001' }]) {
  test(`postlaunch ${workerSession ? 'changed' : 'missing'} native session binding refuses before worker RPC`, async () => {
    const fixture = new ControllerFixture();
    fixture.channel.workerSession = workerSession;
    fixture.channel.awaitWorker = async () => peer;
    fixture.channel.receive = async () => assert.fail('Worker RPC must not run.');
    await assert.rejects(fixture.controller.run(), /session eligibility/);
    assert.deepEqual(fixture.calls, ['bootstrap', 'restore']);
  });
}

for (const [nested, elevated] of [[true, false], [false, false], [true, true], [false, true]]) {
  test(`CLI trust uses one covered-tree inspection with nested=${nested} elevated=${elevated}`, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'owned-cli-trust-'));
    const instance = { directory: join(directory, 'instance'), node: join(directory, 'node', 'node.exe') };
    const selection = { root: nested ? join(instance.directory, 'versions', 'selected') : join(directory, 'selected') };
    const root = join(directory, 'caller');
    for (const path of [instance.directory, selection.root, root]) mkdirSync(path, { recursive: true });
    const calls = [];
    try {
      const reasons = [];
      await verifyCliSelectionTrust(root, instance, selection, {
        context: async () => ({ ...cliContext, ordinaryEligible: false, reason: 'owned-unknown-or-elevated',
          actorFacts: { ...facts, elevated, parentThreadImpersonation: 'unverified' } }),
        report: reason => reasons.push(reason),
        inspect: async path => { calls.push(path); },
      });
      assert.deepEqual(calls, [
        instance.directory, ...(!nested ? [selection.root] : []),
        root, join(directory, 'node'),
      ]);
      assert.equal(reasons.length, 1);
      calls.length = 0;
      await assert.rejects(verifyCliSelectionTrust(root, instance, selection, {
        context: async () => ({ ...cliContext, ordinaryEligible: false }), report: () => {},
        inspect: async path => { calls.push(path); throw new Error('Owned untrusted writer model'); },
      }), /untrusted writer/);
      assert.deepEqual(calls, [instance.directory]);
    } finally { rmSync(directory, { recursive: true }); }
  });
}

test('ordinary CLI shortcut uses complete actual helper context without reading target account claims', async () => {
  await verifyCliSelectionTrust('unused-root', { elevated: true, sameUser: false }, { ownerSid: other }, {
    context: async () => cliContext,
    inspect: async () => assert.fail('Ordinary non-elevated dispatch must not scan administrator code roots.'),
    report: () => assert.fail('Verified ordinary context needs no strict-fallback warning.'),
  });
});

for (const [name, mutation] of [
  ['primary-only', { observation: undefined, actorFacts: { ...facts, parentThreadImpersonation: 'unverified' } }],
  ['thread token', { actorFacts: { ...facts, parentThreadImpersonation: 'observed-impersonating' } }],
  ['thread churn', { observation: { ...cliContext.observation, completeStableThreadSet: false } }],
  ['primary drift', { observation: { ...cliContext.observation, primaryStable: false } }],
  ['elevated', { actorFacts: { ...facts, elevated: true } }],
  ['enabled administrator', { actorFacts: { ...facts, enabledAdministrator: true } }],
]) {
  test(`CLI ${name} observation cannot select the ordinary shortcut even with a positive flag`, async () => {
    let checked = false;
    const reasons = [];
    await assert.rejects(verifyCliSelectionTrust('root', { directory: 'owned-directory', sameUser: true }, {}, {
      context: async () => ({ ...cliContext, ...mutation }),
      report: reason => reasons.push(reason),
      inspect: async () => { checked = true; throw new Error('Owned strict-path sentinel'); },
    }), /strict-path sentinel/);
    assert.equal(checked, true);
    assert.equal(reasons.length, 1);
  });
}

test('CLI unverified helper exit remains fatal and cannot become fallback success', async () => {
  for (const result of [
    { ...cliContext, helperExit: undefined }, { ...cliContext, cleanupUnverified: true },
    { ...cliContext, identity: { ...cliContext.identity, pid: process.pid + 1 } },
  ]) {
    await assert.rejects(verifyCliSelectionTrust('root', {}, {}, {
      context: async () => result, inspect: async () => assert.fail('No fallback after unverified helper exit.'),
    }), /unverified/);
  }
  await assert.rejects(verifyCliSelectionTrust('root', {}, {}, {
    context: async () => { throw new Error('Owned exit-unverified error'); },
    inspect: async () => assert.fail('Thrown native errors must not be swallowed.'),
  }), /exit-unverified/);
});

test('worker session checks send only native-captured minimal identities and never excluded processes', () => {
  const fixture = new ControllerFixture();
  const binding = { ...fixture.binding, root: 'C:\\owned\\legacy' };
  const session = new AccountWorkerSession({
    operationId: binding.operationId, targetSid: current, sessionId: 2, targetSession,
    document: { binding, digest: operationDigest(binding), publicKey: fixture.signatures.publicKey },
  }, peer);
  const captured = [11, 12, 13].map(pid => ({ ...peer, pid, imagePath: 'unneeded-path', argvSha256: 'unneeded-hash' }));
  const plan = { ownerSid: current, root: binding.root, port: binding.port,
    roots: { supervisor: captured[0], bridge: captured[1] }, observed: [captured[2]], excluded: [{ ...peer, pid: 99 }] };
  const queries = [];
  session.queryProcessSessions = value => { queries.push(value); };
  session.verifyProcessSessions(plan);
  assert.deepEqual(queries, [{ identities: captured.map(({ pid, creationTime, ownerSid }) => ({ pid, creationTime, ownerSid })) }]);
  assert.throws(() => session.verifyProcessSessions({ ...plan, ownerSid: other }), /protected operation/);
  assert.equal(queries.length, 1);
});

test('worker session capture validates 512 canonical unique identities before query dispatch', () => {
  const fixture = new ControllerFixture();
  const binding = { ...fixture.binding, root: 'C:\\owned\\legacy' };
  const session = new AccountWorkerSession({
    operationId: binding.operationId, targetSid: current, sessionId: 2, targetSession,
    document: { binding, digest: operationDigest(binding), publicKey: fixture.signatures.publicKey },
  }, peer);
  const identities = Array.from({ length: 512 }, (_, index) => ({ ...peer, pid: index + 1 }));
  const plan = { ownerSid: current, root: binding.root, port: binding.port,
    roots: { supervisor: identities[0], bridge: identities[1] }, observed: identities.slice(2), excluded: [] };
  const queries = [];
  session.queryProcessSessions = value => queries.push(value);
  session.verifyProcessSessions(plan);
  assert.equal(queries[0].identities.length, 512);
  assert.throws(() => session.verifyProcessSessions({ ...plan, observed: [...plan.observed, { ...peer, pid: 513 }] }),
    /identity count/);
  for (const changed of [
    { pid: 1 }, { pid: 1.5 }, { pid: 2147483648 }, { ownerSid: other },
    { creationTime: '01' }, { creationTime: 1 }, { creationTime: '-1' },
  ]) {
    const observed = [...plan.observed];
    observed[0] = { ...observed[0], ...changed };
    assert.throws(() => session.verifyProcessSessions({ ...plan, observed }), /identity|duplicate/);
  }
  assert.equal(queries.length, 1, 'Malformed scopes never reach the query host');
});
