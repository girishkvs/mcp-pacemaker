import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync, rmSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { LegacyUpgradeFixture } from './helpers/legacy-upgrade-fixture.mjs';
import { retainedRegistry } from './helpers/managed-registry.mjs';
import { runAccountController } from '../bin/account-upgrade-controller.mjs';
import { minimalTaskRecord } from '../bin/task-only-controller.mjs';
import { backendStatus } from '../bin/managed-runtime.mjs';
import { readManagedJson } from '../bin/managed-state.mjs';
import { npmCliPath } from '../bin/update-check.mjs';
import * as channelApi from '../bin/windows-task-channel.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 960000 };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

class OwnedAccountTask {
  constructor(fixture, registry, { launchWorker = true, original = fixture.originalTask, crashAt } = {}) {
    this.fixture = fixture;
    this.registry = registry;
    this.launchWorker = launchWorker;
    this.record = structuredClone(original);
    this.original = structuredClone(original);
    this.actions = [];
    this.operations = [];
    this.metrics = [];
    this.crashAt = crashAt;
  }
  timedApi() {
    return {
      ...channelApi,
      queryTaskChannelCaller: () => this.measure('controller-caller', () => channelApi.queryTaskChannelCaller()),
      createTaskChannel: async options => {
        const channel = await this.measure('channel-create', () => channelApi.createTaskChannel(options));
        let verb = 'pre-peer';
        const receive = channel.receive;
        channel.receive = async () => {
          const packet = await receive();
          verb = packet.frame.verb;
          return packet;
        };
        const authorize = channel.authorize;
        channel.authorize = () => this.measure(`authorize:${verb}`, authorize);
        return channel;
      },
    };
  }
  async measure(action, operation) {
    const started = performance.now();
    try { return await operation(); }
    finally { this.metrics.push({ action, elapsedMs: performance.now() - started, at: new Date().toISOString() }); }
  }
  inspect() { return { record: structuredClone(this.record), profilePath: this.fixture.directory, allowDemandStart: true }; }
  session() {
    const identity = this.fixture.initialProcesses;
    return { sessionId: this.sessionId,
      supervisorImage: { path: identity.roots.supervisor.imagePath, sha256: identity.roots.supervisor.imageSha256 } };
  }
  change(expected, kind, apply) {
    assert.deepEqual(expected, this.record);
    const originalSecurity = structuredClone(this.record.security);
    apply(this.record);
    const semantic = { ...this.record };
    delete semantic.xml;
    delete semantic.xmlSha256;
    this.record.xml = JSON.stringify(semantic);
    this.record.xmlSha256 = hash(this.record.xml);
    assert.deepEqual(this.record.security, originalSecurity);
    this.actions.push(kind);
    return structuredClone(this.record);
  }
  bootstrap(expected, original, bootstrap) {
    this.bootstrapSpec = bootstrap;
    this.args = [...bootstrap.arguments.matchAll(/"([^"]*)"/g)].map(match => match[1]);
    const manifestPath = this.args[this.args.indexOf('--manifest') + 1];
    this.operations.push(dirname(manifestPath));
    const manifest = readManagedJson(manifestPath);
    this.currentBinding = manifest.document.binding;
    this.fixture.instances.push(manifest.document.binding.destination);
    return this.change(expected, 'bootstrap', record => {
      record.actions = [{ type: 0, path: bootstrap.nodePath, arguments: bootstrap.arguments, workingDirectory: bootstrap.cwd }];
      for (const trigger of record.triggers) trigger.enabled = false;
      record.settings.restartCount = 0;
    });
  }
  hold(expected) {
    return this.change(expected, 'hold', record => {
      for (const trigger of record.triggers) trigger.enabled = false;
      record.settings.restartCount = 0;
    });
  }
  repoint(expected, original, launcher) {
    return this.change(expected, 'repoint', record => {
      record.actions = [{ type: 0, path: 'wscript.exe', arguments: `"${launcher}"`, workingDirectory: '' }];
    });
  }
  release(expected) {
    return this.change(expected, 'release', record => {
      record.triggers = structuredClone(this.original.triggers);
      record.settings.restartCount = this.original.settings.restartCount;
    });
  }
  restore(expected, original) {
    assert.deepEqual(expected, this.record);
    this.actions.push('restore');
    this.record = structuredClone(original);
    return structuredClone(this.record);
  }
  launch(expected) {
    assert.deepEqual(expected, this.record);
    if (this.launchWorker) {
      const userconfig = join(this.fixture.directory, 'worker.npmrc');
      const globalconfig = join(this.fixture.directory, 'worker-global.npmrc');
      writeFileSync(userconfig, `registry=${this.registry}\nstrict-ssl=true\nfetch-retries=0\n`);
      writeFileSync(globalconfig, '');
      const env = {
        ...this.fixture.env(),
        npm_execpath: process.env.MCP_UPGRADE_TEST_NPM_CLI || npmCliPath(),
        npm_config_registry: this.registry, npm_config_userconfig: userconfig, npm_config_globalconfig: globalconfig,
      };
      delete env.NODE_OPTIONS;
      if (this.crashAt) {
        env.NODE_OPTIONS = `--import=${pathToFileURL(fileURLToPath(new URL('./fixtures/account-worker-crash-hook.mjs', import.meta.url))).href}`;
        env.MCP_ACCOUNT_OWNED_CRASH = this.crashAt;
        env.MCP_ACCOUNT_OWNED_CRASH_RECORD = join(this.fixture.directory, 'owned-worker-crash.json');
      }
      assert.equal(this.bootstrapSpec.nodePath, process.execPath);
      this.workerExit = this.fixture.launchWorker(this.args, env);
    }
    return { requested: true, instanceGuid: 'owned-correlation-only', readinessProven: false };
  }
  retainAndRemoveOperations() {
    for (const path of this.operations) {
      const journal = join(path, 'controller-journal.json');
      if (existsSync(journal) && process.env.MCP_ACCOUNT_TEST_EVIDENCE) {
        const name = path.split(/[\\/]/).pop();
        writeFileSync(join(process.env.MCP_ACCOUNT_TEST_EVIDENCE, `${name}.json`), readFileSync(journal), { flag: 'wx', mode: 0o600 });
      }
      rmSync(path, { recursive: true });
    }
  }
}

for (const restoreFails of [false, true]) {
test(`review15 actual worker decline ${restoreFails ? 'retains controller-only recovery evidence on failed restoration' : 'restores original task'} without changing backend generation`, windows, async () => {
  const fixture = new LegacyUpgradeFixture({ taskOwner: 'builtin-administrators' });
  let registry, adapter;
  try {
    const old = await fixture.start();
    registry = await retainedRegistry(fixture.artifact(), '2.0.3');
    adapter = new OwnedAccountTask(fixture, registry.url);
    if (restoreFails) adapter.restore = async () => { throw new Error('Owned task restoration denied'); };
    const actor = await channelApi.queryTaskChannelCaller();
    adapter.sessionId = actor.identity.sessionId;
    let prompts = 0;
    const operation = runAccountController(fileURLToPath(new URL('../', import.meta.url)), {
      explicit: true, targetSid: actor.identity.ownerSid, taskPath: fixture.originalTask.path,
      args: ['upgrade', '--to', '2.0.3', '--registry', registry.url],
    }, { task: adapter, channelApi: adapter.timedApi(), confirm: async () => ++prompts === 1, report: () => {} });
    if (restoreFails) {
      await assert.rejects(operation, /Manual verified restoration.*no controller-operation-only recovery command/);
      assert.equal(await adapter.workerExit, 1, fixture.log);
      const journal = readManagedJson(join(dirname(adapter.currentBinding.manifestPath), 'controller-journal.json'));
      const manifest = readManagedJson(adapter.currentBinding.manifestPath);
      assert.equal(journal.phase, 'uncertain');
      assert.deepEqual(journal.initial, adapter.original);
      assert.deepEqual(manifest.document.initialTask, adapter.original);
      assert.deepEqual(adapter.actions, ['bootstrap']);
    } else {
      assert.equal((await operation).status, 'cancelled');
      assert.equal(await adapter.workerExit, 0, fixture.log);
      assert.deepEqual(adapter.record, adapter.original);
      assert.deepEqual(adapter.actions, ['bootstrap', 'restore']);
    }
    assert.equal(prompts, 2);
    assert.deepEqual(adapter.record.security, adapter.original.security);
    assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
    assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
    assert.equal(existsSync(adapter.currentBinding.destination), false);
    assert.deepEqual(registry.requests, []);
  } finally {
    if (adapter?.workerExit) await adapter.workerExit;
    await registry?.close();
    try { await fixture.cleanup(); }
    finally { adapter?.retainAndRemoveOperations(); }
  }
});
}

for (const phase of ['published', 'hold-ack', 'legacy-held']) {
  test(`review16-17 owned worker crash at ${phase} retains initial link and repeated recovery is read-only`, windows, async () => {
    const fixture = new LegacyUpgradeFixture({ taskOwner: 'builtin-administrators' });
    let registry, adapter;
    try {
      const old = await fixture.start();
      registry = await retainedRegistry(fixture.artifact(), '2.0.3');
      adapter = new OwnedAccountTask(fixture, registry.url, { crashAt: phase });
      const actor = await channelApi.queryTaskChannelCaller();
      adapter.sessionId = actor.identity.sessionId;
      const invoke = scope => runAccountController(fileURLToPath(new URL('../', import.meta.url)), scope, {
        task: adapter, channelApi: adapter.timedApi(), confirm: async () => true, report: () => {},
      });
      await assert.rejects(invoke({
        explicit: true, targetSid: actor.identity.ownerSid, taskPath: fixture.originalTask.path,
        args: ['upgrade', '--to', '2.0.3', '--registry', registry.url],
      }));
      assert.equal(await adapter.workerExit, 86, fixture.log);
      const crash = readManagedJson(join(fixture.directory, 'owned-worker-crash.json'));
      const binding = adapter.currentBinding;
      const controller = readManagedJson(join(dirname(binding.manifestPath), 'controller-journal.json'));
      assert.equal(controller.peer.pid, crash.pid);
      const record = readManagedJson(join(crash.destination, 'instance.json'));
      if (process.env.MCP_ACCOUNT_TEST_EVIDENCE) {
        writeFileSync(join(process.env.MCP_ACCOUNT_TEST_EVIDENCE, `${phase}-owned-crash.json`), JSON.stringify({
          crash, observedExitCode: 86, peer: controller.peer, instance: record,
          runtimeJournal: readManagedJson(join(crash.destination, 'journal.json')),
        }, null, 2), { flag: 'wx', mode: 0o600 });
      }
      assert.deepEqual(record.controllerOperation, {
        manifestPath: binding.manifestPath, operationId: binding.operationId,
        taskPath: binding.taskPath, targetSid: binding.targetSid,
      });
      for (const lock of [join(crash.destination, 'upgrade.lock'), join(fixture.home, 'legacy-upgrade', 'upgrade.lock')]) {
        if (!existsSync(lock)) continue;
        assert.equal(readManagedJson(lock).pid, crash.pid);
        unlinkSync(lock);
      }
      assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
      adapter.crashAt = undefined;
      const scope = { explicit: true, targetSid: actor.identity.ownerSid,
        instance: crash.destination, args: ['upgrade', '--recover'] };
      const recovered = await invoke(scope);
      assert.equal(recovered.status, 'legacy-aborted');
      assert.equal(await adapter.workerExit, 0, fixture.log);
      assert.deepEqual(adapter.record, adapter.original);
      assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
      const actions = [...adapter.actions];
      const operations = [...adapter.operations];
      assert.equal((await invoke(scope)).status, 'legacy-aborted');
      assert.deepEqual(adapter.actions, actions);
      assert.deepEqual(adapter.operations, operations);
      assert.deepEqual(adapter.record, adapter.original);
      assert.equal((await backendStatus(fixture.port)).instanceId, old.instanceId);
      assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
    } catch (error) {
      throw new Error(`${error.message}\nOwned worker output:\n${fixture.log}`, { cause: error });
    } finally {
      if (adapter?.workerExit) await adapter.workerExit;
      await registry?.close();
      try { await fixture.cleanup(); }
      finally { adapter?.retainAndRemoveOperations(); }
    }
  });
}

for (const [kind, failsStartup] of [['legacy', false], ['legacy', true], ['managed', false], ['managed', true]]) {
  test(`original-account worker actual same-user pipe ${failsStartup ? 'rolls back' : 'upgrades'} ${kind} builtin-admin-owned model without controller runtime execution`, windows, async () => {
    const fixture = new LegacyUpgradeFixture({ taskOwner: 'builtin-administrators' });
    let registry;
    let adapter;
    try {
      await fixture.start();
      let directory;
      let original = fixture.originalTask;
      if (kind === 'managed') {
        fixture.task.stableRecords = () => [minimalTaskRecord(fixture.task.read().current)];
        const plan = await fixture.plan();
        await fixture.approve(plan);
        const migrated = await fixture.upgrader().execute(plan);
        directory = migrated.directory;
        original = fixture.task.read().current;
      }
      const old = await backendStatus(fixture.port);
      const targetVersion = kind === 'legacy' ? '2.0.3' : '2.0.4';
      const artifact = fixture.artifact(failsStartup ? root => {
        const path = join(root, 'bin', 'mcp-bridge.mjs');
        const code = readFileSync(path, 'utf8');
        const anchor = "const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));";
        assert.ok(code.includes(anchor));
        writeFileSync(path, code.replace(anchor, `if (!CONFIG.includes('preflight')) throw new Error('owned startup failure');\n${anchor}`));
      } : undefined, targetVersion);
      registry = await retainedRegistry(artifact, targetVersion);
      adapter = new OwnedAccountTask(fixture, registry.url, { original });
      const actor = await channelApi.queryTaskChannelCaller();
      adapter.sessionId = actor.identity.sessionId;
      const scope = { explicit: true, targetSid: actor.identity.ownerSid,
        ...(directory ? { instance: directory } : { taskPath: fixture.originalTask.path }),
        args: ['upgrade', '--to', targetVersion, '--registry', registry.url] };
      const operation = runAccountController(fileURLToPath(new URL('../', import.meta.url)), scope, {
        task: adapter, channelApi: adapter.timedApi(), confirm: async () => true, report: () => {},
      });
      if (failsStartup) await assert.rejects(operation, /worker failed/);
      else assert.equal((await operation).status, 'upgraded');
      const code = await adapter.workerExit;
      assert.equal(code, failsStartup ? 1 : 0, fixture.log);
      if (failsStartup) {
        const directory = fixture.instances[fixture.instances.length - 1];
        assert.equal(readManagedJson(join(directory, 'journal.json')).phase, kind === 'legacy' ? 'legacy-rolled-back' : 'rolled-back', fixture.log);
      }
      const status = await backendStatus(fixture.port);
      const expectedVersion = failsStartup ? old.version : targetVersion;
      assert.equal(status.version, expectedVersion);
      assert.notEqual(status.instanceId, old.instanceId);
      assert.deepEqual(readFileSync(fixture.config), fixture.originalConfig);
      assert.deepEqual(adapter.record.security, adapter.original.security);
      assert.equal(adapter.record.security.ownerSid, 'S-1-5-32-544');
      assert.equal(await fixture.cliVersion(), expectedVersion);
      assert.ok(registry.requests.length > 0);
    } catch (error) {
      const rollbackOutput = fixture.instances.map(directory => join(directory, 'rollback-launcher.log'))
        .filter(existsSync).map(path => readFileSync(path, 'utf8')).join('\n');
      throw new Error(`Owned account operation failed: ${error.message}\nWorker output:\n${fixture.log}\nRollback output:\n${rollbackOutput}`, { cause: error });
    } finally {
      if (adapter?.workerExit) await adapter.workerExit;
      await registry?.close();
      if (adapter && process.env.MCP_ACCOUNT_TEST_EVIDENCE) {
        writeFileSync(join(process.env.MCP_ACCOUNT_TEST_EVIDENCE, `${kind}-${failsStartup ? 'rollback' : 'upgrade'}-timings.json`), JSON.stringify({
          metrics: adapter.metrics,
          observation: 'Native API promise timings only; no concurrent reads of the worker activation journal.',
        }, null, 2), { flag: 'wx', mode: 0o600 });
      }
      try { await fixture.cleanup(); }
      finally { adapter?.retainAndRemoveOperations(); }
    }
  });
}
