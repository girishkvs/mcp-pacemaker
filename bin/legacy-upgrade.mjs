import { randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  acquireInstanceLock, createInstance, directoryIdentity, durableJson,
  readInstanceState, readManagedJson, readRecoveryContext, snapshotPackage, verifySelection,
  legacyMigrationPhases,
} from './managed-state.mjs';
import { inspectInstance, listenerOpen, startInstance, stopInstance } from './managed-runtime.mjs';
import { PoolingFiles } from './pooling-files.mjs';
import { registerDefaultCli } from './cli-dispatch.mjs';
import { servicePaths } from './service-control.mjs';
import { WindowsLegacyTaskAdapter } from './legacy-task.mjs';
import { requireOrdinaryUpgradeCaller } from './windows-task-channel.mjs';
import {
  legacyPlanDigest, parseLegacyRegistration, requireLegacyApproval, verifyLegacyConfig, verifyLegacyListener, verifyLegacyPackage,
} from './legacy-installation.mjs';

export const legacyPhases = legacyMigrationPhases;

export function legacyDormant(instance) {
  const path = join(instance.directory, 'journal.json');
  if (!existsSync(path)) return false;
  const { journal } = readRecoveryContext(instance.directory);
  if (journal.legacy?.protocol !== 1 ||
      !['legacy-rolled-back', 'legacy-aborted'].includes(journal.phase)) return false;
  const validator = new LegacyUpgrader();
  validator.validateJournal(instance, journal);
  validator.assertRestoredTask(instance.port, journal.legacy.taskCurrent, journal.legacy.registration);
  const source = journal.phase === 'legacy-rolled-back' ? journal.restoredLegacyProcesses : journal.legacy.processes;
  if (source?.protocol !== 1 ||
      source.kind !== 'legacy-observed-process-set' ||
      source.root !== journal.legacy.root ||
      source.port !== instance.port ||
      source.ownerSid !== journal.legacy.registration.userSid ||
      source.treeCompleteness !== 'unproven' ||
      source.roots?.bridge?.ownerSid !== source.ownerSid ||
      source.roots?.supervisor?.ownerSid !== source.ownerSid) {
    throw new Error('Dormant legacy source binding is invalid.');
  }
  if (journal.phase === 'legacy-rolled-back') validator.assertPartialStop(journal.legacyStop);
  else if (journal.legacyStop ||
      journal.targetStop) throw new Error('Aborted preparation contains conflicting shutdown evidence.');
  return true;
}

export class LegacyUpgrader {
  constructor({ stage, task = new WindowsLegacyTaskAdapter(), processes, checkpoint = () => {} } = {}) {
    this.stage = stage;
    this.task = task;
    this.processes = processes;
    this.checkpoint = checkpoint;
  }

  async processApi() {
    return this.processes ?? await import('./windows-legacy-process.mjs');
  }

  assertRestoredTask(port, actual, original) {
    if (typeof this.task.assertRestored === 'function') {
      this.task.assertRestored(port, actual, original);
      return;
    }
    if (!isDeepStrictEqual(actual, original)) throw new Error('Restored legacy registration is not the original identity.');
  }

  publishPrepared(instance, destination, journal) {
    destination = resolve(destination);
    const parent = dirname(destination);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    directoryIdentity(parent);
    if (existsSync(destination)) throw new Error('Managed destination exists; no candidate was overwritten.');
    durableJson(join(instance.directory, 'journal.json'), journal);
    const launcher = join(destination, 'stable-launcher.mjs');
    if (/["\r\n]/.test(instance.node + launcher)) throw new Error('Unsupported Windows launcher path.');
    writeFileSync(join(instance.directory, 'launcher.vbs'),
      `Set shell = CreateObject("WScript.Shell")\r\nshell.Run """${instance.node}"" ""${launcher}""", 0, False\r\n`);
    durableJson(join(instance.directory, 'instance.json'), {
      ...readManagedJson(join(instance.directory, 'instance.json')), directory: destination,
    });
    renameSync(instance.directory, destination);
    const published = readInstanceState(destination);
    this.validateJournal(published, readRecoveryContext(destination).journal);
    return published;
  }

  transition(instance, journal, phase, changes = {}) {
    const current = readInstanceState(instance.directory);
    if (current.id !== journal.instanceId ||
        current.directoryIdentity !== instance.directoryIdentity ||
        current.active.root !== journal.target.root) throw new Error('Legacy migration instance identity changed.');
    Object.assign(journal, changes, { phase });
    durableJson(join(instance.directory, 'journal.json'), journal);
    this.checkpoint(phase, journal);
  }

  async taskMatches(instance, expected) {
    if (this.task.verifyBinding) return await this.task.verifyBinding(instance, expected);
    const actual = await this.task.inspect(instance.port);
    if (actual.length !== 1 ||
        !isDeepStrictEqual(actual[0], expected)) throw new Error('Selected legacy registration changed. Its task hold was not released.');
    return actual[0];
  }

  verifySource(instance, legacy, { cliPath } = {}) {
    if (verifyLegacyPackage(legacy.root, { cliPath }) !== legacy.rootIdentity) throw new Error('Legacy root directory identity changed.');
    verifyLegacyConfig(instance.config, legacy);
    new PoolingFiles(instance.config).verify(join(dirname(instance.config), 'state.json'), legacy.stateAuthority);
  }

  validateJournal(instance, journal) {
    const legacy = journal.legacy;
    const operationValid = typeof journal.operation === 'string' &&
      /^[a-f0-9-]{36}$/.test(journal.operation);
    if (!operationValid ||
        !legacy ||
        legacy.protocol !== 1 ||
        legacy.acknowledged !== 'restart-with-uncertain-http-and-partial-tree-v1' ||
        !legacy.processes ||
        legacy.processes.treeCompleteness !== 'unproven' ||
        legacy.processes.root !== legacy.root ||
        legacy.processes.port !== instance.port ||
        legacy.processes.ownerSid !== legacy.registration?.userSid ||
        legacy.rootIdentity !== directoryIdentity(legacy.root) ||
        legacy.backendInstanceId !== journal.originalInstanceId ||
        !isDeepStrictEqual(journal.authority, legacy.authority) ||
        !isDeepStrictEqual(journal.sessionState, legacy.sessions) ||
        !legacy.cli ||
        legacy.cli.path !== join(legacy.root, 'bin', 'cli.mjs') ||
        legacy.cli.saved !== join(legacy.root, 'bin', `cli.mjs.legacy-${journal.operation}`) ||
        legacy.cli.staged !== join(legacy.root, 'bin', `cli.mjs.next-${journal.operation}`) ||
        journal.binding.config !== instance.config ||
        journal.binding.port !== instance.port) throw new Error('Legacy recovery binding or acknowledgement is invalid.');
    const registered = parseLegacyRegistration([legacy.registration], instance.port);
    if (registered.root !== legacy.root) throw new Error('Legacy journal task and package roots disagree.');
    if (['legacy-stopped', 'legacy-launching', 'legacy-wiring', 'legacy-admitting'].includes(journal.phase)) {
      this.assertPartialStop(journal.legacyStop);
    }
  }

  async execute(plan) {
    await requireOrdinaryUpgradeCaller();
    const approvalDigest = legacyPlanDigest(plan);
    requireLegacyApproval(plan);
    this.verifySource(plan.instance, plan.legacy);
    await this.taskMatches(plan.instance, plan.legacy.registration);
    const operation = randomUUID();
    const parent = join(dirname(plan.instance.config), 'legacy-upgrade');
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    let releaseWork;
    try { releaseWork = acquireInstanceLock(parent); }
    catch (error) {
      if (error.code === 'EEXIST') {
        throw new Error(`Legacy preparation lock remains at ${join(parent, 'upgrade.lock')}. Verify the original upgrader has exited, preserve its preparation files, and remove only its lock before retrying. This attempt did not change a task or process.`);
      }
      throw error;
    }
    const work = join(parent, operation);
    let session;
    let instance;
    let journal;
    let releaseInstance;
    let published = false;
    try {
      mkdirSync(work, { mode: 0o700 });
      this.verifySource(plan.instance, plan.legacy);
      await this.taskMatches(plan.instance, plan.legacy.registration);
      const target = await this.stage({ ...plan, instance: { ...plan.instance, directory: work } }, operation);
      const capability = readManagedJson(join(target.root, 'bin', 'upgrade-capability.json'));
      if (capability.legacyRestartProtocol !== 1) throw new Error('Target does not support legacy restart recovery; old service was not touched.');
      const recovery = snapshotPackage(target.root, join(work, 'recovery'));
      verifySelection(recovery);
      this.verifySource(plan.instance, plan.legacy);
      await this.taskMatches(plan.instance, plan.legacy.registration);
      const api = await this.processApi();
      session = await api.prepareLegacyProcesses({
        port: plan.instance.port, root: plan.legacy.root, expected: plan.legacy.processes,
      });
      await verifyLegacyListener(plan.instance, plan.legacy);
      if (legacyPlanDigest(plan) !== approvalDigest) throw new Error('Legacy plan changed after acknowledgement.');
      const pointer = join(dirname(plan.instance.config), 'cli-instance.json');
      if (existsSync(pointer)) throw new Error('A default managed CLI selection already exists; legacy migration refused.');
      instance = createInstance({
        ...plan.instance, directory: join(work, 'candidate'), root: target.root, selection: target,
      });
      await this.checkpoint('legacy-candidate-created', { instance, operation, work });
      for (const file of ['cli-dispatch.mjs', 'task-scope.mjs', 'task-transaction-protocol.mjs']) {
        copyFileSync(new URL(`./${file}`, import.meta.url), join(instance.directory, file));
      }
      const configBackup = join(work, 'servers.backup.json');
      new PoolingFiles(instance.config).stage(configBackup, instance.config, plan.legacy.authority, readFileSync(instance.config));
      const cliPath = join(plan.legacy.root, 'bin', 'cli.mjs');
      const cliFiles = new PoolingFiles(cliPath);
      const original = cliFiles.inspect(cliPath);
      const backup = join(work, 'cli.backup.mjs');
      const backupAuthority = cliFiles.stage(backup, cliPath, original, readFileSync(cliPath));
      const taskBackup = join(work, 'legacy-task.json');
      new PoolingFiles(instance.config).stage(taskBackup, instance.config, plan.legacy.authority,
        Buffer.from(JSON.stringify({
          name: plan.legacy.registration.name, path: plan.legacy.registration.path,
          xml: plan.legacy.registration.xml, security: plan.legacy.registration.security,
        })));
      const staged = join(plan.legacy.root, 'bin', `cli.mjs.next-${operation}`);
      const shim = Buffer.from([
        '#!/usr/bin/env node',
        `import { dispatchCli } from ${JSON.stringify(pathToFileURL(join(plan.instance.directory, 'cli-dispatch.mjs')).href)};`,
        `try { await dispatchCli(${JSON.stringify(recovery.root)}); }`,
        'catch (error) { console.error(error.message); process.exitCode = 1; }',
        '',
      ].join('\n'));
      const stagedAuthority = cliFiles.stage(staged, cliPath, original, shim);
      journal = {
        protocol: 1, operation, instanceId: instance.id, previous: null, target, recovery,
        binding: { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port },
        authority: plan.legacy.authority, sessionState: plan.legacy.sessions,
        originalInstanceId: plan.legacy.backendInstanceId,
        phase: 'legacy-prepared', launchToken: randomUUID(), configBackup,
        legacy: {
          ...plan.legacy, approvalDigest, acknowledged: 'restart-with-uncertain-http-and-partial-tree-v1',
          taskCurrent: plan.legacy.registration, taskBackup,
          cli: { path: cliPath, original, backup, backupAuthority, staged, stagedAuthority,
            saved: join(plan.legacy.root, 'bin', `cli.mjs.legacy-${operation}`) },
        },
      };
      instance = this.publishPrepared(instance, plan.instance.directory, journal);
      published = true;
      releaseInstance = acquireInstanceLock(instance.directory);
      this.transition(instance, journal, 'legacy-prepared');
      this.verifySource(instance, journal.legacy);
      await verifyLegacyListener(instance, journal.legacy);
      this.transition(instance, journal, 'legacy-holding');
      journal.legacy.taskCurrent = await this.task.hold(instance.port, journal.legacy.taskCurrent);
      if (journal.legacy.taskCurrent.enabled &&
          this.task.holdKind !== 'automatic-triggers') throw new Error('Selected legacy registration did not remain held.');
      await this.taskMatches(instance, journal.legacy.taskCurrent);
      this.transition(instance, journal, 'legacy-held');
      this.verifySource(instance, journal.legacy);
      await verifyLegacyListener(instance, journal.legacy);
      this.transition(instance, journal, 'legacy-stopping');
      await this.taskMatches(instance, journal.legacy.taskCurrent);
      const legacyStop = await session.stop();
      this.transition(instance, journal, 'legacy-stopping', { legacyStop });
      this.assertPartialStop(legacyStop);
      this.transition(instance, journal, 'legacy-stopped', { legacyStop });
      return await this.activate(instance, journal);
    } catch (error) {
      if (journal &&
          published) {
        this.transition(instance, journal, journal.phase, { error: error.message });
        if (['legacy-stopped', 'legacy-launching', 'legacy-wiring'].includes(journal.phase)) {
          if (error.cleanupUnverified) throw new Error('Target shutdown is unverified; task hold and legacy recovery journal were retained.', { cause: error });
          await this.rollback(instance, journal, { startupProof: error.startupProof });
        }
      }
      throw error;
    } finally {
      try { await session?.close(); }
      finally {
        try { releaseInstance?.(); }
        finally { releaseWork(); }
      }
    }
  }

  assertPartialStop(receipt) {
    if (receipt?.legacyRootStopVerified !== true ||
        receipt.observedDescendantsStopped !== true ||
        receipt.treeCompleteness !== 'unproven' ||
        !Array.isArray(receipt.errors) ||
        receipt.errors.length ||
        'stopped' in receipt ||
        'activeProcesses' in receipt) throw new Error('Legacy root/observed-set shutdown is incomplete. Registration remains held; no activation was authorized.');
  }

  async verifyOldStopped(instance, journal) {
    this.assertPartialStop(journal.legacyStop);
    const api = await this.processApi();
    this.assertPartialStop(await api.verifyLegacyProcessesGone(journal.legacy.processes));
    if (await listenerOpen(instance.port)) throw new Error('Selected port has a listener after legacy stop; it was not touched.');
  }

  async activate(instance, journal) {
    await this.verifyOldStopped(instance, journal);
    this.verifySource(instance, journal.legacy);
    await this.taskMatches(instance, journal.legacy.taskCurrent);
    verifySelection(journal.target);
    this.transition(instance, journal, 'legacy-launching');
    const started = await startInstance(instance.directory, { pending: true, token: journal.launchToken });
    const ready = await inspectInstance(started.instance);
    if (!ready.held ||
        ready.traffic ||
        ready.instanceId === journal.originalInstanceId ||
        !isDeepStrictEqual(ready.authority, journal.authority)) throw new Error('New managed backend is not safely held with the expected config.');
    verifyLegacyConfig(instance.config, journal.legacy);
    this.transition(instance, journal, 'legacy-wiring', { targetInstanceId: ready.instanceId });
    journal.legacy.taskCurrent = await this.task.repoint(instance.port, journal.legacy.taskCurrent,
      join(instance.directory, 'launcher.vbs'));
    this.transition(instance, journal, 'legacy-wiring');
    this.selectCli(instance, journal);
    journal.legacy.taskCurrent = await this.task.enable(instance.port, journal.legacy.taskCurrent);
    await this.taskMatches(instance, journal.legacy.taskCurrent);
    const records = await this.task.stableRecords(instance.port);
    durableJson(join(instance.directory, 'instance.json'), {
      ...readManagedJson(join(instance.directory, 'instance.json')),
      autostart: records.length ? { kind: 'stable', records } : { kind: 'none' },
    });
    verifyLegacyConfig(instance.config, journal.legacy);
    this.transition(instance, journal, 'legacy-admitting');
    await inspectInstance(started.instance, 'activate', journal);
    this.transition(instance, journal, 'committed');
    return {
      status: 'upgraded', directory: instance.directory, port: instance.port, version: journal.target.version,
      legacyStop: journal.legacyStop,
      warning: 'Legacy HTTP outcomes were not certified or replayed. Historical orphan coverage is unproven; unattributed processes were left untouched.',
    };
  }

  selectCli(instance, journal) {
    const cli = journal.legacy.cli;
    const files = new PoolingFiles(cli.path);
    files.verify(cli.path, cli.original);
    files.verify(cli.staged, cli.stagedAuthority);
    files.move(cli.path, cli.saved, cli.original);
    this.checkpoint('legacy-cli-original-moved', journal);
    files.move(cli.staged, cli.path, cli.stagedAuthority);
    this.checkpoint('legacy-cli-selected', journal);
    registerDefaultCli(dirname(instance.config), instance);
    const pointer = join(dirname(instance.config), 'cli-instance.json');
    const selected = readManagedJson(pointer);
    if (selected.id !== instance.id ||
        selected.directory !== instance.directory) throw new Error('Default CLI selection belongs to another instance.');
    journal.legacy.pointerAuthority = new PoolingFiles(instance.config).inspect(pointer);
    this.transition(instance, journal, 'legacy-wiring');
  }

  restoreCli(instance, journal) {
    const cli = journal.legacy.cli;
    const files = new PoolingFiles(cli.path);
    files.verify(cli.backup, cli.backupAuthority);
    if (existsSync(cli.saved)) {
      files.verify(cli.saved, cli.original);
      if (existsSync(cli.path)) {
        files.verify(cli.path, cli.stagedAuthority);
        files.move(cli.path, cli.staged, cli.stagedAuthority);
      }
      files.move(cli.saved, cli.path, cli.original);
    } else files.verify(cli.path, cli.original);
    const pointer = join(dirname(instance.config), 'cli-instance.json');
    if (existsSync(pointer)) {
      const selected = readManagedJson(pointer);
      if (selected.id !== instance.id ||
          selected.directory !== instance.directory ||
          !journal.legacy.pointerAuthority) throw new Error('Default CLI selection changed or its write outcome is uncertain.');
      new PoolingFiles(instance.config).remove(pointer, journal.legacy.pointerAuthority);
    }
  }

  async stopTarget(instance, journal, startupProof) {
    if (journal.phase === 'legacy-stopped') return;
    if (startupProof) {
      const record = readManagedJson(servicePaths(instance.config, instance.port).record);
      if (record.id !== startupProof.supervisorId ||
          record.root !== journal.target.root ||
          record.config !== instance.config ||
          record.port !== instance.port ||
          record.managedInstance !== instance.directory ||
          startupProof.launchToken !== journal.launchToken) throw new Error('Target startup-stop proof does not match this migration.');
      if (await listenerOpen(instance.port)) throw new Error('Port is occupied after target startup shutdown.');
      journal.targetStop = { kind: 'modern-startup', receipt: startupProof };
      return;
    }
    if (await listenerOpen(instance.port)) {
      const ready = await inspectInstance(instance);
      if (!ready.held ||
          ready.traffic) throw new Error('Target may have admitted work; automatic legacy rollback refused.');
    }
    // This requires the exact new managed service record and its shutdown proof.
    // A closed port cannot establish that an interrupted launch has finished.
    journal.targetStop = { kind: 'modern-managed', receipt: await stopInstance(instance) };
  }

  async rollback(instance, journal, { startupProof } = {}) {
    verifyLegacyConfig(instance.config, journal.legacy);
    await this.taskMatches(instance, journal.legacy.taskCurrent);
    const phase = journal.phase;
    await this.stopTarget(instance, journal, startupProof);
    this.transition(instance, journal, 'legacy-rollback-stopping', { rollbackFrom: phase });
    await this.verifyOldStopped(instance, journal);
    const cli = journal.legacy.cli;
    this.verifySource(instance, journal.legacy, { cliPath: existsSync(cli.saved) ? cli.saved : cli.path });
    if (journal.legacy.taskCurrent.enabled) {
      journal.legacy.taskCurrent = await this.task.hold(instance.port, journal.legacy.taskCurrent);
      this.transition(instance, journal, 'legacy-rollback-stopping');
    }
    this.transition(instance, journal, 'legacy-cli-restoring');
    this.restoreCli(instance, journal);
    this.verifySource(instance, journal.legacy);
    this.transition(instance, journal, 'legacy-task-restoring');
    journal.legacy.taskCurrent = await this.task.restore(instance.port, journal.legacy.taskCurrent, journal.legacy.registration);
    await this.taskMatches(instance, journal.legacy.taskCurrent);
    this.assertRestoredTask(instance.port, journal.legacy.taskCurrent, journal.legacy.registration);
    this.transition(instance, journal, 'legacy-rollback-launching');
    await this.task.start(instance.port, journal.legacy.taskCurrent);
    const deadline = Date.now() + 15000;
    let lastError;
    while (Date.now() < deadline) {
      try {
        const api = await this.processApi();
        const old = await api.prepareLegacyProcesses({ port: instance.port, root: journal.legacy.root });
        try {
          const listener = await verifyLegacyListener(instance, journal.legacy, { sameGeneration: false });
          if (listener.status.instanceId === journal.originalInstanceId) throw new Error('Original legacy generation unexpectedly survived.');
          this.transition(instance, journal, 'legacy-rolled-back', { restoredLegacyProcesses: old.plan });
          return { status: 'rolled-back', directory: instance.directory, port: instance.port, version: '1.3.0',
            treeCompleteness: 'unproven', warning: 'Legacy restarted; uncertain calls were not replayed.' };
        } finally { await old.close(); }
      } catch (error) { lastError = error; }
      await new Promise(resolveWait => setTimeout(resolveWait, 100));
    }
    throw new Error('Legacy restart outcome is uncertain; retained code, task and journal require inspection.', { cause: lastError });
  }

  async recover(directory) {
    await requireOrdinaryUpgradeCaller();
    const { instance, journal } = readRecoveryContext(directory);
    this.validateJournal(instance, journal);
    verifySelection(journal.recovery);
    if (['legacy-rolled-back', 'legacy-aborted'].includes(journal.phase)) {
      return { status: journal.phase, directory, port: instance.port };
    }
    const accountHolding = journal.phase === 'legacy-holding' &&
      this.task.holdKind === 'automatic-triggers' &&
      typeof this.task.verifyBinding === 'function';
    if (['legacy-prepared', 'legacy-held'].includes(journal.phase) ||
        accountHolding) {
      this.verifySource(instance, journal.legacy);
      await this.taskMatches(instance, journal.legacy.taskCurrent);
      const api = await this.processApi();
      const old = await api.prepareLegacyProcesses({
        port: instance.port, root: journal.legacy.root, expected: journal.legacy.processes,
      });
      try {
        await verifyLegacyListener(instance, journal.legacy);
        if (journal.phase !== 'legacy-prepared') {
          journal.legacy.taskCurrent = await this.task.restore(instance.port, journal.legacy.taskCurrent, journal.legacy.registration);
          this.assertRestoredTask(instance.port, journal.legacy.taskCurrent, journal.legacy.registration);
        }
        this.transition(instance, journal, 'legacy-aborted');
        return { status: 'legacy-aborted', directory, port: instance.port };
      } finally { await old.close(); }
    }
    if (journal.phase === 'legacy-stopping') {
      const api = await this.processApi();
      const legacyStop = await api.verifyLegacyProcessesGone(journal.legacy.processes);
      this.assertPartialStop(legacyStop);
      this.transition(instance, journal, 'legacy-stopped', { legacyStop });
    }
    if (['legacy-stopped', 'legacy-launching', 'legacy-wiring'].includes(journal.phase)) {
      return await this.rollback(instance, journal);
    }
    throw new Error(`Legacy recovery at ${journal.phase} has an uncertain task, launch or admission outcome. No process was stopped or replayed; retain the selected task hold and journal.`);
  }
}
