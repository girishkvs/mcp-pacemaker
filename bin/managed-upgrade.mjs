import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import {
  acquireInstanceLock, createInstance, directoryIdentity, durableJson,
  loadInstance, readInstanceState, readRecoveryContext, readManagedJson, verifySelection,
} from './managed-state.mjs';
import { acquireUpgrade, configuredRegistry, exactVersion, unpackUpgrade, verifyArchive } from './upgrade-package.mjs';
import { inspectInstance, listenerOpen, startInstance, stopInstance } from './managed-runtime.mjs';
import { PoolingFiles, hasPoolingTransaction } from './pooling-files.mjs';
import { inspectAutostart } from './upgrade-autostart.mjs';
import { validateRegistry } from './update-check.mjs';
import { servicePaths } from './service-control.mjs';
import { stageCliDependencies } from './upgrade-dependencies.mjs';
import { LegacyUpgrader, legacyDormant } from './legacy-upgrade.mjs';
import { requireOrdinaryUpgradeCaller } from './windows-task-channel.mjs';
import { LEGACY_WARNING, prepareLegacyPlan } from './legacy-installation.mjs';

const terminal = ['committed', 'rolled-back', 'aborted'];
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function sessionState(config) {
  const path = join(dirname(config), 'sessions.json');
  return existsSync(path) ? new PoolingFiles(config).inspect(path) : null;
}

function verifyRollbackState(instance, journal) {
  new PoolingFiles(instance.config).verify(instance.config, journal.authority);
  if (!same(sessionState(instance.config), journal.sessionState)) throw new Error('Persisted session state changed; rollback/activation refused.');
  if (hasPoolingTransaction(instance.config)) throw new Error('Config outcome is uncertain; automatic rollback refused.');
}

function instanceBinding(instance) {
  return { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port };
}

function validateJournal(instance, journal) {
  const binding = instanceBinding(instance);
  if (journal.sxs &&
      journal.binding?.port === 0) binding.port = 0;
  const matches = journal.protocol === 1 &&
    journal.instanceId === instance.id &&
    same(binding, journal.binding) &&
    [journal.previous?.root, journal.target?.root].includes(instance.active.root);
  if (!matches) throw new Error('Journal configuration or active selection does not match this managed instance.');
}

function assertNoPendingJournal(instance) {
  const path = join(instance.directory, 'journal.json');
  if (!existsSync(path)) return;
  const journal = readManagedJson(path);
  validateJournal(instance, journal);
  if (!terminal.includes(journal.phase)) throw new Error('An unfinished upgrade requires --recover --instance <directory>.');
}

export function upgradeOptions(options) {
  if (options.self &&
      (options.to || options.sxs || options.plan || options.recover || options.instance || options.yes)) {
    throw new Error('--self is guidance only; do not combine it with managed upgrade options.');
  }
  if (options.port !== undefined &&
      !options.sxs) throw new Error('--port is only valid with --sxs. Normal upgrades preserve the selected instance port.');
  if (options.recover) {
    if (!options.instance ||
        options.to ||
        options.sxs ||
        options.plan ||
        options.registry !== undefined) throw new Error('--recover requires --instance and cannot select a new target or registry.');
    return { ...options };
  }
  exactVersion(options.to);
  let port = 0;
  if (options.port !== undefined) {
    if (!/^[1-9][0-9]*$/.test(String(options.port))) throw new Error('--sxs --port must be an integer from 1 to 65535.');
    port = Number(options.port);
    if (port > 65535) throw new Error('--sxs --port must be an integer from 1 to 65535.');
  }
  return { ...options, ...(options.sxs ? { port } : {}), registry: validateRegistry(options.registry) };
}

export function discoverInstances(home) {
  const parent = join(home, 'managed');
  if (!existsSync(parent)) return [];
  return readdirSync(parent, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && !entry.isSymbolicLink())
    .map(entry => readInstanceState(join(parent, entry.name)))
    .filter(instance => !legacyDormant(instance))
    .map(instance => loadInstance(instance.directory));
}

export async function planUpgrade(options, { home, legacy, autostart: inspectStart = inspectAutostart } = {}) {
  const selected = upgradeOptions(options);
  const instances = selected.instance ? [loadInstance(resolve(selected.instance))] : discoverInstances(home);
  if (!instances.length &&
      !selected.instance) {
    const prepared = await prepareLegacyPlan(selected, { home, ...legacy });
    return {
      protocol: 1, options: selected, instance: prepared.instance, legacy: prepared.legacy,
      legacyRuntime: { task: prepared.task, processes: prepared.processes },
      from: '1.3.0', to: selected.to, targetMajor: Number(selected.to.split('.')[0]),
      majorChange: selected.to.split('.')[0] !== '1',
      registry: await configuredRegistry(selected.registry), port: prepared.instance.port,
      affectedInstances: [prepared.legacy.backendInstanceId],
      autostart: { kind: 'legacy', name: prepared.legacy.registration.name },
      downtime: LEGACY_WARNING,
      rollback: 'Only before target admission, with unchanged config/session authority and verified captured-root/observed-set stop. Uncertain launch, task or HTTP outcomes require explicit recovery.',
      hostWiring: 'Unchanged. The same installed CLI entry will dispatch the selected managed version.',
      legacyAdoption: 'One-time restart; tree completeness stays unproven. Unattributed historical processes are left untouched.',
    };
  }
  if (instances.length !== 1) {
    throw new Error(instances.length
      ? 'Multiple managed instances found. Select exactly one with --instance <directory>; --port is reserved for --sxs.'
      : 'No stable managed installation found. Legacy 1.3 cannot prove idle HTTP work or close admission; automatic legacy migration is blocked. No download, service, autostart or host-wiring change was made.');
  }
  const instance = instances[0];
  if (selected.sxs) servicePaths(join(dirname(instance.config), 'sxs-00000000', 'servers.json'), selected.port || 65535);
  assertNoPendingJournal(instance);
  const autostart = await inspectStart(instance);
  const running = await inspectInstance(instance);
  if (running.unsafe) throw new Error('Unresolved configuration transaction blocks upgrade.');
  if (selected.sxs &&
      selected.port &&
      await listenerOpen(selected.port)) throw new Error('Explicit --sxs port is busy. No listener was adopted or stopped.');
  return {
    protocol: 1, options: selected, instance,
    from: running.version, to: selected.to,
    targetMajor: Number(selected.to.split('.')[0]),
    majorChange: selected.to.split('.')[0] !== running.version.split('.')[0],
    registry: await configuredRegistry(selected.registry),
    port: selected.sxs ? selected.port || 'OS-assigned when the new listener binds' : instance.port,
    affectedInstances: [instance.id], autostart,
    downtime: selected.sxs ? 'Existing service remains running.' : 'Short restart; active clients may need a reload. No zero-downtime handoff.',
    rollback: 'Automatic only before target admission, with unchanged configuration bytes and authority and verified stop. Uncertain outcomes require manual recovery.',
    hostWiring: 'Unchanged. SxS does not rewire any client.',
    legacyAdoption: 'Not performed. Unknown or older supervisors/autostart are refused before interruption.',
  };
}

export function describeUpgrade(plan) {
  return [
    `Managed ${plan.options.sxs ? 'SxS' : 'upgrade'}: ${plan.from} -> ${plan.to} (target major ${plan.targetMajor}${plan.majorChange ? '; explicit major change' : ''})`,
    `Instance: ${plan.instance.id}\nDirectory: ${plan.instance.directory}\nConfig: ${plan.instance.config}`,
    `Port: ${plan.port}\nRegistry: ${plan.registry}`,
    plan.downtime, plan.hostWiring, `Rollback: ${plan.rollback}`,
    `Legacy: ${plan.legacyAdoption}`,
    'Target archive integrity, runtime/engine/capability and packaged startup are checked before interruption.',
  ].join('\n');
}

export class ManagedUpgrader {
  constructor({ acquire = acquireUpgrade, dependencies = stageCliDependencies, checkpoint = () => {}, legacy,
    autostart = inspectAutostart, beforeInterruption = async () => {},
    beforeStop = async () => {}, beforeAdmission = async () => {} } = {}) {
    this.acquire = acquire;
    this.dependencies = dependencies;
    this.checkpoint = checkpoint;
    this.legacy = legacy;
    this.autostart = autostart;
    this.beforeInterruption = beforeInterruption;
    this.beforeStop = beforeStop;
    this.beforeAdmission = beforeAdmission;
  }

  transition(directory, journal, phase, changes = {}) {
    validateJournal(readInstanceState(directory), journal);
    Object.assign(journal, changes, { phase });
    durableJson(join(directory, 'journal.json'), journal);
    this.checkpoint(phase, journal);
  }

  async stage(plan, operation) {
    const work = join(plan.instance.directory, 'staging', operation);
    mkdirSync(work, { recursive: true, mode: 0o700 });
    const artifact = await this.acquire(plan.to, work, { registry: plan.registry });
    verifyArchive(artifact.bytes, artifact.integrity);
    const root = join(plan.instance.directory, 'versions', `${plan.to}-${operation}`);
    mkdirSync(dirname(root), { recursive: true, mode: 0o700 });
    mkdirSync(root, { mode: 0o700 });
    const nodeVersion = execFileSync(plan.instance.node, ['--version'], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
    }).trim().replace(/^v/, '');
    const inventory = unpackUpgrade(artifact.bytes, plan.to, root, nodeVersion);
    const dependencyFiles = await this.dependencies(root, { registry: plan.registry, cache: join(work, 'cache') });
    inventory.files.push(...dependencyFiles);
    const selection = { root, version: plan.to, directoryIdentity: directoryIdentity(root), files: inventory.files };
    durableJson(join(work, 'verified-package.json'), selection);
    const preflight = realpathSync(mkdtempSync(join(tmpdir(), 'up-')));
    const preflightIdentity = directoryIdentity(preflight);
    const config = join(preflight, 'preflight.json');
    writeFileSync(config, '{}\n', { flag: 'wx', mode: 0o600 });
    const cliVersion = execFileSync(plan.instance.node, [join(root, 'bin', 'cli-main.mjs'), '--version'], {
      encoding: 'utf8', windowsHide: true, timeout: 15000,
      env: { ...process.env, HOME: preflight, USERPROFILE: preflight, MCP_PACEMAKER_CLI_INSTANCE: '' },
    }).trim();
    if (cliVersion !== plan.to) throw new Error('Packaged target CLI version/startup did not verify.');
    const fixture = createInstance({
      directory: join(preflight, 'instance'), root, config, port: 0, selection, node: plan.instance.node,
    });
    let started;
    let stopped = false;
    try {
      started = await startInstance(fixture.directory, { pending: true });
      await inspectInstance(started.instance);
    } catch (error) {
      stopped = error.startupStopped === true;
      throw error;
    }
    finally {
      if (started) {
        await stopInstance(started.instance);
        stopped = true;
      }
      if (stopped) {
        if (directoryIdentity(preflight) !== preflightIdentity) throw new Error('Preflight directory identity changed; retained.');
        rmSync(preflight, { recursive: true });
      }
    }
    return selection;
  }

  async execute(plan) {
    await requireOrdinaryUpgradeCaller();
    if (plan.legacy) {
      const upgrader = new LegacyUpgrader({
        ...plan.legacyRuntime, ...this.legacy, checkpoint: this.checkpoint, stage: this.stage.bind(this),
      });
      return await upgrader.execute(plan);
    }
    const source = loadInstance(plan.instance.directory);
    const release = acquireInstanceLock(source.directory);
    const operation = randomUUID();
    let journal;
    let destination = source.directory;
    try {
      const locked = loadInstance(source.directory, { verifyFiles: false });
      const matchesPlan = locked.id === source.id &&
        source.id === plan.instance.id &&
        locked.directoryIdentity === source.directoryIdentity &&
        source.directoryIdentity === plan.instance.directoryIdentity &&
        same(locked.active, source.active) &&
        same(source.active, plan.instance.active) &&
        same(instanceBinding(locked), instanceBinding(source)) &&
        same(instanceBinding(source), instanceBinding(plan.instance));
      if (!matchesPlan) throw new Error('Managed selection changed after the plan; create a new plan.');
      assertNoPendingJournal(source);
      await this.autostart(source);
      const current = await inspectInstance(source);
      if (current.unsafe) throw new Error('Unresolved transaction blocks upgrade.');
      const sessions = sessionState(source.config);
      const target = await this.stage(plan, operation);
      verifySelection(target);
      const reloaded = loadInstance(source.directory, { verifyFiles: false });
      if (reloaded.id !== source.id ||
          !same(reloaded.active, source.active)) throw new Error('Instance or active selection changed while staging; nothing was stopped.');
      await this.autostart(source);
      if (plan.options.sxs) {
        return await this.startSxs(source, plan, target, operation);
      }
      journal = {
        protocol: 1, operation, instanceId: source.id, previous: source.active, target,
        binding: instanceBinding(source),
        authority: current.authority, originalInstanceId: current.instanceId,
        sessionState: sessions, launchToken: randomUUID(), phase: 'prepared',
      };
      const backup = join(source.directory, 'staging', operation, 'servers.backup.json');
      new PoolingFiles(source.config).stage(backup, source.config, current.authority, readFileSync(source.config));
      journal.configBackup = backup;
      await this.beforeInterruption(source, journal);
      this.transition(destination, journal, 'prepared');
      this.transition(destination, journal, 'quiescing');
      const drained = await inspectInstance(source, 'quiesce');
      if (!same(drained.authority, journal.authority)) throw new Error('Configuration changed while staging; retry from a new plan.');
      verifyRollbackState(source, journal);
      await this.beforeStop(source, journal);
      this.transition(destination, journal, 'stopping', { quiescedInstanceId: drained.instanceId });
      const stoppedProof = await stopInstance(source, drained.instanceId);
      this.transition(destination, journal, 'stopped', { stoppedProof });
      return await this.activate(destination, journal);
    } catch (error) {
      if (journal) {
        if (['prepared', 'quiescing'].includes(journal.phase)) {
          this.transition(destination, journal, journal.phase, { error: error.message });
        } else if (['stopped', 'selecting', 'selected', 'launching'].includes(journal.phase)) {
          if (error.cleanupUnverified) throw new Error('Target shutdown is unverified; automatic rollback refused. Preserve the journal and package.', { cause: error });
          await this.rollback(destination, journal, error.message, { startupProof: error.startupProof });
        }
      }
      throw error;
    } finally {
      release();
    }
  }

  async startSxs(source, plan, target, operation) {
    const current = await inspectInstance(source);
    if (current.unsafe ||
        current.configBusy) throw new Error('Configuration work is unresolved; SxS config was not copied.');
    if (plan.options.port &&
        await listenerOpen(plan.options.port)) throw new Error('Explicit --sxs port became busy; old instance was not touched.');
    const directory = join(dirname(source.directory), `sxs-${operation}`);
    const profile = join(dirname(source.config), `sxs-${operation.slice(0, 8)}`);
    mkdirSync(profile, { mode: 0o700 });
    const config = join(profile, 'servers.json');
    const files = new PoolingFiles(source.config);
    const authority = files.inspect(source.config);
    files.stage(config, source.config, authority, readFileSync(source.config));
    const sxs = createInstance({
      directory, root: target.root, config, port: plan.options.port,
      cwd: source.cwd, node: source.node,
    });
    const ordered = selection => [...selection.files].sort((left, right) => left.path.localeCompare(right.path));
    if (!same(ordered(sxs.active), ordered(target))) throw new Error('SxS package copy does not match the verified archive.');
    const release = acquireInstanceLock(directory);
    const journal = {
      protocol: 1, operation, instanceId: sxs.id, previous: null, target: sxs.active,
      recovery: source.active,
      binding: instanceBinding(sxs), authority: new PoolingFiles(config).inspect(config),
      sessionState: null, launchToken: randomUUID(), phase: 'starting', sxs: true,
    };
    try {
      this.transition(directory, journal, 'starting');
      this.transition(directory, journal, 'launching');
      const started = await startInstance(directory, { pending: true, token: journal.launchToken });
      verifyRollbackState(started.instance, journal);
      this.transition(directory, journal, 'admitting', {
        targetInstanceId: started.ready.instanceId, binding: instanceBinding(started.instance),
      });
      await inspectInstance(started.instance, 'activate', journal);
      this.transition(directory, journal, 'committed');
      return { status: 'sxs-started', directory, port: started.instance.port, version: target.version };
    } catch (error) {
      if (journal.phase === 'launching' &&
          error.startupStopped === true) this.transition(directory, journal, 'aborted', { error: error.message });
      throw new Error(`SxS operation did not complete at ${directory}: ${error.message}`, { cause: error });
    } finally { release(); }
  }

  async activate(directory, journal) {
    const instance = loadInstance(directory, { verifyFiles: false });
    verifyRollbackState(instance, journal);
    verifySelection(journal.target);
    this.transition(directory, journal, 'selecting');
    durableJson(join(directory, 'active.json'), journal.target);
    this.transition(directory, journal, 'selected');
    this.transition(directory, journal, 'launching');
    const started = await startInstance(directory, { pending: true, token: journal.launchToken });
    const ready = await inspectInstance(started.instance);
    if (!ready.held ||
        ready.traffic ||
        ready.instanceId === journal.originalInstanceId ||
        !same(ready.authority, journal.authority)) throw new Error('Held target readiness/configuration could not be verified.');
    verifyRollbackState(started.instance, journal);
    await this.beforeAdmission(started.instance, journal);
    // Once this durable intent exists, a lost IPC acknowledgement is never automatic rollback authority.
    this.transition(directory, journal, 'admitting', { targetInstanceId: ready.instanceId });
    await inspectInstance(started.instance, 'activate', journal);
    this.transition(directory, journal, 'committed');
    return { status: 'upgraded', directory, port: started.instance.port, version: journal.target.version };
  }

  async verifyRollbackStop(instance, proof) {
    if (!proof?.selection ||
        !['startup', 'managed'].includes(proof.kind) ||
        !proof.receipt ||
        proof.receipt.root !== proof.selection.root ||
        proof.receipt.config !== instance.config ||
        proof.receipt.port !== instance.port) throw new Error('Rollback shutdown proof is incomplete.');
    if (proof.kind === 'startup') {
      const record = readManagedJson(servicePaths(instance.config, instance.port).record);
      if (!proof.receipt.launchToken ||
          record.protocol !== 1 ||
          record.id !== proof.receipt.supervisorId ||
          record.root !== proof.selection.root ||
          record.config !== instance.config ||
          record.port !== instance.port ||
          record.socket !== servicePaths(instance.config, instance.port).socket ||
          record.managedInstance !== instance.directory) throw new Error('Verified startup-stop generation changed.');
      if (await listenerOpen(instance.port)) throw new Error('A listener exists after verified startup shutdown; no rollback launch was attempted.');
      return;
    }
    const previous = { ...instance, active: proof.selection };
    const stopped = await stopInstance(previous, proof.quiescedInstanceId);
    if (stopped.alreadyStopped !== true ||
        stopped.supervisorId !== proof.receipt.supervisorId) throw new Error('Completed rollback shutdown proof does not match the stopped generation.');
  }

  async rollback(directory, journal, error, { startupProof } = {}) {
    const instance = readInstanceState(directory);
    verifyRollbackState(instance, journal);
    verifySelection(journal.previous);
    await this.beforeStop(instance, journal);
    const neverLaunched = ['stopped', 'selecting', 'selected'].includes(journal.phase);
    const rollbackNotLaunched = ['rollback-selecting', 'rollback-selected'].includes(journal.phase);
    let proof;
    if (neverLaunched) {
      proof = { kind: 'managed', selection: journal.previous, receipt: journal.stoppedProof,
        quiescedInstanceId: journal.quiescedInstanceId };
      await this.verifyRollbackStop(instance, proof);
    } else if (rollbackNotLaunched) {
      proof = journal.rollbackStopProof;
      await this.verifyRollbackStop(instance, proof);
    } else if (startupProof) {
      proof = { kind: 'startup', selection: instance.active, receipt: startupProof };
      await this.verifyRollbackStop(instance, proof);
    } else if (await listenerOpen(instance.port)) {
      const state = await inspectInstance(instance);
      if (!state.held ||
          state.traffic) throw new Error('Target may have served traffic; automatic rollback refused.');
      proof = { kind: 'managed', selection: instance.active, receipt: await stopInstance(instance) };
    } else {
      const record = readManagedJson(servicePaths(instance.config, instance.port).record);
      const priorStopId = journal.rollbackStopProof?.receipt?.supervisorId ?? journal.stoppedProof?.supervisorId;
      if (record.id === priorStopId) throw new Error('Launch intent has no new generation proof; a closed port is not proof that launch cannot still occur.');
      proof = { kind: 'managed', selection: instance.active, receipt: await stopInstance(instance) };
    }
    this.transition(directory, journal, 'rollback-selecting', { rollback: true, error, rollbackStopProof: proof });
    durableJson(join(directory, 'active.json'), journal.previous);
    this.checkpoint('rollback-active-written', journal);
    this.transition(directory, journal, 'rollback-selected');
    this.transition(directory, journal, 'rollback-launching', { launchToken: randomUUID() });
    const started = await startInstance(directory, { pending: true, token: journal.launchToken });
    const ready = await inspectInstance(started.instance);
    if (!ready.held ||
        ready.traffic ||
        !same(ready.authority, journal.authority)) throw new Error('Rollback backend is not safely held for admission.');
    verifyRollbackState(started.instance, journal);
    this.checkpoint('rollback-launched', journal);
    await this.beforeAdmission(started.instance, journal);
    this.transition(directory, journal, 'admitting-rollback');
    await inspectInstance(started.instance, 'activate', journal);
    this.transition(directory, journal, 'rolled-back');
    return { status: 'rolled-back', directory, port: started.instance.port, version: journal.previous.version };
  }

  async recover(directory) {
    await requireOrdinaryUpgradeCaller();
    const identity = readInstanceState(resolve(directory));
    // A lock surviving process death is not silently stolen using a reusable PID.
    if (existsSync(join(identity.directory, 'upgrade.lock'))) {
      throw new Error('Upgrade lock remains. Verify the original upgrader has exited and preserve the journal before removing only this instance lock.');
    }
    const release = acquireInstanceLock(identity.directory);
    try {
      const { instance, journal } = readRecoveryContext(identity.directory);
      if (instance.id !== identity.id ||
          instance.directoryIdentity !== identity.directoryIdentity) throw new Error('Recovery instance directory changed while acquiring its lock.');
      validateJournal(instance, journal);
      verifySelection(journal.previous ?? journal.recovery ?? journal.target);
      if (journal.legacy?.protocol === 1 &&
          journal.phase !== 'committed') {
        return await new LegacyUpgrader({ ...this.legacy, checkpoint: this.checkpoint }).recover(instance.directory);
      }
      if (terminal.includes(journal.phase)) return { status: journal.phase, directory: instance.directory, port: instance.port };
      if (journal.sxs) {
        if (!['starting', 'launching'].includes(journal.phase)) throw new Error('SxS admission may have occurred; manual recovery required.');
        if (journal.phase === 'launching') {
          if (!instance.port) throw new Error('SxS port allocation or launch outcome is unknown. Wait for verified readiness or verified shutdown; no abort was recorded.');
          if (!(await listenerOpen(instance.port))) {
            await stopInstance(instance);
          } else {
            const state = await inspectInstance(instance);
            if (!state.held ||
                state.traffic) throw new Error('SxS traffic outcome is uncertain; no stop attempted.');
            await stopInstance(instance);
          }
        }
        this.transition(instance.directory, journal, 'aborted');
        return { status: 'aborted', directory: instance.directory, port: instance.port };
      }
      if (['prepared', 'quiescing'].includes(journal.phase)) {
        await this.beforeStop(instance, journal);
        await inspectInstance(instance, 'resume');
        this.transition(instance.directory, journal, 'aborted');
        return { status: 'aborted', directory: instance.directory, port: instance.port };
      }
      if (journal.phase === 'stopping') {
        await this.beforeStop(instance, journal);
        const stoppedProof = await stopInstance(instance, journal.quiescedInstanceId);
        this.transition(instance.directory, journal, 'stopped', { stoppedProof });
      }
      if (['stopped', 'selecting', 'selected', 'launching',
        'rollback-selecting', 'rollback-selected', 'rollback-launching'].includes(journal.phase)) {
        return await this.rollback(instance.directory, journal, 'Recovered interrupted activation.');
      }
      throw new Error('Admission may have occurred. Automatic recovery/rollback is refused; inspect backend and configuration before a new operation.');
    } finally { release(); }
  }
}
