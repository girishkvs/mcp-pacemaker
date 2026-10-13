import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { AccountTaskAdapter, windowsArgument } from './account-task-adapter.mjs';
import { authorizeTaskActor } from './task-scope.mjs';
import { accountOperationReference, accountRecoveryTerminalPhases, ControllerSignatures, operationDigest, taskRevision, canonicalJson } from './task-transaction-protocol.mjs';
import { TaskOnlyController, workerTaskRecord } from './task-only-controller.mjs';
import { readInstanceState, readManagedJson, readRecoveryContext } from './managed-state.mjs';
import { parseLegacyRegistration, verifyLegacyPackage, LEGACY_WARNING } from './legacy-installation.mjs';
import { exactVersion } from './upgrade-package.mjs';
import { canonicalPort } from './cli-selection.mjs';
import { validateRegistry } from './update-check.mjs';

const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');

export function accountUpgradeOptions(args) {
  const result = {};
  let command = false;
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (value === 'upgrade' && !command) { command = true; continue; }
    if (['--plan', '--recover', '--yes'].includes(value)) {
      if (result[value.slice(2)]) throw new Error('Repeated account operation flag.');
      result[value.slice(2)] = true;
      continue;
    }
    const key = ['--to', '--registry', '--instance', '--controller-root'].find(option => value === option || value.startsWith(`${option}=`));
    if (key) {
      const argument = value === key ? args[++index] : value.slice(key.length + 1);
      if (!argument || argument.startsWith('-') || result[key.slice(2)]) throw new Error('Invalid account operation option.');
      result[key.slice(2)] = argument;
      continue;
    }
    throw new Error(`Unsupported account-management option: ${value}`);
  }
  if (!command || (result.recover ? Boolean(result.to) : !result.to)) throw new Error('Select an exact --to version or --recover.');
  if (result.recover &&
      (result.plan || result.registry !== undefined)) throw new Error('Explicit account recovery cannot combine --plan or --registry; it uses the recorded operation.');
  if (result.to) exactVersion(result.to);
  if (result.registry) result.registry = validateRegistry(result.registry);
  if (result.yes && !result.plan) throw new Error('Original-account task bootstrap and restart require interactive confirmation; --yes cannot attest paused callers.');
  return result;
}

export async function runAccountController(root, scope, {
  channelApi, task, confirm, report = console.log, powershell,
} = {}) {
  if (process.platform !== 'win32') throw new Error('Explicit account management is Windows-only; --all-users is unsupported.');
  const options = accountUpgradeOptions(scope.args);
  if (options.instance !== undefined &&
      options.instance !== scope.instance) throw new Error('Account instance selector disagrees with the parsed scope.');
  if (options.recover &&
      !scope.instance) throw new Error('Explicit account recovery requires --instance, not --task.');
  const api = channelApi ?? await import('./windows-task-channel.mjs');
  const { actorFacts: actor } = await api.queryTaskChannelCaller();
  authorizeTaskActor(actor, scope.targetSid);
  if (actor.elevated || actor.ownerSid !== scope.targetSid) await api.inspectTrustedCodeRoot(root);
  const ps = powershell ?? join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe');
  if (!task && (actor.elevated || actor.ownerSid !== scope.targetSid)) await api.inspectTrustedCodeRoot(dirname(ps));
  let selected;
  let taskPath = scope.taskPath;
  if (scope.instance) {
    selected = readInstanceState(resolve(scope.instance));
    if (options.recover && selected.controllerOperation?.targetSid === scope.targetSid) {
      taskPath = selected.controllerOperation.taskPath;
    } else {
      const records = selected.autostart?.records;
      if (selected.autostart?.kind !== 'stable' ||
          records?.length !== 1 ||
          typeof records[0].name !== 'string') throw new Error('Explicit account management requires one verified existing per-user registration.');
      taskPath = `\\${records[0].name}`;
    }
  }
  const adapter = task ?? new AccountTaskAdapter({ taskPath, targetSid: scope.targetSid, powershell: ps });
  const context = await adapter.inspect();
  const actual = context.record;
  if (actual.path !== taskPath ||
      actual.userSid !== scope.targetSid ||
      actual.logonType !== 3 ||
      actual.runLevel !== 0 ||
      !actual.enabled ||
      context.allowDemandStart !== true) throw new Error('The exact original interactive account cannot demand-start this registration.');
  if (Buffer.byteLength(canonicalJson(actual)) > 8192) throw new Error('Task record exceeds the bounded account-channel contract.');
  const home = selected ? dirname(selected.config) : join(realpathSync.native(context.profilePath), '.mcp-pacemaker');
  let sourceRoot;
  let port;
  let from;
  let original = actual;
  let prior;
  if (options.recover) {
    if (!selected?.controllerOperation?.manifestPath) throw new Error('Recovery requires --instance with a recorded protected controller operation.');
    const manifestPath = selected.controllerOperation.manifestPath;
    await api.inspectTrustedCodeRoot(dirname(manifestPath));
    const manifest = readManagedJson(manifestPath);
    prior = readManagedJson(join(dirname(manifestPath), 'controller-journal.json'));
    if (canonicalJson(selected.controllerOperation) !== canonicalJson(accountOperationReference(prior.binding)) ||
        canonicalJson(manifest.document?.binding) !== canonicalJson(prior.binding) ||
        manifest.document.digest !== operationDigest(prior.binding) ||
        prior.binding.operationId !== manifest.operationId ||
        manifest.targetSid !== scope.targetSid ||
        manifest.sessionId !== prior.binding.sessionId ||
        prior.binding.targetSid !== scope.targetSid ||
        prior.binding.destination !== selected.directory ||
        prior.binding.config !== selected.config ||
        prior.binding.port !== selected.port ||
        prior.binding.taskPath !== taskPath ||
        taskRevision(prior.current) !== taskRevision(actual)) throw new Error('Protected controller recovery state disagrees with the selected task.');
    if (manifest.document.initialTask &&
        (taskRevision(manifest.document.initialTask) !== prior.binding.initialTaskRevision ||
          taskRevision(prior.initial) !== prior.binding.initialTaskRevision)) {
      throw new Error('Protected pre-bootstrap task revision disagrees with its operation binding.');
    }
    original = prior.original;
    sourceRoot = prior.binding.root;
    port = prior.binding.port;
    from = prior.binding.from;
    const recovery = readRecoveryContext(selected.directory);
    if (accountRecoveryTerminalPhases.includes(recovery.journal.phase)) {
      if (!['completed', 'failed-restored', 'restored'].includes(prior.phase)) {
        throw new Error('Runtime journal is terminal but task outcome is unresolved; no bootstrap or automatic task rewrite was attempted.');
      }
      report('This runtime and controller transaction is already settled; no task or runtime change was made.');
      return { status: recovery.journal.phase, directory: selected.directory, port: selected.port };
    }
  } else if (selected) {
    sourceRoot = selected.active.root;
    port = selected.port;
    from = selected.active.version;
    if (actual.actions.length !== 1 ||
        actual.actions[0].arguments !== `"${join(selected.directory, 'launcher.vbs')}"`) throw new Error('The selected task is not bound to the managed launcher.');
  } else {
    const state = readManagedJson(join(home, 'state.json'));
    const ports = [...new Set((state.hosts ?? []).map(host => canonicalPort(host.port)))];
    if (ports.length !== 1) throw new Error('Account migration requires exactly one existing legacy port.');
    port = ports[0];
    sourceRoot = parseLegacyRegistration([workerTaskRecord(actual, scope.targetSid)], port).root;
    verifyLegacyPackage(sourceRoot);
    from = '1.3.0';
  }
  const session = options.recover
    ? { sessionId: prior.binding.sessionId, supervisorImage: prior.binding.legacySupervisorImage }
    : await adapter.session(actual, port, sourceRoot, selected ? { config: selected.config, cwd: selected.cwd } : undefined);
  if (!Number.isInteger(session.sessionId) || session.sessionId <= 0) throw new Error('No verified original interactive session is available.');
  const operationId = randomUUID();
  const destination = selected?.directory ?? join(home, 'managed', `legacy-${port}-${operationId}`);
  const parent = realpathSync.native(options['controller-root'] ?? process.env.LOCALAPPDATA ?? homedir());
  const manifestPath = join(parent, operationId, 'manifest.json');
  const scriptPath = fileURLToPath(new URL('./account-upgrade-worker.mjs', import.meta.url));
  const nodePath = realpathSync.native(process.execPath);
  const workerArgs = [scriptPath, '--manifest', manifestPath, '--operation', operationId, '--controller-root', parent];
  const binding = {
    protocol: 1, operationId, manifestPath, taskPath, targetSid: scope.targetSid, sessionId: session.sessionId,
    kind: prior?.binding.kind ?? (selected ? 'managed' : 'legacy'), recover: Boolean(options.recover),
    root: sourceRoot, home, config: selected?.config ?? join(home, 'servers.json'), port,
    from, to: options.to ?? prior.binding.to, registry: options.registry ?? prior?.binding.registry ?? null,
    destination, launcher: join(destination, 'launcher.vbs'),
    originalTaskRevision: taskRevision(original), initialTaskRevision: taskRevision(actual),
    legacySupervisorImage: session.supervisorImage ?? null,
    previousControllerOperation: selected?.controllerOperation ?? null,
    processQueryImage: { path: ps, sha256: hash(ps) },
    bootstrapTask: { nodePath, arguments: workerArgs.map(windowsArgument).join(' '), cwd: root },
  };
  report(`Account scope: ${actor.ownerSid === scope.targetSid ? 'current user' : 'explicit other user'}; per-user installation only.\nTask: ${taskPath}\nPort: ${port}\nOriginal account/session preserved. No all-users conversion.\n${binding.kind === 'legacy' ? LEGACY_WARNING : 'Managed admission and job lifetime proof remain required.'}`);
  if (options.plan) {
    report('Read-only plan. Native logged-on session eligibility is checked at execution before bootstrap. Original-user dependency policy, staging and executable preflight will be verified before stop. No task was changed.');
    return { status: 'planned', targetSid: scope.targetSid, taskPath, port };
  }
  if (!confirm) throw new Error('Interactive bootstrap confirmation is required.');
  if (await confirm('Temporarily hold automatic starts and launch the trusted preparation worker under this exact original account? The current backend is not stopped by bootstrap.') !== true) {
    return { status: 'cancelled' };
  }
  const signatures = new ControllerSignatures();
  const channel = await api.createTaskChannel({
    operationId, targetSid: scope.targetSid, sessionId: session.sessionId,
    bootstrap: { nodePath, scriptPath, nodeSha256: hash(nodePath), scriptSha256: hash(scriptPath), argv: workerArgs },
    manifestParent: parent,
    manifest: {
      binding, digest: operationDigest(binding), publicKey: signatures.publicKey,
      initialTask: actual,
      authorizedTaskRevisions: [
        taskRevision(workerTaskRecord(original, scope.targetSid)),
        taskRevision(workerTaskRecord(actual, scope.targetSid)),
      ],
    },
  });
  if (channel.manifestPath !== manifestPath) {
    await channel.close();
    throw new Error('Protected operation path differs from the sealed bootstrap.');
  }
  const controller = new TaskOnlyController({
    binding, original, initial: actual, task: adapter, channel, signatures, confirm,
    journalPath: join(dirname(manifestPath), 'controller-journal.json'),
  });
  report(`Recovery evidence: ${dirname(manifestPath)}`);
  return controller.run();
}
