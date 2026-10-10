import { existsSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { durableJson, loadInstance, readInstanceState, readManagedJson, readRecoveryContext, verifySelection } from './managed-state.mjs';
import { managementScope } from './task-scope.mjs';

export function registerDefaultCli(home, instance) {
  const path = join(home, 'cli-instance.json');
  if (existsSync(path)) {
    const selected = readManagedJson(path);
    const current = loadInstance(selected.directory, { verifyFiles: false });
    if (selected.protocol !== 1 ||
        selected.id !== current.id) throw new Error('Default CLI routing identity changed.');
    return;
  }
  durableJson(path, { protocol: 1, id: instance.id, directory: instance.directory });
}

export function normalizeInstanceSelection(args) {
  let directory;
  const remaining = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--') {
      remaining.push(...args.slice(index));
      break;
    }
    if (argument !== '--instance' &&
        !argument.startsWith('--instance=')) {
      remaining.push(argument);
      const takesValue = ['--port', '--config', '--client', '--from', '--since', '--server', '--grep',
        '--enable', '--disable', '--count', '--undo', '--to', '--registry'].includes(argument);
      if (takesValue &&
          index + 1 < args.length) {
        if (args[index + 1] === '--') {
          remaining.push(...args.slice(index + 1));
          break;
        }
        remaining.push(args[++index]);
      }
      continue;
    }
    const value = argument === '--instance' ? args[++index] : argument.slice('--instance='.length);
    if (!value ||
        value.length > 4096 ||
        value.startsWith('-') ||
        value.includes('\0')) throw new Error('Invalid --instance value; no default fallback was selected.');
    const canonical = realpathSync.native(resolve(value));
    if (directory &&
        canonical !== directory) throw new Error('Conflicting --instance selectors; no action was taken.');
    directory = canonical;
  }
  return { directory, explicit: directory !== undefined, args: remaining };
}

export async function verifyCliSelectionTrust(root, instance, selection, { context, inspect, report = console.error }) {
  const caller = await context();
  if (caller.proofScope !== 'cli-effective-context-snapshot' ||
      caller.identity?.pid !== process.pid ||
      typeof caller.identity.ownerSid !== 'string' ||
      caller.identity.ownerSid !== caller.actorFacts?.ownerSid ||
      caller.helperExit?.code !== 0 ||
      caller.helperExit.signal !== null ||
      caller.cleanupUnverified === true) throw new Error('CLI effective-context identity or helper exit is unverified; no target code was imported.');
  const observation = caller.observation;
  const complete = observation?.method === 'pss-threads-held-token-query' &&
    observation.processAccess === '0x101400' &&
    observation.captureFlags === '0x80' &&
    observation.threadContextFlags === 0 &&
    observation.completeStableThreadSet === true &&
    observation.primaryStable === true &&
    observation.atomicFutureProtection === false &&
    Number.isSafeInteger(observation.threadCount) &&
    observation.threadCount > 0;
  const ordinary = caller.ordinaryEligible === true &&
    complete &&
    caller.actorFacts.elevated === false &&
    caller.actorFacts.enabledAdministrator === false &&
    caller.actorFacts.guardThreadImpersonating === false &&
    caller.actorFacts.parentThreadImpersonation === 'observed-none';
  if (ordinary) return;
  report(`CLI strict code-root checks: ${JSON.stringify(caller.reason ?? 'effective-context-unverified')}.`);
  await inspect(instance.directory);
  const within = relative(realpathSync.native(instance.directory), realpathSync.native(selection.root));
  const covered = within === '' ||
    (!isAbsolute(within) && within !== '..' && !within.startsWith(`..${sep}`));
  if (!covered) await inspect(selection.root);
  await inspect(root);
  await inspect(dirname(instance.node));
}

export async function dispatchCli(root, args = process.argv.slice(2)) {
  const scope = managementScope(args);
  if (scope.explicit) {
    const { runAccountController } = await import(pathToFileURL(join(root, 'bin', 'account-upgrade-controller.mjs')).href);
    const confirm = async message => {
      if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Explicit account management requires interactive confirmation.');
      const prompts = await import('@clack/prompts');
      return await prompts.confirm({ message }) === true;
    };
    const result = await runAccountController(root, scope, { confirm });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  const normalized = normalizeInstanceSelection(args);
  let { directory } = normalized;
  process.argv = [...process.argv.slice(0, 2), ...normalized.args];
  const end = normalized.args.indexOf('--');
  const options = end < 0 ? normalized.args : normalized.args.slice(0, end);
  const recovery = options.includes('upgrade') && options.includes('--recover');
  const pointer = join(homedir(), '.mcp-pacemaker', 'cli-instance.json');
  let expectedId;
  if (!directory &&
      existsSync(pointer)) {
    const selected = readManagedJson(pointer);
    if (selected.protocol !== 1) throw new Error('Unknown default CLI routing protocol.');
    directory = selected.directory;
    expectedId = selected.id;
  }
  let target = root;
  if (directory) {
    const instance = readInstanceState(directory);
    if (expectedId &&
        instance.id !== expectedId) throw new Error('Default CLI instance identity changed.');
    let selection = instance.active;
    const journalPath = join(directory, 'journal.json');
    if (existsSync(journalPath)) {
      const { journal } = readRecoveryContext(directory);
      if (recovery ||
          !['committed', 'rolled-back', 'aborted'].includes(journal.phase)) {
        selection = journal.previous ?? journal.recovery;
        if (!selection) throw new Error('Interrupted activation has no retained recovery CLI.');
      }
    }
    if (recovery &&
        !existsSync(journalPath)) throw new Error('No activation journal exists for this instance.');
    if (selection) {
      verifySelection(selection);
      if (process.platform === 'win32') {
        const { inspectTrustedCodeRoot, queryCliCallerContext } = await import(pathToFileURL(join(root, 'bin', 'windows-task-channel.mjs')).href);
        await verifyCliSelectionTrust(root, instance, selection, { inspect: inspectTrustedCodeRoot, context: queryCliCallerContext });
      }
      target = selection.root;
    }
    process.env.MCP_PACEMAKER_CLI_CONTEXT = JSON.stringify({
      directory: instance.directory, id: instance.id, explicit: normalized.explicit, recovery,
    });
  } else {
    delete process.env.MCP_PACEMAKER_CLI_CONTEXT;
  }
  delete process.env.MCP_PACEMAKER_CLI_INSTANCE;
  await import(pathToFileURL(join(target, 'bin', 'cli-main.mjs')).href);
}
