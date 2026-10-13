import { canonicalSid } from './task-transaction-protocol.mjs';

export function managementScope(args) {
  let targetSid;
  let taskPath;
  let instance;
  let controllerRoot = false;
  const remaining = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--') { remaining.push(...args.slice(index)); break; }
    if (argument === '--all-users' || argument.startsWith('--all-users=')) {
      throw new Error('--all-users is not implemented. Installation and implicit discovery default to the current user.');
    }
    const key = ['--user', '--task', '--instance'].find(option => argument === option || argument.startsWith(`${option}=`));
    if (!key) {
      if (argument === '--controller-root' || argument.startsWith('--controller-root=')) controllerRoot = true;
      remaining.push(argument);
      if (['--to', '--registry', '--port', '--config', '--from', '--client', '--grep', '--server', '--controller-root'].includes(argument) &&
          index + 1 < args.length) {
        if (args[index + 1] === '--') { remaining.push(...args.slice(index + 1)); break; }
        remaining.push(args[++index]);
      }
      continue;
    }
    const value = argument === key ? args[++index] : argument.slice(key.length + 1);
    if (!value || value.startsWith('-') || value.length > 4096 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`Invalid ${key} selector.`);
    if (key === '--user') {
      canonicalSid(value);
      if (targetSid && targetSid !== value) throw new Error('Conflicting target users.');
      targetSid = value;
    } else if (key === '--task') {
      if (!value.startsWith('\\') || value.includes('/') || value.split('\\').some((part, i) => i > 0 && (!part || part === '.' || part === '..'))) {
        throw new Error('An exact absolute Task Scheduler path is required.');
      }
      if (taskPath && taskPath !== value) throw new Error('Conflicting task selectors.');
      taskPath = value;
    } else {
      if (instance && instance !== value) throw new Error('Conflicting instance selectors.');
      instance = value;
      remaining.push('--instance', value);
    }
  }
  if (targetSid || taskPath) {
    if (!targetSid || Boolean(taskPath) === Boolean(instance)) throw new Error('Explicit user management requires --user <SID> and exactly one --task <path> or --instance <directory>.');
    if (remaining[0] !== 'upgrade' && !remaining.includes('upgrade')) throw new Error('Explicit user/task scope currently supports upgrade only.');
    if (remaining.includes('--sxs') || remaining.includes('--self')) throw new Error('Explicit account management does not support SxS or guidance mode.');
  }
  if (controllerRoot && !targetSid) throw new Error('--controller-root is only for explicit account management.');
  return { targetSid, taskPath, instance, explicit: targetSid !== undefined, args: remaining };
}

export function authorizeTaskActor(actor, targetSid) {
  canonicalSid(targetSid);
  canonicalSid(actor.ownerSid);
  if (targetSid === actor.ownerSid) return 'current-user';
  const admin = actor.elevated === true &&
    actor.enabledAdministrator === true &&
    actor.restricted === false &&
    actor.appContainer === false &&
    actor.guardThreadImpersonating === false &&
    actor.parentThreadImpersonation === 'observed-none';
  if (!admin) throw new Error('Another user requires an already-elevated administrator token with verified enabled membership and no restricted/AppContainer/observed impersonation context. No elevation or privilege change was attempted.');
  return 'explicit-other-user';
}
