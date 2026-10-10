#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { AccountWorkerSession } from './account-worker-session.mjs';
import { readProtectedManifest } from './windows-task-channel.mjs';
import { confirmLegacyUpgrade, legacyPlanDigest } from './legacy-installation.mjs';
import { ManagedUpgrader, describeUpgrade, planUpgrade } from './managed-upgrade.mjs';
import { readRecoveryContext } from './managed-state.mjs';
import { accountOperationReference, accountRecoveryTerminalPhases, operationDigest, taskRevision, verifyTargetSession } from './task-transaction-protocol.mjs';

export async function executeAccountUpgrade(session) {
  const binding = session.binding;
  process.chdir(binding.home);
  const native = await import('./windows-legacy-process.mjs');
  const processes = {
    ...native,
    prepareLegacyProcesses: async options => {
      const held = await native.prepareLegacyProcesses(options);
      try { session.verifyProcessSessions(held.plan); }
      catch (error) { await held.close(); throw error; }
      return {
        ...held,
        stop: async () => {
          await session.call('INSPECT');
          session.verifyProcessSessions(held.plan);
          return held.stop();
        },
      };
    },
  };
  const upgrader = new ManagedUpgrader({
    legacy: { task: session, processes },
    autostart: instance => session.inspectAutostart(instance),
    beforeInterruption: async () => {
      await session.hold(binding.port, session.logical);
    },
    beforeStop: async () => {
      await session.call('INSPECT');
      session.verifyManagedProcessSession();
    },
    beforeAdmission: async (instance, journal) => {
      if (journal.rollback) {
        await session.restore(binding.port, session.logical, session.original);
        return;
      }
      const current = await session.repoint(binding.port, session.logical, binding.launcher);
      await session.enable(binding.port, current);
    },
  });
  if (binding.recover) {
    const { instance, journal } = readRecoveryContext(binding.destination);
    if (instance.config !== binding.config ||
        instance.port !== binding.port ||
        (journal.legacy && journal.legacy.root !== binding.root)) throw new Error('Recovery is outside the protected account scope.');
    if (accountRecoveryTerminalPhases.includes(journal.phase)) {
      throw new Error('Runtime recovery became terminal before worker approval; retry the read-only controller check.');
    }
    const approved = await session.call('PLAN', {
      digest: operationDigest({ instance: instance.id, phase: journal.phase, target: {
        root: journal.target.root, version: journal.target.version, directoryIdentity: journal.target.directoryIdentity,
        inventorySha256: createHash('sha256').update(JSON.stringify(journal.target.files)).digest('hex'),
      } }),
      summary: 'Recover only this original-account instance. Uncertain task/traffic outcomes remain a refusal; no calls are replayed.',
    });
    if (!approved.approved) return { status: 'cancelled', directory: binding.destination, port: binding.port };
    await session.hold(binding.port, session.logical);
    const result = await upgrader.recover(binding.destination);
    if (accountRecoveryTerminalPhases.includes(result.status) &&
        result.status !== 'committed' &&
        taskRevision(session.logical) !== taskRevision(session.original)) {
      await session.restore(binding.port, session.logical, session.original);
    }
    return result;
  }
  const options = { to: binding.to, registry: binding.registry ?? undefined,
    ...(binding.kind === 'managed' ? { instance: binding.destination } : {}) };
  const plan = await planUpgrade(options, {
    home: binding.home, legacy: { task: session, processes },
    autostart: instance => session.inspectAutostart(instance),
  });
  if (plan.instance.config !== binding.config ||
      plan.instance.port !== binding.port ||
      (plan.legacy && plan.legacy.root !== binding.root)) throw new Error('Original-account discovery disagrees with the approved installation.');
  plan.instance.directory = binding.destination;
  if (plan.legacy) {
    plan.instance.controllerOperation = accountOperationReference(binding);
    const accepted = await confirmLegacyUpgrade(plan, {
      interactive: true,
      confirm: async message => {
        const result = await session.call('PLAN', { digest: legacyPlanDigest(plan), summary: message });
        return result.approved === true && result.digest === legacyPlanDigest(plan);
      },
    });
    if (!accepted) return { status: 'cancelled', directory: binding.destination, port: binding.port };
  } else {
    const result = await session.call('PLAN', {
      digest: operationDigest({ instance: plan.instance.id, to: plan.to, port: plan.port }),
      summary: describeUpgrade(plan),
    });
    if (!result.approved) return { status: 'cancelled', directory: binding.destination, port: binding.port };
  }
  return upgrader.execute(plan);
}

export async function runAccountWorker(args = process.argv.slice(2), { execute = executeAccountUpgrade } = {}) {
  if (args.length !== 6 ||
      args[0] !== '--manifest' ||
      args[2] !== '--operation' ||
      args[4] !== '--controller-root') throw new Error('Invalid original-account bootstrap arguments.');
  const protectedInput = await readProtectedManifest(args[1], { operationId: args[3], manifestParent: args[5] });
  if (protectedInput.document.document.binding.manifestPath !== args[1]) throw new Error('Worker manifest path does not match the protected scope.');
  verifyTargetSession(protectedInput.targetSession, protectedInput.document.targetSession);
  const session = await new AccountWorkerSession(protectedInput.document, protectedInput.readerIdentity).open();
  try {
    const result = await execute(session);
    if (result.status === 'cancelled') return result;
    await session.call('DONE', {
      status: result.status, directory: result.directory, port: result.port,
      version: result.version ?? session.binding.from,
    });
    return result;
  } catch (error) {
    if (!session.failure) {
      await session.call('FAILED', { message: 'The original-account operation did not complete; retain both journals.' }).catch(() => {});
    }
    throw error;
  } finally { session.close(); }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAccountWorker().catch(error => { console.error(error.message); process.exitCode = 1; });
}
