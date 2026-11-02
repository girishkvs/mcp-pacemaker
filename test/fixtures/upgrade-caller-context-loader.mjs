import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
export async function load(url, context, nextLoad) {
  const target = new URL('../../bin/windows-task-channel.mjs', import.meta.url).href;
  if (url !== target) return nextLoad(url, context);
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const anchor = 'const caller = await queryCliCallerContext();';
  if (source.split(anchor).length !== 2) throw new Error('Expected unique private guard-fault injection point.');
  const fault = process.env.OWNED_CALLER_GUARD_FAULT;
  if (!['elevated', 'unknown', 'reason'].includes(fault)) throw new Error('Unknown private guard fault.');
  // The reason fault refuses with the reason the host names before each call, and counts how many
  // observations the guard asks for.
  const verdict = fault === 'reason'
    ? 'ordinaryEligible: false, reason: process.env.OWNED_CALLER_GUARD_REASON,'
    : 'ordinaryEligible: true,';
  const model = `{
    ${verdict} identity: { ownerSid: 'owned-model', sessionId: 2 },
    actorFacts: { ownerSid: 'owned-model', sessionId: 2, elevated: ${fault === 'elevated'},
      enabledAdministrator: ${fault === 'elevated'}, guardThreadImpersonating: false, parentThreadImpersonation: 'observed-none' },
    observation: { method: 'pss-threads-held-token-query', processAccess: '0x101400', captureFlags: '0x80',
      threadContextFlags: 0, completeStableThreadSet: true, primaryStable: ${fault !== 'unknown'},
      atomicFutureProtection: false, threadCount: 5 },
    helperExit: { code: 0, signal: null }
  }`;
  const count = fault === 'reason' ? 'globalThis.ownedCallerObservations++; ' : '';
  return { format: 'module', shortCircuit: true, source: source.replace(anchor, `${count}const caller = ${model};`) };
}
