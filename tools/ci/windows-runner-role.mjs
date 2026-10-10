// Stock hosted Windows runners are a portable/build and native-reproducibility lane. They are not
// an ordinary user-runtime environment: the hosted account is the built-in Administrator with a
// full elevated token, and Task Scheduler ignores RunLevel for that account, so the product's
// user-runtime contract refuses there by design.
//
// This role records that observation and proves the refusal is the real product behaviour. If a
// runner ever does satisfy the ordinary contract, this fails loudly so the lane is promoted to
// user-runtime integration instead of silently staying portable.
import assert from 'node:assert/strict';
import { queryCliCallerContext } from '../../bin/windows-task-channel.mjs';
import { requireUserRuntimeContext } from '../../bin/runtime-context.mjs';

// A cold runner pays JIT and antimalware cost on the first spawn of the freshly built helper,
// which can exceed its ready deadline. Retry only that startup condition: this call classifies
// the runner, and retrying it does not relax anything the refusal below has to prove.
async function classifyCaller() {
  for (let attempt = 1; ; attempt++) {
    try {
      return await queryCliCallerContext();
    } catch (error) {
      if (attempt >= 3 ||
          !/ready deadline exceeded/.test(error.message)) throw error;
      console.log(JSON.stringify({ coldStartRetry: attempt, reason: error.message }));
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

const caller = await classifyCaller();
const facts = caller.actorFacts ?? {};
const observed = {
  proofScope: caller.proofScope,
  ordinaryEligible: caller.ordinaryEligible,
  reason: caller.reason,
  elevated: facts.elevated,
  enabledAdministrator: facts.enabledAdministrator,
  sessionId: caller.identity?.sessionId,
};

if (caller.ordinaryEligible === true) {
  console.log(JSON.stringify({ role: 'user-runtime-capable', ...observed }));
  throw new Error('This Windows runner satisfies the ordinary user-runtime contract. ' +
    'Move it to the Windows integration lane and run the complete source suite there; ' +
    'do not leave real coverage unexecuted in the portable role.');
}

await assert.rejects(requireUserRuntimeContext(), error => {
  assert.match(error.message, /requires a verified ordinary caller/);
  return true;
}, 'A privileged Windows caller must be refused before any runtime work');

console.log(JSON.stringify({
  role: 'portable-build-and-native-only',
  windowsUserRuntimeIntegration: 'not-qualified-on-this-runner',
  elevatedRefusal: 'verified',
  ...observed,
}));
