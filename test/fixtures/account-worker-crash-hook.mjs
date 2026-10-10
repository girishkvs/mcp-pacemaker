import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LegacyUpgrader } from '../../bin/legacy-upgrade.mjs';
import { AccountWorkerSession } from '../../bin/account-worker-session.mjs';

const worker = fileURLToPath(new URL('../../bin/account-upgrade-worker.mjs', import.meta.url));
if (resolve(process.argv[1] ?? '') === worker) {
  const phase = process.env.MCP_ACCOUNT_OWNED_CRASH;
  const crash = destination => {
    writeFileSync(process.env.MCP_ACCOUNT_OWNED_CRASH_RECORD,
      JSON.stringify({ phase, pid: process.pid, destination, at: new Date().toISOString() }), { flag: 'wx' });
    process.exit(86);
  };
  if (phase === 'published') {
    const publish = LegacyUpgrader.prototype.publishPrepared;
    LegacyUpgrader.prototype.publishPrepared = function (...args) {
      const result = publish.apply(this, args);
      crash(result.directory);
      return result;
    };
  } else if (phase === 'hold-ack') {
    const taskCall = AccountWorkerSession.prototype.taskCall;
    AccountWorkerSession.prototype.taskCall = async function (verb, ...args) {
      const result = await taskCall.call(this, verb, ...args);
      if (verb === 'HOLD') crash(this.binding.destination);
      return result;
    };
  } else if (phase === 'legacy-held') {
    const transition = LegacyUpgrader.prototype.transition;
    LegacyUpgrader.prototype.transition = function (instance, journal, next, ...args) {
      const result = transition.call(this, instance, journal, next, ...args);
      if (next === phase) crash(instance.directory);
      return result;
    };
  } else throw new Error('Unknown owned worker crash boundary.');
}
