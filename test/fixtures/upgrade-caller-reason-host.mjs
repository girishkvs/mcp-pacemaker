// Feeds the real requireOrdinaryUpgradeCaller one modeled native refusal per named reason, and
// reports how many observations it asked for and how it refused.
import { register } from 'node:module';

process.env.OWNED_CALLER_GUARD_FAULT = 'reason';
register(new URL('./upgrade-caller-context-loader.mjs', import.meta.url));
const api = await import('../../bin/windows-task-channel.mjs');
const results = [];
for (const reason of process.argv.slice(2)) {
  process.env.OWNED_CALLER_GUARD_REASON = reason;
  globalThis.ownedCallerObservations = 0;
  let failure = null;
  try {
    await api.requireOrdinaryUpgradeCaller();
  } catch (error) {
    failure = error.message;
  }
  results.push({ reason, observations: globalThis.ownedCallerObservations, failure });
}
console.log(JSON.stringify(results));
