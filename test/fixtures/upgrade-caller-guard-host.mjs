import assert from 'node:assert/strict';
import fs from 'node:fs';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports, register } from 'node:module';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const mode = process.argv[2];
assert.ok(['ordinary', 'actual-elevated', 'model-elevated', 'model-unknown'].includes(mode));
if (mode.startsWith('model-')) {
  process.env.OWNED_CALLER_GUARD_FAULT = mode.slice('model-'.length);
  register(new URL('./upgrade-caller-context-loader.mjs', import.meta.url));
}
const api = await import('../../bin/windows-task-channel.mjs');
const actualContext = await api.queryCliCallerContext();
assert.equal(actualContext.identity.pid, process.pid);
assert.equal(actualContext.helperExit.code, 0);
if (mode === 'actual-elevated') assert.equal(actualContext.actorFacts.elevated, true);
else assert.equal(actualContext.ordinaryEligible, true, actualContext.reason);
const counters = { writes: 0, runtimeLaunches: 0, planReads: 0 };
for (const name of ['mkdirSync', 'writeFileSync', 'appendFileSync', 'renameSync', 'copyFileSync', 'rmSync', 'unlinkSync']) {
  fs[name] = () => { counters.writes++; throw new Error('OWNED_UNEXPECTED_WRITE'); };
}
const helper = fileURLToPath(new URL('../../bin/windows-task-channel/TaskChannelGuard.exe', import.meta.url));
const spawn = childProcess.spawn;
const helpers = [];
childProcess.spawn = function(file, args, options) {
  if (file !== helper) {
    counters.runtimeLaunches++;
    throw new Error('OWNED_UNEXPECTED_LAUNCH');
  }
  const child = spawn(file, args, options);
  const observation = { pid: child.pid, events: [] };
  helpers.push(observation);
  let buffer = '';
  child.stdout.on('data', bytes => {
    buffer += bytes.toString();
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const frame = JSON.parse(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
      if (frame.type === 'started') observation.identity = frame.guardIdentity;
      observation.events.push(frame.type);
    }
  });
  child.on('close', (code, signal) => { observation.exit = { code, signal }; });
  return child;
};
for (const name of ['fork', 'execFileSync', 'execSync', 'spawnSync']) {
  childProcess[name] = () => { counters.runtimeLaunches++; throw new Error('OWNED_UNEXPECTED_LAUNCH'); };
}
const read = fs.readFileSync;
const sentinel = join(tmpdir(), `owned-guard-sentinel-${process.pid}`);
fs.readFileSync = function(path, ...args) {
  if (String(path).startsWith(sentinel)) throw new Error('OWNED_AFTER_GUARD');
  return read(path, ...args);
};
syncBuiltinESMExports();
const { ManagedUpgrader } = await import('../../bin/managed-upgrade.mjs');
const { LegacyUpgrader } = await import('../../bin/legacy-upgrade.mjs');
const plan = new Proxy({}, { get() { counters.planReads++; throw new Error('OWNED_AFTER_GUARD'); } });
const calls = [
  ['managed-execute', () => new ManagedUpgrader().execute(plan)],
  ['managed-recover', () => new ManagedUpgrader().recover(sentinel)],
  ['legacy-execute', () => new LegacyUpgrader().execute(plan)],
  ['legacy-recover', () => new LegacyUpgrader().recover(sentinel)],
];
const results = [];
for (const [name, call] of calls) {
  let failure;
  try { await call(); } catch (error) { failure = error.message; }
  assert.ok(failure, name);
  if (mode === 'ordinary') assert.doesNotMatch(failure, /requires a verified ordinary caller/, name);
  else assert.match(failure, /requires a verified ordinary caller/, name);
  results.push({ name, failure });
}
assert.equal(counters.writes, 0);
assert.equal(counters.runtimeLaunches, 0);
if (mode !== 'ordinary') assert.equal(counters.planReads, 0);
await new Promise(resolve => setImmediate(resolve));
console.log(JSON.stringify({
  qualification: mode.startsWith('model-') ? 'private in-memory caller-fact fault; actual host context recorded separately' : 'actual native caller context',
  mode, actualContext, counters, results, helpers,
}));
