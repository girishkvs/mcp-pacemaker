// Builds one task-channel guard variant and calls the real requireOrdinaryUpgradeCaller from that
// pack, recording what every guard launch reported. With end-after-snapshot, a caller thread ends
// after the guard's first snapshot, as a retiring worker thread does.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

const variant = process.argv[2];
assert.ok(['end-after-snapshot', 'churn', 'token'].includes(variant));
const directory = mkdtempSync(join(tmpdir(), 'mcp-caller-churn-'));
const observations = [];
let warmup = null;
let worker;
let watch;
let accepted = false;
let failure = null;
try {
  const pack = join(directory, 'pack');
  const barrier = join(directory, 'lifecycle');
  const args = ['-NoProfile', '-NonInteractive', '-File',
    fileURLToPath(new URL('./windows-task-channel/build-context-variant.ps1', import.meta.url)),
    '-SourceRoot', fileURLToPath(new URL('../..', import.meta.url)), '-Destination', pack, '-Variant', variant];
  if (variant === 'end-after-snapshot') args.push('-LedgerPath', barrier);
  const built = childProcess.spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 120000 });
  assert.equal(built.status, 0, built.stderr);
  // A cold runner pays antimalware cost on the first start of a freshly built binary, which can
  // exceed the guard's ready deadline. Pay it here, before the launches being counted. With empty
  // stdin the guard ends on CHANNEL_DISCONNECTED before observing anything, so this cannot reach
  // the lifecycle barrier.
  const warming = performance.now();
  const warm = childProcess.spawnSync(join(pack, 'bin', 'windows-task-channel', 'TaskChannelGuard.exe'), [],
    { input: '', windowsHide: true, timeout: 60000 });
  warmup = { status: warm.status, ms: Math.round(performance.now() - warming) };
  const spawn = childProcess.spawn;
  childProcess.spawn = function(file, ...rest) {
    const child = spawn.call(this, file, ...rest);
    if (basename(file) !== 'TaskChannelGuard.exe') return child;
    const observation = { reason: 'NO_RESULT' };
    observations.push(observation);
    let buffer = '';
    child.stdout.on('data', text => {
      buffer += text;
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const frame = JSON.parse(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
        if (frame.type !== 'result') continue;
        observation.ordinaryEligible = frame.ordinaryEligible;
        observation.reason = frame.reason ?? null;
      }
    });
    return child;
  };
  syncBuiltinESMExports();
  if (variant === 'end-after-snapshot') {
    // The variant guard waits after its first snapshot until this thread has ended.
    worker = new Worker('setInterval(() => {}, 1000);', { eval: true });
    await new Promise(resolve => worker.once('online', resolve));
    watch = setInterval(() => {
      if (!worker ||
          !existsSync(`${barrier}.entered`)) return;
      const ending = worker;
      worker = undefined;
      ending.terminate().then(() => writeFileSync(`${barrier}.ended`, 'ended'));
    }, 10);
  }
  const api = await import(pathToFileURL(join(pack, 'bin', 'windows-task-channel.mjs')).href);
  await api.requireOrdinaryUpgradeCaller();
  accepted = true;
} catch (error) {
  failure = error.message;
} finally {
  clearInterval(watch);
  await worker?.terminate();
  // A cleanup failure is reported below rather than thrown, so it cannot hide what was observed.
  try { rmSync(directory, { recursive: true, force: true, maxRetries: 10 }); } catch {}
}
console.log(JSON.stringify({ variant, accepted, failure, observations, warmup, removed: !existsSync(directory) }));
