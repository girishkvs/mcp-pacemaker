// Fault interception exists only in this disposable child, never in the package.
import fs from 'node:fs';
import childProcess from 'node:child_process';
import { PoolingConfigStore, recoverPoolingConfig } from '../../bin/pooling-config.mjs';

const [path, point] = process.argv.slice(2);
if (point === 'recover') {
  try {
    process.stdout.write(JSON.stringify(recoverPoolingConfig(path)) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ code: error.code, message: error.message }) + '\n');
    process.exitCode = 1;
  }
} else {
  const block = () => {
    fs.writeSync(1, 'CHECKPOINT\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  };
  let moves = 0;
  if (process.platform === 'win32') {
    const original = childProcess.spawnSync;
    childProcess.spawnSync = (command, args, options) => {
      const moving = args[0] === 'move-no-replace';
      if (moving) {
        moves++;
        if (point === 'before-first' && moves === 1) block();
      }
      const result = original(command, args, options);
      if (result.status !== 0) {
        const stderr = String(result.stderr ?? '');
        process.stderr.write(`NATIVE_FAILURE ${JSON.stringify({
          action: args[0], pid: result.pid, status: result.status, signal: result.signal,
          errorCode: result.error?.code,
          nativeError: /^MCPERR nativeError=(-?\d+)\r?$/m.exec(stderr)?.[1] ?? null,
        })}\n`);
        process.stderr.write(`NATIVE_STDERR ${stderr.slice(-8192)}\n`);
      }
      if (!moving) return result;
      if (result.status !== 0) throw new Error('Fixture move failed');
      if ((point === 'between' && moves === 1) ||
          (point === 'update-between' && moves === 1) ||
          (point === 'update-after' && moves === 2) ||
          (point === 'after-second' && moves === 2)) block();
      return result;
    };
  } else {
    const originalLink = fs.linkSync;
    const originalUnlink = fs.unlinkSync;
    fs.linkSync = (source, destination) => {
      moves++;
      if (point === 'before-first' && moves === 1) block();
      const result = originalLink(source, destination);
      if ((point === 'first-link' && moves === 1) ||
          (point === 'second-link' && moves === 2)) block();
      return result;
    };
    fs.unlinkSync = (source) => {
      const result = originalUnlink(source);
      if ((point === 'between' && source === path) ||
          (point === 'update-between' && source.endsWith('.pending.json')) ||
          (point === 'update-after' && source.endsWith('.pending-next.json')) ||
          (point === 'after-second' && source.endsWith('.pending.json'))) block();
      return result;
    };
  }
  const store = new PoolingConfigStore(path);
  const receipt = store.stageApply({ name: 'alpha', mode: 'pool', minWarm: 2, revision: store.revision() });
  if (point === 'pending') block();
  if (point.startsWith('update-')) {
    store.stageApply({ name: 'alpha', mode: 'pool', minWarm: 3, revision: store.revision() });
  }
  store.commitBatch({ batchId: receipt.batchId, generation: receipt.generation });
  if (point === 'complete') block();
  throw new Error('Fixture missed its checkpoint');
}
