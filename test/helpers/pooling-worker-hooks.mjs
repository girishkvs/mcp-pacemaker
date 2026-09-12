import fs from 'node:fs';
import childProcess from 'node:child_process';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import workerThreads, { isMainThread, parentPort, workerData } from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';
import { PoolingFiles, hashBytes } from '../../bin/pooling-files.mjs';
import { PoolingConfigStore } from '../../bin/pooling-config.mjs';

// Only disposable bridges with this fixture marker get an adjustable clock.
// Advance the real 9s budget without holding a native-phase gate for 9s.
if (isMainThread) {
  const configIndex = process.argv.indexOf('--config');
  const directory = configIndex < 0 ? undefined : dirname(process.argv[configIndex + 1]);
  if (directory &&
      fs.existsSync(join(directory, 'bridge-clock'))) {
    const offset = new BigInt64Array(new SharedArrayBuffer(8));
    const readTime = process.hrtime.bigint;
    process.hrtime.bigint = () => readTime() + Atomics.load(offset, 0);
    const Worker = workerThreads.Worker;
    workerThreads.Worker = class extends Worker {
      constructor(filename, options) {
        super(filename, {
          ...options,
          workerData: { ...options.workerData, poolingTestOffset: offset.buffer },
        });
      }
    };
    syncBuiltinESMExports();
    const setTimer = global.setTimeout;
    const clearTimer = global.clearTimeout;
    const timers = new Map();
    global.setTimeout = (callback, milliseconds, ...args) => {
      const timer = setTimer(() => {
        timers.delete(timer);
        callback(...args);
      }, milliseconds);
      timers.set(timer, {
        deadline: process.hrtime.bigint() + BigInt(Math.ceil(milliseconds)) * 1000000n,
        callback: () => callback(...args),
      });
      return timer;
    };
    global.clearTimeout = (timer) => {
      timers.delete(timer);
      clearTimer(timer);
    };
    setInterval(() => {
      const path = join(directory, 'advance-clock');
      if (!fs.existsSync(path)) return;
      const milliseconds = Number(fs.readFileSync(path, 'utf8'));
      fs.unlinkSync(path);
      Atomics.add(offset, 0, BigInt(milliseconds) * 1000000n);
      fs.appendFileSync(join(directory, 'events.jsonl'), JSON.stringify({
        event: 'deadline-passed', at: Date.now(), tick: String(process.hrtime.bigint()),
      }) + '\n');
      for (const [timer, operation] of timers) {
        if (operation.deadline > process.hrtime.bigint()) continue;
        global.clearTimeout(timer);
        operation.callback();
      }
    }, 10).unref();
  }
}

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  if (workerData.poolingTestClock) {
    const clock = new BigInt64Array(workerData.poolingTestClock);
    process.hrtime.bigint = () => Atomics.load(clock, 0);
  } else if (workerData.poolingTestOffset) {
    const offset = new BigInt64Array(workerData.poolingTestOffset);
    const readTime = process.hrtime.bigint;
    process.hrtime.bigint = () => readTime() + Atomics.load(offset, 0);
  }
  const directory = dirname(workerData.configPath);
  const stage = fs.readFileSync(join(directory, 'stage'), 'utf8');
  const helper = fileURLToPath(new URL('../../bin/windows/PoolingSecurityHelper.exe', import.meta.url));
  const slowHelper = fileURLToPath(new URL('./pooling-slow-helper.mjs', import.meta.url));
  const spawnSync = childProcess.spawnSync;
  let held = false;
  let slowed = false;
  let setupDelayed = false;
  let method;
  let deadline;

  const record = (event, extra = {}) => {
    fs.appendFileSync(join(directory, 'events.jsonl'), JSON.stringify({
      event, at: Date.now(), tick: String(process.hrtime.bigint()), method, deadline, ...extra,
    }) + '\n');
  };
  const enabled = () => !fs.existsSync(join(directory, 'disable-hook'));
  const hold = (point) => {
    if (held ||
        point !== stage ||
        !enabled()) return;
    held = true;
    record('phase-held', { phase: point });
    fs.writeFileSync(join(directory, 'entered-next'), point);
    fs.renameSync(join(directory, 'entered-next'), join(directory, 'entered'));
    const limit = performance.now() + 5000;
    const sleeper = new Int32Array(new SharedArrayBuffer(4));
    while (!fs.existsSync(join(directory, 'release'))) {
      if (performance.now() >= limit) throw new Error('Test gate was not released');
      Atomics.wait(sleeper, 0, 0, 10);
    }
  };
  const exitWorker = (point) => {
    if (stage !== point ||
        !enabled()) return;
    hold(point);
    record('worker-exit', { exitCode: 23 });
    process.exit(23);
  };
  record('hooks-ready');
  const on = parentPort.on.bind(parentPort);
  parentPort.on = (event, listener) => on(event, event === 'message' ? (message) => {
    method = message.method;
    deadline = message.deadline === undefined ? undefined : String(message.deadline);
    if (method !== 'close') record('operation-start');
    return listener(message);
  } : listener);
  const postMessage = parentPort.postMessage.bind(parentPort);
  parentPort.postMessage = (message, ...args) => {
    if (message.result?.commitState === 'committed') exitWorker('worker-exit-after-completion');
    record('operation-result', { code: message.error?.code, completedLate: message.completedLate });
    return postMessage(message, ...args);
  };

  childProcess.spawnSync = (command, args, options) => {
    if (command !== helper) return spawnSync(command, args, options);
    const setupDelayPath = join(directory, 'helper-setup-delay');
    if (!setupDelayed &&
        enabled() &&
        fs.existsSync(setupDelayPath)) {
      const milliseconds = Number(fs.readFileSync(setupDelayPath, 'utf8'));
      if (!Number.isSafeInteger(milliseconds) ||
          milliseconds < 0 ||
          milliseconds > 6000) throw new Error('Invalid test helper setup delay');
      setupDelayed = true;
      record('setup-delayed', { milliseconds });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
    }
    const slowInspection = stage === 'slow-helper' &&
      args[0] === 'inspect-access' &&
      !slowed &&
      enabled();
    const stageDelayPath = join(directory, 'helper-stage-delay');
    const slowStage = args[0] === 'stage' &&
      !slowed &&
      enabled() &&
      fs.existsSync(stageDelayPath);
    const slow = slowInspection || slowStage;
    const delayMs = slowStage ? Number(fs.readFileSync(stageDelayPath, 'utf8')) : 1500;
    if (!Number.isSafeInteger(delayMs) ||
        delayMs < 0 ||
        delayMs > 6000) throw new Error('Invalid test helper stage delay');
    if (slow) slowed = true;
    // The frozen operation clock advances only at test checkpoints. Its remaining
    // budget must not become a real spawnSync timer. Bound native work separately
    // with the helper's 10s wall watchdog and the fixture's whole-lifetime guard.
    // Real and offset clocks still use the unmodified production timeout.
    const wallTimeout = workerData.poolingTestClock ? 10000 : options.timeout;
    const nativeOptions = { ...options, timeout: wallTimeout };
    record('helper', {
      kind: args[0], timeout: options.timeout, wallTimeout, executable: basename(command),
      shell: options.shell, slow, delayMs: slow ? delayMs : undefined,
    });
    const started = performance.now();
    const result = slow
      ? spawnSync(process.execPath, [slowHelper, directory, command, args[0], String(delayMs)], nativeOptions)
      : spawnSync(command, args, nativeOptions);
    record('helper-return', {
      kind: args[0], slow, error: result.error?.code, status: result.status,
      signal: result.signal, elapsedMs: performance.now() - started,
      errorMessage: result.error?.message?.slice(0, 512),
      stderr: result.stderr?.slice(0, 1024), stdout: result.stdout?.slice(0, 512),
      realHelperCompleted: slow
        ? result.stderr?.includes('TEST_REAL_HELPER_COMPLETED') ?? false
        : result.status === 0,
    });
    return result;
  };

  const nativeStage = PoolingFiles.prototype.stage;
  PoolingFiles.prototype.stage = function (path, source, descriptor, bytes, execution) {
    record('stage-start', { path: basename(path) });
    hold('stage-start');
    const result = nativeStage.call(this, path, source, descriptor, bytes, execution);
    // Native stage has already created a secure descriptor, written, flushed,
    // and checked the complete candidate. There is no JS data-write phase.
    record('stage-complete', {
      path: basename(path), size: result.size, revision: result.revision,
      identity: result.identity,
      security: result.security, sourceSecurity: descriptor.security,
      bytesMatch: fs.readFileSync(path).equals(bytes),
    });
    hold('stage-complete');
    return result;
  };
  const save = PoolingFiles.prototype.save;
  PoolingFiles.prototype.save = function (state) {
    const result = save.call(this, state);
    record('journal-saved', { phase: state.phase });
    if (state.phase === 'pending') hold('draft-published');
    if (state.phase === 'prepared') {
      hold('commit-prepared');
      exitWorker('worker-exit-before-commit');
    }
    return result;
  };
  const verify = PoolingFiles.prototype.verify;
  PoolingFiles.prototype.verify = function (path, ...args) {
    const result = verify.call(this, path, ...args);
    if (path === this.paths.pending &&
        this.record?.phase === 'prepared') {
      record('last-preflight');
      hold('last-preflight');
    }
    return result;
  };
  const move = PoolingFiles.prototype.move;
  PoolingFiles.prototype.move = function (source, destination, descriptor, execution) {
    const result = move.call(this, source, destination, descriptor, execution);
    record('file-placed', { source: basename(source), destination: basename(destination) });
    if (destination === this.active) {
      record('config-committed', {
        revision: descriptor.revision,
        bytesMatch: hashBytes(fs.readFileSync(destination)) === descriptor.revision,
      });
      hold('active-placed');
      exitWorker('worker-exit-after-placement');
    }
    return result;
  };
  const commitBatch = PoolingConfigStore.prototype.commitBatch;
  PoolingConfigStore.prototype.commitBatch = function (...args) {
    const result = commitBatch.apply(this, args);
    record('commit-completed', { commitState: result.commitState });
    hold('commit-completed');
    if (stage === 'commit-completed' &&
        fs.existsSync(join(directory, 'delay-commit-after-release'))) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1700);
    }
    return result;
  };
  const remove = PoolingFiles.prototype.remove;
  PoolingFiles.prototype.remove = function (path, ...args) {
    if ([this.paths.pending, this.paths.next, this.paths.old].includes(path) &&
        fs.existsSync(join(directory, 'fail-cleanup'))) {
      record('cleanup-refused', { path: basename(path) });
      const error = new Error('Test cleanup failure');
      error.code = 'EACCES';
      throw error;
    }
    return remove.call(this, path, ...args);
  };
}
