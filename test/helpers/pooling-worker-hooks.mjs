import fs from 'node:fs';
import childProcess from 'node:child_process';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import { PoolingConfigStore } from '../../bin/pooling-config.mjs';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  const clock = workerData.poolingTestClock ? new BigInt64Array(workerData.poolingTestClock) : undefined;
  if (clock) {
    process.hrtime.bigint = () => Atomics.load(clock, 0);
  }
  const config = workerData.configPath;
  const directory = dirname(config);
  const stage = fs.readFileSync(join(directory, 'stage'), 'utf8');
  const helper = fileURLToPath(new URL('../../bin/windows/PoolingSecurityHelper.exe', import.meta.url));
  const slowHelper = fileURLToPath(new URL('./pooling-slow-helper.mjs', import.meta.url));
  const native = { ...fs };
  const spawnSync = childProcess.spawnSync;
  const temporaryDescriptors = new Set();
  const sourceDescriptors = new Set();
  let held = false;
  let flushes = 0;
  let backupPublished = false;

  const record = (event, extra = {}) => {
    native.appendFileSync(join(directory, 'events.jsonl'),
      JSON.stringify({ event, at: Date.now(), ...extra }) + '\n');
  };
  const startupDelayMs = workerData.poolingTestStartupDelayMs ?? 0;
  const operationCostMs = workerData.poolingTestOperationCostMs ?? 0;
  for (const milliseconds of [startupDelayMs, operationCostMs]) {
    if (!Number.isSafeInteger(milliseconds) ||
        milliseconds < 0 ||
        milliseconds > 2000) throw new Error('Invalid test phase duration');
  }
  if (startupDelayMs) {
    record('startup-held', { milliseconds: startupDelayMs });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, startupDelayMs);
  }
  if (workerData.poolingTestStartGate) {
    const gate = new Int32Array(workerData.poolingTestStartGate);
    Atomics.wait(gate, 0, 0, 5000);
    if (Atomics.load(gate, 0) !== 1) throw new Error('Test queue was not released');
  }
  record('hooks-ready');
  if (operationCostMs) {
    if (!clock) throw new Error('Test operation cost requires a controlled clock');
    const apply = PoolingConfigStore.prototype.apply;
    PoolingConfigStore.prototype.apply = function (...args) {
      const result = apply.apply(this, args);
      Atomics.add(clock, 0, BigInt(operationCostMs) * 1000000n);
      record('operation-finished', { costMs: operationCostMs, tick: String(process.hrtime.bigint()) });
      return result;
    };
  }
  const hold = (point) => {
    if (held ||
        point !== stage ||
        native.existsSync(join(directory, 'disable-hook'))) return;
    held = true;
    record(point);
    native.writeFileSync(join(directory, 'entered'), point);
    const deadline = performance.now() + 5000;
    const sleeper = new Int32Array(new SharedArrayBuffer(4));
    while (!native.existsSync(join(directory, 'release'))) {
      if (performance.now() >= deadline) throw new Error('Test gate was not released');
      Atomics.wait(sleeper, 0, 0, 10);
    }
  };
  const exitWorker = (point) => {
    if (stage !== point ||
        native.existsSync(join(directory, 'disable-hook'))) return;
    hold(point);
    record('worker-exit', { exitCode: 23 });
    process.exit(23);
  };
  const postMessage = parentPort.postMessage.bind(parentPort);
  parentPort.postMessage = (message, ...args) => {
    if (message.result) exitWorker('worker-exit-after-completion');
    record('operation-result', { id: message.id, code: message.error?.code, ok: message.result?.ok });
    return postMessage(message, ...args);
  };

  childProcess.spawnSync = (command, args, options) => {
    if (command !== helper) return spawnSync(command, args, options);
    // Frozen logical time cannot drive spawnSync's real timeout. Native work
    // keeps a separate wall watchdog; real-clock tests retain production options.
    const nativeOptions = clock ? { ...options, timeout: 10000 } : options;
    record('helper', { kind: args[0], timeout: options.timeout, wallTimeout: nativeOptions.timeout,
      executable: basename(command), shell: options.shell });
    if (args[0] === 'copy') hold('copy-start');
    const slow = stage === 'slow-helper' &&
      !native.existsSync(join(directory, 'disable-hook'));
    const result = slow
      ? spawnSync(process.execPath, [slowHelper, directory, command, args[0]], nativeOptions)
      : spawnSync(command, args, nativeOptions);
    record('helper-return', { kind: args[0], error: result.error?.code, status: result.status,
      signal: result.signal, stderr: result.stderr?.slice(0, 1024),
      realHelperCompleted: slow
        ? result.stderr?.includes('TEST_REAL_HELPER_COMPLETED') ?? false : result.status === 0 });
    if (args[0] === 'copy') hold('copy-complete');
    return result;
  };
  fs.lstatSync = (path, ...args) => {
    if (path === config) exitWorker('worker-exit-before-commit');
    return native.lstatSync(path, ...args);
  };
  fs.openSync = (path, ...args) => {
    const fd = native.openSync(path, ...args);
    if (path === config) sourceDescriptors.add(fd);
    if (typeof path === 'string' &&
        path.includes('.pooling-')) temporaryDescriptors.add(fd);
    return fd;
  };
  fs.closeSync = (fd) => {
    temporaryDescriptors.delete(fd);
    sourceDescriptors.delete(fd);
    return native.closeSync(fd);
  };
  fs.writeFileSync = (fd, ...args) => {
    if (temporaryDescriptors.has(fd)) record('staging-data-write');
    return native.writeFileSync(fd, ...args);
  };
  fs.fsyncSync = (fd) => {
    const result = native.fsyncSync(fd);
    if (temporaryDescriptors.has(fd) &&
        ++flushes === 2) hold('data-flushed');
    return result;
  };
  fs.readFileSync = (fd, ...args) => {
    const result = native.readFileSync(fd, ...args);
    if (backupPublished &&
        sourceDescriptors.has(fd)) hold('last-preflight');
    return result;
  };
  fs.renameSync = (source, destination) => {
    if (destination === config) {
      hold('commit-entered');
      if (native.existsSync(join(directory, 'delay-commit-after-release'))) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1700);
      }
    }
    const result = native.renameSync(source, destination);
    if (destination === config) {
      record('config-committed');
      exitWorker('worker-exit-after-rename');
    }
    if (destination === `${config}.bak`) {
      backupPublished = true;
      hold('backup-published');
    }
    return result;
  };
  fs.unlinkSync = (path) => {
    if (path.includes('.pooling-') &&
        native.existsSync(join(directory, 'fail-cleanup'))) {
      const error = new Error('Test cleanup failure');
      error.code = 'EACCES';
      throw error;
    }
    return native.unlinkSync(path);
  };
}
