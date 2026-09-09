import fs from 'node:fs';
import childProcess from 'node:child_process';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainThread, parentPort, workerData } from 'node:worker_threads';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  if (workerData.poolingTestClock) {
    const clock = new BigInt64Array(workerData.poolingTestClock);
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
    return postMessage(message, ...args);
  };

  childProcess.spawnSync = (command, args, options) => {
    if (command !== helper) return spawnSync(command, args, options);
    record('helper', { kind: args[0], timeout: options.timeout, executable: basename(command), shell: options.shell });
    if (args[0] === 'copy') hold('copy-start');
    const slow = stage === 'slow-helper' &&
      !native.existsSync(join(directory, 'disable-hook'));
    const result = slow
      ? spawnSync(process.execPath, [slowHelper, directory, command, args[0]], options)
      : spawnSync(command, args, options);
    if (slow) {
      record('helper-return', { error: result.error?.code, status: result.status,
        realHelperCompleted: result.stderr?.includes('TEST_REAL_HELPER_COMPLETED') ?? false });
    }
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
