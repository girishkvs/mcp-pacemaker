import childProcess from 'node:child_process';
import { basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainThread, workerData } from 'node:worker_threads';

// Loaded only by the diagnostic discrimination tests, never by the CI target.
if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  const fault = process.env.MCP_POOLING_TRACE_TEST_FAULT;
  if (fault === 'worker-start') {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 9200);
  }
  const nativeSpawn = childProcess.spawnSync;
  let calls = 0;
  childProcess.spawnSync = (command, args, options) => {
    if (basename(command) !== 'PoolingSecurityHelper.exe') return nativeSpawn(command, args, options);
    calls++;
    const selected = fault === 'first-helper' ? 1 : fault === 'post-stage' ? 4 : 0;
    if (calls !== selected) return nativeSpawn(command, args, options);
    return nativeSpawn(process.execPath, [
      fileURLToPath(new URL('./pooling-slow-helper.mjs', import.meta.url)),
      dirname(workerData.configPath), command, args[0], '9200',
    ], options);
  };
}
