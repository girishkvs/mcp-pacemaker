import fs from 'node:fs';
import { dirname, join } from 'node:path';
import { isMainThread, workerData } from 'node:worker_threads';
import { PoolingConfigStore } from '../../bin/pooling-config.mjs';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  for (const method of ['stageApply', 'stageUndo']) {
    const original = PoolingConfigStore.prototype[method];
    PoolingConfigStore.prototype[method] = function (request, execution) {
      const result = original.call(this, request, execution);
      if (result.pending &&
          result.accepted !== false &&
          fs.existsSync(join(dirname(workerData.configPath), 'cancel-publication'))) {
        execution.cancel();
      }
      if (result.cancelled) {
        const directory = dirname(workerData.configPath);
        fs.appendFileSync(join(directory, 'completed-cancellations'), 'cancelled\n');
        if (fs.existsSync(join(directory, 'cancel-cancellation'))) execution.cancel();
        if (fs.existsSync(join(directory, 'hold-cancellation'))) {
          fs.writeFileSync(join(directory, 'cancellation-completed'), 'completed');
          const wait = new Int32Array(new SharedArrayBuffer(4));
          while (!fs.existsSync(join(directory, 'release-cancellation'))) {
            Atomics.wait(wait, 0, 0, 10);
          }
        }
      }
      return result;
    };
  }
}
