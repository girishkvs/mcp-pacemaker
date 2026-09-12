// Test-only fault after real placement; no production clock or deadline is changed.
import childProcess from 'node:child_process';
import { basename } from 'node:path';
import { PoolingFiles } from '../../bin/pooling-files.mjs';
import { PoolingConfigError } from '../../bin/pooling-errors.mjs';

export class PostCommitFault {
  constructor(path, { commit = 1, realExpiry = false } = {}) {
    this.path = path;
    this.commit = commit;
    this.realExpiry = realExpiry;
    this.moves = 0;
    this.placed = false;
    this.helperResults = [];
  }

  install() {
    const fault = this;
    this.move = PoolingFiles.prototype.move;
    this.inspect = PoolingFiles.prototype.inspect;
    this.spawn = childProcess.spawnSync;
    PoolingFiles.prototype.move = function (source, destination, descriptor, execution) {
      const result = fault.move.call(this, source, destination, descriptor, execution);
      if (this.active === fault.path &&
          destination === this.active &&
          ++fault.moves === fault.commit) fault.trigger(execution);
      return result;
    };
    PoolingFiles.prototype.inspect = function (path, execution, ...rest) {
      const rejectVerification = fault.placed &&
        execution === fault.execution &&
        (!fault.realExpiry || process.platform !== 'win32');
      if (rejectVerification) {
        throw new PoolingConfigError(500, 'IO_ERROR',
          'Unable to inspect, stage, or move a config transaction file.');
      }
      return fault.inspect.call(this, path, execution, ...rest);
    };
    childProcess.spawnSync = function (command, args, options) {
      const result = fault.spawn.call(this, command, args, options);
      if (fault.placed &&
          basename(String(command)) === 'PoolingSecurityHelper.exe' &&
          args[0] === 'inspect-access') {
        fault.helperResults.push({
          timeoutMs: options.timeout, errorCode: result.error?.code ?? null, status: result.status,
        });
      }
      return result;
    };
  }

  trigger(execution) {
    this.placed = true;
    this.execution = execution;
    if (!this.realExpiry) return;
    const remaining = Number(execution.deadline - process.hrtime.bigint()) / 1e6;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, remaining) + 10);
    this.expiredAfterPlacement = process.hrtime.bigint() >= execution.deadline;
  }

  restore() {
    if (!this.move) return;
    PoolingFiles.prototype.move = this.move;
    PoolingFiles.prototype.inspect = this.inspect;
    childProcess.spawnSync = this.spawn;
    this.move = undefined;
  }
}
