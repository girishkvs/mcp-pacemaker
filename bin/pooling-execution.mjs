import { PoolingConfigError } from './pooling-config.mjs';

export const POOLING_BUDGET_MS = 9000;

const ACTIVE = 0;
const CANCELLED = 1;
const EXPIRED = 2;
const COMMITTING = 3;
const FINISHED = 4;
const FINISHED_LATE = 5;
const FINISHED_COMMITTED = 6;

export class PoolingExecution {
  constructor(deadline, buffer = new SharedArrayBuffer(4)) {
    this.deadline = deadline;
    this.state = new Int32Array(buffer);
  }

  check() {
    if (process.hrtime.bigint() >= this.deadline) {
      Atomics.compareExchange(this.state, 0, ACTIVE, EXPIRED);
    }
    const state = Atomics.load(this.state, 0);
    if (state === CANCELLED) {
      throw new PoolingConfigError(408, 'WRITER_CANCELLED', 'Pooling change was cancelled before config commit.');
    }
    if (state === EXPIRED) {
      throw new PoolingConfigError(504, 'WRITER_DEADLINE', 'Pooling change expired before config commit. Reread the config.');
    }
  }

  remainingMs() {
    this.check();
    return Math.max(1, Math.ceil(Number(this.deadline - process.hrtime.bigint()) / 1e6));
  }

  beginCommit() {
    this.check();
    if (Atomics.compareExchange(this.state, 0, ACTIVE, COMMITTING) !== ACTIVE) this.check();
    // This is authorization to enter rename, not a cancellable filesystem transaction.
    if (process.hrtime.bigint() >= this.deadline) {
      Atomics.store(this.state, 0, EXPIRED);
      this.check();
    }
  }

  complete() {
    if (Atomics.load(this.state, 0) === COMMITTING) {
      const late = process.hrtime.bigint() >= this.deadline;
      Atomics.store(this.state, 0, late ? FINISHED_LATE : FINISHED_COMMITTED);
      return late;
    }
    this.check();
    if (Atomics.compareExchange(this.state, 0, ACTIVE, FINISHED) !== ACTIVE) this.check();
  }

  fail() {
    Atomics.store(this.state, 0, FINISHED);
  }

  cancel(expired = false) {
    const state = Atomics.compareExchange(this.state, 0, ACTIVE, expired ? EXPIRED : CANCELLED);
    if (state === FINISHED ||
        state === FINISHED_COMMITTED) return undefined;
    if (state === FINISHED_LATE) return this.committedLate();
    if (state === COMMITTING) {
      return new PoolingConfigError(504, 'WRITER_OUTCOME_UNKNOWN',
        'Config commit already started. Its outcome is not yet known. Do not replay this change; reread the config.');
    }
    try {
      this.check();
    } catch (error) {
      return error;
    }
  }

  committedLate() {
    return new PoolingConfigError(504, 'WRITER_DEADLINE_COMMITTED',
      'Config commit finished after its deadline. Do not replay this change; reread the config.');
  }

  workerFailure() {
    const state = Atomics.load(this.state, 0);
    if (state === FINISHED_LATE) return this.committedLate();
    if (state === COMMITTING ||
        state === FINISHED_COMMITTED) {
      return new PoolingConfigError(500, 'WRITER_OUTCOME_UNKNOWN',
        'Pooling writer stopped after config commit started. Its outcome is unknown. Do not replay this change; reread the config.');
    }
  }
}
