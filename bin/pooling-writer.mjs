import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { PoolingConfigStore, PoolingConfigError } from './pooling-config.mjs';
import { PoolingExecution, POOLING_BUDGET_MS } from './pooling-execution.mjs';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  const store = new PoolingConfigStore(workerData.configPath);
  parentPort.on('message', ({ id, method, request, deadline, buffer }) => {
    if (method === 'close') {
      parentPort.close();
      return;
    }
    const execution = new PoolingExecution(deadline, buffer);
    try {
      execution.check();
      if (method !== 'apply' &&
          method !== 'undo') {
        throw new PoolingConfigError(400, 'INVALID_REQUEST', 'Unknown pooling operation.');
      }
      const result = store[method](request, execution);
      const completedLate = execution.complete();
      parentPort.postMessage({ id, result, completedLate });
    } catch (error) {
      execution.fail();
      const known = error instanceof PoolingConfigError;
      parentPort.postMessage({ id, error: {
        statusCode: known ? error.statusCode : 500,
        code: known ? error.code : 'WRITER_FAILED',
        message: known ? error.message : 'Pooling writer failed. Reread the config before retrying.',
      } });
    }
  });
}

export class PoolingConfigWriter {
  #configPath;
  #worker;
  #pending = new Map();
  #sequence = 0;
  #closed = false;
  #closing;
  #resolveClose;
  #failure;

  constructor(configPath) {
    this.#configPath = configPath;
  }

  apply(request, options = {}) {
    return this.#send('apply', request, options);
  }

  undo(request, options = {}) {
    return this.#send('undo', request, options);
  }

  #send(method, request, options) {
    if (this.#closed) {
      return Promise.reject(new PoolingConfigError(503, 'WRITER_CLOSED', 'Pooling writer is shutting down.'));
    }
    if (this.#failure) return Promise.reject(this.#failure);
    const defaultDeadline = process.hrtime.bigint() + BigInt(POOLING_BUDGET_MS) * 1000000n;
    const deadline = options.deadline === undefined ? defaultDeadline
      : options.deadline < defaultDeadline ? options.deadline : defaultDeadline;
    const execution = new PoolingExecution(deadline);
    if (options.signal?.aborted) return Promise.reject(execution.cancel());
    try {
      execution.check();
    } catch (error) {
      return Promise.reject(error);
    }
    if (this.#pending.size >= 16) {
      return Promise.reject(new PoolingConfigError(503, 'WRITER_BUSY', 'Too many pending pooling changes.'));
    }
    if (!this.#worker) this.#start();
    const id = ++this.#sequence;
    return new Promise((resolve, reject) => {
      const pending = { resolve, reject, execution, options, settled: false };
      const cancel = (expired) => {
        if (pending.settled) return;
        const error = execution.cancel(expired);
        if (!error) return;
        this.#settle(pending, error);
      };
      pending.abort = () => cancel(false);
      this.#pending.set(id, pending);
      try {
        options.signal?.addEventListener('abort', pending.abort, { once: true });
        pending.timer = setTimeout(() => cancel(true), execution.remainingMs());
        this.#worker.postMessage({ id, method, request, deadline, buffer: execution.state.buffer });
      } catch (error) {
        this.#pending.delete(id);
        this.#settle(pending, error);
      }
    });
  }

  #start() {
    this.#worker = new Worker(new URL(import.meta.url), {
      workerData: { kind: 'mcp-pooling-writer', configPath: this.#configPath },
    });
    this.#worker.on('message', ({ id, result, error, completedLate }) => {
      const pending = this.#pending.get(id);
      if (!pending) return;
      this.#pending.delete(id);
      const failure = error
        ? new PoolingConfigError(error.statusCode, error.code, error.message)
        : completedLate ? pending.execution.committedLate() : undefined;
      if (pending.settled ||
          completedLate) this.#lateSettlement(pending, failure, result);
      this.#settle(pending, failure, result);
    });
    this.#worker.on('error', () => this.#failed());
    this.#worker.on('exit', (code) => {
      if (code !== 0 ||
          this.#pending.size > 0 ||
          !this.#closed) {
        this.#failed();
      }
      this.#worker = null;
      this.#resolveClose?.();
    });
  }

  #failed() {
    this.#failure ??= new PoolingConfigError(500, 'WRITER_FAILED',
      'Pooling writer stopped. Reread the config and restart the bridge before retrying.');
    for (const pending of this.#pending.values()) {
      const commitFailure = pending.execution.workerFailure();
      const failure = commitFailure ?? this.#failure;
      if (pending.settled ||
          commitFailure) this.#lateSettlement(pending, failure, undefined, Boolean(commitFailure));
      this.#settle(pending, failure);
    }
    this.#pending.clear();
  }

  #settle(pending, error, result) {
    if (pending.settled) return;
    pending.settled = true;
    clearTimeout(pending.timer);
    pending.options.signal?.removeEventListener('abort', pending.abort);
    if (error) pending.reject(error);
    else pending.resolve(result);
  }

  #lateSettlement(pending, error, result, commitStarted = false) {
    if (pending.options.onLateSettlement) {
      try {
        pending.options.onLateSettlement({ error, committed: Boolean(result), commitStarted });
      } catch {
        process.emitWarning('Unable to reconcile a pooling operation without a normal result.');
      }
    } else if (error &&
        error.code !== 'WRITER_CANCELLED' &&
        error.code !== 'WRITER_DEADLINE') {
      process.emitWarning(`Pooling operation settled without a normal result (${error.code}). Reread the config.`);
    }
  }

  close() {
    this.#closed = true;
    if (this.#closing) return this.#closing;
    if (!this.#worker) return Promise.resolve();
    this.#closing = new Promise((resolve) => { this.#resolveClose = resolve; });
    this.#worker.postMessage({ method: 'close' });
    return this.#closing;
  }
}
