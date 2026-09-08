import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { PoolingConfigStore, PoolingConfigError } from './pooling-config.mjs';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  const store = new PoolingConfigStore(workerData.configPath);
  parentPort.on('message', ({ id, method, request }) => {
    if (method === 'close') {
      parentPort.close();
      return;
    }
    try {
      if (method !== 'apply' &&
          method !== 'undo') {
        throw new PoolingConfigError(400, 'INVALID_REQUEST', 'Unknown pooling operation.');
      }
      parentPort.postMessage({ id, result: store[method](request) });
    } catch (error) {
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

  apply(request) {
    return this.#send('apply', request);
  }

  undo(request) {
    return this.#send('undo', request);
  }

  #send(method, request) {
    if (this.#closed) {
      return Promise.reject(new PoolingConfigError(503, 'WRITER_CLOSED', 'Pooling writer is shutting down.'));
    }
    if (this.#failure) return Promise.reject(this.#failure);
    if (this.#pending.size >= 16) {
      return Promise.reject(new PoolingConfigError(503, 'WRITER_BUSY', 'Too many pending pooling changes.'));
    }
    if (!this.#worker) this.#start();
    const id = ++this.#sequence;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#worker.postMessage({ id, method, request });
      } catch (error) {
        this.#pending.delete(id);
        reject(error);
      }
    });
  }

  #start() {
    this.#worker = new Worker(new URL(import.meta.url), {
      workerData: { kind: 'mcp-pooling-writer', configPath: this.#configPath },
    });
    this.#worker.on('message', ({ id, result, error }) => {
      const pending = this.#pending.get(id);
      if (!pending) return;
      this.#pending.delete(id);
      if (error) pending.reject(new PoolingConfigError(error.statusCode, error.code, error.message));
      else pending.resolve(result);
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
    for (const pending of this.#pending.values()) pending.reject(this.#failure);
    this.#pending.clear();
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
