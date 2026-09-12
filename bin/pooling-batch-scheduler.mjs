export const POOLING_RELOAD_DELAY_MS = 5000;

export class PoolingBatchScheduler {
  #reload;
  #onError;
  #clock;
  #pending;
  #running;
  #timer;
  #closed = false;

  constructor({ reload, onError, clock = {
    now: () => performance.now(),
    wallNow: () => Date.now(),
    setTimeout,
    clearTimeout,
  } }) {
    if (typeof reload !== 'function' ||
        typeof onError !== 'function') {
      throw new TypeError('Pooling reload and error callbacks are required.');
    }
    this.#reload = reload;
    this.#onError = onError;
    this.#clock = clock;
  }

  schedule(generation) {
    if (this.#closed) throw new Error('Pooling batch scheduler is closed.');
    if (generation === undefined ||
        generation === null) {
      throw new TypeError('An accepted pending generation is required.');
    }
    this.#pending = {
      generation,
      deadline: this.#clock.now() + POOLING_RELOAD_DELAY_MS,
    };
    this.#arm();
    return this.snapshot();
  }

  snapshot() {
    const remainingMs = this.#pending
      ? Math.max(0, Math.ceil(this.#pending.deadline - this.#clock.now())) : null;
    return {
      pending: this.#pending ? {
        generation: this.#pending.generation,
        remainingMs,
        applyAt: this.#clock.wallNow() + remainingMs,
      } : null,
      applying: this.#running?.generation ?? null,
    };
  }

  cancelPending() {
    const cancelled = Boolean(this.#pending);
    this.#clearTimer();
    this.#pending = undefined;
    return cancelled;
  }

  reloadNow() {
    if (this.#closed) return Promise.reject(new Error('Pooling batch scheduler is closed.'));
    this.#clearTimer();
    if (this.#running) {
      return this.#pending
        ? this.#running.promise.then(() => this.reloadNow()) : this.#running.promise;
    }
    return this.#pending ? this.#startReload() : Promise.resolve(null);
  }

  close() {
    this.#closed = true;
    this.cancelPending();
    return this.#running?.promise ?? Promise.resolve(null);
  }

  #clearTimer() {
    if (this.#timer !== undefined) {
      this.#clock.clearTimeout(this.#timer);
      this.#timer = undefined;
    }
  }

  #arm() {
    this.#clearTimer();
    if (this.#closed ||
        !this.#pending) return;
    const pending = this.#pending;
    this.#timer = this.#clock.setTimeout(() => {
      if (this.#closed ||
          this.#pending !== pending) return;
      this.#timer = undefined;
      if (this.#running) return;
      // Timed reloads report through onError; explicit reload callers also receive the rejection.
      this.#startReload().catch(() => {});
    }, Math.max(0, pending.deadline - this.#clock.now()));
    this.#timer?.unref?.();
  }

  #startReload() {
    const { generation } = this.#pending;
    this.#clearTimer();
    this.#pending = undefined;
    const running = { generation, promise: undefined };
    this.#running = running;
    running.promise = Promise.resolve()
      .then(() => this.#reload(generation))
      .catch((error) => {
        this.#reportError(error, generation);
        throw error;
      })
      .finally(() => {
        this.#running = undefined;
        this.#arm();
      });
    return running.promise;
  }

  #reportError(error, generation) {
    const reportFailure = () => process.emitWarning('Pooling reload error observer failed.', {
      code: 'MCP_POOLING_ERROR_OBSERVER_FAILED',
    });
    try {
      Promise.resolve(this.#onError(error, generation)).catch(reportFailure);
    } catch {
      reportFailure();
    }
  }
}
