import { PoolingConfigError, POOLING_SAVE_WARNING } from './pooling-config.mjs';
import { PoolingConfigWriter } from './pooling-writer.mjs';
import { PoolingBatchScheduler, POOLING_RELOAD_DELAY_MS } from './pooling-batch-scheduler.mjs';
import { POOLING_BUDGET_MS } from './pooling-execution.mjs';

export class PoolingBatches {
  #writer;
  #reload;
  #revision;
  #notify;
  #captureSnapshot;
  #onError;
  #scheduler;
  #tail = Promise.resolve();
  #queued = 0;
  #records = new Map();
  #pending;
  #applying;
  #closed = false;
  #closing;
  #watchReload;

  constructor({ configPath, reload, revision, notify, captureSnapshot, onError }) {
    this.#writer = new PoolingConfigWriter(configPath);
    this.#reload = reload;
    this.#revision = revision;
    this.#notify = notify;
    this.#captureSnapshot = captureSnapshot;
    this.#onError = onError;
    this.#scheduler = new PoolingBatchScheduler({
      reload: (generation) => this.#enqueue(() => this.#commit(generation)),
      onError: (error) => this.#onError(error),
    });
  }

  snapshot() {
    const scheduled = this.#scheduler.snapshot();
    const batches = [...this.#records.values()].reverse().map((record) => ({
      ...record,
      changes: record.changes.map((change) => ({ ...change })),
      applyAt: record.status === 'pending' &&
        record.id === this.#pending?.batchId ? scheduled.pending?.applyAt ?? null : null,
    }));
    return {
      batchDelayMs: POOLING_RELOAD_DELAY_MS, batches,
      ...(process.platform === 'win32' ? { saveWarning: POOLING_SAVE_WARNING } : {}),
    };
  }

  stage(request, options = {}) {
    if (this.#closed) return Promise.reject(this.#closedError());
    if (this.#queued >= 16) {
      return Promise.reject(new PoolingConfigError(503, 'WRITER_BUSY', 'Too many pending pooling changes.'));
    }
    const deadline = options.deadline ??
      process.hrtime.bigint() + BigInt(POOLING_BUDGET_MS) * 1000000n;
    const arrivingDuring = this.#applying;
    this.#queued++;
    return this.#enqueue(async () => {
      if (this.#closed) throw this.#closedError();
      let submitted = request;
      if (!Object.hasOwn(request, 'undoId') &&
          arrivingDuring?.committedRevision &&
          request.revision === arrivingDuring.revision) {
        submitted = { ...request, revision: arrivingDuring.committedRevision };
      }
      const method = Object.hasOwn(request, 'undoId') ? 'stageUndo' : 'stageApply';
      let result;
      try {
        result = await this.#writer[method](submitted, {
          ...options, deadline,
          onLateSettlement: (settlement) => {
            this.#enqueue(() => this.#lateStage(settlement))
              .catch((error) => this.#onError(error));
            options.onLateSettlement?.(settlement);
          },
        });
      } catch (error) {
        if (error.cancelledBatchId) {
          this.#cancelledBatch(error.cancelledBatchId);
          this.#notify();
        }
        throw error;
      }
      if (result.pending &&
          result.accepted !== false &&
          options.signal?.aborted) {
        await this.#writer.rejectStage({ generation: result.generation });
        throw new PoolingConfigError(408, 'WRITER_CANCELLED',
          'Pooling change was cancelled before config commit.');
      }
      if (this.#closed) throw this.#closedError();
      if (result.cancelled) {
        this.#cancelledBatch(result.batchId);
      } else if (result.pending) {
        this.#pending = {
          batchId: result.batchId, generation: result.generation,
          revision: result.revision, draftRevision: result.draftRevision,
        };
        this.#records.delete(result.batchId);
        this.#records.set(result.batchId, {
          id: result.batchId, status: 'pending', revision: result.revision,
          changes: result.changes.map((change) => ({ ...change })),
        });
        if (result.accepted !== false) this.#scheduler.schedule(result.generation);
        this.#trim();
      }
      this.#notify();
      const { generation, draftRevision, changes, accepted, ...receipt } = result;
      return this.#captureSnapshot
        ? { ...receipt, snapshot: this.#captureSnapshot() }
        : receipt;
    }).finally(() => { this.#queued--; });
  }

  async reloadNow(reason = 'admin request') {
    if (this.#closed) throw this.#closedError();
    const deadline = process.hrtime.bigint() + BigInt(POOLING_BUDGET_MS) * 1000000n;
    await this.#tail;
    let result;
    do {
      if (process.hrtime.bigint() >= deadline) {
        throw new PoolingConfigError(504, 'WRITER_DEADLINE',
          'Reload could not start within its request budget. Reread batch status.');
      }
      result = await this.#scheduler.reloadNow();
    } while (!result && this.#pending);
    return result ?? this.#enqueue(() => this.#reloadSaved(reason));
  }

  reloadSaved(reason) {
    if (this.#closed) return Promise.resolve(null);
    if (!this.#watchReload) {
      this.#watchReload = this.#enqueue(() => this.#reloadSaved(reason))
        .finally(() => { this.#watchReload = undefined; });
    }
    return this.#watchReload;
  }

  close() {
    if (this.#closing) return this.#closing;
    this.#closed = true;
    this.#closing = Promise.allSettled([this.#scheduler.close(), this.#tail])
      .then(() => this.#writer.close());
    return this.#closing;
  }

  #enqueue(operation) {
    const next = this.#tail.then(operation);
    this.#tail = next.catch(() => {});
    return next;
  }

  #closedError() {
    return new PoolingConfigError(503, 'WRITER_CLOSED', 'Pooling changes are shutting down.');
  }

  #trim() {
    while (this.#records.size > 32) {
      const oldest = [...this.#records].find(([, record]) =>
        record.status !== 'pending' && record.status !== 'applying');
      if (!oldest) break;
      this.#records.delete(oldest[0]);
    }
  }

  #reloadSaved(reason) {
    const result = this.#reload(reason);
    if (!result.ok) {
      throw new PoolingConfigError(result.statusCode ?? 500, result.code ?? 'RELOAD_FAILED',
        result.publicError ?? 'Unable to activate the saved configuration.');
    }
    this.#notify();
    return result;
  }

  #cancelledBatch(batchId) {
    if (this.#pending?.batchId === batchId) {
      this.#scheduler.cancelPending();
      this.#pending = undefined;
    }
    const record = this.#records.get(batchId);
    if (record) record.status = 'cancelled';
  }

  #lateStage({ cancelledBatchId, error }) {
    if (cancelledBatchId) {
      this.#cancelledBatch(cancelledBatchId);
      this.#notify();
    }
    if (error &&
        error.code !== 'WRITER_CANCELLED' &&
        error.code !== 'WRITER_DEADLINE') {
      this.#onError(error);
    }
  }

  async #commit(generation) {
    if (this.#closed ||
        this.#pending?.generation !== generation) return null;
    const pending = this.#pending;
    const record = this.#records.get(pending.batchId);
    this.#pending = undefined;
    this.#applying = pending;
    record.status = 'applying';
    this.#notify();
    try {
      const committed = await this.#writer.commitBatch({
        batchId: pending.batchId, generation,
      }, {
        onLateSettlement: (settlement) => {
          this.#enqueue(() => this.#lateCommit(pending, settlement))
            .catch((error) => this.#onError(error));
        },
      });
      pending.committedRevision = committed.revision;
      let reloaded;
      try {
        reloaded = this.#reloadSaved('pooling batch');
      } catch (error) {
        error.commitState = 'committed';
        throw error;
      }
      record.status = 'applied';
      record.revision = committed.revision;
      this.#notify();
      return reloaded;
    } catch (error) {
      this.#failedCommit(pending, error);
      throw error;
    } finally {
      this.#applying = undefined;
    }
  }

  #failedCommit(pending, error) {
    let state = error.commitState ?? 'not-committed';
    if (state !== 'not-committed') {
      try {
        this.#reloadSaved('pooling commit reconciliation');
        if (this.#revision() === pending.draftRevision) {
          state = 'committed';
          pending.committedRevision = pending.draftRevision;
        }
      } catch {
        this.#onError(new PoolingConfigError(500, 'RECONCILIATION_FAILED',
          'Config commit could not be reconciled. Reread batch status before any further change.'));
      }
    }
    error.commitState = state;
    const record = this.#records.get(pending.batchId);
    if (record) {
      record.status = 'failed';
      record.commitState = state;
      record.error = error instanceof PoolingConfigError
        ? error.message : 'Unable to apply the pending configuration.';
      if (state === 'committed') record.revision = pending.draftRevision;
    }
    this.#notify();
  }

  #lateCommit(pending, { error, result, commitStarted }) {
    const failure = error ?? new PoolingConfigError(504, 'WRITER_DEADLINE_COMMITTED',
      'Config commit completed without a normal response. Reread active settings; do not replay it.');
    failure.commitState ??= result?.commitState ?? (commitStarted ? 'unknown' : 'not-committed');
    this.#failedCommit(pending, failure);
  }
}
