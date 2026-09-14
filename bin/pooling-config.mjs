import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { JsonSpans } from './pooling-editor.mjs';
import { PoolingConfigError, poolingIOError, poolingConflict, recoveryError } from './pooling-errors.mjs';
import { PoolingFiles, readPoolingBytes, MAX_CONFIG_BYTES } from './pooling-files.mjs';

export { PoolingConfigError } from './pooling-errors.mjs';
export { recoverPoolingConfig, hasPoolingTransaction, MAX_CONFIG_BYTES } from './pooling-files.mjs';
export const MAX_MIN_WARM = 32;
export const MAX_UNDO_ENTRIES = 32;
export const MAX_UNDO_BYTES = 8 * 1024 * 1024;
export const POOLING_SAVE_WARNING =
  'New config copies inherit folder auditing. Custom per-file audit rules may not carry forward.';

export class PoolingConfigStore {
  #configPath;
  #files;
  #undos = new Map();
  #undoBytes = 0;
  #execution;
  #pending;
  #publication;
  #closed = false;
  #started = false;

  constructor(configPath) {
    if (typeof configPath !== 'string' ||
        !configPath ||
        /[\x00-\x1f\x7f]/.test(configPath)) {
      throw new PoolingConfigError(400, 'INVALID_PATH', 'A config file path is required.');
    }
    this.#configPath = resolve(configPath);
    this.#files = new PoolingFiles(this.#configPath);
  }

  // Internal only: servers can contain credentials. Never serialize through HTTP.
  snapshot() {
    const current = this.#read();
    return { revision: current.revision, servers: new JsonSpans(current.bytes).servers };
  }

  revision() {
    return this.snapshot().revision;
  }

  pendingSummary() {
    const pending = this.#pending;
    if (!pending) return null;
    return {
      id: pending.batchId, batchId: pending.batchId, generation: pending.generation,
      revision: pending.base.revision, status: 'pending',
      changes: pending.changes.map((change) => ({ ...change })),
    };
  }

  stageApply(request, execution) {
    this.#publication = undefined;
    return this.#execute(() => this.#stageApply(request), execution);
  }

  stageUndo(request, execution) {
    this.#publication = undefined;
    return this.#execute(() => this.#stageUndo(request), execution);
  }

  rejectStage({ generation }, execution) {
    return this.#execute(() => {
      const publication = this.#publication;
      if (!publication ||
          publication.generation !== generation ||
          this.#pending?.generation !== generation) {
        return { ok: true, discarded: false };
      }
      const abandoned = this.#pending;
      const prior = publication.prior;
      if (prior) {
        this.#files.save({
          phase: 'updating', base: prior.base, draft: prior.draft, next: abandoned.draft,
          previous: this.#files.record.previous,
        });
        this.#restoreDraft(prior, abandoned.draft);
      } else {
        this.#files.discard(this.#execution);
        this.#releaseReservation(abandoned);
      }
      this.#pending = prior;
      this.#publication = undefined;
      return { ok: true, discarded: true };
    }, execution);
  }

  commitBatch(request, execution) {
    return this.#execute(() => this.#commitBatch(request), execution, true);
  }

  apply(request, execution) {
    const staged = this.stageApply(request, execution);
    if (!staged.pending) return staged;
    const committed = this.commitBatch({ batchId: staged.batchId, generation: staged.generation }, execution);
    const { name, mode, minWarm, undoId } = staged;
    return {
      ok: true, name, mode, ...(minWarm === undefined ? {} : { minWarm }),
      revision: committed.revision, undoId,
    };
  }

  undo(request, execution) {
    const staged = this.stageUndo(request, execution);
    if (!staged.pending) return staged;
    const committed = this.commitBatch({ batchId: staged.batchId, generation: staged.generation }, execution);
    const { name, mode, minWarm } = staged;
    return {
      ok: true, name, mode, ...(minWarm === undefined ? {} : { minWarm }),
      revision: committed.revision,
    };
  }

  close() {
    this.#closed = true;
    // All file operations are synchronous in the writer. Its message queue
    // drains entered work before close; pending bytes and the journal remain.
    try { this.#files.close(); } catch (error) { throw poolingIOError(error); }
  }

  #execute(operation, execution, committing = false) {
    if (this.#closed) {
      const error = new PoolingConfigError(503, 'WRITER_CLOSED', 'Config store is closed.');
      if (committing) error.commitState = 'not-committed';
      throw error;
    }
    this.#execution = execution;
    try {
      if (!committing) execution?.check();
      return operation();
    } catch (error) {
      const failure = poolingIOError(error);
      if (committing) failure.commitState ??= 'not-committed';
      throw failure;
    } finally {
      this.#execution = undefined;
    }
  }

  #start() {
    this.#execution?.trace?.record('store-start');
    this.#execution?.check();
    this.#files.acquire();
    if (!this.#started) {
      if (['entered', 'failed'].includes(this.#files.record?.phase)) throw recoveryError();
      this.#files.recover(this.#execution);
      this.#started = true;
    } else if (!this.#pending &&
               ['pending', 'prepared'].includes(this.#files.record?.phase)) {
      // A deadline can prevent cleanup. The next fresh operation may discard
      // these owned, unentered bytes; it never replays the failed request.
      this.#files.discard(this.#execution);
    }
    this.#execution?.trace?.record('store-ready');
  }

  #read() {
    this.#execution?.check();
    return readPoolingBytes(this.#configPath);
  }

  #source(revision) {
    const current = this.#read();
    this.#checkRevision(current.revision, revision);
    if (this.#pending) this.#checkRevision(revision, this.#pending.base.revision);
    return current;
  }

  #stageApply(request) {
    this.#validateRequest(request, ['name', 'mode', 'minWarm', 'revision']);
    if (request.mode !== 'pool' &&
        request.mode !== 'isolated') {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'Mode must be pool or isolated.');
    }
    if (Object.hasOwn(request, 'minWarm')) {
      if (request.mode !== 'pool') {
        throw new PoolingConfigError(400, 'INVALID_REQUEST', 'minWarm is only valid for pool mode.');
      }
      this.#validateMinWarm(request.minWarm);
    }
    const current = this.#source(request.revision);
    const document = new JsonSpans(this.#pending?.bytes ?? current.bytes);
    const server = this.#server(document.servers, request.name);
    const changes = new Map();
    if (request.mode === 'pool') {
      const minWarm = request.minWarm ?? server.minWarm ?? 1;
      this.#validateMinWarm(minWarm);
      changes.set('sharing', 'pool');
      changes.set('minWarm', minWarm);
    } else {
      if (Object.hasOwn(server, 'sharing')) changes.set('sharing', 'isolated');
      changes.set('minWarm', undefined);
    }
    const bytes = document.update(request.name, changes);
    this.#validateCandidate(bytes);
    const state = this.#state(new JsonSpans(bytes).servers, request.name);
    if (bytes.equals(this.#pending?.bytes ?? current.bytes)) {
      // A no-op is not a new acceptance and must not reset the parent's timer.
      if (this.#pending) {
        this.#verifyPending();
        const activeState = this.#state(new JsonSpans(current.bytes).servers, request.name);
        if (JSON.stringify(activeState) !== JSON.stringify(state)) {
          return { ...this.#receipt(state), accepted: false };
        }
      }
      return { ok: true, ...state, revision: current.revision };
    }
    this.#stage(current, bytes, request.name);
    return this.#receipt(state);
  }

  #stageUndo(request) {
    this.#validateRequest(request, ['name', 'undoId', 'revision']);
    if (typeof request.undoId !== 'string' ||
        !/^[0-9a-f-]{36}$/.test(request.undoId)) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A valid undoId is required.');
    }
    const pending = this.#pending;
    if (pending?.undoId === request.undoId) {
      if (!pending.names.has(request.name)) throw this.#undoConflict();
      const current = this.#source(request.revision);
      this.#verifyPending();
      this.#execution?.check();
      this.#files.discard(this.#execution);
      this.#releaseReservation(pending);
      this.#pending = undefined;
      return { ok: true, cancelled: true, batchId: pending.batchId, revision: current.revision };
    }
    const record = this.#undos.get(request.undoId);
    if (!record ||
        record.reserved ||
        !record.names.has(request.name)) throw this.#undoConflict();
    if (pending) {
      throw new PoolingConfigError(409, 'PENDING_CONFLICT', 'Cancel or apply the current batch before undoing another batch.');
    }
    this.#checkRevision(request.revision, record.revision);
    const current = this.#source(record.revision);
    this.#validateCandidate(record.bytes);
    const state = this.#state(new JsonSpans(record.bytes).servers, request.name);
    this.#stage(current, record.bytes, request.name, record.names, request.undoId);
    record.reserved = this.#pending.batchId;
    return this.#receipt(state);
  }

  #validateCandidate(bytes) {
    if (bytes.length > MAX_CONFIG_BYTES) {
      throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Updated config would exceed 1 MiB.');
    }
    const document = new JsonSpans(bytes);
    document.validateComplete();
    return document;
  }

  #stage(current, bytes, name, names, restoring) {
    this.#start();
    const files = this.#files;
    const prior = this.#pending;
    if (prior) this.#verifyPending();
    const base = prior?.base ?? files.inspect(this.#configPath, this.#execution);
    this.#checkRevision(base.revision, current.revision);
    const destination = prior ? files.paths.next : files.paths.pending;
    let draft;
    try {
      draft = files.stage(destination, this.#configPath, base, bytes, this.#execution);
      files.verify(this.#configPath, base, this.#execution);
      this.#execution?.check();
      if (prior) {
        files.save({ ...files.record, phase: 'updating', next: draft });
        files.move(files.paths.pending, files.paths.old, prior.draft, this.#execution);
        files.move(files.paths.next, files.paths.pending, draft, this.#execution);
      }
      this.#execution?.check();
      this.#execution?.trace?.record('publish-start');
      files.save({
        // Retain the prior native draft until this publication is durable.
        // A later operation can clean it using the recorded identity.
        phase: 'pending', base, draft, next: prior?.draft ?? null,
        previous: files.record?.previous ?? null,
      });
      this.#execution?.trace?.record('publish-end');
    } catch (error) {
      // Before publication, only a returned, verified identity authorizes
      // deleting the new file. Failed helper output is not ownership proof.
      try {
        if (prior && files.record?.phase === 'updating') {
          this.#restoreDraft(prior, draft);
        } else if (draft) {
          files.remove(destination, draft, 1, this.#execution);
        } else if (fs.existsSync(destination)) {
          files.poisoned = true;
        }
      } catch (cleanupError) {
        if (this.#abandoned(cleanupError)) {
          if (draft && !files.poisoned) {
            if (!prior) {
              files.save({
                phase: 'pending', base, draft, next: null,
                previous: files.record?.previous ?? null,
              });
            } else if (files.record?.phase === 'pending') {
              files.save({ ...files.record, next: draft });
            }
          }
          throw error;
        }
        files.poisoned = true;
        throw recoveryError();
      }
      throw error;
    }
    const included = new Set(names ?? prior?.names ?? []);
    included.add(name);
    const document = new JsonSpans(bytes);
    this.#pending = {
      batchId: prior?.batchId ?? randomUUID(),
      undoId: prior?.undoId ?? randomUUID(),
      generation: randomUUID(),
      base, draft, bytes, before: prior?.before ?? current.bytes, names: included,
      changes: [...included].map((includedName) => this.#state(document.servers, includedName)),
      restoring: prior?.restoring ?? restoring,
    };
    this.#publication = { generation: this.#pending.generation, prior };
  }

  #restoreDraft(prior, draft) {
    const files = this.#files;
    const topology = files.topology(this.#execution);
    if (topology.pending?.identity === draft?.identity) files.remove(files.paths.pending, draft, 1, this.#execution);
    if (fs.existsSync(files.paths.old)) {
      files.move(files.paths.old, files.paths.pending, prior.draft, this.#execution);
    }
    if (fs.existsSync(files.paths.next)) files.remove(files.paths.next, draft, 1, this.#execution);
    files.verify(files.paths.pending, prior.draft, this.#execution);
    files.save({
      phase: 'pending', base: prior.base, draft: prior.draft, next: null,
      previous: files.record.previous,
    });
  }

  #verifyPending() {
    this.#files.acquire();
    if (this.#files.record?.phase === 'updating') {
      this.#restoreDraft(this.#pending, this.#files.record.next);
    }
    this.#files.verify(this.#configPath, this.#pending.base, this.#execution);
    this.#files.verify(this.#files.paths.pending, this.#pending.draft, this.#execution);
    if (this.#files.record?.phase === 'pending' &&
        this.#files.record.next) {
      for (const path of [this.#files.paths.old, this.#files.paths.next]) {
        if (fs.existsSync(path)) {
          this.#files.verify(path, this.#files.record.next, this.#execution);
        }
      }
      for (const path of [this.#files.paths.old, this.#files.paths.next]) {
        if (fs.existsSync(path)) {
          this.#files.remove(path, this.#files.record.next, 1, this.#execution);
        }
      }
      this.#files.save({ ...this.#files.record, next: null });
    }
  }

  #receipt(state) {
    const pending = this.#pending;
    return {
      ok: true, ...state, revision: pending.base.revision, pending: true,
      batchId: pending.batchId, undoId: pending.undoId, generation: pending.generation,
      draftRevision: pending.draft.revision,
      changes: pending.changes.map((change) => ({ ...change })),
    };
  }

  #commitBatch(request) {
    this.#publication = undefined;
    const pending = this.#pending;
    const validRequest = request &&
      typeof request === 'object' &&
      !Array.isArray(request) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(request)) &&
      Reflect.ownKeys(request).length === 2 &&
      ['batchId', 'generation'].every((key) =>
        Object.hasOwn(Object.getOwnPropertyDescriptor(request, key) ?? {}, 'value'));
    if (!pending ||
        !validRequest ||
        request.batchId !== pending.batchId ||
        request.generation !== pending.generation) {
      throw new PoolingConfigError(409, 'BATCH_CONFLICT', 'The pending batch generation changed.');
    }
    const files = this.#files;
    let entered = false;
    try {
      this.#execution?.check();
      this.#verifyPending();
      const candidate = readPoolingBytes(files.paths.pending);
      this.#validateCandidate(candidate.bytes);
      this.#checkRevision(candidate.revision, pending.draft.revision);
      const previous = files.record.previous;
      files.save({ ...files.record, phase: 'prepared' });
      if (previous) {
        files.remove(files.paths.previous, previous, 1, this.#execution);
        files.save({ ...files.record, previous: null });
      } else if (fs.existsSync(files.paths.previous)) throw poolingConflict();
      this.#verifyPending();
      this.#execution?.check();
      this.#execution?.beginCommit();
      entered = true;
      files.save({ ...files.record, phase: 'entered' });
      files.move(this.#configPath, files.paths.previous, pending.base, this.#execution);
      files.move(files.paths.pending, this.#configPath, pending.draft, this.#execution);
      files.verify(this.#configPath, pending.draft, this.#execution);
      files.verify(files.paths.previous, pending.base, this.#execution);
      files.idle(pending.base);
      this.#finish(pending);
      return {
        ok: true, batchId: pending.batchId, revision: pending.draft.revision,
        changes: pending.changes.map((change) => ({ ...change })),
        commitState: 'committed',
      };
    } catch (error) {
      const failure = poolingIOError(error);
      let commitState = entered ? 'unknown' : 'not-committed';
      if (entered) {
        try {
          const topology = files.topology(this.#execution);
          if (topology.active?.identity === pending.draft.identity &&
              topology.active.revision === pending.draft.revision &&
              topology.active.security === pending.draft.security &&
              topology.previous?.identity === pending.base.identity &&
              !topology.pending) {
            commitState = 'committed';
          } else if (topology.active?.identity === pending.base.identity &&
                     topology.active.revision === pending.base.revision &&
                     topology.active.security === pending.base.security &&
                     !topology.previous) {
            commitState = 'not-committed';
          }
        } catch { /* Failed inspection leaves the outcome unknown. */ }
      }
      if (commitState === 'not-committed') {
        try { files.discard(this.#execution); } catch (cleanupError) {
          if (!this.#abandoned(cleanupError)) files.poisoned = true;
        }
        this.#releaseReservation(pending);
      } else {
        if (pending.restoring) this.#forget(pending.restoring);
        try {
          if (commitState === 'committed') files.idle(pending.base);
        } catch { files.poisoned = true; }
        // Keep the durable checkpoint for fresh, fully verified recovery.
        // This writer cannot retry an outcome it could not establish.
        if (commitState === 'unknown') files.poisoned = true;
      }
      this.#pending = undefined;
      failure.commitState = commitState;
      throw failure;
    }
  }

  #finish(pending) {
    if (pending.restoring) this.#forget(pending.restoring);
    this.#remember(pending.undoId, {
      names: pending.names, bytes: pending.before, revision: pending.draft.revision,
    });
    this.#pending = undefined;
  }

  #releaseReservation(pending) {
    const record = this.#undos.get(pending.restoring);
    if (record?.reserved === pending.batchId) record.reserved = undefined;
  }

  #abandoned(error) {
    return error?.code === 'WRITER_CANCELLED' ||
      error?.code === 'WRITER_DEADLINE';
  }

  #undoConflict() {
    return new PoolingConfigError(409, 'UNDO_CONFLICT', 'Undo is unavailable. Reread the config.');
  }

  #validateRequest(request, allowed) {
    if (!request ||
        Array.isArray(request) ||
        typeof request !== 'object') {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A request object is required.');
    }
    const prototype = Object.getPrototypeOf(request);
    if (prototype !== Object.prototype &&
        prototype !== null) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A plain request object is required.');
    }
    for (const key of Reflect.ownKeys(request)) {
      const descriptor = Object.getOwnPropertyDescriptor(request, key);
      if (!allowed.includes(key) ||
          !Object.hasOwn(descriptor, 'value')) {
        throw new PoolingConfigError(400, 'INVALID_REQUEST', 'Only pooling request fields are allowed.');
      }
    }
    const validName = typeof request.name === 'string' &&
      request.name.length > 0 &&
      request.name.length <= 256 &&
      !/[\x00-\x1f\x7f-\x9f]/.test(request.name) &&
      !['__proto__', 'constructor', 'prototype'].includes(request.name);
    if (!validName) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A valid server name is required.');
    }
    if (typeof request.revision !== 'string' ||
        !/^[a-f0-9]{64}$/.test(request.revision)) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A SHA256 content revision is required.');
    }
  }

  #validateMinWarm(value) {
    if (!Number.isSafeInteger(value) ||
        value < 1 ||
        value > MAX_MIN_WARM) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', `minWarm must be an integer from 1 to ${MAX_MIN_WARM}.`);
    }
  }

  #server(servers, name) {
    if (!Object.hasOwn(servers, name)) {
      throw new PoolingConfigError(404, 'SERVER_NOT_FOUND', 'Server is not configured.');
    }
    const server = servers[name];
    const isStdio = server &&
      !Array.isArray(server) &&
      typeof server === 'object' &&
      (!Object.hasOwn(server, 'type') || server.type === 'stdio') &&
      !Object.hasOwn(server, 'url') &&
      server.sharing !== 'shared' &&
      typeof server.command === 'string' &&
      server.command.trim().length > 0;
    if (!isStdio) {
      throw new PoolingConfigError(400, 'UNSUPPORTED_SERVER', 'Only configured stdio servers support pooling.');
    }
    return server;
  }

  #state(servers, name) {
    const server = this.#server(servers, name);
    const state = { name, mode: server.sharing === 'pool' ? 'pool' : 'isolated' };
    const hasSafeMinWarm = state.mode === 'pool' &&
      Number.isSafeInteger(server.minWarm) &&
      server.minWarm >= 1 &&
      server.minWarm <= MAX_MIN_WARM;
    if (hasSafeMinWarm) state.minWarm = server.minWarm;
    return state;
  }

  #checkRevision(actual, expected) {
    if (actual !== expected) throw poolingConflict();
  }

  #remember(id, record) {
    this.#undos.set(id, record);
    this.#undoBytes += record.bytes.length;
    while (this.#undos.size > MAX_UNDO_ENTRIES ||
           this.#undoBytes > MAX_UNDO_BYTES) {
      const oldest = [...this.#undos].find(([, entry]) => !entry.reserved);
      if (!oldest) throw this.#undoConflict();
      this.#forget(oldest[0]);
    }
  }

  #forget(id) {
    const record = this.#undos.get(id);
    if (!record) return;
    this.#undoBytes -= record.bytes.length;
    this.#undos.delete(id);
  }
}
