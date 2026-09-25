import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { MAX_CONFIG_BYTES } from '../../bin/pooling-files.mjs';

const methods = ['lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync'];
const statFields = ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'];

export class PoolingConflictDiagnostics {
  constructor(files, configPath) {
    this.files = files;
    this.configPath = resolve(configPath);
  }

  capture(request, operation) {
    this.conflict = undefined;
    this.state = { bytes: 0, hash: createHash('sha256'), incomplete: false };
    const originals = methods.map((method) => this.files[method]);
    try {
      for (const [index, method] of methods.entries()) {
        this.files[method] = (...args) => {
          const result = originals[index].apply(this.files, args);
          try {
            this.observe(method, args, result);
          } catch {
            this.state.incomplete = true;
          }
          return result;
        };
      }
      return operation();
    } catch (error) {
      try {
        if (error?.code === 'REVISION_CONFLICT') {
          this.conflict = { site: 'stageApply:unclassified', changedFields: [], incomplete: true };
          this.conflict = this.describe(request);
        }
      } catch {
        // Diagnostic failures must not replace the original operation error.
      }
      throw error;
    } finally {
      for (const [index, method] of methods.entries()) this.files[method] = originals[index];
      this.state = undefined;
    }
  }

  snapshot(stat) {
    const snapshot = {};
    for (const field of statFields) {
      const value = stat[field];
      if (typeof value === 'bigint' &&
          value >= -(1n << 63n) &&
          value < (1n << 64n)) {
        snapshot[field] = value;
      } else {
        this.state.incomplete = true;
      }
    }
    return snapshot;
  }

  observe(method, args, result) {
    const state = this.state;
    if (state.closed) return;
    if (method === 'lstatSync' ||
        method === 'openSync') {
      const active = typeof args[0] === 'string' &&
        resolve(args[0]) === this.configPath;
      if (!active) return;
      if (method === 'lstatSync' &&
          !state.before &&
          args[1]?.bigint === true) state.before = this.snapshot(result);
      if (method === 'openSync' &&
          state.before &&
          state.fd === undefined) {
        if (Number.isSafeInteger(result)) state.fd = result;
        else state.incomplete = true;
      }
      return;
    }
    if (state.fd === undefined ||
        args[0] !== state.fd) return;
    if (method === 'fstatSync') {
      if (!state.opened) state.opened = this.snapshot(result);
      else if (!state.after) state.after = this.snapshot(result);
      else state.incomplete = true;
    } else if (method === 'readSync') {
      const validRead = Buffer.isBuffer(args[1]) &&
        Number.isSafeInteger(args[2]) &&
        args[2] >= 0 &&
        Number.isSafeInteger(result) &&
        result >= 0 &&
        result <= args[1].length - args[2] &&
        state.bytes + result <= MAX_CONFIG_BYTES;
      if (!validRead) {
        state.incomplete = true;
        return;
      }
      state.bytes += result;
      if (result === 0) state.eof = true;
      else state.hash.update(args[1].subarray(args[2], args[2] + result));
    } else if (method === 'closeSync') {
      state.closed = true;
    }
  }

  changed(before, after, fields) {
    return before && after ? fields.filter((field) => before[field] !== after[field]) : [];
  }

  describe(request) {
    const state = this.state;
    const unknown = { site: 'stageApply:unclassified', changedFields: [], incomplete: state.incomplete };
    if (state.incomplete) return unknown;
    const opened = this.changed(state.before, state.opened, ['dev', 'ino', 'size']);
    if (opened.length) {
      return { site: 'boundedRead:open', changedFields: opened, incomplete: false };
    }
    const after = this.changed(state.opened, state.after, ['size', 'mtimeNs', 'ctimeNs']);
    if (after.length) {
      return { site: 'boundedRead:after-read', changedFields: after, incomplete: false };
    }
    const complete = state.closed &&
      state.eof &&
      state.after &&
      state.bytes === Number(state.after.size);
    if (!complete) return unknown;
    const revision = Object.getOwnPropertyDescriptor(request ?? {}, 'revision')?.value;
    const validRevision = typeof revision === 'string' &&
      revision.length === 64 &&
      /^[0-9a-f]{64}$/.test(revision);
    if (validRevision &&
        state.hash.digest('hex') !== revision) {
      return { site: 'stageApply:request-revision', changedFields: ['revision'], incomplete: false };
    }
    return unknown;
  }
}
