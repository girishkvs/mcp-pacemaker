import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { threadId } from 'node:worker_threads';

export const TRACE_MAX_EVENTS = 192;
export const TRACE_MAX_BYTES = 65536;
export const TRACE_MAX_LINE_BYTES = 1024;
const methods = ['apply', 'undo', 'stageApply', 'stageUndo', 'rejectStage', 'commitBatch'];
const codes = ['NONE', 'UNKNOWN', 'ETIMEDOUT', 'EACCES', 'EPERM', 'ENOENT', 'EIO',
  'WRITER_DEADLINE', 'WRITER_CANCELLED', 'WRITER_FAILED', 'WRITER_OUTCOME_UNKNOWN',
  'WRITER_DEADLINE_COMMITTED', 'WRITER_BUSY', 'WRITER_CLOSED', 'REVISION_CONFLICT',
  'IO_ERROR', 'ACCESS_DENIED', 'FILE_BUSY', 'RECOVERY_REQUIRED', 'STORE_BUSY'];
const integer = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
const state = (value) => Number.isInteger(value) && value >= 0 && value <= 6;
const duration = (value) => Number.isFinite(value) && Math.abs(value) <= 120000;
const boolean = (value) => typeof value === 'boolean';
const method = (value) => methods.includes(value);
const code = (value) => codes.includes(value);
const action = (value) => ['inspect-access', 'stage', 'move-no-replace'].includes(value);
const fields = {
  'request-start': {},
  'body-end': { bytes: integer },
  'response': { status: (value) => Number.isInteger(value) && value >= 100 && value <= 599 },
  'queue-enter': { queued: integer, applying: boolean },
  'queue-leave': {},
  'writer-send': { method, queued: integer, cold: boolean },
  'worker-ready': {},
  'worker-enter': { method, state },
  'worker-result': { state },
  'worker-error': { code, state },
  'writer-expire': { expired: boolean, state },
  'writer-result': { code, state },
  'store-start': {},
  'store-ready': {},
  'helper-start': { action, call: integer, timeoutMs: duration },
  'helper-end': { action, call: integer, helperPid: integer,
    exit: (value) => value === null || Number.isInteger(value) && Math.abs(value) <= 0xffffffff, code },
  'publish-start': {},
  'publish-end': {},
  'capture-truncated': {},
  'capture-failed': {},
  'capture-invalid': {},
};
const base = ['version', 'event', 'operation', 'pid', 'thread', 'sequence', 'elapsedMs', 'remainingMs'];
const uuid = (value) => typeof value === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);

export function validateTraceRecord(record) {
  if (!record ||
      Object.getPrototypeOf(record) !== Object.prototype ||
      !Object.hasOwn(fields, record.event)) throw new Error('Invalid pooling trace record.');
  const schema = fields[record.event];
  const keys = [...base, ...Object.keys(schema)];
  const valid = record.version === 1 && uuid(record.operation) &&
    integer(record.pid) && integer(record.thread) && integer(record.sequence) &&
    record.sequence > 0 && record.sequence <= TRACE_MAX_EVENTS &&
    duration(record.elapsedMs) && duration(record.remainingMs) &&
    Object.keys(record).length === keys.length &&
    keys.every((key) => Object.hasOwn(record, key)) &&
    Object.entries(schema).every(([key, validate]) => validate(record[key]));
  if (!valid ||
      Buffer.byteLength(JSON.stringify(record) + '\n') > TRACE_MAX_LINE_BYTES) {
    throw new Error('Invalid pooling trace record.');
  }
  return record;
}

export function traceErrorCode(error) {
  try {
    return error == null ? 'NONE' : codes.includes(error.code) ? error.code : 'UNKNOWN';
  } catch {
    return 'UNKNOWN';
  }
}

class PoolingTraceOperation {
  constructor(sink, deadline, context) {
    this.sink = sink;
    this.deadline = deadline;
    this.context = context;
    this.calls = 0;
  }

  helper() {
    return ++this.calls;
  }

  record(event, extra = {}) {
    this.sink.record(this, event, extra);
  }
}

export class PoolingTrace {
  constructor(directory) {
    this.directory = directory;
    this.events = 0;
    this.bytes = 0;
    this.stopped = false;
    this.failed = false;
  }

  operation(deadline, context) {
    if (!this.directory) return undefined;
    try {
      context ??= { operation: randomUUID(), started: String(process.hrtime.bigint()), deadline: String(deadline) };
      const valid = uuid(context.operation) &&
        typeof context.started === 'string' && /^\d{1,24}$/.test(context.started) &&
        typeof context.deadline === 'string' && /^\d{1,24}$/.test(context.deadline);
      if (!valid) return undefined;
      return new PoolingTraceOperation(this, deadline ?? BigInt(context.deadline), {
        operation: context.operation, started: context.started, deadline: context.deadline,
      });
    } catch {
      this.failed = true;
      return undefined;
    }
  }

  record(operation, event, extra) {
    if (this.stopped) return;
    try {
      const now = process.hrtime.bigint();
      const milliseconds = (value) => Math.round(Math.max(-120000, Math.min(120000, Number(value) / 1e6)) * 1000) / 1000;
      const record = {
        version: 1, event, operation: operation.context.operation,
        pid: process.pid, thread: threadId, sequence: this.events + 1,
        elapsedMs: milliseconds(now - BigInt(operation.context.started)),
        remainingMs: milliseconds(operation.deadline - now),
      };
      try {
        if (!Object.hasOwn(fields, event) ||
            Object.keys(extra).some((key) => !Object.hasOwn(fields[event], key))) {
          throw new Error('Invalid pooling trace fields.');
        }
        Object.assign(record, extra);
        validateTraceRecord(record);
      } catch {
        record.event = 'capture-invalid';
        for (const key of Object.keys(record)) {
          if (!base.includes(key)) delete record[key];
        }
        this.stopped = true;
      }
      const full = this.events >= TRACE_MAX_EVENTS - 1 ||
        this.bytes + Buffer.byteLength(JSON.stringify(record) + '\n') > TRACE_MAX_BYTES - TRACE_MAX_LINE_BYTES;
      if (full ||
          this.failed) {
        record.event = this.failed ? 'capture-failed' : 'capture-truncated';
        for (const key of Object.keys(record)) {
          if (!base.includes(key)) delete record[key];
        }
        this.stopped = true;
      }
      validateTraceRecord(record);
      const line = JSON.stringify(record) + '\n';
      fs.appendFileSync(join(this.directory, `${process.pid}-${threadId}.jsonl`), line,
        { flag: this.events === 0 ? 'wx' : 'a', mode: 0o600 });
      this.events++;
      this.bytes += Buffer.byteLength(line);
    } catch {
      // Diagnostics must never replace the operation's result or error.
      this.failed = true;
    }
  }
}

export const poolingTrace = new PoolingTrace(process.env.MCP_POOLING_TRACE_DIR);
