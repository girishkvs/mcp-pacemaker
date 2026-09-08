import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { TextDecoder } from 'node:util';

export const SHARED_DEFAULTS = Object.freeze({
  sharedLingerMs: 30 * 60_000,
  sharedDrainTimeoutMs: 30_000,
  sharedRetryDelayMs: 1_000,
  sharedMaxSessions: 128,
  sharedMaxInFlight: 8,
  sharedMaxQueued: 32,
  sharedMaxIds: 4_096,
  sharedMaxCursors: 256,
  sharedMaxLineBytes: 1_048_576,
  sharedMaxBufferBytes: 4_194_304,
});

const LIMITS = {
  sharedLingerMs: [0, 2_147_483_647],
  sharedDrainTimeoutMs: [1, 2_147_483_647],
  sharedRetryDelayMs: [1, 2_147_483_647],
  sharedMaxSessions: [1, 1_024],
  sharedMaxInFlight: [1, 1_024],
  sharedMaxQueued: [0, 4_096],
  sharedMaxIds: [1, 65_536],
  sharedMaxCursors: [1, 4_096],
  sharedMaxLineBytes: [256, 16_777_216],
  sharedMaxBufferBytes: [256, 67_108_864],
};
const VERSIONS = new Set(['2025-03-26', '2025-06-18', '2025-11-25']);
const MAX_JSON_DEPTH = 64;
const SERVER_CAPABILITY_SHAPES = {
  tools: { listChanged: 'boolean' },
  prompts: { listChanged: 'boolean' },
  resources: { subscribe: 'boolean', listChanged: 'boolean' },
  logging: {},
  completions: {},
  tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } },
  experimental: {},
};

export class SharedSessionManager extends EventEmitter {
  constructor({ spawn, kill, onFailure = () => {}, onInitialized = () => {}, onResponse = () => {}, log = () => {},
    initTimeoutMs = 180_000, requestTimeoutMs = 30_000 } = {}) {
    super();
    for (const fn of [spawn, kill, onFailure, onInitialized, onResponse, log]) {
      if (typeof fn !== 'function') throw new TypeError('Shared callbacks must be functions');
    }
    this.validateInteger('initTimeoutMs', initTimeoutMs, 1, 2_147_483_647);
    this.validateInteger('requestTimeoutMs', requestTimeoutMs, 1, 2_147_483_647);
    Object.assign(this, { spawn, kill, onFailure, onInitialized, onResponse, log, initTimeoutMs, requestTimeoutMs });
    this.groups = new Map();
    this.cooldowns = new Map();
    this.closed = false;
    this.sequence = 0n;
  }

  validateInteger(name, value, min, max) {
    if (!Number.isSafeInteger(value) ||
        value < min ||
        value > max) {
      throw new TypeError(`${name} must be a safe integer between ${min} and ${max}`);
    }
  }

  record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  validId(value) {
    return typeof value === 'string' || Number.isSafeInteger(value);
  }

  withinDepth(value, depth = 0) {
    if (depth > MAX_JSON_DEPTH) return false;
    if (value === null ||
        typeof value !== 'object') return true;
    return Object.values(value).every((entry) => this.withinDepth(entry, depth + 1));
  }

  validCapabilityRecord(value, shape = SERVER_CAPABILITY_SHAPES) {
    if (!this.record(value)) return false;
    return Object.entries(value).every(([key, entry]) => {
      if (!Object.hasOwn(shape, key)) return false;
      return shape[key] === 'boolean' ? typeof entry === 'boolean' : this.validCapabilityRecord(entry, shape[key]);
    });
  }

  canonical(value, depth = 0) {
    if (depth > MAX_JSON_DEPTH) throw this.error('SHARED_INVALID_CONFIG', 'validation', 'unsent');
    if (value === null) return 'null';
    if (Array.isArray(value)) {
      return `[${Array.from(value, (entry) => this.canonical(entry, depth + 1)).join(',')}]`;
    }
    if (this.record(value)) {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype &&
          prototype !== null) {
        throw this.error('SHARED_INVALID_CONFIG', 'validation', 'unsent');
      }
      return `{${Object.keys(value).sort().map((key) =>
        `${JSON.stringify(key)}:${this.canonical(value[key], depth + 1)}`).join(',')}}`;
    }
    if (typeof value === 'string' ||
        typeof value === 'boolean' ||
        (typeof value === 'number' && Number.isFinite(value))) {
      return JSON.stringify(value);
    }
    throw this.error('SHARED_INVALID_CONFIG', 'validation', 'unsent');
  }

  options(definition) {
    const options = {};
    for (const [name, fallback] of Object.entries(SHARED_DEFAULTS)) {
      const value = Object.hasOwn(definition, name) ? definition[name] : fallback;
      this.validateInteger(name, value, ...LIMITS[name]);
      options[name] = value;
    }
    return options;
  }

  validateInitialize(params) {
    const valid = this.record(params) && VERSIONS.has(params.protocolVersion) &&
      this.record(params.capabilities) && Object.keys(params.capabilities).length === 0 &&
      this.record(params.clientInfo) && typeof params.clientInfo.name === 'string' &&
      typeof params.clientInfo.version === 'string';
    if (!valid) throw this.error('SHARED_INCOMPATIBLE', 'initialize', 'unsent');
  }

  detail(kind, phase, execution, generation = null) {
    return { kind, phase, execution, generation };
  }

  error(kind, phase, execution, generation = null) {
    const error = new Error(`shared: ${kind}`);
    error.code = kind;
    error.data = this.detail(kind, phase, execution, generation);
    return error;
  }

  rpcError(id, detail, code = -32002) {
    return { jsonrpc: '2.0', id, error: { code, message: `shared: ${detail.kind}`, data: detail } };
  }

  async acquire(name, definition, initializeParams) {
    if (this.closed) throw this.error('SHARED_SHUTDOWN', 'admission', 'unsent');
    const wrongTransport = this.record(definition) && definition.type !== undefined &&
      definition.type !== 'stdio';
    if (typeof name !== 'string' ||
        !name.length ||
        !this.record(definition) ||
        definition.sharing !== 'shared' ||
        wrongTransport) {
      throw this.error('SHARED_INCOMPATIBLE', 'admission', 'unsent');
    }
    this.validateInitialize(initializeParams);
    const options = this.options(definition);
    const configKey = this.canonical(definition);
    const initKey = this.canonical(initializeParams);
    if (Buffer.byteLength(configKey) + Buffer.byteLength(initKey) > options.sharedMaxLineBytes) {
      throw this.error('SHARED_INPUT_LIMIT', 'admission', 'unsent');
    }
    let group = this.groups.get(name);
    if (group) {
      if (group.configKey !== configKey ||
          group.initKey !== initKey) {
        throw this.error('SHARED_INCOMPATIBLE', 'admission', 'unsent', group.generation);
      }
      if (group.state !== 'starting' &&
          group.state !== 'ready') {
        throw this.error(`SHARED_${group.state.toUpperCase()}`, 'admission', 'unsent', group.generation);
      }
    } else {
      const retryAt = this.cooldowns.get(name);
      if (retryAt > Date.now()) {
        const error = this.error('SHARED_RETRY_LATER', 'admission', 'unsent');
        error.retryAfterMs = retryAt - Date.now();
        throw error;
      }
      this.cooldowns.delete(name);
      if (this.groups.size >= 128) throw this.error('SHARED_GROUP_LIMIT', 'admission', 'unsent');
      group = new SharedGroup(this, name, JSON.parse(configKey), JSON.parse(initKey),
        configKey, initKey, options, String(++this.sequence));
      this.groups.set(name, group);
      group.start();
    }
    if (group.members.size + group.waiters >= options.sharedMaxSessions) {
      throw this.error('SHARED_SESSION_LIMIT', 'admission', 'unsent', group.generation);
    }
    group.waiters++;
    clearTimeout(group.lingerTimer);
    try {
      await group.ready;
      if (group.state !== 'ready') {
        throw this.error('SHARED_RETIRED', 'admission', 'unsent', group.generation);
      }
      const child = new SharedChild(group);
      group.members.add(child);
      return child;
    } finally {
      group.waiters--;
      group.idle();
    }
  }

  recycle(name) {
    const group = this.groups.get(name);
    if (!group) return { found: false };
    group.drain('SHARED_RECYCLED');
    return { found: true, ...group.inspect() };
  }

  remove(name) {
    this.cooldowns.delete(name);
    const group = this.groups.get(name);
    if (!group) return { found: false };
    group.stop('SHARED_REMOVED', false);
    return { found: true, ...group.inspect() };
  }

  shutdown() {
    this.closed = true;
    const groups = [...this.groups.values()];
    for (const group of groups) group.stop('SHARED_SHUTDOWN', false);
    this.cooldowns.clear();
    return { groups: groups.length };
  }

  inspect(name) {
    return this.groups.get(name)?.inspect() ?? null;
  }

  retired(group) {
    if (this.groups.get(group.name) === group) this.groups.delete(group.name);
    if (group.failed &&
        !this.closed) {
      this.cooldowns.delete(group.name);
      this.cooldowns.set(group.name, Date.now() + group.options.sharedRetryDelayMs);
      if (this.cooldowns.size > 128) this.cooldowns.delete(this.cooldowns.keys().next().value);
    }
    const detail = { name: group.name, ...group.inspect(), reason: group.reason, failed: group.failed };
    queueMicrotask(() => this.emit('retired', detail));
  }
}

class JsonLines {
  constructor(limit, receive, fail) {
    this.limit = limit;
    this.receive = receive;
    this.fail = fail;
    this.buffer = Buffer.alloc(0);
    this.decoder = new TextDecoder('utf-8', { fatal: true });
    this.closed = false;
  }

  write(chunk) {
    if (this.closed) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let start = 0;
    while (start < bytes.length) {
      const end = bytes.indexOf(10, start);
      const stop = end < 0 ? bytes.length : end;
      const part = bytes.subarray(start, stop);
      if (this.buffer.length + part.length > this.limit) {
        this.close();
        this.fail('SHARED_INPUT_LIMIT');
        return;
      }
      const line = this.buffer.length ? Buffer.concat([this.buffer, part]) : part;
      if (end < 0) {
        this.buffer = Buffer.from(line);
        return;
      }
      this.buffer = Buffer.alloc(0);
      let message;
      try {
        message = JSON.parse(this.decoder.decode(line));
      } catch {
        this.close();
        this.fail('SHARED_INVALID_JSON');
        return;
      }
      this.receive(message);
      if (this.closed) return;
      start = end + 1;
    }
  }

  close() {
    this.closed = true;
    this.buffer = Buffer.alloc(0);
  }
}

class SharedChild extends EventEmitter {
  constructor(group) {
    super();
    this.group = group;
    this.pid = group.child.pid;
    this.__spawnedAt = group.child.__spawnedAt ?? group.spawnedAt;
    this.__sharedSession = true;
    this.__sharedGeneration = group.generation;
    this.exitCode = null;
    this.signalCode = null;
    this.active = true;
    this.outputFailed = false;
    this.phase = 'attached';
    this.ids = new Set();
    this.retainedBytes = 0;
    this.pending = new Map();
    this.cursors = new Map();
    this.queue = [];
    this.stdout = new Readable({ read() {} });
    this.stderr = new Readable({ read() {} });
    this.lines = new JsonLines(group.options.sharedMaxLineBytes,
      (message) => group.clientMessage(this, message),
      (kind) => group.detach(this, kind));
    this.stdin = new Writable({
      highWaterMark: group.options.sharedMaxBufferBytes,
      write: (chunk, encoding, callback) => {
        if (!this.active) {
          callback(group.manager.error('SHARED_DETACHED', 'transport', 'unsent', group.generation));
          return;
        }
        this.lines.write(chunk);
        callback();
      },
      final: (callback) => {
        group.detach(this, this.lines.buffer.length ? 'SHARED_INVALID_JSON' : 'SHARED_DETACHED');
        callback();
      },
    });
    this.stdin.on('error', () => group.detach(this, 'SHARED_INPUT_CLOSED'));
    this.stdout.on('error', () => group.detach(this, 'SHARED_OUTPUT_CLOSED'));
    this.stdout.on('close', () => group.detach(this, 'SHARED_OUTPUT_CLOSED'));
    this.initTimer = setTimeout(() => group.detach(this, 'SHARED_SESSION_INIT_TIMEOUT'),
      group.manager.initTimeoutMs);
  }

  writeMessage(message) {
    if (!this.active) {
      throw this.group.manager.error('SHARED_DETACHED', 'admission', 'unsent', this.group.generation);
    }
    this.group.clientMessage(this, message);
  }

  send(message) {
    if (!this.active ||
        this.outputFailed) return false;
    let line;
    try {
      line = `${JSON.stringify(message)}\n`;
    } catch {
      this.outputFailed = true;
      this.group.detach(this, 'SHARED_SERIALIZATION_FAILED');
      return false;
    }
    if (this.stdout.readableLength + Buffer.byteLength(line) > this.group.options.sharedMaxBufferBytes) {
      this.group.detach(this, 'SHARED_OUTPUT_LIMIT');
      return false;
    }
    this.stdout.push(line);
    return true;
  }

  finish(kind) {
    if (!this.active) return;
    this.active = false;
    this.phase = 'closed';
    this.lines.close();
    clearTimeout(this.initTimer);
    this.ids.clear();
    this.retainedBytes = 0;
    this.cursors.clear();
    this.pending.clear();
    this.stdin.destroy();
    this.stdout.push(null);
    this.stderr.push(null);
    const expected = ['SHARED_DETACHED', 'SHARED_RECYCLED', 'SHARED_REMOVED', 'SHARED_SHUTDOWN'].includes(kind);
    this.exitCode = expected ? 0 : 1;
    const detail = this.group.manager.detail(kind, 'session', 'none', this.group.generation);
    queueMicrotask(() => {
      this.emit('sharedFailure', detail);
      this.emit('exit', this.exitCode, this.signalCode);
      this.emit('close', this.exitCode, this.signalCode);
    });
  }

  detach() {
    return this.group.detach(this, 'SHARED_DETACHED');
  }
}

class SharedGroup {
  constructor(manager, name, definition, params, configKey, initKey, options, generation) {
    Object.assign(this, { manager, name, definition, params, configKey, initKey, options, generation });
    this.state = 'starting';
    this.members = new Set();
    this.waiters = 0;
    this.operations = new Map();
    this.progress = new Map();
    this.lanes = [];
    this.queued = 0;
    this.queuedBytes = 0;
    this.sequence = 0n;
    this.prefix = randomUUID();
    this.initId = this.id('init');
    this.failed = false;
    this.reported = false;
    this.killRequested = false;
    this.blocked = false;
    this.pumping = false;
    this.ready = new Promise((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    this.lines = new JsonLines(options.sharedMaxLineBytes,
      (message) => this.childMessage(message), (kind) => this.stop(kind, true));
  }

  id(prefix) {
    return `${this.prefix}:${this.generation}:${prefix}:${++this.sequence}`;
  }

  start() {
    this.spawnedAt = Date.now();
    this.initTimer = setTimeout(() => this.stop('SHARED_INIT_TIMEOUT', true), this.manager.initTimeoutMs);
    Promise.resolve().then(() => this.manager.spawn(this.name, this.definition)).then((child) => {
      this.child = child;
      this.listen(child);
      if (this.state === 'stopping') {
        this.kill();
        return;
      }
      const validChild = child.stdin?.writable && child.stdout?.readable &&
        child.exitCode == null && child.signalCode == null;
      if (!validChild) {
        this.stop('SHARED_CHILD_UNAVAILABLE', true);
        return;
      }
      const params = structuredClone(this.params);
      if (Object.hasOwn(params._meta ?? {}, 'progressToken')) {
        params._meta.progressToken = this.id('init-progress');
      }
      this.write({ jsonrpc: '2.0', id: this.initId, method: 'initialize', params });
    }).catch(() => {
      if (this.child) {
        this.stop('SHARED_SPAWN_FAILED', true);
      } else {
        this.stop('SHARED_SPAWN_FAILED', true);
        this.dead();
      }
    });
  }

  listen(child) {
    child.once('exit', () => this.exited());
    child.once('close', () => this.exited());
    child.on('error', () => this.stop('SHARED_CHILD_ERROR', true));
    child.stdin?.on('error', () => this.stop('SHARED_STDIN_ERROR', true));
    child.stdin?.on('drain', () => {
      this.blocked = false;
      this.pump();
    });
    child.stdout?.on('data', (chunk) => this.lines.write(chunk));
    child.stdout?.on('error', () => this.stop('SHARED_STDOUT_ERROR', true));
    child.stdout?.on('end', () => {
      if (this.state !== 'stopping' &&
          this.state !== 'dead') {
        this.stop('SHARED_STDOUT_CLOSED', true);
      }
    });
    child.stderr?.resume();
  }

  write(message) {
    if (!this.child ||
        this.state === 'dead') return false;
    let line;
    try {
      line = `${JSON.stringify(message)}\n`;
    } catch {
      this.stop('SHARED_SERIALIZATION_FAILED', true);
      return false;
    }
    const bytes = Buffer.byteLength(line);
    if (bytes > this.options.sharedMaxLineBytes ||
        this.child.stdin.writableLength + bytes > this.options.sharedMaxBufferBytes) {
      this.stop('SHARED_UPSTREAM_BUFFER_LIMIT', true);
      return false;
    }
    try {
      const accepted = this.child.stdin.write(line, (error) => {
        if (error) this.stop('SHARED_STDIN_ERROR', true);
      });
      if (!accepted) this.blocked = true;
      return true;
    } catch {
      this.stop('SHARED_STDIN_ERROR', true);
      return false;
    }
  }

  inspect() {
    return {
      generation: this.generation, state: this.state, pid: this.child?.pid ?? null,
      members: this.members.size, waiters: this.waiters,
      unresolved: this.operations.size, queued: this.queued,
    };
  }

  clientMessage(owner, message) {
    if (!owner.active) return;
    const valid = this.manager.record(message) && message.jsonrpc === '2.0' &&
      typeof message.method === 'string' && !Object.hasOwn(message, 'result') &&
      !Object.hasOwn(message, 'error');
    if (!valid) {
      this.detach(owner, 'SHARED_INVALID_MESSAGE');
      return;
    }
    if (!Object.hasOwn(message, 'id')) {
      if (this.checkClientInput(owner, message)) this.notification(owner, message);
      return;
    }
    if (!this.manager.validId(message.id)) {
      this.detach(owner, 'SHARED_INVALID_ID');
      return;
    }
    if (owner.ids.has(message.id)) {
      this.detach(owner, 'SHARED_DUPLICATE_ID');
      return;
    }
    if (owner.ids.size >= this.options.sharedMaxIds) {
      this.detach(owner, 'SHARED_ID_LIMIT');
      return;
    }
    const idBytes = Buffer.byteLength(JSON.stringify(message.id));
    if (owner.retainedBytes + idBytes > this.options.sharedMaxBufferBytes) {
      this.detach(owner, 'SHARED_RETAINED_LIMIT');
      return;
    }
    owner.retainedBytes += idBytes;
    owner.ids.add(message.id);
    if (!this.checkClientInput(owner, message)) return;
    if (message.method === 'initialize') {
      let key;
      try {
        key = this.manager.canonical(message.params);
      } catch {
        this.reject(owner, message.id, 'SHARED_INCOMPATIBLE', -32003);
        return;
      }
      if (owner.phase !== 'attached' ||
          key !== this.initKey) {
        this.reject(owner, message.id, 'SHARED_INCOMPATIBLE', -32003);
        return;
      }
      owner.phase = 'initialized';
      owner.send({ jsonrpc: '2.0', id: message.id, result: this.result });
      return;
    }
    if (owner.phase !== 'ready') {
      this.reject(owner, message.id, 'SHARED_NOT_INITIALIZED');
      return;
    }
    if (this.state !== 'ready') {
      this.reject(owner, message.id, 'SHARED_DRAINING');
      return;
    }
    const allowed = ['tools/list', 'tools/call', 'ping'].includes(message.method);
    const paramsValid = message.params === undefined || this.manager.record(message.params);
    const task = Object.hasOwn(message.params ?? {}, 'task');
    if (!allowed ||
        !paramsValid ||
        task) {
      this.reject(owner, message.id, 'SHARED_UNSUPPORTED_METHOD', -32601);
      return;
    }
    if (message.method.startsWith('tools/') &&
        !this.result.capabilities.tools) {
      this.reject(owner, message.id, 'SHARED_UNSUPPORTED_METHOD', -32601);
      return;
    }
    let request;
    try {
      request = structuredClone(message);
    } catch {
      this.reject(owner, message.id, 'SHARED_CLONE_FAILED', -32602);
      return;
    }
    if (message.method === 'tools/list' &&
        Object.hasOwn(message.params ?? {}, 'cursor')) {
      const cursor = owner.cursors.get(message.params.cursor);
      if (cursor === undefined) {
        this.reject(owner, message.id, 'SHARED_CURSOR_INVALID', -32003);
        return;
      }
      request.params.cursor = cursor;
    }
    const token = message.params?._meta?.progressToken;
    if (token !== undefined &&
        !this.manager.validId(token)) {
      this.reject(owner, message.id, 'SHARED_INVALID_PROGRESS', -32602);
      return;
    }
    if (token !== undefined &&
        [...owner.pending.values()].some((operation) => operation.token === token)) {
      this.reject(owner, message.id, 'SHARED_DUPLICATE_PROGRESS', -32602);
      return;
    }
    const canDispatch = !this.blocked && this.operations.size < this.options.sharedMaxInFlight &&
      this.queued === 0;
    if (!canDispatch &&
        this.queued >= this.options.sharedMaxQueued) {
      this.reject(owner, message.id, 'SHARED_QUEUE_LIMIT', -32004);
      return;
    }
    request.id = this.id('request');
    const operation = { owner, originalId: message.id, request, token, dispatched: false, settled: false };
    if (token !== undefined) {
      operation.progressId = this.id('progress');
      request.params._meta.progressToken = operation.progressId;
    }
    operation.bytes = Buffer.byteLength(JSON.stringify(request)) + 1;
    if (operation.bytes > this.options.sharedMaxLineBytes ||
        operation.bytes > this.options.sharedMaxBufferBytes) {
      this.reject(owner, message.id, 'SHARED_REQUEST_LIMIT', -32004);
      return;
    }
    if (!canDispatch &&
        this.queuedBytes + operation.bytes > this.options.sharedMaxBufferBytes) {
      this.reject(owner, message.id, 'SHARED_QUEUE_LIMIT', -32004);
      return;
    }
    operation.timer = setTimeout(() => this.timeout(operation), this.manager.requestTimeoutMs);
    owner.pending.set(message.id, operation);
    if (canDispatch) {
      this.dispatch(operation);
    } else {
      owner.queue.push(operation);
      this.queued++;
      this.queuedBytes += operation.bytes;
      if (!this.lanes.includes(owner)) this.lanes.push(owner);
      this.pump();
    }
  }

  checkClientInput(owner, message) {
    let kind;
    if (!this.manager.withinDepth(message)) {
      kind = 'SHARED_DEPTH_LIMIT';
    } else {
      try {
        if (Buffer.byteLength(JSON.stringify(message)) > this.options.sharedMaxLineBytes) {
          kind = 'SHARED_INPUT_LIMIT';
        }
      } catch {
        kind = 'SHARED_SERIALIZATION_FAILED';
      }
    }
    if (!kind) return true;
    if (Object.hasOwn(message, 'id')) this.reject(owner, message.id, kind, -32602);
    else this.detach(owner, kind);
    return false;
  }

  reject(owner, id, kind, code = -32002) {
    owner.send(this.manager.rpcError(id,
      this.manager.detail(kind, 'admission', 'unsent', this.generation), code));
  }

  notification(owner, message) {
    if (message.method === 'notifications/initialized') {
      if (owner.phase !== 'initialized') {
        this.detach(owner, 'SHARED_NOT_INITIALIZED');
        return;
      }
      owner.phase = 'ready';
      clearTimeout(owner.initTimer);
      return;
    }
    if (message.method !== 'notifications/cancelled') {
      this.detach(owner, 'SHARED_UNSUPPORTED_NOTIFICATION');
      return;
    }
    const operation = owner.pending.get(message.params?.requestId);
    if (!operation) return;
    if (operation.dispatched) {
      this.cancel(operation);
      this.settle(operation, 'SHARED_CANCELLED', -32800);
    } else {
      this.unqueue(operation);
      this.settle(operation, 'SHARED_CANCELLED', -32800);
      this.pump();
    }
  }

  dispatch(operation) {
    if (this.child.stdin.writableLength + operation.bytes > this.options.sharedMaxBufferBytes) {
      this.settle(operation, 'SHARED_UPSTREAM_BUFFER_LIMIT', -32004);
      return;
    }
    operation.dispatched = true;
    this.operations.set(operation.request.id, operation);
    if (operation.progressId) this.progress.set(operation.progressId, operation);
    this.write(operation.request);
  }

  pump() {
    if (this.pumping) return;
    this.pumping = true;
    try {
      while (this.state === 'ready' &&
          !this.blocked &&
          this.operations.size < this.options.sharedMaxInFlight &&
          this.lanes.length) {
        const owner = this.lanes.shift();
        const operation = owner.queue.shift();
        this.queued--;
        this.queuedBytes -= operation.bytes;
        if (owner.queue.length) this.lanes.push(owner);
        this.dispatch(operation);
      }
    } finally {
      this.pumping = false;
    }
  }

  unqueue(operation) {
    const queue = operation.owner.queue;
    const index = queue.indexOf(operation);
    if (index < 0) return;
    queue.splice(index, 1);
    this.queued--;
    this.queuedBytes -= operation.bytes;
    if (!queue.length) this.lanes = this.lanes.filter((owner) => owner !== operation.owner);
  }

  settle(operation, kind, code = -32002) {
    if (operation.settled) return;
    operation.settled = true;
    const execution = operation.dispatched ? 'potentially-executed' : 'unsent';
    operation.owner.send(this.manager.rpcError(operation.originalId,
      this.manager.detail(kind, operation.dispatched ? 'execution' : 'queue', execution, this.generation), code));
    if (!operation.dispatched) {
      clearTimeout(operation.timer);
      operation.owner.pending.delete(operation.originalId);
    }
  }

  cancel(operation) {
    if (operation.cancelled) return;
    operation.cancelled = true;
    this.write({ jsonrpc: '2.0', method: 'notifications/cancelled',
      params: { requestId: operation.request.id } });
  }

  timeout(operation) {
    if (operation.dispatched) {
      this.settle(operation, 'SHARED_REQUEST_TIMEOUT', -32001);
      this.cancel(operation);
      this.drain('SHARED_REQUEST_TIMEOUT', true);
    } else {
      this.unqueue(operation);
      this.settle(operation, 'SHARED_QUEUE_TIMEOUT', -32001);
      this.pump();
    }
  }

  childMessage(message) {
    if (this.state === 'stopping' ||
        this.state === 'dead') return;
    if (!this.manager.withinDepth(message)) {
      this.stop('SHARED_UPSTREAM_DEPTH_LIMIT', true);
      return;
    }
    if (!this.manager.record(message) ||
        message.jsonrpc !== '2.0') {
      this.stop('SHARED_INVALID_MESSAGE', true);
      return;
    }
    if (Object.hasOwn(message, 'method')) {
      if (typeof message.method !== 'string' ||
          Object.hasOwn(message, 'result') ||
          Object.hasOwn(message, 'error')) {
        this.stop('SHARED_INVALID_MESSAGE', true);
        return;
      }
      if (Object.hasOwn(message, 'id')) {
        this.callback(message);
      } else {
        this.childNotification(message);
      }
      return;
    }
    const response = this.manager.validId(message.id) &&
      (Object.hasOwn(message, 'result') !== Object.hasOwn(message, 'error'));
    const validError = !Object.hasOwn(message, 'error') ||
      (this.manager.record(message.error) && Number.isSafeInteger(message.error.code) &&
        typeof message.error.message === 'string');
    if (!response ||
        !validError) {
      this.stop('SHARED_INVALID_MESSAGE', true);
      return;
    }
    if (message.id === this.initId &&
        this.state === 'starting') {
      this.initialized(message);
      return;
    }
    const operation = this.operations.get(message.id);
    if (!operation) return;
    this.operations.delete(message.id);
    this.progress.delete(operation.progressId);
    clearTimeout(operation.timer);
    operation.owner.pending.delete(operation.originalId);
    if (!operation.settled &&
        operation.owner.active) {
      const response = { ...message, id: operation.originalId };
      if (operation.request.method === 'tools/list' &&
          this.manager.record(response.result) &&
          Object.hasOwn(response.result, 'nextCursor')) {
        if (typeof response.result.nextCursor !== 'string') {
          this.settle(operation, 'SHARED_CURSOR_INVALID', -32003);
          this.stop('SHARED_CURSOR_INVALID', true);
          return;
        }
        if (operation.owner.cursors.size >= this.options.sharedMaxCursors) {
          this.settle(operation, 'SHARED_CURSOR_LIMIT', -32004);
        } else {
          const cursor = this.id('cursor');
          const bytes = Buffer.byteLength(cursor) + Buffer.byteLength(response.result.nextCursor);
          if (operation.owner.retainedBytes + bytes > this.options.sharedMaxBufferBytes) {
            this.settle(operation, 'SHARED_RETAINED_LIMIT', -32004);
          } else {
            operation.owner.retainedBytes += bytes;
            operation.owner.cursors.set(cursor, response.result.nextCursor);
            response.result = { ...response.result, nextCursor: cursor };
          }
        }
      }
      if (!operation.settled) operation.owner.send(response);
    }
    this.acceptedResponse();
    this.pump();
    this.idle();
  }

  acceptedResponse() {
    const failed = () => this.manager.log(this.name, 'shared: onResponse callback failed');
    try {
      Promise.resolve(this.manager.onResponse(this.name)).catch(failed);
    } catch {
      failed();
    }
  }

  initialized(message) {
    if (Object.hasOwn(message, 'error')) {
      const error = this.manager.error('SHARED_INIT_REJECTED', 'initialize', 'unsent', this.generation);
      error.upstreamError = message.error;
      this.rejectReady(error);
      this.stop('SHARED_INIT_REJECTED', true);
      return;
    }
    const result = message.result;
    const valid = this.manager.record(result) && VERSIONS.has(result.protocolVersion) &&
      this.manager.record(result.serverInfo) && typeof result.serverInfo.name === 'string' &&
      typeof result.serverInfo.version === 'string' && this.manager.validCapabilityRecord(result.capabilities);
    if (!valid) {
      this.stop('SHARED_INIT_INCOMPATIBLE', true);
      return;
    }
    this.result = { ...result, capabilities: Object.hasOwn(result.capabilities, 'tools')
      ? { tools: result.capabilities.tools } : {} };
    if (!this.write({ jsonrpc: '2.0', method: 'notifications/initialized' })) return;
    if (this.state !== 'starting') return;
    this.state = 'ready';
    clearTimeout(this.initTimer);
    this.resolveReady();
    this.idle();
    this.sampleInitialization();
  }

  sampleInitialization() {
    const completedAt = Date.now();
    const spawnedAt = this.child.__spawnedAt;
    if (!Number.isSafeInteger(spawnedAt) ||
        spawnedAt < 0 ||
        spawnedAt > completedAt) {
      this.manager.log(this.name, 'shared: initialization latency unavailable; invalid child __spawnedAt');
      return;
    }
    const failed = () => this.manager.log(this.name, 'shared: onInitialized callback failed');
    try {
      Promise.resolve(this.manager.onInitialized(this.name, completedAt - spawnedAt)).catch(failed);
    } catch {
      failed();
    }
  }

  callback(message) {
    if (!this.manager.validId(message.id)) {
      this.stop('SHARED_INVALID_ID', true);
      return;
    }
    if (message.method === 'ping') {
      this.write({ jsonrpc: '2.0', id: message.id, result: {} });
      return;
    }
    this.write(this.manager.rpcError(message.id,
      this.manager.detail('SHARED_UNSUPPORTED_CALLBACK', 'callback', 'none', this.generation), -32601));
    this.stop('SHARED_UNSUPPORTED_CALLBACK', true);
  }

  childNotification(message) {
    if (message.method === 'notifications/progress') {
      const operation = this.progress.get(message.params?.progressToken);
      if (!operation ||
          operation.settled ||
          !operation.owner.active) return;
      const notification = { ...message, params: { ...message.params, progressToken: operation.token } };
      // The HTTP adapter uses this event to bind progress to the original POST, not GET SSE.
      if (operation.owner.listenerCount('sharedProgress') === 0) {
        this.detach(operation.owner, 'SHARED_PROGRESS_UNROUTABLE');
        return;
      }
      try {
        operation.owner.emit('sharedProgress', { requestId: operation.originalId, message: notification });
      } catch {
        this.detach(operation.owner, 'SHARED_PROGRESS_DELIVERY_FAILED');
      }
      return;
    }
    if (message.method === 'notifications/tools/list_changed' &&
        this.result?.capabilities.tools?.listChanged === true) {
      for (const owner of this.members) {
        if (owner.phase === 'ready') owner.send({ jsonrpc: '2.0', method: message.method });
      }
      return;
    }
    if (message.method === 'notifications/message') {
      this.manager.log(this.name, 'shared: unowned log notification dropped');
      return;
    }
    if (message.method === 'notifications/resources/list_changed' ||
        message.method === 'notifications/prompts/list_changed') {
      this.manager.log(this.name, `shared: unexposed catalog notification dropped: ${message.method}`);
      return;
    }
    this.stop('SHARED_UNSUPPORTED_NOTIFICATION', true);
  }

  detach(owner, kind) {
    if (!owner.active) return false;
    this.members.delete(owner);
    for (const operation of [...owner.queue]) {
      this.unqueue(operation);
      this.settle(operation, kind);
    }
    for (const operation of [...owner.pending.values()]) {
      if (operation.dispatched) {
        this.settle(operation, kind);
        this.cancel(operation);
      }
    }
    owner.finish(kind);
    this.pump();
    this.idle();
    return true;
  }

  idle() {
    clearTimeout(this.lingerTimer);
    if (this.state === 'draining' &&
        this.operations.size === 0) {
      this.stop(this.reason, this.failed);
      return;
    }
    if (this.state === 'ready' &&
        this.members.size === 0 &&
        this.waiters === 0 &&
        this.operations.size === 0) {
      this.lingerTimer = setTimeout(() => this.stop('SHARED_LINGER_EXPIRED', false), this.options.sharedLingerMs);
      this.lingerTimer.unref();
    }
  }

  drain(kind, failed = false) {
    if (this.state === 'stopping' ||
        this.state === 'dead' ||
        this.state === 'draining') return;
    if (this.state === 'starting') {
      this.stop(kind, failed);
      return;
    }
    this.state = 'draining';
    this.reason = kind;
    this.failed = failed;
    clearTimeout(this.lingerTimer);
    for (const owner of this.members) {
      for (const operation of [...owner.queue]) {
        this.unqueue(operation);
        this.settle(operation, 'SHARED_DRAINING');
      }
    }
    this.drainTimer = setTimeout(() => this.stop('SHARED_DRAIN_TIMEOUT', true),
      this.options.sharedDrainTimeoutMs);
    this.manager.emit('draining', { name: this.name, ...this.inspect(), reason: kind });
    this.idle();
  }

  report(kind) {
    if (this.state === 'dead') return;
    this.failed = true;
    if (this.reported) return;
    this.reported = true;
    const detail = this.manager.detail(kind, this.state, 'potentially-executed', this.generation);
    this.manager.onFailure(this.name, detail);
    this.manager.emit('failure', { name: this.name, ...detail });
  }

  stop(kind, failed) {
    if (this.state === 'dead' ||
        this.state === 'stopping') return;
    this.state = 'stopping';
    this.reason = kind;
    clearTimeout(this.initTimer);
    clearTimeout(this.lingerTimer);
    clearTimeout(this.drainTimer);
    this.lines.close();
    this.rejectReady(this.manager.error(kind, 'initialize', 'unsent', this.generation));
    for (const owner of this.members) {
      for (const operation of [...owner.queue]) {
        this.unqueue(operation);
        this.settle(operation, kind);
      }
    }
    for (const operation of this.operations.values()) {
      clearTimeout(operation.timer);
      this.settle(operation, kind);
    }
    this.operations.clear();
    this.progress.clear();
    for (const owner of this.members) owner.finish(kind);
    this.members.clear();
    if (failed) this.report(kind);
    this.kill();
  }

  kill() {
    if (!this.child ||
        this.killRequested ||
        this.state === 'dead') return;
    this.killRequested = true;
    if (this.child.exitCode != null ||
        this.child.signalCode != null) {
      this.dead();
      return;
    }
    this.stopTimer = setTimeout(() => this.report('SHARED_KILL_TIMEOUT'), this.options.sharedDrainTimeoutMs);
    this.stopTimer.unref();
    try {
      Promise.resolve(this.manager.kill(this.child)).catch(() => this.report('SHARED_KILL_FAILED'));
    } catch {
      this.report('SHARED_KILL_FAILED');
    }
  }

  exited() {
    if (this.state === 'dead') return;
    if (this.state !== 'stopping') this.stop('SHARED_CHILD_EXIT', true);
    this.dead();
  }

  dead() {
    if (this.state === 'dead') return;
    clearTimeout(this.stopTimer);
    this.state = 'dead';
    this.manager.retired(this);
  }
}
