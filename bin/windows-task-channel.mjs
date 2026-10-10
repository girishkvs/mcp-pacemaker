import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, lstatSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HELPER = fileURLToPath(new URL('./windows-task-channel/TaskChannelGuard.exe', import.meta.url));
const METADATA = fileURLToPath(new URL('./windows-task-channel/TaskChannelGuard.build.json', import.meta.url));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

class TaskChannel {
  constructor() {
    this.started = deferred();
    this.worker = deferred();
    this.completion = deferred();
    this.pending = new Map();
    this.frames = [];
    this.waiters = [];
    this.sequence = 0;
    this.buffer = '';
    this.failure = null;
    this.intentionalClose = false;
  }

  verifyHelper() {
    const metadataBytes = readFileSync(METADATA);
    if (!lstatSync(METADATA).isFile() ||
        lstatSync(METADATA).isSymbolicLink()) throw new Error('Invalid packaged task channel metadata path');
    if (metadataBytes.length > 65536) throw new Error('Task channel metadata exceeds bounds');
    const metadata = JSON.parse(metadataBytes);
    const digest = metadata.binarySha256;
    const valid = metadata.schemaVersion === 1 &&
      metadata.binary === 'TaskChannelGuard.exe' &&
      typeof digest === 'string' &&
      digest.length === 64 &&
      [...digest].every(character => '0123456789abcdef'.includes(character));
    if (!valid) throw new Error('Invalid packaged task channel digest');
    const stat = lstatSync(HELPER);
    if (!stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.size < 1 ||
        stat.size > 4 * 1024 * 1024 ||
        createHash('sha256').update(readFileSync(HELPER)).digest('hex') !== digest) {
      throw new Error('Packaged task channel helper identity mismatch');
    }
  }

  async start(request) {
    if (process.platform !== 'win32') throw new Error('Task channel requires Windows');
    this.verifyHelper();
    const bytes = this.encode(request, 65536);
    this.child = spawn(HELPER, [], {
      detached: true, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.stdout.setEncoding('utf8');
    this.child.stderr.setEncoding('utf8');
    this.child.on('error', error => this.fail(error));
    this.child.stdin.on('error', error => this.fail(error));
    this.child.stdout.on('error', error => this.fail(error));
    this.child.stderr.on('error', error => this.fail(error));
    let diagnosticBytes = 0;
    this.child.stderr.on('data', text => {
      diagnosticBytes += Buffer.byteLength(text);
      if (diagnosticBytes > 2048) this.fail(new Error('Unexpected task guard diagnostics'));
    });
    this.child.stdout.on('data', text => this.consume(text));
    this.child.on('close', (code, signal) => {
      clearTimeout(this.timer);
      const receipt = { code, signal,
        reason: this.failure?.message ?? this.closeReason ?? (code === 0 ? 'completed' : `native-exit-${code}`) };
      this.exited = true;
      this.exitReceipt = receipt;
      this.fail(this.failure ?? new Error(`Task channel closed (native exit ${code})`));
      this.completion.resolve(receipt);
    });
    this.timer = setTimeout(() => this.fail(new Error('Task channel ready deadline exceeded')), 15000);
    this.child.stdin.write(bytes);
    try {
      const ready = await this.started.promise;
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.fail(new Error('Task channel lifetime exceeded')),
        (request.lifetimeMs ?? 60000) + 3000);
      return ready;
    } catch (error) {
      error.guardIdentity ??= structuredClone(this.guardIdentity);
      try {
        error.helperExit = await this.close();
        error.cleanupUnverified = false;
      } catch (closeError) {
        error.cleanupUnverified = true;
        error.cleanupError = closeError.message;
        error.message += `; ${closeError.message}`;
      }
      throw error;
    }
  }

  encode(value, maximum = 16384) {
    if (!value ||
        typeof value !== 'object' ||
        Array.isArray(value)) throw new Error('Task channel requires an object frame');
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
    if (bytes.length > maximum) throw new Error('Task channel frame exceeds bounds');
    return bytes;
  }

  consume(text) {
    this.buffer += text;
    if (Buffer.byteLength(this.buffer) > 131072) return this.fail(new Error('Task channel output exceeds bounds'));
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      try { this.event(JSON.parse(line)); }
      catch (error) { this.fail(error); return; }
    }
  }

  event(message) {
    if (!message ||
        typeof message.type !== 'string') throw new Error('Invalid task channel event');
    if (message.type === 'started') {
      const identity = message.guardIdentity;
      if (this.guardIdentity ||
          identity?.pid !== this.child.pid ||
          typeof identity.creationTime !== 'string') throw new Error('Invalid task guard startup identity');
      this.guardIdentity = structuredClone(identity);
    } else if (message.type === 'failed') {
      const error = new Error(`Task channel refused: ${message.reason}`);
      error.code = message.reason;
      error.guardIdentity = message.guardIdentity;
      error.detail = message;
      this.fail(error);
    } else if (message.type === 'ready' ||
        message.type === 'result') {
      if (this.ready) throw new Error('Duplicate task channel readiness');
      if (message.guardIdentity?.pid !== this.child.pid) throw new Error('Task guard process binding mismatch');
      this.ready = message;
      this.started.resolve(structuredClone(message));
    } else if (message.type === 'worker') {
      if (!this.ready ||
          this.peer) throw new Error('Unexpected task channel peer');
      this.peer = structuredClone(message.peer);
      this.workerSession = structuredClone(message.targetSession);
      this.worker.resolve(structuredClone(this.peer));
    } else if (message.type === 'frame') {
      if (!this.peer ||
          JSON.stringify(message.peer) !== JSON.stringify(this.peer)) throw new Error('Task channel peer changed');
      const received = { peer: structuredClone(this.peer), frame: message.frame };
      if (this.waiters.length) this.waiters.shift().resolve(received);
      else {
        if (this.frames.length >= 32) throw new Error('Task channel receive queue exceeds bounds');
        this.frames.push(received);
      }
    } else if (message.type === 'sent' ||
        message.type === 'authorized') {
      const pending = this.pending.get(message.id);
      if (!pending) throw new Error('Unexpected task channel acknowledgement');
      this.pending.delete(message.id);
      pending.resolve(structuredClone(message));
    } else if (message.type === 'closed') {
      this.closeReason = message.reason;
    } else throw new Error('Unknown task channel event');
  }

  fail(error) {
    this.failure ??= error;
    this.failure.guardIdentity ??= structuredClone(this.guardIdentity);
    this.started.reject(this.failure);
    this.worker.reject(this.failure);
    for (const pending of this.pending.values()) pending.reject(this.failure);
    this.pending.clear();
    for (const waiter of this.waiters) waiter.reject(this.failure);
    this.waiters = [];
    this.frames = [];
    if (this.child?.stdin.writable) this.child.stdin.end();
  }

  request(action, frame) {
    if (this.failure) return Promise.reject(this.failure);
    if (!this.peer &&
        action !== 'authorize') return Promise.reject(new Error('Task channel peer is not verified'));
    if (this.pending.size >= 32) return Promise.reject(new Error('Task channel command queue exceeds bounds'));
    if (frame !== undefined) this.encode(frame);
    const id = ++this.sequence;
    const pending = deferred();
    this.pending.set(id, pending);
    this.child.stdin.write(this.encode({ action, id, ...(frame === undefined ? {} : { frame }) }, 65536));
    return pending.promise;
  }

  receive() {
    if (this.failure) return Promise.reject(this.failure);
    if (this.frames.length) return Promise.resolve(this.frames.shift());
    if (this.waiters.length >= 32) return Promise.reject(new Error('Task channel waiter queue exceeds bounds'));
    const pending = deferred();
    this.waiters.push(pending);
    return pending.promise;
  }

  async close() {
    if (!this.child) return;
    if (!this.exited &&
        !this.intentionalClose) {
      this.intentionalClose = true;
      if (this.child.stdin.writable) this.child.stdin.write('{"action":"close"}\n');
    }
    let timer;
    try {
      return await Promise.race([this.completion.promise, new Promise((_, reject) => {
        timer = setTimeout(() => {
          if (this.child.stdin.writable) this.child.stdin.end();
          const error = new Error('Task guard exit unverified; retain owned cleanup evidence');
          error.guardIdentity = structuredClone(this.guardIdentity);
          error.cleanupUnverified = true;
          reject(error);
        }, 5000);
      })]);
    } finally { clearTimeout(timer); }
  }
}

export async function createTaskChannel(options) {
  const channel = new TaskChannel();
  const { operationId, targetSid, sessionId, bootstrap, manifestParent, manifest,
    expectedCreationTime, handshakeTimeoutMs = 30000, lifetimeMs = 900000 } = options;
  const ready = await channel.start({
    action: 'serve', operationId, targetSid, sessionId, bootstrap, manifestParent,
    document: manifest, expectedCreationTime, handshakeTimeoutMs, lifetimeMs,
  });
  return {
    ...ready,
    pid: channel.child.pid,
    awaitWorker: () => channel.worker.promise,
    get workerSession() { return structuredClone(channel.workerSession); },
    send: frame => channel.request('send', frame),
    authorize: () => channel.request('authorize'),
    receive: () => channel.receive(),
    closed: channel.completion.promise,
    close: () => channel.close(),
  };
}

async function query(request) {
  const channel = new TaskChannel();
  const result = await channel.start(request);
  const exit = await channel.completion.promise;
  if (exit.code !== 0 ||
      exit.signal !== null) throw new Error(`Task channel query failed: ${exit.reason}`);
  return { ...result, helperExit: exit };
}

export function queryTaskChannelCaller() {
  return query({ action: 'caller' });
}

export async function queryCliCallerContext() {
  const result = await query({ action: 'cli-context' });
  if (result.proofScope !== 'cli-effective-context-snapshot' ||
      result.identity?.pid !== process.pid ||
      typeof result.ordinaryEligible !== 'boolean') {
    throw new Error('CLI context caller binding or proof scope is unverified');
  }
  return result;
}

export async function requireOrdinaryUpgradeCaller() {
  if (process.platform !== 'win32') return;
  const caller = await queryCliCallerContext();
  const facts = caller.actorFacts;
  const observation = caller.observation;
  const ordinary = caller.ordinaryEligible === true &&
    facts?.ownerSid === caller.identity.ownerSid &&
    facts?.sessionId === caller.identity.sessionId &&
    facts?.elevated === false &&
    facts?.enabledAdministrator === false &&
    facts?.guardThreadImpersonating === false &&
    facts?.parentThreadImpersonation === 'observed-none' &&
    observation?.method === 'pss-threads-held-token-query' &&
    observation?.processAccess === '0x101400' &&
    observation?.captureFlags === '0x80' &&
    observation?.threadContextFlags === 0 &&
    observation?.completeStableThreadSet === true &&
    observation?.primaryStable === true &&
    observation?.atomicFutureProtection === false &&
    Number.isInteger(observation?.threadCount) &&
    observation.threadCount > 0 &&
    observation.threadCount <= 128 &&
    caller.helperExit?.code === 0 &&
    caller.helperExit?.signal === null;
  if (!ordinary) {
    throw new Error('Windows upgrade execution requires a verified ordinary caller; no elevation or runtime-authority fallback was attempted.');
  }
}

export function readProtectedManifest(path, { operationId, manifestParent }) {
  return query({ action: 'read-manifest', path, operationId, manifestParent });
}

export function inspectTrustedCodeRoot(root) {
  return query({ action: 'inspect-root', root });
}
