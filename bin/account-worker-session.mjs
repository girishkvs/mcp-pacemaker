import { connect } from 'node:net';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { closeSync, openSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { accountOperationReference, operationDigest, taskRevision, WorkerSignatures } from './task-transaction-protocol.mjs';
import { minimalTaskRecord } from './task-only-controller.mjs';
import { durableJson, readManagedJson } from './managed-state.mjs';
import { fileURLToPath } from 'node:url';

export class AccountWorkerSession {
  constructor(publicManifest, identity) {
    this.manifest = publicManifest;
    this.binding = publicManifest.document.binding;
    if (this.binding.operationId !== publicManifest.operationId ||
        this.binding.targetSid !== identity.ownerSid ||
        this.binding.sessionId !== identity.sessionId ||
        publicManifest.targetSid !== identity.ownerSid ||
        publicManifest.sessionId !== identity.sessionId ||
        operationDigest(this.binding) !== publicManifest.document.digest) throw new Error('Protected operation scope does not match the actual worker.');
    this.signatures = new WorkerSignatures({
      publicKey: publicManifest.document.publicKey, operationId: publicManifest.operationId,
      digest: publicManifest.document.digest, identity, targetSession: publicManifest.targetSession,
    });
    this.queue = [];
    this.waiters = [];
    this.holdKind = 'automatic-triggers';
    this.destination = this.binding.destination;
    this.allowed = new Set(publicManifest.document.authorizedTaskRevisions ?? []);
  }

  async open() {
    this.socket = connect(this.manifest.endpoint);
    this.socket.setEncoding('utf8');
    let pending = '';
    const fail = error => {
      this.failure = error;
      for (const waiter of this.waiters.splice(0)) waiter.reject(error);
    };
    this.socket.on('error', fail);
    this.socket.on('close', () => fail(new Error('Controller channel closed; no reconnect or privileged fallback.')));
    this.socket.on('data', chunk => {
      pending += chunk;
      if (Buffer.byteLength(pending) > 16384) { this.socket.destroy(new Error('Oversized controller response.')); return; }
      const newline = pending.indexOf('\n');
      if (newline < 0) return;
      const text = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      try {
        const response = JSON.parse(text);
        const waiter = this.waiters.shift();
        if (waiter) waiter.resolve(response);
        else this.queue.push(response);
        if (this.queue.length > 1 || pending.length) this.socket.destroy(new Error('Unsolicited controller frames.'));
      } catch (error) { this.socket.destroy(error); }
    });
    await new Promise((resolveConnected, reject) => {
      this.socket.once('connect', resolveConnected);
      this.socket.once('error', reject);
    });
    const hello = await this.call('HELLO', { challenge: this.signatures.challenge, identity: this.signatures.identity });
    this.original = hello.original;
    this.logical = this.original;
    this.allowed.add(taskRevision(this.original));
    return this;
  }

  async call(verb, body = null) {
    if (this.failure) throw this.failure;
    if (this.busy) throw new Error('Only one original-account task request may be outstanding.');
    this.busy = true;
    let timer;
    try {
      const request = this.signatures.request(verb, body);
      const response = new Promise((resolveResponse, reject) => {
        timer = setTimeout(() => reject(new Error('Controller response timed out; task outcome is uncertain.')), verb === 'PLAN' ? 300000 : 30000);
        if (this.queue.length) resolveResponse(this.queue.shift());
        else this.waiters.push({ resolve: resolveResponse, reject });
      });
      this.socket.write(`${JSON.stringify(request)}\n`);
      return this.signatures.accept(await response, request);
    } catch (error) {
      this.failure = error;
      this.socket.destroy();
      throw error;
    } finally { clearTimeout(timer); this.busy = false; }
  }

  async inspectLegacySource() {
    await this.call('INSPECT');
    return [this.original];
  }

  async verifyBinding(instance, expected) {
    if (instance.port !== this.binding.port ||
        instance.config !== this.binding.config ||
        !this.allowed.has(taskRevision(expected))) throw new Error('Worker task binding is outside the protected operation.');
    await this.call('INSPECT');
    return expected;
  }

  async taskCall(verb, expected) {
    if (!this.allowed.has(taskRevision(expected))) throw new Error('Unknown worker task revision.');
    const result = await this.call(verb);
    this.logical = result.record;
    this.allowed.add(taskRevision(result.record));
    return result.record;
  }

  async hold(port, expected) {
    if (port !== this.binding.port) throw new Error('Task hold is outside the original account port.');
    const path = join(this.binding.destination, 'instance.json');
    const instance = readManagedJson(path);
    if (instance.config !== this.binding.config ||
        instance.port !== port) throw new Error('Worker instance differs from its protected operation.');
    const reference = accountOperationReference(this.binding);
    if (!isDeepStrictEqual(instance.controllerOperation, reference)) {
      if ((this.binding.kind === 'legacy' && !this.binding.recover) ||
          !isDeepStrictEqual(instance.controllerOperation ?? null, this.binding.previousControllerOperation ?? null)) {
        throw new Error('Published controller operation is missing or changed; no task hold was requested.');
      }
      durableJson(path, { ...instance, controllerOperation: reference });
    }
    return this.taskCall('HOLD', expected);
  }
  repoint(port, expected, launcher) {
    if (launcher !== this.binding.launcher) throw new Error('Worker cannot choose the elevated task launcher.');
    return this.taskCall('REPOINT', expected);
  }
  enable(port, expected) { return this.taskCall('ENABLE', expected); }
  restore(port, expected, original) {
    if (taskRevision(original) !== taskRevision(this.original)) throw new Error('Worker cannot supply a replacement task definition.');
    return this.taskCall('RESTORE', expected);
  }
  async stableRecords() { return (await this.call('RECORDS')).records; }

  async start(port, expected) {
    if (port !== this.binding.port ||
        taskRevision(expected) !== taskRevision(this.original)) throw new Error('Rollback is outside the original-account binding.');
    const image = this.binding.legacySupervisorImage;
    if (!image ||
        createHash('sha256').update(readFileSync(image.path)).digest('hex') !== image.sha256) throw new Error('Original supervisor image changed before rollback.');
    const log = openSync(join(this.binding.destination, 'rollback-launcher.log'), 'a', 0o600);
    let child;
    try {
      child = spawn(image.path, [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
        '-File', join(this.binding.root, 'supervisor', 'supervise.ps1'), '-Port', String(port),
      ], { cwd: dirname(this.binding.config), env: { ...process.env }, windowsHide: true,
        stdio: ['ignore', log, log] });
    } finally { closeSync(log); }
    await new Promise((resolveStart, reject) => {
      child.once('spawn', resolveStart);
      child.once('error', reject);
    });
    child.once('exit', (code, signal) => {
      durableJson(join(this.binding.destination, 'rollback-launch-exit.json'), { pid: child.pid, code, signal, imagePath: image.path });
    });
    child.unref();
  }

  verifyProcessSessions(plan) {
    if (plan.ownerSid !== this.binding.targetSid ||
        plan.root !== this.binding.root ||
        plan.port !== this.binding.port) throw new Error('Legacy process scope differs from the protected operation.');
    const identities = [plan.roots.supervisor, plan.roots.bridge, ...plan.observed]
      .map(({ pid, creationTime, ownerSid }) => ({ pid, creationTime, ownerSid }));
    if (identities.length < 2 ||
        identities.length > 512 ||
        new Set(identities.map(identity => identity.pid)).size !== identities.length) {
      throw new Error('Unsupported captured identity count or duplicate process.');
    }
    for (const identity of identities) {
      if (!Number.isInteger(identity.pid) ||
          identity.pid <= 0 ||
          identity.pid > 2147483647 ||
          identity.ownerSid !== this.binding.targetSid ||
          typeof identity.creationTime !== 'string' ||
          !/^[1-9][0-9]{0,18}$/.test(identity.creationTime)) {
        throw new Error('Invalid captured original-user identity.');
      }
    }
    this.queryProcessSessions({ identities });
  }

  verifyManagedProcessSession() {
    this.queryProcessSessions({ port: this.binding.port });
  }

  queryProcessSessions(selection) {
    const image = this.binding.processQueryImage;
    if (!image ||
        createHash('sha256').update(readFileSync(image.path)).digest('hex') !== image.sha256) throw new Error('Original-user query host changed.');
    const input = JSON.stringify({ ownerSid: this.binding.targetSid, sessionId: this.binding.sessionId, ...selection });
    if (Buffer.byteLength(input, 'utf8') > 131072) throw new Error('Worker identity request exceeds its bound.');
    const output = execFileSync(image.path, ['-NoProfile', '-NonInteractive', '-File',
      fileURLToPath(new URL('../autostart/windows/inspect-worker-process-sessions.ps1', import.meta.url)),
    ], {
      input,
      encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 16384,
    });
    if (JSON.parse(output).verified !== true) throw new Error('Original-user process session inspection did not verify.');
  }

  async inspectAutostart(instance) {
    if (instance.directory !== this.binding.destination ||
        instance.autostart.kind !== 'stable' ||
        !isDeepStrictEqual(instance.autostart.records, [minimalTaskRecord(this.original)])) throw new Error('Managed autostart does not match the selected original registration.');
    await this.call('INSPECT');
    return { kind: 'stable', launcher: this.binding.launcher };
  }

  close() { this.socket?.end(); }
}
