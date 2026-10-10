import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';

const domain = 'mcp-pacemaker/task-only-controller/v1';
const verbs = new Set(['HELLO', 'PLAN', 'INSPECT', 'HOLD', 'REPOINT', 'RESTORE', 'ENABLE', 'RECORDS', 'DONE', 'FAILED']);
export const accountRecoveryTerminalPhases = Object.freeze(['committed', 'rolled-back', 'aborted', 'legacy-rolled-back', 'legacy-aborted']);
const exact = (value, keys) => value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export function canonicalJson(value, depth = 0) {
  if (depth > 16) throw new Error('Protocol nesting exceeds its bound.');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    if (value.length > 16384) throw new Error('Protocol string exceeds its bound.');
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) {
    if (value.length > 128) throw new Error('Protocol array exceeds its bound.');
    return `[${value.map(item => canonicalJson(item, depth + 1)).join(',')}]`;
  }
  if (!value ||
      typeof value !== 'object' ||
      Object.getPrototypeOf(value) !== Object.prototype) throw new Error('Unsupported protocol value.');
  const keys = Object.keys(value).sort();
  if (keys.length > 128 ||
      keys.some(key => ['__proto__', 'constructor', 'prototype'].includes(key))) throw new Error('Invalid protocol keys.');
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(',')}}`;
}

export function operationDigest(value) {
  return createHash('sha256').update(`${domain}/operation\0${canonicalJson(value)}`).digest('hex');
}

export function taskRevision(record) {
  const value = { ...record };
  delete value.currentUserSid;
  return operationDigest(value);
}

export function accountOperationReference(binding) {
  return { manifestPath: binding.manifestPath, operationId: binding.operationId,
    taskPath: binding.taskPath, targetSid: binding.targetSid };
}

export function canonicalSid(value) {
  if (typeof value !== 'string' ||
      value.length > 184 ||
      !value.startsWith('S-1-')) throw new Error('A canonical numeric Windows SID is required.');
  const parts = value.slice(4).split('-');
  if (parts.length < 2 ||
      parts.length > 16 ||
      parts.some(part => !part ||
        part.length > 15 ||
        (part.length > 1 && part[0] === '0') ||
        [...part].some(character => character < '0' || character > '9'))) throw new Error('A canonical numeric Windows SID is required.');
  return value;
}

export function validateTaskRequest(value, operationId, sequence, stateDigest) {
  if (!exact(value, ['protocol', 'operationId', 'sequence', 'stateDigest', 'verb', 'body']) ||
      value.protocol !== 1 ||
      value.operationId !== operationId ||
      value.sequence !== sequence ||
      value.stateDigest !== stateDigest ||
      !verbs.has(value.verb) ||
      Buffer.byteLength(canonicalJson(value)) > 16384) throw new Error('Invalid, stale or out-of-order task request.');
  if (['INSPECT', 'HOLD', 'REPOINT', 'RESTORE', 'ENABLE', 'RECORDS'].includes(value.verb) &&
      value.body !== null) throw new Error('Task requests cannot select a path, principal or definition.');
  if (value.verb === 'HELLO' &&
      (!exact(value.body, ['challenge', 'identity']) ||
        typeof value.body.challenge !== 'string' ||
        !/^[a-f0-9]{64}$/.test(value.body.challenge))) throw new Error('Invalid worker challenge.');
  if (value.verb === 'PLAN' &&
      (!exact(value.body, ['digest', 'summary']) ||
        !/^[a-f0-9]{64}$/.test(value.body.digest) ||
        typeof value.body.summary !== 'string' ||
        value.body.summary.length > 4096)) throw new Error('Invalid worker plan.');
  if (value.verb === 'DONE' &&
      !exact(value.body, ['status', 'directory', 'port', 'version'])) throw new Error('Invalid worker completion.');
  if (value.verb === 'FAILED' &&
      (!exact(value.body, ['message']) || typeof value.body.message !== 'string' || value.body.message.length > 512)) {
    throw new Error('Invalid worker failure.');
  }
  return value;
}

export function peerBinding(identity) {
  if (!identity ||
      !Number.isSafeInteger(identity.pid) ||
      identity.pid < 1 ||
      typeof identity.creationTime !== 'string' ||
      !/^[1-9][0-9]{0,19}$/.test(identity.creationTime) ||
      !Number.isSafeInteger(identity.sessionId) ||
      identity.sessionId < 1) throw new Error('Incomplete observed worker identity.');
  return { pid: identity.pid, creationTime: identity.creationTime,
    ownerSid: canonicalSid(identity.ownerSid), sessionId: identity.sessionId };
}

export function verifyTargetSession(value, expected) {
  if (!value ||
      value.source !== 'wts-account-sid-snapshot' ||
      value.atomicRunExBinding !== false ||
      !['active', 'disconnected'].includes(value.state) ||
      value.ownerSid !== expected.ownerSid ||
      value.sessionId !== expected.sessionId ||
      typeof value.logonTime !== 'string' ||
      !/^[1-9][0-9]{0,19}$/.test(value.logonTime) ||
      (expected.logonTime !== undefined && value.logonTime !== expected.logonTime) ||
      typeof value.observedAt !== 'string' ||
      !Number.isFinite(Date.parse(value.observedAt))) {
    throw new Error('Original-account session eligibility is missing, stale or changed; no atomic desktop reservation is claimed.');
  }
  return value;
}

export class ControllerSignatures {
  constructor() {
    const keys = generateKeyPairSync('ed25519');
    this.key = keys.privateKey;
    this.publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  }

  response({ operationId, digest, challenge, peer, targetSession, sequence, request, stateDigest, body }) {
    const value = { protocol: 1, operationId, digest, challenge, peer: peerBinding(peer),
      targetSession, sequence, requestDigest: operationDigest(request), stateDigest, body };
    const bytes = Buffer.from(`${domain}/response\0${canonicalJson(value)}`);
    return { ...value, signature: sign(null, bytes, this.key).toString('base64') };
  }
}

export class WorkerSignatures {
  constructor({ publicKey, operationId, digest, identity, targetSession }) {
    this.key = createPublicKey({ key: Buffer.from(publicKey, 'base64'), type: 'spki', format: 'der' });
    if (this.key.asymmetricKeyType !== 'ed25519') throw new Error('Unsupported controller signature key.');
    this.operationId = operationId;
    this.digest = digest;
    this.identity = peerBinding(identity);
    this.targetSession = verifyTargetSession(targetSession, this.identity);
    this.challenge = randomBytes(32).toString('hex');
    this.sequence = 0;
    this.stateDigest = digest;
  }

  request(verb, body = null) {
    return { protocol: 1, operationId: this.operationId, sequence: this.sequence,
      stateDigest: this.stateDigest, verb, body };
  }

  accept(response, request) {
    if (!exact(response, ['protocol', 'operationId', 'digest', 'challenge', 'peer', 'targetSession', 'sequence',
      'requestDigest', 'stateDigest', 'body', 'signature'])) throw new Error('Malformed controller response.');
    const { signature, ...value } = response;
    if (value.protocol !== 1 ||
        value.operationId !== this.operationId ||
        value.digest !== this.digest ||
        value.challenge !== this.challenge ||
        value.sequence !== this.sequence ||
        value.requestDigest !== operationDigest(request) ||
        canonicalJson(value.peer) !== canonicalJson(this.identity) ||
        !/^[a-f0-9]{64}$/.test(value.stateDigest) ||
        typeof signature !== 'string' ||
        signature.length !== 88 ||
        !verify(null, Buffer.from(`${domain}/response\0${canonicalJson(value)}`), this.key, Buffer.from(signature, 'base64'))) {
      throw new Error('Controller authentication or transcript binding failed.');
    }
    verifyTargetSession(value.targetSession, this.targetSession);
    this.sequence++;
    this.stateDigest = value.stateDigest;
    return value.body;
  }
}
