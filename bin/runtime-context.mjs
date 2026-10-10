import { closeSync, openSync, readSync } from 'node:fs';
import { requireOrdinaryUpgradeCaller } from './windows-task-channel.mjs';

export class UserRuntimeContext {
  constructor({ host = process, linuxStatus, windowsCheck = requireOrdinaryUpgradeCaller } = {}) {
    this.host = host;
    this.linuxStatus = linuxStatus ?? (() => this.readLinuxStatus());
    this.windowsCheck = windowsCheck;
  }

  refuse(reason, code = 'USER_RUNTIME_CONTEXT_UNVERIFIED') {
    throw Object.assign(new Error(`User-runtime execution refused: ${reason}. No identity or privilege change was attempted.`),
      { code });
  }

  identity() {
    const value = {};
    for (const [name, method] of [['uid', 'getuid'], ['euid', 'geteuid'], ['gid', 'getgid'], ['egid', 'getegid']]) {
      if (typeof this.host[method] !== 'function') this.refuse('effective identity is unavailable');
      value[name] = this.host[method]();
      if (!Number.isSafeInteger(value[name]) ||
          value[name] < 0 ||
          value[name] > 0xffffffff) this.refuse('effective identity is invalid');
    }
    if (value.uid === 0 ||
        value.euid === 0) this.refuse("run this operation from the installation owner's non-root session", 'USER_RUNTIME_PRIVILEGED');
    if (value.uid !== value.euid ||
        value.gid !== value.egid) this.refuse('real and effective identities differ', 'USER_RUNTIME_PRIVILEGED');
    return value;
  }

  readLinuxStatus() {
    const buffer = Buffer.alloc(16385);
    const file = openSync('/proc/self/status', 'r');
    try {
      let length = 0;
      while (length < buffer.length) {
        const read = readSync(file, buffer, length, buffer.length - length, null);
        if (read === 0) break;
        length += read;
      }
      if (length > 16384) this.refuse('Linux process status exceeds its bound');
      return buffer.toString('utf8', 0, length);
    } finally { closeSync(file); }
  }

  capabilities(status, identity) {
    if (typeof status !== 'string' ||
        Buffer.byteLength(status) > 16384) this.refuse('Linux process status is invalid');
    const lines = status.split('\n');
    for (const [name, expected] of [['Uid', identity.uid], ['Gid', identity.gid]]) {
      const selected = lines.filter(line => line.startsWith(`${name}:`));
      if (selected.length !== 1) this.refuse(`Linux ${name} observation is unavailable`);
      const fields = selected[0].slice(name.length + 1).trim().split(/\s+/);
      if (fields.length !== 4 ||
          fields.some(field => !/^(0|[1-9][0-9]*)$/.test(field) || Number(field) !== expected)) {
        this.refuse(`Linux real, effective, saved or filesystem ${name} differs`, 'USER_RUNTIME_PRIVILEGED');
      }
    }
    const capabilities = {};
    for (const name of ['CapInh', 'CapPrm', 'CapEff', 'CapAmb']) {
      const selected = lines.filter(line => line.startsWith(`${name}:`));
      if (selected.length !== 1) this.refuse(`Linux ${name} observation is unavailable`);
      const value = selected[0].slice(name.length + 1).trim();
      if (!/^[0-9a-fA-F]{16}$/.test(value)) this.refuse(`Linux ${name} observation is invalid`);
      if (BigInt(`0x${value}`) !== 0n) this.refuse(`Linux ${name} contains privileges`, 'USER_RUNTIME_PRIVILEGED');
      capabilities[name] = value.toLowerCase();
    }
    return capabilities;
  }

  async require() {
    if (this.host.platform === 'win32') {
      const proof = await this.windowsCheck();
      if (proof?.ordinaryEligible !== true ||
          proof.proofScope !== 'cli-effective-context-snapshot') this.refuse('Windows caller proof is unavailable');
      return { platform: 'win32', proofScope: 'user-runtime-context-snapshot', ordinary: true,
        native: proof, atomicFutureProtection: false };
    }
    if (!['linux', 'darwin'].includes(this.host.platform)) this.refuse('this platform has no supported identity observer');
    const before = this.identity();
    let capabilities;
    if (this.host.platform === 'linux') {
      try { capabilities = this.capabilities(this.linuxStatus(), before); }
      catch (error) {
        if (error.code?.startsWith('USER_RUNTIME_')) throw error;
        throw Object.assign(new Error('User-runtime execution refused: Linux process status could not be read.', { cause: error }),
          { code: 'USER_RUNTIME_CONTEXT_UNVERIFIED' });
      }
    }
    const after = this.identity();
    if (Object.keys(before).some(name => before[name] !== after[name])) this.refuse('effective identity changed during observation');
    return { platform: this.host.platform, proofScope: 'user-runtime-context-snapshot', ordinary: true,
      identity: after, ...(capabilities ? { capabilities } : {}), atomicFutureProtection: false };
  }
}

export async function requireUserRuntimeContext() {
  return new UserRuntimeContext().require();
}
