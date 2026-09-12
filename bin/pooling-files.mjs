import fs from 'node:fs';
import childProcess from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, extname, basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PoolingConfigError, poolingIOError, poolingConflict, recoveryError } from './pooling-errors.mjs';
import { JsonSpans } from './pooling-editor.mjs';

export const MAX_CONFIG_BYTES = 1024 * 1024;
export const MAX_TRANSACTION_BYTES = 16384;
const HELPER = fileURLToPath(new URL('./windows/PoolingSecurityHelper.exe', import.meta.url));
const HEX = '0123456789abcdef';

export function hashBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function hex(value, length) {
  return typeof value === 'string' &&
    value.length === length &&
    [...value].every((character) => HEX.includes(character));
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function validDescriptor(value) {
  if (!exactKeys(value, ['identity', 'revision', 'security', 'size']) ||
      !hex(value.revision, 64) ||
      !hex(value.security, 64) ||
      !Number.isSafeInteger(value.size) ||
      value.size < 0 ||
      value.size > MAX_CONFIG_BYTES ||
      typeof value.identity !== 'string') return false;
  const parts = value.identity.split(':');
  return parts.length === 2 &&
    parts.every((part) => part.length > 0 &&
      part.length <= 32 &&
      [...part].every((character) => HEX.includes(character)));
}

function expected(descriptor) {
  return { identity: descriptor.identity, revision: descriptor.revision, security: descriptor.security };
}

function same(a, b) {
  return Boolean(a && b &&
    a.identity === b.identity &&
    a.revision === b.revision &&
    a.security === b.security &&
    a.size === b.size);
}

function exists(path) {
  try {
    fs.lstatSync(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function boundedRead(path, limit, links = 1) {
  let fd;
  try {
    const before = fs.lstatSync(path, { bigint: true });
    if (!before.isFile() ||
        before.isSymbolicLink() ||
        before.nlink < 1n ||
        before.nlink > BigInt(links) ||
        before.size > BigInt(limit)) {
      throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Config must be a regular, bounded file without links.');
    }
    fd = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(fd, { bigint: true });
    if (before.dev !== stat.dev ||
        before.ino !== stat.ino ||
        before.size !== stat.size) throw poolingConflict();
    const buffer = Buffer.alloc(limit + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = fs.readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > limit) {
      throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Config exceeds its size limit.');
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (after.size !== stat.size ||
        after.mtimeNs !== stat.mtimeNs ||
        after.ctimeNs !== stat.ctimeNs) throw poolingConflict();
    return { bytes: buffer.subarray(0, size), stat };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function readPoolingBytes(path) {
  try {
    const result = boundedRead(path, MAX_CONFIG_BYTES);
    return { ...result, revision: hashBytes(result.bytes) };
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new PoolingConfigError(404, 'CONFIG_NOT_FOUND', 'Config file does not exist.');
    }
    throw poolingIOError(error);
  }
}

// The two data placements are not atomic. POSIX link+unlink provides exclusive
// destination creation and retains the inode. Recovery accounts for either
// intermediate two-link state. Directory fsync is used on POSIX; Windows uses
// the helper's file flushes, not a power-loss guarantee for directory entries.
export class PoolingFiles {
  constructor(configPath) {
    this.active = resolve(configPath);
    const extension = extname(this.active);
    const stem = basename(this.active, extension);
    const directory = dirname(this.active);
    this.paths = {
      pending: join(directory, `${stem}.pending${extension}`),
      next: join(directory, `${stem}.pending-next${extension}`),
      old: join(directory, `${stem}.pending-old${extension}`),
      previous: join(directory, `${stem}.previous${extension}`),
    };
    this.directory = `${this.active}.pooling-transaction`;
    this.lock = join(this.directory, 'owner');
    this.record = null;
    this.records = [];
    this.owner = null;
    this.poisoned = false;
  }

  syncDirectory(path = dirname(this.active)) {
    if (process.platform === 'win32') return;
    const fd = fs.openSync(path, 'r');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }

  helper(action, source, destination, body, execution) {
    execution?.check();
    const result = childProcess.spawnSync(HELPER, [action], {
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
      encoding: 'utf8',
      input: body === undefined ? undefined : JSON.stringify(body),
      maxBuffer: 16384,
      timeout: Math.min(10000, execution?.remainingMs() ?? 10000),
      env: { ...process.env, MCP_POOL_SOURCE: source, MCP_POOL_TEMP: destination ?? '' },
    });
    // The caller must inspect disk state after a late/failed move. Do not turn
    // an entered commit into a supposedly cancelled operation here.
    if (result.status === 3) throw poolingConflict();
    if (result.error ||
        result.status !== 0) {
      execution?.check();
      const lines = String(result.stderr ?? '').split('\n').map((line) => line.trim());
      if (lines.includes('MCPERR nativeError=5')) {
        throw new PoolingConfigError(403, 'ACCESS_DENIED', 'Config source write access or security preservation was refused.');
      }
      if (lines.includes('MCPERR nativeError=32')) {
        throw new PoolingConfigError(409, 'FILE_BUSY', 'A config transaction file is in use.');
      }
      throw new PoolingConfigError(500, 'IO_ERROR', 'Unable to inspect, stage, or move a config transaction file.');
    }
    let descriptor;
    try { descriptor = JSON.parse(result.stdout); } catch { throw poolingIOError(); }
    if (!validDescriptor(descriptor)) throw poolingIOError();
    return descriptor;
  }

  inspect(path, execution, links = 1) {
    execution?.check();
    if (process.platform === 'win32') return this.helper('inspect-access', path, undefined, undefined, execution);
    const { bytes, stat } = boundedRead(path, MAX_CONFIG_BYTES, links);
    return {
      identity: `${stat.dev.toString(16)}:${stat.ino.toString(16)}`,
      revision: hashBytes(bytes),
      security: hashBytes(Buffer.from(`${stat.mode}:${stat.uid}:${stat.gid}`)),
      size: bytes.length,
    };
  }

  verify(path, descriptor, execution, links = 1) {
    if (!same(this.inspect(path, execution, links), descriptor)) throw poolingConflict();
  }

  stage(path, source, descriptor, bytes, execution) {
    execution?.check();
    if (process.platform === 'win32') {
      return this.helper('stage', source, path,
        { expected: expected(descriptor), bytes: bytes.toString('base64') }, execution);
    }
    this.verify(source, descriptor, execution);
    let input;
    let output;
    try {
      input = fs.openSync(source, fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW ?? 0));
      const stat = fs.fstatSync(input, { bigint: true });
      if ((stat.mode & 0o222n) === 0n) {
        throw new PoolingConfigError(403, 'ACCESS_DENIED', 'Config source write access was refused.');
      }
      const identity = `${stat.dev.toString(16)}:${stat.ino.toString(16)}`;
      if (identity !== descriptor.identity) throw poolingConflict();
      // 0600 prevents inherited POSIX ACL grants from exposing bytes. Owner,
      // group and mode are set before writing. Extended ACL/label cloning is
      // not provided by Node; copies never gain source-external mode grants.
      output = fs.openSync(path, 'wx', 0o600);
      const created = fs.fstatSync(output, { bigint: true });
      if (created.uid !== stat.uid ||
          created.gid !== stat.gid) fs.fchownSync(output, Number(stat.uid), Number(stat.gid));
      // Keep private copies private rather than widening an inherited ACL mask.
      fs.fchmodSync(output, Number(stat.mode & 0o600n));
      this.verify(source, descriptor, execution);
      execution?.check();
      fs.writeFileSync(output, bytes);
      fs.fsyncSync(output);
    } finally {
      if (output !== undefined) fs.closeSync(output);
      if (input !== undefined) fs.closeSync(input);
    }
    this.syncDirectory();
    const staged = this.inspect(path, execution);
    if (staged.revision !== hashBytes(bytes)) throw poolingConflict();
    this.verify(source, descriptor, execution);
    return staged;
  }

  move(source, destination, descriptor, execution) {
    execution?.check();
    if (process.platform === 'win32') {
      const moved = this.helper('move-no-replace', source, destination,
        { expected: expected(descriptor) }, execution);
      if (!same(moved, descriptor)) throw poolingConflict();
      return;
    }
    this.verify(source, descriptor, execution);
    fs.linkSync(source, destination);
    this.syncDirectory();
    this.verify(source, descriptor, execution, 2);
    this.verify(destination, descriptor, execution, 2);
    fs.unlinkSync(source);
    this.syncDirectory();
    this.verify(destination, descriptor, execution);
  }

  remove(path, descriptor, links = 1, execution) {
    this.verify(path, descriptor, execution, links);
    fs.unlinkSync(path);
    this.syncDirectory();
  }

  writeMetadata(path, value) {
    const bytes = Buffer.from(JSON.stringify(value));
    if (bytes.length > MAX_TRANSACTION_BYTES) throw recoveryError();
    const fd = fs.openSync(path, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, bytes);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    this.syncDirectory(dirname(path));
    return this.metadata(path);
  }

  metadata(path) {
    const { bytes, stat } = boundedRead(path, MAX_TRANSACTION_BYTES);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch { throw recoveryError(); }
    // Records have one canonical encoding; this also rejects duplicate keys,
    // malformed UTF-8 and trailing data without a second permissive parser.
    if (!Buffer.from(JSON.stringify(value)).equals(bytes)) throw recoveryError();
    return { value, hash: hashBytes(bytes), identity: `${stat.dev}:${stat.ino}`, path };
  }

  removeMetadata(record) {
    const current = this.metadata(record.path);
    if (current.hash !== record.hash ||
        current.identity !== record.identity) throw recoveryError();
    fs.unlinkSync(record.path);
    this.syncDirectory(dirname(record.path));
  }

  validateOwner(record) {
    const value = record.value;
    if (!exactKeys(value, ['version', 'pid', 'id']) ||
        value.version !== 1 ||
        !Number.isSafeInteger(value.pid) ||
        value.pid <= 0 ||
        typeof value.id !== 'string' ||
        value.id.length !== 36) throw recoveryError();
  }

  acquire() {
    if (this.owner) {
      const current = this.metadata(join(this.lock, 'process.json'));
      if (current.hash !== this.owner.hash ||
          current.identity !== this.owner.identity) throw recoveryError();
      if (this.poisoned) throw recoveryError();
      return;
    }
    if (!exists(this.directory)) {
      try {
        fs.mkdirSync(this.directory, { mode: 0o700 });
        this.syncDirectory();
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    const stat = fs.lstatSync(this.directory);
    if (!stat.isDirectory() ||
        stat.isSymbolicLink()) throw recoveryError();
    let acquired = false;
    try {
      fs.mkdirSync(this.lock, { mode: 0o700 });
      acquired = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    if (!acquired) {
      const ownerStat = fs.lstatSync(this.lock);
      if (!ownerStat.isDirectory() ||
          ownerStat.isSymbolicLink()) throw recoveryError();
      const owner = this.metadata(join(this.lock, 'process.json'));
      this.validateOwner(owner);
      try {
        process.kill(owner.value.pid, 0);
        throw new PoolingConfigError(409, 'STORE_BUSY', 'Another config transaction owner is still running.');
      } catch (error) {
        if (error.code !== 'ESRCH') throw error;
      }
      // Exclusive takeover gate: all normal entrants refuse an existing owner.
      // A death inside takeover leaves a closed gate and requires inspection,
      // rather than allowing two recovery processes to remove each other's lock.
      try { fs.mkdirSync(join(this.lock, 'takeover')); } catch { throw recoveryError(); }
      this.removeMetadata(owner);
    }
    this.owner = this.writeMetadata(join(this.lock, 'process.json'),
      { version: 1, pid: process.pid, id: randomUUID() });
    try {
      if (!acquired) fs.rmdirSync(join(this.lock, 'takeover'));
      this.syncDirectory(this.directory);
      this.load();
    } catch (error) {
      this.poisoned = true;
      throw error;
    }
  }

  load() {
    const names = fs.readdirSync(this.directory);
    const records = [];
    if (names.length > 3) throw recoveryError();
    for (const name of names) {
      if (name === 'owner') continue;
      if (!name.startsWith('state-') ||
          !name.endsWith('.json')) throw recoveryError();
      const record = this.metadata(join(this.directory, name));
      const envelope = record.value;
      if (!exactKeys(envelope, ['version', 'sequence', 'state', 'checksum']) ||
          envelope.version !== 1 ||
          !Number.isSafeInteger(envelope.sequence) ||
          envelope.sequence < 1 ||
          name !== `state-${envelope.sequence}.json` ||
          envelope.checksum !== hashBytes(Buffer.from(JSON.stringify(envelope.state)))) throw recoveryError();
      this.validateState(envelope.state);
      records.push(record);
    }
    records.sort((a, b) => a.value.sequence - b.value.sequence);
    if (records.length === 2 &&
        records[1].value.sequence !== records[0].value.sequence + 1) throw recoveryError();
    this.records = records;
    this.record = records.at(-1)?.value.state ?? null;
  }

  validateState(state) {
    if (!exactKeys(state, ['phase', 'base', 'draft', 'next', 'previous']) ||
        !['idle', 'pending', 'updating', 'prepared', 'entered', 'failed'].includes(state.phase)) throw recoveryError();
    for (const key of ['base', 'draft', 'next', 'previous']) {
      if (state[key] !== null &&
          !validDescriptor(state[key])) throw recoveryError();
    }
    if (state.phase === 'idle') {
      if (state.base !== null ||
          state.draft !== null ||
          state.next !== null) throw recoveryError();
    } else if (!state.base ||
               !state.draft ||
               (state.phase === 'updating' && !state.next) ||
               (!['pending', 'updating'].includes(state.phase) && state.next)) throw recoveryError();
  }

  save(state) {
    this.acquire();
    this.validateState(state);
    try {
      // At most two bounded records exist, including the crash interval.
      while (this.records.length > 1) this.removeMetadata(this.records.shift());
      const sequence = (this.records[0]?.value.sequence ?? 0) + 1;
      if (!Number.isSafeInteger(sequence)) throw recoveryError();
      const record = this.writeMetadata(join(this.directory, `state-${sequence}.json`), {
        version: 1, sequence, state,
        checksum: hashBytes(Buffer.from(JSON.stringify(state))),
      });
      this.records.push(record);
      this.record = state;
      while (this.records.length > 1) this.removeMetadata(this.records.shift());
    } catch (error) {
      this.poisoned = true;
      throw error;
    }
  }

  idle(previous = this.record?.previous ?? null) {
    this.save({ phase: 'idle', base: null, draft: null, next: null, previous });
  }

  topology(execution) {
    const result = {};
    for (const [key, path] of Object.entries({ active: this.active, ...this.paths })) {
      result[key] = exists(path) ? this.inspect(path, execution, process.platform === 'win32' ? 1 : 2) : null;
    }
    return result;
  }

  discard(execution) {
    this.acquire();
    const state = this.record;
    const topology = this.topology(execution);
    const owned = [state?.draft, state?.next].filter(Boolean);
    // Validate the entire set before deleting anything. A failed helper can
    // leave an unknown candidate; its mere filename is never cleanup authority.
    for (const key of ['pending', 'next', 'old']) {
      if (topology[key] &&
          !owned.some((descriptor) => same(descriptor, topology[key]))) throw recoveryError();
    }
    for (const key of ['pending', 'next', 'old']) {
      if (topology[key]) this.remove(this.paths[key], topology[key], 2, execution);
    }
    this.idle(topology.previous ? state.previous : null);
  }

  recover(execution) {
    execution?.check();
    this.acquire();
    if (!this.record) {
      const topology = this.topology(execution);
      if (topology.pending ||
          topology.next ||
          topology.old ||
          topology.previous) throw recoveryError();
      return { outcome: 'none' };
    }
    const state = this.record;
    if (state.phase === 'failed') throw recoveryError();
    const topology = this.topology(execution);
    if (!same(topology.previous, state.previous) &&
        (topology.previous || state.previous) &&
        state.phase !== 'entered' &&
        !(state.phase === 'prepared' && !topology.previous)) throw recoveryError();
    if (state.phase === 'idle') {
      if (topology.pending ||
          topology.next ||
          topology.old) throw recoveryError();
      return { outcome: 'none' };
    }
    if (state.phase !== 'entered') {
      this.discard(execution);
      return { outcome: 'discarded', commitState: 'not-committed' };
    }
    if (topology.next ||
        topology.old ||
        (topology.previous && !same(topology.previous, state.base)) ||
        (topology.pending && !same(topology.pending, state.draft))) throw recoveryError();
    const candidatePath = topology.pending ? this.paths.pending : this.active;
    const candidate = boundedRead(candidatePath, MAX_CONFIG_BYTES, 2);
    new JsonSpans(candidate.bytes).validateComplete();
    if (same(topology.active, state.base)) {
      if (!topology.pending) throw recoveryError();
      if (topology.previous) {
        if (process.platform === 'win32') throw recoveryError();
        this.remove(this.active, state.base, 2, execution);
      } else {
        this.move(this.active, this.paths.previous, state.base, execution);
      }
    } else if (topology.active &&
               !same(topology.active, state.draft)) throw recoveryError();
    if (!same(this.inspect(this.paths.previous, execution), state.base)) throw recoveryError();
    if (!exists(this.active)) {
      this.move(this.paths.pending, this.active, state.draft, execution);
    } else {
      this.verify(this.active, state.draft, execution, 2);
      if (exists(this.paths.pending)) {
        if (process.platform === 'win32') throw recoveryError();
        this.remove(this.paths.pending, state.draft, 2, execution);
      }
    }
    this.verify(this.active, state.draft, execution);
    this.idle(state.base);
    return { outcome: 'committed', commitState: 'committed', revision: state.draft.revision };
  }

  close() {
    if (!this.owner) return;
    this.removeMetadata(this.owner);
    this.owner = null;
    fs.rmdirSync(this.lock);
    this.syncDirectory(this.directory);
  }
}

export function hasPoolingTransaction(configPath) {
  return exists(`${resolve(configPath)}.pooling-transaction`);
}

export function recoverPoolingConfig(configPath) {
  const files = new PoolingFiles(configPath);
  try {
    return files.recover();
  } catch (error) {
    if (error instanceof PoolingConfigError &&
        error.code === 'STORE_BUSY') throw error;
    throw recoveryError();
  } finally {
    try { files.close(); } catch { throw recoveryError(); }
  }
}
