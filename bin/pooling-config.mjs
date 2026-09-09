import fs from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import childProcess from 'node:child_process';

export const MAX_MIN_WARM = 32;
export const MAX_UNDO_ENTRIES = 32;
export const MAX_UNDO_BYTES = 8 * 1024 * 1024;
export const MAX_CONFIG_BYTES = 1024 * 1024;

const WINDOWS_SECURITY_HELPER = fileURLToPath(new URL('./windows/PoolingSecurityHelper.exe', import.meta.url));

export class PoolingConfigError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.name = 'PoolingConfigError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

class JsonSpans {
  constructor(bytes) {
    this.text = bytes.toString('utf8');
    this.offset = 0;
    try {
      if (!Buffer.from(this.text).equals(bytes)) {
        throw new Error();
      }
      this.servers = JSON.parse(this.text);
      if (!this.servers ||
          Array.isArray(this.servers) ||
          typeof this.servers !== 'object') {
        throw new Error();
      }
      this.root = this.value(0);
    } catch {
      throw new PoolingConfigError(400, 'INVALID_CONFIG',
        'Config must be a UTF-8 JSON object without duplicate keys or excessive nesting.');
    }
  }

  whitespace() {
    while (' \t\r\n'.includes(this.text[this.offset] ?? '\0')) {
      this.offset++;
    }
  }

  string() {
    const start = this.offset++;
    while (this.text[this.offset] !== '"') {
      this.offset += this.text[this.offset] === '\\' ? 2 : 1;
    }
    this.offset++;
    return JSON.parse(this.text.slice(start, this.offset));
  }

  value(depth) {
    if (depth > 128) {
      throw new Error();
    }
    this.whitespace();
    const start = this.offset;
    const token = this.text[this.offset];
    const properties = new Map();
    if (token === '{') {
      this.offset++;
      this.whitespace();
      while (this.text[this.offset] !== '}') {
        const keyStart = this.offset;
        const key = this.string();
        const keyEnd = this.offset;
        if (properties.has(key)) {
          throw new Error();
        }
        this.whitespace();
        this.offset++;
        const value = this.value(depth + 1);
        properties.set(key, { keyStart, keyEnd, value });
        this.whitespace();
        if (this.text[this.offset] !== ',') {
          break;
        }
        this.offset++;
        this.whitespace();
      }
      this.offset++;
    } else if (token === '[') {
      this.offset++;
      this.whitespace();
      while (this.text[this.offset] !== ']') {
        this.value(depth + 1);
        this.whitespace();
        if (this.text[this.offset] !== ',') {
          break;
        }
        this.offset++;
      }
      this.offset++;
    } else if (token === '"') {
      this.string();
    } else {
      while (this.offset < this.text.length &&
             !' \t\r\n,}]'.includes(this.text[this.offset])) {
        this.offset++;
      }
    }
    return { start, end: this.offset, properties };
  }

  update(name, changes) {
    const server = this.root.properties.get(name).value;
    const entries = [...server.properties.values()];
    const edits = [];
    const additions = [];
    for (const [key, value] of changes) {
      const property = server.properties.get(key);
      if (!property) {
        if (value !== undefined) {
          additions.push([key, value]);
        }
        continue;
      }
      if (value === undefined) {
        const index = entries.indexOf(property);
        const previous = entries[index - 1];
        const next = entries[index + 1];
        edits.push({
          start: previous ? previous.value.end : property.keyStart,
          end: previous ? property.value.end : next.keyStart,
          text: '',
        });
      } else if (this.servers[name][key] !== value) {
        edits.push({ start: property.value.start, end: property.value.end, text: JSON.stringify(value) });
      }
    }
    if (additions.length) {
      const first = entries[0];
      const last = entries.at(-1);
      const spacing = this.text.slice(server.start + 1, first.keyStart);
      const colon = this.text.slice(first.keyEnd, first.value.start);
      const text = additions.map(([key, value]) =>
        `,${spacing}${JSON.stringify(key)}${colon}${JSON.stringify(value)}`).join('');
      edits.push({ start: last.value.end, end: last.value.end, text });
    }
    let text = this.text;
    for (const edit of edits.sort((a, b) => b.start - a.start)) {
      text = text.slice(0, edit.start) + edit.text + text.slice(edit.end);
    }
    return Buffer.from(text);
  }
}

export class PoolingConfigStore {
  #configPath;
  #undos = new Map();
  #undoBytes = 0;
  #execution;

  constructor(configPath) {
    if (typeof configPath !== 'string' ||
        !configPath ||
        /[\x00-\x1f\x7f]/.test(configPath)) {
      throw new PoolingConfigError(400, 'INVALID_PATH', 'A config file path is required.');
    }
    this.#configPath = resolve(configPath);
  }

  // Internal only: servers can contain credentials. Never serialize this through HTTP.
  snapshot() {
    const current = this.#read();
    return { revision: current.revision, servers: new JsonSpans(current.bytes).servers };
  }

  revision() {
    return this.snapshot().revision;
  }

  apply(request, execution) {
    return this.#execute(() => this.#apply(request), execution);
  }

  undo(request, execution) {
    return this.#execute(() => this.#undo(request), execution);
  }

  #execute(operation, execution) {
    this.#execution = execution;
    try {
      execution?.check();
      return operation();
    } finally {
      this.#execution = undefined;
    }
  }

  #apply(request) {
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
    this.#checkRevision(this.#read().revision, request.revision);
    const current = this.#read(true);
    this.#checkRevision(current.revision, request.revision);
    const document = new JsonSpans(current.bytes);
    const server = this.#server(document.servers, request.name);
    const changes = new Map();
    if (request.mode === 'pool') {
      const minWarm = request.minWarm ?? server.minWarm ?? 1;
      this.#validateMinWarm(minWarm);
      changes.set('sharing', 'pool');
      changes.set('minWarm', minWarm);
    } else {
      if (Object.hasOwn(server, 'sharing')) {
        changes.set('sharing', 'isolated');
      }
      changes.set('minWarm', undefined);
    }
    const next = document.update(request.name, changes);
    if (next.length > MAX_CONFIG_BYTES) {
      throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Updated config would exceed 1 MiB.');
    }
    const state = this.#state(new JsonSpans(next).servers, request.name);
    if (next.equals(current.bytes)) {
      return { ok: true, ...state, revision: current.revision };
    }
    const revision = this.#hash(next);
    const undoId = randomUUID();
    this.#replace(current, next);
    this.#remember(undoId, { name: request.name, bytes: current.bytes, revision });
    return { ok: true, ...state, revision, undoId };
  }

  #undo(request) {
    this.#validateRequest(request, ['name', 'undoId', 'revision']);
    if (typeof request.undoId !== 'string' ||
        !/^[0-9a-f-]{36}$/.test(request.undoId)) {
      throw new PoolingConfigError(400, 'INVALID_REQUEST', 'A valid undoId is required.');
    }
    const record = this.#undos.get(request.undoId);
    if (!record ||
        record.name !== request.name) {
      throw new PoolingConfigError(409, 'UNDO_CONFLICT', 'Undo is unavailable. Reread the config.');
    }
    this.#checkRevision(request.revision, record.revision);
    this.#checkRevision(this.#read().revision, record.revision);
    const current = this.#read(true);
    this.#checkRevision(current.revision, record.revision);
    const state = this.#state(new JsonSpans(record.bytes).servers, request.name);
    this.#replace(current, record.bytes);
    this.#forget(request.undoId);
    return { ok: true, ...state, revision: this.#hash(record.bytes) };
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
    if (hasSafeMinWarm) {
      state.minWarm = server.minWarm;
    }
    return state;
  }

  #hash(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
  }

  #checkRevision(actual, expected) {
    if (actual !== expected) {
      throw new PoolingConfigError(409, 'REVISION_CONFLICT', 'Config changed. Reread it before applying or undoing.');
    }
  }

  #read(captureSecurity = false) {
    this.#execution?.check();
    let fd;
    try {
      const pathStat = fs.lstatSync(this.#configPath);
      if (!pathStat.isFile() ||
          pathStat.nlink !== 1) {
        throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Config must be a regular file without links.');
      }
      const security = captureSecurity && process.platform === 'win32' ? this.#windowsSecurity() : undefined;
      fd = fs.openSync(this.#configPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() ||
          stat.nlink !== 1 ||
          stat.size > MAX_CONFIG_BYTES) {
        throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Config must be a regular file of at most 1 MiB.');
      }
      if (pathStat.dev !== stat.dev ||
          pathStat.ino !== stat.ino) {
        throw new PoolingConfigError(409, 'REVISION_CONFLICT', 'Config changed. Reread it before applying or undoing.');
      }
      const bytes = fs.readFileSync(fd);
      if (bytes.length > MAX_CONFIG_BYTES) {
        throw new PoolingConfigError(400, 'UNSUPPORTED_FILE', 'Config must be at most 1 MiB.');
      }
      return { bytes, stat, revision: this.#hash(bytes), security };
    } catch (error) {
      throw this.#ioError(error, 'read');
    } finally {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
          throw new PoolingConfigError(500, 'IO_ERROR', 'Unable to close the config file.');
        }
      }
    }
  }

  #checkCurrent(expected) {
    const current = this.#read();
    this.#checkRevision(current.revision, expected.revision);
    const fields = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink'];
    if (process.platform !== 'win32') fields.push('ctimeMs');
    const changedFields = fields
      .filter((key) => current.stat[key] !== expected.stat[key]);
    if (changedFields.length) {
      throw new PoolingConfigError(409, 'REVISION_CONFLICT',
        `Config file or permissions changed (${changedFields.join(', ')}). Reread the config.`);
    }
    // NTFS metadata updates can change ctime without changing the config or its permissions.
    if (process.platform === 'win32' &&
        current.stat.ctimeMs !== expected.stat.ctimeMs) {
      const security = this.#windowsSecurity();
      if (!expected.security.startsWith('F:') ||
          !security.startsWith('F:')) {
        throw new PoolingConfigError(409, 'REVISION_CONFLICT', 'Config metadata changed and full security state could not be verified. Reread the config.');
      }
      if (security !== expected.security) {
        throw new PoolingConfigError(409, 'REVISION_CONFLICT', 'Config permissions or file attributes changed. Reread the config.');
      }
    }
  }

  #runWindowsSecurity(operation, environment = {}) {
    const result = childProcess.spawnSync(WINDOWS_SECURITY_HELPER, [operation], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: Math.min(10000, this.#execution?.remainingMs() ?? 10000),
      env: { ...process.env, MCP_POOL_SOURCE: this.#configPath, ...environment },
    });
    this.#execution?.check();
    if (result.status === 3) {
      throw new PoolingConfigError(409, 'REVISION_CONFLICT', 'Config permissions or file attributes changed. Reread the config.');
    }
    if (result.error ||
        result.status !== 0) {
      throw new PoolingConfigError(500, 'IO_ERROR', 'Unable to inspect or preserve config file permissions.');
    }
    return result.stdout.trim();
  }

  #windowsSecurity() {
    const fingerprint = this.#runWindowsSecurity('inspect');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const valid = fingerprint.length === 46 &&
      (fingerprint[0] === 'F' || fingerprint[0] === 'P') &&
      fingerprint[1] === ':' && fingerprint[45] === '=' &&
      [...fingerprint.slice(2, 45)].every((character) => alphabet.includes(character));
    if (!valid) {
      throw new PoolingConfigError(500, 'IO_ERROR', 'Unable to inspect config file permissions.');
    }
    return fingerprint;
  }

  #permissions(files, current) {
    if (process.platform === 'win32') {
      // chmod on Windows cannot preserve a restrictive DACL. Copy it before writing secrets.
      this.#runWindowsSecurity('copy', {
        MCP_POOL_TEMP: files[0].path,
        MCP_POOL_BACKUP: files[1].path,
        MCP_POOL_SECURITY: current.security,
      });
      return;
    }
    const stat = current.stat;
    for (const file of files) {
      const created = fs.fstatSync(file.fd);
      if (created.uid !== stat.uid ||
          created.gid !== stat.gid) {
        fs.fchownSync(file.fd, stat.uid, stat.gid);
      }
    }
  }

  #replace(current, bytes) {
    this.#execution?.check();
    if (process.platform === 'win32' &&
        !current.security.startsWith('F:')) {
      throw new PoolingConfigError(403, 'SECURITY_UNAVAILABLE',
        'Automatic pooling edits require readable audit policy so security can be preserved. No config data was written.');
    }
    const files = [];
    try {
      for (let index = 0; index < 2; index++) {
        this.#execution?.check();
        const path = join(dirname(this.#configPath), `.pooling-${randomUUID()}.tmp`);
        const fd = fs.openSync(path, 'wx', 0o600);
        files.push({ path, fd, owned: true });
      }
      this.#permissions(files, current);
      for (const [index, file] of files.entries()) {
        this.#execution?.check();
        fs.writeFileSync(file.fd, index === 0 ? bytes : current.bytes);
        if (process.platform !== 'win32') {
          fs.fchmodSync(file.fd, current.stat.mode & 0o7777);
        }
        fs.fsyncSync(file.fd);
        fs.closeSync(file.fd);
        file.fd = undefined;
      }
      this.#checkCurrent(current);
      this.#execution?.check();
      fs.renameSync(files[1].path, `${this.#configPath}.bak`);
      files[1].owned = false;
      // No portable filesystem CAS: an external writer can still race this last check + rename.
      this.#checkCurrent(current);
      this.#execution?.beginCommit();
      fs.renameSync(files[0].path, this.#configPath);
      files[0].owned = false;
    } catch (error) {
      throw this.#ioError(error, 'write');
    } finally {
      this.#cleanup(files);
    }
  }

  #cleanup(files) {
    let failed = false;
    for (const file of files) {
      if (file.fd !== undefined) {
        try {
          fs.closeSync(file.fd);
        } catch {
          failed = true;
        }
      }
      if (file.owned) {
        try {
          fs.unlinkSync(file.path);
        } catch (error) {
          if (error.code !== 'ENOENT') {
            failed = true;
          }
        }
      }
    }
    if (failed) {
      throw new PoolingConfigError(500, 'IO_ERROR', 'Unable to clean up config transaction files.');
    }
  }

  #ioError(error, operation) {
    if (error instanceof PoolingConfigError) {
      return error;
    }
    if (operation === 'read' &&
        error.code === 'ENOENT') {
      return new PoolingConfigError(404, 'CONFIG_NOT_FOUND', 'Config file does not exist.');
    }
    return new PoolingConfigError(500, 'IO_ERROR', `Unable to ${operation} the config file.`);
  }

  #remember(id, record) {
    this.#undos.set(id, record);
    this.#undoBytes += record.bytes.length;
    while (this.#undos.size > MAX_UNDO_ENTRIES ||
           this.#undoBytes > MAX_UNDO_BYTES) {
      this.#forget(this.#undos.keys().next().value);
    }
  }

  #forget(id) {
    this.#undoBytes -= this.#undos.get(id).bytes.length;
    this.#undos.delete(id);
  }
}
