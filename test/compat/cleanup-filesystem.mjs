import assert from 'node:assert/strict';
import { basename, dirname, sep } from 'node:path';

// Deterministic cleanup fault injection. No operation reaches the real filesystem.
export class CleanupFileSystem {
  constructor() {
    this.entries = new Map();
    this.nextId = 1;
    this.removals = [];
  }

  create(path, type, text = '') {
    const entry = { type, text, id: this.nextId++ };
    this.entries.set(path, entry);
    return entry;
  }

  mkdtempSync(prefix) {
    const path = `${prefix}memory-${this.nextId}`;
    this.create(path, 'directory');
    return path;
  }

  failOnce(method, path, code = 'EPERM') {
    this.failure = { method, path, code };
  }

  checkFailure(method, path) {
    if (this.failure?.method === method &&
        this.failure.path === path) {
      const { code } = this.failure;
      this.failure = undefined;
      throw Object.assign(new Error(`${method}: ${code}: ${path}`), { code });
    }
  }

  entry(path) {
    const entry = this.entries.get(path);
    if (!entry) throw Object.assign(new Error(`ENOENT: ${path}`), { code: 'ENOENT' });
    return entry;
  }

  lstatSync(path) {
    this.beforeStat?.(path);
    return this.stat(this.entry(path));
  }

  stat(entry) {
    return {
      dev: 1n, ino: BigInt(entry.id), birthtimeNs: BigInt(entry.id), nlink: 1n,
      isDirectory: () => entry.type === 'directory',
      isFile: () => entry.type === 'file',
      isSymbolicLink: () => entry.type === 'link',
    };
  }

  openSync(path, flags) {
    this.beforeOpen?.(path);
    this.checkFailure('openSync', path);
    if (flags === 'wx') this.writeFileSync(path, '', { flag: 'wx' });
    else assert.equal(flags, 'r+');
    return { entry: this.entry(path), closed: false };
  }

  fstatSync(file) {
    assert.equal(file.closed, false);
    return this.stat(file.entry);
  }

  ftruncateSync(file, length) {
    assert.equal(file.closed, false);
    file.entry.text = Buffer.from(file.entry.text).subarray(0, length).toString();
  }

  closeSync(file) {
    file.closed = true;
  }

  readFileSync(path) {
    const entry = this.entry(path);
    return entry.type === 'link' ? this.readFileSync(entry.text) : entry.text;
  }

  writeFileSync(path, text, options = {}) {
    if (typeof path !== 'string') {
      assert.equal(path.closed, false);
      const bytes = Buffer.from(text);
      path.entry.text = Buffer.concat([bytes, Buffer.from(path.entry.text).subarray(bytes.length)]).toString();
      return;
    }
    if (options.flag === 'wx' &&
        this.entries.has(path)) {
      throw Object.assign(new Error(`EEXIST: ${path}`), { code: 'EEXIST' });
    }
    if (this.entries.has(path)) this.entry(path).text = text;
    else this.create(path, 'file', text);
  }

  readdirSync(path) {
    assert.equal(this.entry(path).type, 'directory');
    return [...this.entries.keys()].filter((entry) => dirname(entry) === path).map((entry) => basename(entry)).sort();
  }

  unlinkSync(path) {
    this.checkFailure('unlinkSync', path);
    assert.notEqual(this.entry(path).type, 'directory');
    this.entries.delete(path);
    this.removals.push(path);
    this.afterRemoval?.(path);
  }

  rmdirSync(path) {
    this.checkFailure('rmdirSync', path);
    assert.deepEqual(this.readdirSync(path), []);
    this.entries.delete(path);
    this.removals.push(path);
    this.afterRemoval?.(path);
  }

  renameSync(from, to) {
    for (const path of [from, ...this.descendants(from)]) {
      const entry = this.entry(path);
      this.entries.delete(path);
      this.entries.set(to + path.slice(from.length), entry);
    }
  }

  descendants(path) {
    return [...this.entries.keys()].filter((entry) => entry.startsWith(path + sep));
  }
}
