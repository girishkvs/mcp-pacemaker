import assert from 'node:assert/strict';
import fs from 'node:fs';
import { dirname, join } from 'node:path';

export class SyntheticIdentity {
  constructor(t, path, field, handleChanged = false) {
    this.before = 24488322978684223n;
    this.after = 24488322978684225n;
    this.changed = false;
    assert.notEqual(this.before, this.after);
    assert.equal(Number(this.before), Number(this.after));
    const native = { ...fs };
    const handles = new Set();
    t.mock.method(fs, 'openSync', (name, ...args) => {
      const fd = native.openSync(name, ...args);
      if (name === path) handles.add(fd);
      return fd;
    });
    t.mock.method(fs, 'closeSync', (fd) => {
      handles.delete(fd);
      return native.closeSync(fd);
    });
    t.mock.method(fs, 'lstatSync', (name, options) => {
      const stat = native.lstatSync(name, options);
      if (name === path) stat[field] = this.value(options, this.changed);
      return stat;
    });
    t.mock.method(fs, 'fstatSync', (fd, options) => {
      const stat = native.fstatSync(fd, options);
      if (handles.has(fd)) stat[field] = this.value(options, this.changed || handleChanged);
      return stat;
    });
  }

  value(options, changed) {
    const value = changed ? this.after : this.before;
    return options?.bigint ? value : Number(value);
  }
}

export class FileReplacement {
  constructor(path) {
    this.path = path;
    this.replacement = join(dirname(path), 'editor.json');
    this.bytes = fs.readFileSync(path);
    fs.writeFileSync(this.replacement, this.bytes, { mode: 0o600 });
    this.before = this.identity(path);
    this.after = this.identity(this.replacement);
    this.replaced = false;
    assert.notDeepEqual(this.before, this.after, 'both pre-existing files must have distinct exact identities');
  }

  identity(path) {
    const stat = fs.lstatSync(path, { bigint: true });
    return { dev: stat.dev, ino: stat.ino };
  }

  replace() {
    assert.equal(this.replaced, false);
    assert.deepEqual(this.identity(this.path), this.before);
    fs.renameSync(this.replacement, this.path);
    this.replaced = true;
    this.verify();
  }

  verify() {
    assert.equal(this.replaced, true);
    assert.deepEqual(this.identity(this.path), this.after, 'the active path must acquire the replacement identity');
    assert.deepEqual(fs.readFileSync(this.path), this.bytes);
  }
}
