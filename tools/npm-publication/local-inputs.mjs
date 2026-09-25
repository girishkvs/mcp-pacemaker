import assert from 'node:assert/strict';
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export function physical(path) {
  const absolute = resolve(path);
  assert.equal(realpathSync.native(absolute), absolute, `Linked input: ${path}`);
  let current = absolute;
  for (;;) {
    assert.equal(lstatSync(current).isSymbolicLink(), false, `Linked ancestor: ${current}`);
    const parent = dirname(current);
    if (parent === current) return absolute;
    current = parent;
  }
}

export function safeName(name) {
  assert.equal(typeof name, 'string');
  assert.ok(name.length > 0 &&
    !isAbsolute(name) &&
    !name.includes('\\') &&
    !/[<>:"|?*\u0000-\u001f]/.test(name));
  assert.ok(name.split('/').every(part => part.length > 0 &&
    part !== '.' &&
    part !== '..' &&
    !/[. ]$/.test(part) &&
    !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)), `Unsafe input name: ${name}`);
  return name;
}

export function outside(root, destination) {
  physical(root);
  physical(dirname(destination));
  const name = relative(resolve(root), resolve(destination));
  assert.ok(name.startsWith(`..${sep}`) ||
    isAbsolute(name), 'Output must be outside the input directory');
}

export class InputSnapshot {
  constructor(root, { maxBytes = 2 * 1024 ** 3, maxFiles = 50_000 } = {}) {
    this.root = physical(root);
    this.maxBytes = maxBytes;
    this.maxFiles = maxFiles;
    this.bytes = 0;
    this.files = [];
    this.directories = [];
    this.names = new Set();
    this.selections = [];
    this.wholeRoot = false;
  }

  addAll() {
    assert.equal(this.names.size, 0, 'Whole-root selection cannot overlap existing selections');
    this.wholeRoot = true;
    for (const name of readdirSync(this.root).sort()) this.add(name, true);
  }

  add(name, nested = false) {
    safeName(name);
    if (!nested) {
      assert.equal(this.wholeRoot, false, 'Cannot extend a whole-root selection');
      this.selections.push(name);
    }
    const key = name.toLowerCase();
    assert.equal(this.names.has(key), false, `Duplicate input: ${name}`);
    this.names.add(key);
    assert.ok(this.names.size <= this.maxFiles, 'Input snapshot exceeds its entry bound');
    const path = join(this.root, name);
    physical(path);
    const info = lstatSync(path);
    if (info.isDirectory()) {
      this.directories.push(name);
      for (const child of readdirSync(path).sort()) this.add(`${name}/${child}`, true);
      return;
    }
    assert.ok(info.isFile(), `Special input: ${name}`);
    assert.ok(info.size <= 128 * 1024 ** 2, `Oversized input: ${name}`);
    this.bytes += info.size;
    assert.ok(this.bytes <= this.maxBytes &&
      this.files.length < this.maxFiles, 'Input snapshot exceeds its bound');
    const bytes = readFileSync(path);
    assert.equal(bytes.length, info.size, `Input changed: ${name}`);
    this.files.push({ path: name, size: bytes.length, sha256: sha256(bytes) });
  }

  copy(destination) {
    assert.equal(existsSync(destination), false, 'Snapshot destination already exists');
    outside(this.root, destination);
    mkdirSync(destination);
    for (const name of this.directories) mkdirSync(join(destination, name), { recursive: true });
    for (const item of this.files) {
      const source = join(this.root, item.path);
      physical(source);
      assert.equal(sha256(readFileSync(source)), item.sha256, `Input changed before copy: ${item.path}`);
      const target = join(destination, item.path);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(source, target);
      assert.equal(sha256(readFileSync(target)), item.sha256, `Copy changed: ${item.path}`);
    }
    this.verify();
    return this.files;
  }

  verify() {
    const fresh = new InputSnapshot(this.root, { maxBytes: this.maxBytes, maxFiles: this.maxFiles });
    if (this.wholeRoot) fresh.addAll();
    else for (const name of this.selections) fresh.add(name);
    assert.deepEqual(fresh.files, this.files, 'Input inventory or content changed');
    assert.deepEqual(fresh.directories, this.directories, 'Input inventory or content changed');
  }
}

export function verifyManifest(root, manifest) {
  assert.equal(manifest.schemaVersion, 2);
  assert.ok(Array.isArray(manifest.files) &&
    manifest.files.length > 0 &&
    manifest.files.length <= 100_000);
  const expected = new Map();
  for (const file of manifest.files) {
    safeName(file.path);
    assert.match(file.sha256, /^[a-f0-9]{64}$/);
    assert.equal(expected.has(file.path.toLowerCase()), false);
    expected.set(file.path.toLowerCase(), file);
  }
  const actual = new InputSnapshot(root, { maxBytes: 3 * 1024 ** 3, maxFiles: 100_000 });
  for (const name of readdirSync(root).sort()) {
    if (name !== 'manifest.json') actual.add(name);
  }
  assert.equal(actual.files.length, expected.size, 'Unexpected or missing copied input');
  for (const file of actual.files) assert.deepEqual(file, expected.get(file.path.toLowerCase()));
  assert.deepEqual(actual.directories, manifest.directories, 'Unexpected or missing copied directory');
}

export function writeManifest(root, metadata) {
  const snapshot = new InputSnapshot(root, { maxBytes: 3 * 1024 ** 3, maxFiles: 100_000 });
  snapshot.addAll();
  const manifest = { schemaVersion: 2, ...metadata, files: snapshot.files, directories: snapshot.directories };
  const bytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
  writeFileSync(join(root, 'manifest.json'), bytes, { flag: 'wx', flush: true });
  return { manifest, sha256: sha256(bytes) };
}
