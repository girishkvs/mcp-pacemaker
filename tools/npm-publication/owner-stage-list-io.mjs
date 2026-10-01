import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OWNER_LIST_LIMITS, boundedOwnerJson, ownerListHash } from './owner-stage-list-audit.mjs';

export function writeOwnerListBytes(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    assert.ok(Number.isInteger(written) &&
      written > 0 &&
      written <= bytes.length - offset, 'Owner read output write failed');
    offset += written;
  }
}

export function ownerListExecutableHash(path) {
  const fd = fs.openSync(path, 'r');
  try {
    const stat = fs.fstatSync(fd);
    assert.ok(stat.isFile() &&
      stat.size <= 256 * 1024 * 1024, 'Unexpected owner read executable');
    const buffer = Buffer.alloc(64 * 1024);
    const digest = createHash('sha256');
    let count;
    while ((count = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      digest.update(buffer.subarray(0, count));
    }
    return digest.digest('hex');
  } finally {
    fs.closeSync(fd);
  }
}

export function readOwnerListJson(path, limit = OWNER_LIST_LIMITS.receiptBytes) {
  const before = fs.lstatSync(path);
  assert.ok(before.isFile() &&
    !before.isSymbolicLink() &&
    before.nlink === 1 &&
    before.size > 0 &&
    before.size <= limit, 'Invalid owner read evidence file');
  const fd = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    assert.equal(opened.ino, before.ino);
    assert.equal(opened.dev, before.dev);
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    assert.ok(length <= limit, 'Owner read evidence exceeds limit');
    const after = fs.fstatSync(fd);
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(length, before.size);
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
  } finally {
    fs.closeSync(fd);
  }
}

export function publishOwnerListJson(directory, name, value) {
  assert.match(name, /^[a-z-]+\.json$/);
  const bytes = boundedOwnerJson(value, OWNER_LIST_LIMITS.receiptBytes);
  const target = join(directory, name);
  const temporary = `${target}.${process.pid}.tmp`;
  let fd;
  let temporaryOwned = false;
  let published = false;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    temporaryOwned = true;
    writeOwnerListBytes(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    assert.deepEqual(readOwnerListJson(temporary), value);
    // Atomic exclusive publication, as in owner-state.atomicJson; never replace an older receipt.
    fs.linkSync(temporary, target);
    published = true;
    fs.unlinkSync(temporary);
    temporaryOwned = false;
    assert.deepEqual(readOwnerListJson(target), value);
    if (process.platform !== 'win32') {
      const directoryFd = fs.openSync(directory, 'r');
      try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
    }
    return { path: target, bytes: bytes.length, sha256: ownerListHash(bytes) };
  } catch (error) {
    if (published) fs.unlinkSync(target);
    throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (temporaryOwned) fs.unlinkSync(temporary);
  }
}

export function ownerListSourceBinding() {
  const directory = dirname(fileURLToPath(import.meta.url));
  return Object.fromEntries([
    'owner-stage-list.mjs', 'owner-stage-list-child.mjs', 'owner-stage-list-audit.mjs',
    'owner-stage-list-io.mjs', 'stage-loader.mjs', 'stage-sdk-loader.json',
  ].map(name => [name, ownerListHash(fs.readFileSync(join(directory, name)))]));
}

export function createOwnerListDirectory(path) {
  path = resolve(path);
  assert.equal(fs.realpathSync.native(dirname(path)), dirname(path), 'Linked owner read output parent');
  fs.mkdirSync(path, { mode: 0o700 });
  const stat = fs.lstatSync(path);
  return { path, dev: stat.dev, ino: stat.ino };
}

export function removeOwnerListDirectory(owned) {
  const stat = fs.lstatSync(owned.path);
  assert.ok(stat.isDirectory() &&
    !stat.isSymbolicLink(), 'Owner read directory replaced');
  assert.equal(stat.dev, owned.dev);
  assert.equal(stat.ino, owned.ino);
  assert.equal(fs.realpathSync.native(owned.path), owned.path);
  fs.rmSync(owned.path, { recursive: true });
}
