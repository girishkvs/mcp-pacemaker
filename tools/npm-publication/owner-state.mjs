import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join, resolve } from 'node:path';
import { digest, exactKeys } from './policy.mjs';
import { ownerBinding } from './owner-bootstrap.mjs';

export function atomicJson(directory, name, value) {
  assert.match(name, /^[a-z0-9-]+\.json$/);
  const target = join(directory, name);
  const temporary = `${target}.${process.pid}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  try {
    // link is atomic and exclusive; rename could replace an earlier outcome.
    fs.linkSync(temporary, target);
  } finally {
    fs.unlinkSync(temporary);
  }
  if (process.platform !== 'win32') {
    const directoryHandle = fs.openSync(directory, 'r');
    try { fs.fsyncSync(directoryHandle); } finally { fs.closeSync(directoryHandle); }
  }
}

export function readJsonFile(path) {
  const stat = fs.lstatSync(path);
  assert.ok(stat.isFile() &&
    !stat.isSymbolicLink() &&
    stat.nlink === 1 &&
    stat.size <= 4 * 1024 * 1024);
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

export function ownerState(env, approval, create = false) {
  const temp = fs.realpathSync.native(env.RUNNER_TEMP);
  const directory = join(temp, 'npm-owner-bootstrap');
  const binding = ownerBinding(approval, env);
  const approvalSha256 = digest(Buffer.from(JSON.stringify(approval))).sha256;
  if (create) {
    fs.mkdirSync(directory, { mode: 0o700 });
    const stat = fs.lstatSync(directory);
    atomicJson(directory, 'ownership.json', {
      schemaVersion: 1, dev: stat.dev, ino: stat.ino, uid: stat.uid, binding, approvalSha256,
    });
    for (const name of ['signed', 'home', 'ledger', 'challenges']) fs.mkdirSync(join(directory, name), { mode: 0o700 });
    atomicJson(directory, 'request.json', approval);
  }
  const check = () => {
    assert.equal(fs.realpathSync.native(directory), resolve(directory));
    const stat = fs.lstatSync(directory);
    assert.ok(stat.isDirectory() &&
      !stat.isSymbolicLink());
    const owner = readJsonFile(join(directory, 'ownership.json'));
    exactKeys(owner, ['schemaVersion', 'dev', 'ino', 'uid', 'binding', 'approvalSha256'], 'owner scratch marker');
    assert.equal(owner.schemaVersion, 1);
    for (const key of ['dev', 'ino', 'uid']) assert.equal(stat[key], owner[key]);
    if (process.getuid) assert.equal(stat.uid, process.getuid());
    assert.deepEqual(owner.binding, binding);
    assert.equal(owner.approvalSha256, approvalSha256);
    assert.deepEqual(readJsonFile(join(directory, 'request.json')), approval);
    for (const name of ['signed', 'home', 'ledger', 'challenges']) {
      const path = join(directory, name);
      const child = fs.lstatSync(path);
      assert.ok(child.isDirectory() &&
        !child.isSymbolicLink());
      assert.equal(fs.realpathSync.native(path), path);
      assert.equal(child.uid, owner.uid);
    }
  };
  check();
  return { directory, binding, approvalSha256, check,
    write: (area, name, value) => {
      assert.ok(['ledger', 'challenges'].includes(area));
      check();
      atomicJson(join(directory, area), name, value);
    } };
}
