import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  closeSync, existsSync, fstatSync, ftruncateSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, readdirSync, rmdirSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const LEGACY_REF = '2d525f4ced01b978a5aeb83aef69145e96cced05';
export const MANIFEST = join(ROOT, 'node_modules', '.cache', 'pacemaker-compat.json');
export const REGISTRY = 'https://registry.npmjs.org/';
const ownedFileSystem = {
  closeSync, fstatSync, ftruncateSync, lstatSync, mkdtempSync, openSync,
  readFileSync, readdirSync, rmdirSync, unlinkSync, writeFileSync,
};

export function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

export function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function candidateInputs() {
  const hashes = {};
  const visit = (path) => {
    const absolute = join(ROOT, path);
    const stat = lstatSync(absolute);
    assert.equal(stat.isSymbolicLink(), false, `Linked candidate input is not supported: ${path}`);
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute).sort()) visit(`${path.replace(/\/$/, '')}/${name}`);
    } else {
      hashes[path] = sha256(absolute);
    }
  };
  for (const path of ['package.json', 'package-lock.json', ...readJson(join(ROOT, 'package.json')).files]) visit(path);
  return hashes;
}

export function assertCandidateInputs(expected) {
  assert.ok(expected, 'Fixture format changed. Run compat:clean and compat:prepare again.');
  const current = candidateInputs();
  const paths = new Set([...Object.keys(current), ...Object.keys(expected)]);
  const changed = [...paths].filter((path) => current[path] !== expected[path]);
  assert.deepEqual(changed, [], 'Candidate inputs changed. Run compat:clean and compat:prepare again.');
}

export function ownedDirectory(fs = ownedFileSystem, marker) {
  assert.ok(marker === undefined || marker === MANIFEST, 'Unsupported ownership marker location');
  const dir = fs.mkdtempSync(join(tmpdir(), 'pacemaker-compat-'));
  const owner = randomUUID();
  const identity = fileIdentity(fs.lstatSync(dir, { bigint: true }));
  // Keep authority outside the tree: a failed child unlink or final rmdir must
  // leave it intact. Cleanup never creates or restores an ownership marker.
  marker ??= `${dir}.compat-owner`;
  const file = fs.openSync(marker, 'wx', 0o600);
  try {
    const markerIdentity = fileIdentity(fs.fstatSync(file, { bigint: true }));
    const owned = { dir, owner, identity, marker, markerIdentity };
    fs.writeFileSync(file, JSON.stringify(owned));
    return owned;
  } finally {
    fs.closeSync(file);
  }
}

function fileIdentity(stat) {
  return { dev: String(stat.dev), ino: String(stat.ino), birthtimeNs: String(stat.birthtimeNs) };
}

function verifyOwnership({ dir, owner, identity, marker, markerIdentity }, fs = ownedFileSystem) {
  assert.equal(dirname(resolve(dir)), resolve(tmpdir()), 'Cleanup is limited to an owned temp directory');
  assert.ok(basename(dir).startsWith('pacemaker-compat-'));
  assert.ok(identity && markerIdentity, 'Fixture ownership identity is missing');
  assert.ok(marker === `${dir}.compat-owner` || marker === MANIFEST, 'Unsupported ownership marker location');
  const stat = fs.lstatSync(marker, { bigint: true });
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), 'Refusing a linked or non-file ownership marker');
  assert.deepEqual(fileIdentity(stat), markerIdentity, 'Ownership marker identity changed');
  const recorded = JSON.parse(fs.readFileSync(marker, 'utf8'));
  assert.equal(recorded.owner, owner, 'Fixture ownership changed');
  assert.equal(recorded.dir, dir, 'Fixture ownership path changed');
  assert.deepEqual(recorded.identity, identity, 'Fixture ownership identity changed');
  assert.equal(recorded.marker, marker, 'Fixture ownership marker path changed');
  assert.deepEqual(recorded.markerIdentity, markerIdentity, 'Fixture ownership marker identity changed');
  return marker;
}

function verifyDirectory(path, identity, fs = ownedFileSystem) {
  const stat = fs.lstatSync(path, { bigint: true });
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), 'Refusing a linked or non-directory fixture path');
  assert.deepEqual(fileIdentity(stat), identity, 'Fixture directory identity changed');
  return stat;
}

export function removeOwnedDirectory(owned, fs = ownedFileSystem) {
  const marker = verifyOwnership(owned, fs);
  const { dir, identity } = owned;
  const remove = (path, parents) => {
    for (const parent of parents) verifyDirectory(parent.path, parent.identity, fs);
    const stat = path === dir ? verifyDirectory(path, identity, fs) : fs.lstatSync(path, { bigint: true });
    if (stat.isSymbolicLink() ||
        !stat.isDirectory()) {
      fs.unlinkSync(path);
      return;
    }
    const ancestry = [...parents, { path, identity: fileIdentity(stat) }];
    for (const name of fs.readdirSync(path)) remove(join(path, name), ancestry);
    for (const parent of ancestry) verifyDirectory(parent.path, parent.identity, fs);
    fs.rmdirSync(path);
  };
  let present = true;
  try { verifyDirectory(dir, identity, fs); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    present = false;
  }
  if (present) remove(dir, [{ path: dir, identity }]);
  // The root can already be absent when a previous marker unlink failed.
  // A missing marker is never accepted, and a replacement root is never owned.
  verifyOwnership(owned, fs);
  let remaining;
  try { remaining = fs.lstatSync(dir, { bigint: true }); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  assert.equal(remaining, undefined, 'Fixture directory reappeared before ownership retirement');
  fs.unlinkSync(marker);
}

export function ownedFixtureManifest(fs = ownedFileSystem) {
  return ownedDirectory(fs, MANIFEST);
}

export function writeFixtureManifest(manifest, fs = ownedFileSystem) {
  assert.equal(manifest.marker, MANIFEST, 'Expected the prepared-fixture ownership marker');
  verifyOwnership(manifest, fs);
  verifyDirectory(manifest.dir, manifest.identity, fs);
  const file = fs.openSync(MANIFEST, 'r+');
  try {
    assert.deepEqual(fileIdentity(fs.fstatSync(file, { bigint: true })), manifest.markerIdentity,
      'Ownership marker identity changed');
    verifyOwnership(manifest, fs);
    verifyDirectory(manifest.dir, manifest.identity, fs);
    const text = JSON.stringify(manifest, null, 2) + '\n';
    fs.writeFileSync(file, text);
    fs.ftruncateSync(file, Buffer.byteLength(text));
  } finally {
    fs.closeSync(file);
  }
}

export function removeFixtureManifest(fs = ownedFileSystem) {
  const stat = fs.lstatSync(MANIFEST, { bigint: true });
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), 'Refusing a linked or non-file fixture manifest');
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  assert.equal(manifest.marker, MANIFEST, 'Expected the prepared-fixture ownership marker');
  removeOwnedDirectory(manifest, fs);
  return manifest.dir;
}

export function isolatedEnvironment(dir) {
  const home = join(dir, 'home');
  const temp = join(dir, 'tmp');
  for (const path of [home, temp, join(home, 'AppData', 'Roaming'), join(home, 'AppData', 'Local')]) {
    mkdirSync(path, { recursive: true });
  }
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (/^MCP_/i.test(name)) delete env[name];
  }
  return {
    ...env, HOME: home, USERPROFILE: home,
    APPDATA: join(home, 'AppData', 'Roaming'), LOCALAPPDATA: join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: home, XDG_STATE_HOME: home, XDG_CACHE_HOME: home,
    TMPDIR: temp, TMP: temp, TEMP: temp,
    MCP_CONFIG_WATCH: '0', MCP_RESUME: '0', MCP_POOL_ADVICE_MS: '1',
    MCP_RECYCLE_MINUTES: '0', MCP_IDLE_TIMEOUT_MS: '0', MCP_HEALTH_INTERVAL_MS: '0',
  };
}

export async function run(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (bytes) => { stdout += bytes; });
  child.stderr.on('data', (bytes) => { stderr += bytes; });
  const result = await new Promise((resolveResult, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolveResult({ code, signal, stdout, stderr }));
  });
  if (result.code !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.code}, ${result.signal})\n${stdout}\n${stderr}`);
  }
  return stdout;
}

export function npm(args, options) {
  assert.ok(process.env.npm_execpath, 'Run preparation through "npm run compat:prepare"');
  return run(process.execPath, [process.env.npm_execpath, ...args], options);
}

export async function npmRestoreArguments(readConfig = npm) {
  const names = ['cache', 'registry', 'replace-registry-host'];
  const values = await Promise.all(names.map((name) => readConfig(['config', 'get', name], { cwd: ROOT })));
  return names.flatMap((name, index) => [`--${name}`, values[index].trim()]);
}

export function checkLockfile(file) {
  const lock = readJson(file);
  for (const [name, entry] of Object.entries(lock.packages)) {
    if (entry.resolved) {
      assert.ok(entry.resolved.startsWith(REGISTRY), `${file}: ${name} does not resolve to the public registry`);
    }
  }
}

export function loadFixtures() {
  assert.ok(existsSync(MANIFEST), 'Missing compatibility fixtures. Run "npm run compat:prepare" first.');
  const manifest = readJson(MANIFEST);
  assert.equal(manifest.legacyRef, LEGACY_REF,
    'Incomplete or incompatible fixtures. Run compat:clean and compat:prepare again.');
  verifyOwnership(manifest);
  verifyDirectory(manifest.dir, manifest.identity);
  assert.equal(manifest.runtimeMajor, process.versions.node.split('.')[0],
    'Node major changed. Run compat:clean and compat:prepare with the test runtime.');
  assert.equal(sha256(manifest.tarball), manifest.tarballSha256, 'Packed candidate changed');
  assert.equal(sha256(join(ROOT, 'package-lock.json')), manifest.candidateLockSha256,
    'Candidate lock changed. Run compat:clean and compat:prepare again.');
  assertCandidateInputs(manifest.candidateInputs);
  for (const [path, hash] of Object.entries(manifest.candidateFiles)) {
    assert.equal(sha256(join(ROOT, path)), hash, `Candidate source changed: ${path}. Reprepare fixtures.`);
    assert.equal(sha256(join(manifest.candidate, path)), hash, `Packed candidate changed: ${path}`);
  }
  for (const [path, hash] of Object.entries(manifest.legacyFiles)) {
    assert.equal(sha256(join(manifest.legacy, path)), hash, `Pinned legacy fixture changed: ${path}`);
  }
  assert.equal(readJson(join(manifest.legacy, 'package.json')).version, '1.3.0');
  assert.equal(readJson(join(manifest.candidate, 'package.json')).version, '2.0.0');
  return manifest;
}
