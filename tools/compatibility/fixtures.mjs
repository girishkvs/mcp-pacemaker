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
export const CURRENT_REF = 'db4812a1cbfb8546c814a656397b9a48ccf0f32c';
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

export function preparationOptions(args) {
  const options = {
    clean: false, historical: false, peerRoot: undefined,
    candidateTarball: undefined, candidateSha256: undefined,
  };
  const seen = new Set();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    assert.ok(['--clean', '--historical', '--peer-root', '--candidate-tarball', '--candidate-sha256'].includes(arg),
      `Unknown preparation option: ${arg}`);
    assert.equal(seen.has(arg), false, `Repeated preparation option: ${arg}`);
    seen.add(arg);
    if (arg === '--clean') options.clean = true;
    if (arg === '--historical') options.historical = true;
    if (['--peer-root', '--candidate-tarball', '--candidate-sha256'].includes(arg)) {
      const value = args[++index];
      assert.ok(value &&
        !value.startsWith('--'), `${arg} requires a value`);
      if (arg === '--peer-root') options.peerRoot = resolve(value);
      if (arg === '--candidate-tarball') options.candidateTarball = resolve(value);
      if (arg === '--candidate-sha256') {
        assert.match(value, /^[a-f0-9]{64}$/, 'A candidate SHA-256 digest is required');
        options.candidateSha256 = value;
      }
    }
  }
  assert.ok(!options.clean ||
    seen.size === 1, '--clean cannot prepare another fixture');
  assert.ok(!options.historical ||
    (!options.peerRoot &&
      !options.candidateTarball), '--historical cannot substitute a patch candidate');
  assert.equal(Boolean(options.candidateTarball), Boolean(options.candidateSha256),
    'Candidate tarball and SHA-256 must be supplied together');
  return options;
}

export function fixturePlan(version, { historical = false, peerVersion } = {}) {
  assert.ok(['1.3.1', '2.0.1'].includes(version), `Unsupported candidate version: ${version}`);
  const plan = {
    mode: historical ? 'historical' : peerVersion ? 'patch-pair' : 'candidate-vs-release',
    legacy: { version: '1.3.0', source: 'release', ref: LEGACY_REF },
    candidate: { version: '2.0.0', source: 'release', ref: CURRENT_REF },
  };
  if (historical) {
    assert.equal(peerVersion, undefined, 'Historical fixtures cannot contain a patch candidate');
    return plan;
  }
  const role = version === '1.3.1' ? 'legacy' : 'candidate';
  const peerRole = role === 'legacy' ? 'candidate' : 'legacy';
  plan[role] = { version, source: 'root' };
  if (peerVersion !== undefined) {
    const expected = version === '1.3.1' ? '2.0.1' : '1.3.1';
    assert.equal(peerVersion, expected, 'The peer must be the explicitly supported opposite-major patch');
    plan[peerRole] = { version: peerVersion, source: 'peer' };
  }
  return plan;
}

export function packedPackage(result, name, version) {
  let packed;
  if (Array.isArray(result)) {
    assert.equal(result.length, 1, 'Expected one npm 11 packed package');
    [packed] = result;
  } else {
    assert.ok(result &&
      typeof result === 'object', 'Expected npm pack JSON');
    assert.deepEqual(Object.keys(result), [name], 'Expected one npm 12 package-name key');
    packed = result[name];
  }
  assert.equal(packed?.name, name, 'Packed package name differs');
  assert.equal(packed.version, version, 'Packed package version differs');
  assert.equal(packed.filename, `${name.replace('@', '').replace('/', '-')}-${version}.tgz`);
  assert.ok(Array.isArray(packed.files) &&
    packed.files.length > 0, 'Packed file metadata is missing');
  const paths = packed.files.map(({ path }) => {
    assert.equal(typeof path, 'string');
    assert.ok(path.length > 0 &&
      !path.startsWith('/') &&
      !path.includes('\\') &&
      !path.includes(':') &&
      !path.split('/').some((part) => part === '..' || part === '.' || part === ''),
    'Unsafe packed file metadata');
    return path;
  });
  assert.equal(new Set(paths).size, paths.length, 'Duplicate packed file metadata');
  return packed;
}

export function candidateInputs(root = ROOT) {
  const hashes = {};
  const visit = (path) => {
    const absolute = join(root, path);
    const stat = lstatSync(absolute);
    assert.equal(stat.isSymbolicLink(), false, `Linked candidate input is not supported: ${path}`);
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute).sort()) visit(`${path.replace(/\/$/, '')}/${name}`);
    } else {
      hashes[path] = sha256(absolute);
    }
  };
  for (const path of ['package.json', 'package-lock.json', ...readJson(join(root, 'package.json')).files]) visit(path);
  return hashes;
}

export function assertCandidateInputs(expected, root = ROOT) {
  assert.ok(expected, 'Fixture format changed. Run compat:clean and compat:prepare again.');
  const current = candidateInputs(root);
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

export function isolatedEnvironment(dir, sourceEnvironment = process.env) {
  const home = join(dir, 'home');
  const temp = join(dir, 'tmp');
  for (const path of [home, temp, join(home, 'AppData', 'Roaming'), join(home, 'AppData', 'Local')]) {
    mkdirSync(path, { recursive: true });
  }
  const env = { ...sourceEnvironment };
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
    throw Object.assign(
      new Error(`${command} ${args.join(' ')} failed (${result.code}, ${result.signal})\n${stdout}\n${stderr}`),
      { exitCode: result.code, signal: result.signal });
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
  assert.equal(manifest.schemaVersion, 2,
    'Incomplete or incompatible fixtures. Run compat:clean and compat:prepare again.');
  verifyOwnership(manifest);
  verifyDirectory(manifest.dir, manifest.identity);
  assert.equal(manifest.runtimeMajor, process.versions.node.split('.')[0],
    'Node major changed. Run compat:clean and compat:prepare with the test runtime.');
  const peerVersion = manifest.peerRoot && readJson(join(manifest.peerRoot, 'package.json')).version;
  const plan = fixturePlan(readJson(join(ROOT, 'package.json')).version, {
    historical: manifest.plan.mode === 'historical', peerVersion,
  });
  assert.deepEqual(manifest.plan, plan, 'The selected version/source pair changed');
  assertCandidateInputs(manifest.candidateInputs);
  for (const role of ['legacy', 'candidate']) {
    const record = manifest.sources[role];
    assert.equal(manifest[role], join(manifest.dir, role), 'Unexpected prepared fixture path');
    assert.equal(sha256(record.archive), record.archiveSha256, `${role} archive changed`);
    assert.equal(readJson(join(manifest[role], 'package.json')).version, plan[role].version);
    if (plan[role].source !== 'release') {
      const source = plan[role].source === 'root' ? ROOT : manifest.peerRoot;
      assertCandidateInputs(record.inputs, source);
      assert.equal(sha256(join(source, 'package-lock.json')), record.lockSha256, `${role} source lock changed`);
    }
    for (const [path, hash] of Object.entries(record.files)) {
      assert.equal(sha256(join(manifest[role], path)), hash, `${role} fixture changed: ${path}`);
    }
  }
  return { ...manifest, legacyVersion: plan.legacy.version, candidateVersion: plan.candidate.version };
}
