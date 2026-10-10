import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync, copyFileSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export const legacyMigrationPhases = [
  'legacy-prepared', 'legacy-holding', 'legacy-held', 'legacy-stopping',
  'legacy-stopped', 'legacy-launching', 'legacy-wiring', 'legacy-admitting',
  'legacy-rollback-stopping', 'legacy-task-restoring', 'legacy-cli-restoring', 'legacy-rollback-launching',
  'legacy-rolled-back', 'legacy-aborted',
];

export function readManagedJson(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      stat.size > 4 * 1024 * 1024) throw new Error('Unsafe managed state file.');
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function durableJson(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify(value, null, 2) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  if (process.platform !== 'win32') {
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
}

export function managedPath(config, port) {
  return join(dirname(resolve(config)), 'managed', String(port));
}

export function directoryIdentity(path) {
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isDirectory() ||
      stat.isSymbolicLink() ||
      realpathSync(path) !== resolve(path)) throw new Error('Managed directory is linked or replaced.');
  return `${stat.dev}:${stat.ino}`;
}

export function readInstanceState(directory) {
  directory = realpathSync.native(directory);
  const instance = readManagedJson(join(directory, 'instance.json'));
  const valid = instance.protocol === 1 &&
    instance.directory === directory &&
    instance.directoryIdentity === directoryIdentity(directory) &&
    typeof instance.id === 'string' &&
    /^[a-f0-9-]{36}$/.test(instance.id) &&
    typeof instance.config === 'string' &&
    resolve(instance.config) === instance.config &&
    typeof instance.cwd === 'string' &&
    resolve(instance.cwd) === instance.cwd &&
    typeof instance.node === 'string' &&
    realpathSync(instance.node) === instance.node &&
    Number.isInteger(instance.port) &&
    instance.port >= 0 &&
    instance.port <= 65535;
  if (!valid) throw new Error('Managed instance identity mismatch.');
  const active = readManagedJson(join(directory, 'active.json'));
  validateSelectionReference(active);
  return { ...instance, active };
}

export function loadInstance(directory, { verifyFiles = true } = {}) {
  const instance = readInstanceState(directory);
  verifySelection(instance.active, { verifyFiles });
  return instance;
}

export function validateSelectionReference(selection) {
  const valid = selection &&
    typeof selection.root === 'string' &&
    selection.root.length <= 4096 &&
    resolve(selection.root) === selection.root &&
    typeof selection.directoryIdentity === 'string' &&
    selection.directoryIdentity.length < 128 &&
    typeof selection.version === 'string' &&
    selection.version.length < 128 &&
    Array.isArray(selection.files) &&
    selection.files.length > 0 &&
    selection.files.length <= 20000;
  if (!valid) throw new Error('Invalid managed package selection reference.');
}

export function readRecoveryContext(directory) {
  const instance = readInstanceState(directory);
  const journal = readManagedJson(join(instance.directory, 'journal.json'));
  const binding = { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port };
  if (journal.sxs &&
      journal.binding?.port === 0) binding.port = 0;
  const phases = [
    'prepared', 'quiescing', 'stopping', 'stopped', 'selecting', 'selected', 'launching',
    'rollback-selecting', 'rollback-selected', 'rollback-launching',
    'admitting', 'admitting-rollback', 'committed', 'rolled-back', 'aborted', 'starting',
  ];
  if (journal.legacy?.protocol === 1) {
    if (journal.previous !== null ||
        journal.legacy.acknowledged !== 'restart-with-uncertain-http-and-partial-tree-v1') {
      throw new Error('Invalid legacy migration journal contract.');
    }
    phases.push(...legacyMigrationPhases);
    validateSelectionReference(journal.recovery);
  }
  if (journal.protocol !== 1 ||
      journal.instanceId !== instance.id ||
      JSON.stringify(journal.binding) !== JSON.stringify(binding) ||
      !phases.includes(journal.phase)) throw new Error('Recovery journal identity or phase is invalid.');
  validateSelectionReference(journal.target);
  if (journal.previous) validateSelectionReference(journal.previous);
  const allowed = [journal.previous, journal.target].filter(Boolean);
  if (!allowed.some(selection => JSON.stringify(selection) === JSON.stringify(instance.active))) {
    throw new Error('Active selection is not an authorized journal selection.');
  }
  if (journal.rollbackStopProof &&
      !allowed.some(selection => JSON.stringify(selection) === JSON.stringify(journal.rollbackStopProof.selection))) {
    throw new Error('Rollback proof names a package outside the activation journal.');
  }
  return { instance, journal };
}

export function verifySelection(selection, { verifyFiles = true } = {}) {
  validateSelectionReference(selection);
  if (!selection ||
      typeof selection.root !== 'string' ||
      selection.directoryIdentity !== directoryIdentity(selection.root)) throw new Error('Active package directory identity changed.');
  const pkg = readManagedJson(join(selection.root, 'package.json'));
  if (pkg.name !== 'mcp-pacemaker' ||
      pkg.version !== selection.version) throw new Error('Active package identity changed.');
  const required = ['package.json', 'bin/mcp-bridge.mjs', 'supervisor/supervise.mjs', 'bin/upgrade-capability.json'];
  if (!Array.isArray(selection.files) ||
      required.some(path => !selection.files.some(file => file.path === path))) {
    throw new Error('Immutable package inventory is missing required files.');
  }
  if (!verifyFiles) return;
  const seen = new Set();
  const directories = new Set();
  for (const file of selection.files) {
    if (typeof file.path !== 'string' ||
        !/^[a-zA-Z0-9_./@+-]+$/.test(file.path) ||
        file.path.split('/').some(part => !part || part === '.' || part === '..') ||
        !/^[a-f0-9]{64}$/.test(file.sha256) ||
        seen.has(file.path.toLowerCase())) throw new Error('Invalid immutable package inventory.');
    seen.add(file.path.toLowerCase());
    const path = resolve(selection.root, file.path);
    if (!path.startsWith(selection.root + '/') &&
        !path.startsWith(selection.root + '\\')) throw new Error('Unsafe package inventory path.');
    const parent = dirname(path);
    if (!directories.has(parent)) {
      if (realpathSync.native(parent) !== parent) throw new Error('Immutable package directory was linked or replaced.');
      directories.add(parent);
    }
    const stat = lstatSync(path);
    if (!stat.isFile() ||
        stat.isSymbolicLink() ||
        createHash('sha256').update(readFileSync(path)).digest('hex') !== file.sha256) throw new Error('Immutable package bytes changed.');
  }
}

export function createInstance({ directory, root, config, port, cwd = dirname(config), node = process.execPath,
  autostart = { kind: 'none' }, selection, controllerOperation }) {
  directory = resolve(directory);
  root = realpathSync(root);
  if (existsSync(directory)) throw new Error('Managed instance already exists; refusing to overwrite it.');
  mkdirSync(dirname(directory), { recursive: true, mode: 0o700 });
  mkdirSync(directory, { mode: 0o700 });
  directory = realpathSync.native(directory);
  const version = readManagedJson(join(root, 'package.json')).version;
  const instance = {
    protocol: 1, id: randomUUID(), directory, directoryIdentity: directoryIdentity(directory),
    config: resolve(config), cwd: resolve(cwd), port, autostart, node: realpathSync(node),
    ...(controllerOperation ? { controllerOperation: structuredClone(controllerOperation) } : {}),
  };
  for (const file of ['stable-launcher.mjs', 'managed-state.mjs']) {
    copyFileSync(new URL(`./${file}`, import.meta.url), join(directory, file));
  }
  if (process.platform === 'win32') {
    const launcher = join(directory, 'stable-launcher.mjs');
    if (/["\r\n]/.test(instance.node + launcher)) throw new Error('Unsupported Windows launcher path.');
    writeFileSync(join(directory, 'launcher.vbs'),
      `Set shell = CreateObject("WScript.Shell")\r\nshell.Run """${instance.node}"" ""${launcher}""", 0, False\r\n`,
      { flag: 'wx', mode: 0o600 });
  }
  durableJson(join(directory, 'instance.json'), instance);
  if (!selection) selection = snapshotPackage(root, join(directory, 'versions', `${version}-${randomUUID()}`));
  verifySelection(selection);
  durableJson(join(directory, 'active.json'), selection);
  return loadInstance(directory, { verifyFiles: false });
}

export function snapshotPackage(source, destination, { dependencies = true } = {}) {
  const pkg = readManagedJson(join(source, 'package.json'));
  if (!Array.isArray(pkg.files)) throw new Error('A packaged file inventory is required for the stable installation.');
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  const files = [];
  const seen = new Set();
  const copy = relative => {
    relative = relative.replace(/\/$/, '');
    if (!/^[a-zA-Z0-9_./@+-]+$/.test(relative) ||
        relative.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Invalid package file inventory.');
    if (seen.has(relative)) return;
    seen.add(relative);
    const path = join(source, relative);
    if (!existsSync(path)) return;
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('Linked package inputs cannot form an immutable installation.');
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path)) copy(`${relative}/${entry}`);
      return;
    }
    if (!stat.isFile() ||
        stat.nlink !== 1) throw new Error('Unsupported package input.');
    const bytes = readFileSync(path);
    const output = join(destination, relative);
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    writeFileSync(output, bytes, { flag: 'wx', mode: stat.mode & 0o777 });
    files.push({ path: relative, sha256: createHash('sha256').update(bytes).digest('hex') });
  };
  for (const path of ['package.json', 'README.md', 'CHANGELOG.md', 'LICENSE', ...pkg.files]) copy(path);
  if (!dependencies) return { root: realpathSync(destination), version: pkg.version, directoryIdentity: directoryIdentity(destination), files };
  if (!existsSync(join(source, 'package-lock.json')) ||
      !existsSync(join(source, 'node_modules'))) throw new Error('Verified CLI dependencies are required before creating a managed installation.');
  copy('package-lock.json');
  if (existsSync(join(source, 'node_modules', '.package-lock.json'))) copy('node_modules/.package-lock.json');
  const lock = readManagedJson(join(source, 'package-lock.json'));
  for (const path of Object.keys(lock.packages ?? {})) {
    if (!path) continue;
    copy(path);
  }
  return { root: realpathSync(destination), version: pkg.version, directoryIdentity: directoryIdentity(destination), files };
}

export function acquireInstanceLock(directory) {
  const identity = directoryIdentity(directory);
  const path = join(directory, 'upgrade.lock');
  const token = randomUUID();
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ token, pid: process.pid }) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
  return () => {
    if (directoryIdentity(directory) !== identity) throw new Error('Locked instance directory was replaced; no lock was removed.');
    if (readManagedJson(path).token !== token) throw new Error('Upgrade lock identity changed; retained for recovery.');
    unlinkSync(path);
  };
}
