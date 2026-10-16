import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { isDeepStrictEqual, promisify } from 'node:util';
import semver from 'semver';
import { npmCliPath } from './update-check.mjs';
import { PoolingFiles } from './pooling-files.mjs';

const execute = promisify(execFile);
const PUBLIC_REGISTRY = 'https://registry.npmjs.org/';
const policies = [
  'registry', 'replace-registry-host', 'offline', 'prefer-offline', 'strict-ssl', 'ca', 'cafile',
  'proxy', 'https-proxy', 'noproxy', 'local-address', 'min-release-age', 'min-release-age-exclude',
  'allow-directory', 'allow-file', 'allow-git', 'allow-remote', 'allow-scripts', 'strict-dep-builds',
];

export function dependencyInventory(root) {
  const files = [];
  const walk = path => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('Linked dependency inputs are unsupported.');
    if (stat.isDirectory()) {
      for (const name of readdirSync(path)) walk(join(path, name));
      return;
    }
    if (!stat.isFile() ||
        stat.nlink !== 1) throw new Error('Unsupported dependency input.');
    files.push({ path: relative(root, path).replaceAll('\\', '/'),
      sha256: createHash('sha256').update(readFileSync(path)).digest('hex') });
  };
  walk(join(root, 'package-lock.json'));
  walk(join(root, 'node_modules'));
  return files;
}

export function validateDependencyLock(root) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion !== 3 ||
      lock.name !== pkg.name ||
      lock.version !== pkg.version ||
      !isDeepStrictEqual(lock.packages?.['']?.dependencies, pkg.dependencies)) {
    throw new Error('Target dependency lock does not match the selected package.');
  }
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue;
    if (!path.startsWith('node_modules/') ||
        path.split('/').some(part => !part || part === '.' || part === '..') ||
        entry.link ||
        semver.valid(entry.version) !== entry.version) throw new Error('Unverifiable target dependency lock entry.');
    if (typeof entry.integrity !== 'string' ||
        !entry.integrity.startsWith('sha512-')) {
      const found = typeof entry.integrity === 'string' ? entry.integrity.split('-')[0] : 'no';
      throw new Error(`Unverifiable target dependency lock entry: ${path}@${entry.version} has ${found} integrity from the registry; SHA-512 is required.`);
    }
    const integrity = Buffer.from(entry.integrity.slice(7), 'base64');
    if (integrity.length !== 64 ||
        `sha512-${integrity.toString('base64')}` !== entry.integrity) throw new Error('Invalid dependency archive integrity.');
    const url = new URL(entry.resolved);
    if (!['https:', 'http:'].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.hash) throw new Error('Unsupported dependency archive source.');
  }
  return lock;
}

// From 2.1.1 a target ships the SHA-512 lock it was released and tested with. npm ci then
// verifies every archive against it, so registry metadata (SHA-1 on some mirrors) and newer
// in-range releases cannot change the staged dependency set.
export function bundledDependencyLock(root) {
  const capabilityPath = join(root, 'bin', 'upgrade-capability.json');
  if (!existsSync(capabilityPath)) return null;
  const capability = JSON.parse(readFileSync(capabilityPath, 'utf8'));
  if (capability.dependencyLock !== 1) return null;
  const path = join(root, 'bin', 'dependency-lock.json');
  const stat = existsSync(path) ? lstatSync(path) : null;
  if (!stat?.isFile() ||
      stat.size === 0) throw new Error('Target declares a bundled dependency lock but does not contain it.');
  return readFileSync(path);
}

// npm points public-registry lock URLs at the configured registry itself, unless
// replace-registry-host is "never" or names only another host or URL prefix.
export function npmMapsPublicRegistry(setting) {
  const value = String(setting ?? 'npmjs');
  return ['npmjs', 'always'].includes(value) ||
    value.includes('registry.npmjs.org');
}

// The bundled lock names the public registry. When npm will not map those URLs, point each
// entry at the registry that resolving it would have used: its scope's registry, else the
// configured one. Integrity covers the archive bytes, not the URL.
export function registryLock(bytes, registry, scopes = {}) {
  const lock = JSON.parse(bytes.toString('utf8'));
  let changed = false;
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    const publicEntry = path &&
      typeof entry.resolved === 'string' &&
      entry.resolved.startsWith(PUBLIC_REGISTRY);
    if (!publicEntry) continue;
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const target = (name.startsWith('@') ? scopes[name.split('/')[0]] : undefined) ?? registry;
    if (!target) continue;
    const base = target.endsWith('/') ? target : `${target}/`;
    if (base === PUBLIC_REGISTRY) continue;
    entry.resolved = base + entry.resolved.slice(PUBLIC_REGISTRY.length);
    changed = true;
  }
  return changed ? Buffer.from(`${JSON.stringify(lock, null, 2)}\n`) : bytes;
}

export async function stageCliDependencies(root, { registry, cache, run = execute } = {}) {
  const cli = npmCliPath();
  const call = async (args, options = {}) => {
    try {
      return await run(process.execPath, [cli, ...args], {
        encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 8 * 1024 * 1024, ...options,
      });
    } catch {
      throw new Error('CLI dependencies were refused or unavailable under configured npm policy. No fallback or policy relaxation was attempted.');
    }
  };
  const configuration = JSON.parse((await call(['config', 'list', '--json'])).stdout);
  const prefix = (await call(['prefix'])).stdout.trim();
  if (!prefix ||
      !existsSync(prefix)) throw new Error('Caller npm project context could not be verified.');
  const env = { ...process.env };
  for (const [key, value] of Object.entries(configuration)) {
    const scoped = key.startsWith('@') && key.endsWith(':registry');
    if (!policies.includes(key) &&
        !scoped) continue;
    if (value === null ||
        value === undefined) continue;
    if (Array.isArray(value)) continue;
    env[`npm_config_${key.replaceAll('-', '_')}`] = String(value);
  }
  if (configuration['strict-ssl'] === false) throw new Error('Managed dependency staging cannot disable TLS verification.');
  const projectConfig = join(prefix, '.npmrc');
  const stagedConfig = join(root, '.npmrc');
  if (existsSync(stagedConfig)) throw new Error('Unexpected target npm configuration.');
  const bundled = bundledDependencyLock(root);
  if (bundled &&
      existsSync(join(root, 'package-lock.json'))) throw new Error('Unexpected target dependency lock.');
  const scopes = Object.fromEntries(Object.entries(configuration)
    .filter(([key, value]) => typeof value === 'string' &&
      /^@[^:/]+:registry$/.test(key))
    .map(([key, value]) => [key.slice(0, -':registry'.length), value]));
  const manifest = readFileSync(join(root, 'package.json'));
  if (existsSync(projectConfig)) {
    const files = new PoolingFiles(projectConfig);
    const identity = files.inspect(projectConfig);
    files.stage(stagedConfig, projectConfig, identity, readFileSync(projectConfig));
  }
  const args = ['--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--bin-links=false',
    '--cache', cache, '--registry', registry];
  try {
    const effective = JSON.parse((await call(['config', 'list', '--json'], { cwd: root, env })).stdout);
    for (const key of Object.keys(configuration)) {
      if (!policies.includes(key) &&
          !(key.startsWith('@') && key.endsWith(':registry'))) continue;
      if (!isDeepStrictEqual(configuration[key], effective[key])) {
        throw new Error('Effective npm policy changed in dependency staging; no dependency resolution was attempted.');
      }
    }
    if (bundled) {
      const staged = npmMapsPublicRegistry(configuration['replace-registry-host'])
        ? bundled
        : registryLock(bundled, registry, scopes);
      writeFileSync(join(root, 'package-lock.json'), staged, { flag: 'wx' });
    } else await call(['install', '--package-lock-only', ...args], { cwd: root, env });
    validateDependencyLock(root);
    const lock = readFileSync(join(root, 'package-lock.json'));
    await call(['ci', ...args], { cwd: root, env });
    if (!readFileSync(join(root, 'package.json')).equals(manifest) ||
        !readFileSync(join(root, 'package-lock.json')).equals(lock)) throw new Error('Dependency staging changed the verified manifest or lock.');
    await call(['ls', '--omit=dev', '--json'], { cwd: root, env });
    return dependencyInventory(root);
  } finally {
    if (existsSync(stagedConfig)) unlinkSync(stagedConfig);
  }
}
