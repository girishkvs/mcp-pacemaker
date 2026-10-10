import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { join, relative } from 'node:path';
import { isDeepStrictEqual, promisify } from 'node:util';
import semver from 'semver';
import { npmCliPath } from './update-check.mjs';
import { PoolingFiles } from './pooling-files.mjs';

const execute = promisify(execFile);
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
        semver.valid(entry.version) !== entry.version ||
        typeof entry.integrity !== 'string' ||
        !entry.integrity.startsWith('sha512-')) throw new Error('Unverifiable target dependency lock entry.');
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
  if (existsSync(projectConfig)) {
    const files = new PoolingFiles(projectConfig);
    const identity = files.inspect(projectConfig);
    files.stage(stagedConfig, projectConfig, identity, readFileSync(projectConfig));
  }
  const manifest = readFileSync(join(root, 'package.json'));
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
    await call(['install', '--package-lock-only', ...args], { cwd: root, env });
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
