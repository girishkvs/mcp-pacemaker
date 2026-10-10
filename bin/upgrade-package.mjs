import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';
import semver from 'semver';
import { npmCliPath, readNpmMetadata, validateRegistry } from './update-check.mjs';

const runFile = promisify(execFile);
const required = [
  'bin/cli.mjs', 'bin/cli-main.mjs', 'bin/cli-dispatch.mjs', 'bin/mcp-bridge.mjs', 'bin/service-control.mjs',
  'supervisor/supervise.mjs', 'supervisor/bridge-child.mjs',
  'bin/upgrade-capability.json', 'ui/dist/index.html',
];

export function exactVersion(value) {
  if (typeof value !== 'string' ||
      semver.valid(value) !== value ||
      semver.prerelease(value)) {
    throw new Error('--to requires a canonical stable version, for example 2.1.0 (not a tag or range).');
  }
  return value;
}

export function verifyArchive(bytes, integrity) {
  if (!Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > 32 * 1024 * 1024) throw new Error('Invalid package archive size.');
  const match = /^sha512-([A-Za-z0-9+/]+={0,2})$/.exec(integrity ?? '');
  if (!match) throw new Error('An exact SHA-512 package integrity is required.');
  const actual = createHash('sha512').update(bytes).digest();
  const expected = Buffer.from(match[1], 'base64');
  if (actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)) throw new Error('Package archive integrity mismatch.');
}

export function unpackUpgrade(bytes, version, destination, nodeVersion = process.versions.node) {
  exactVersion(version);
  const tar = gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 });
  const files = new Map();
  const seen = new Set();
  let offset = 0;
  let ended = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) {
      if (!tar.subarray(offset).every(value => value === 0)) throw new Error('Data after archive terminator.');
      ended = true;
      break;
    }
    const text = (start, size) => header.subarray(start, start + size).toString('utf8').replace(/\0.*$/s, '');
    const octal = (start, size) => {
      const value = text(start, size).trim();
      if (!/^[0-7]+$/.test(value)) throw new Error('Invalid archive numeric field.');
      return Number.parseInt(value, 8);
    };
    const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (octal(148, 8) !== checksum) throw new Error('Archive checksum mismatch.');
    const prefix = text(345, 155);
    const path = `${prefix ? `${prefix}/` : ''}${text(0, 100)}`;
    const type = text(156, 1);
    const size = octal(124, 12);
    if (path === 'package/' &&
        type === '5' &&
        size === 0) {
      offset += 512;
      continue;
    }
    if (!['', '0', '5'].includes(type) ||
        !/^package\/[A-Za-z0-9_./@+-]+$/.test(path)) throw new Error('Unsafe archive entry.');
    const relative = path.slice(8).replace(/\/$/, '');
    const parts = relative.split('/');
    if (parts.some(part => !part || part === '.' || part === '..') ||
        seen.has(relative.toLowerCase()) ||
        /(^|\/)(?:node_modules|\.npmrc|\.git)(\/|$)/i.test(relative)) throw new Error('Unsafe or duplicate archive path.');
    seen.add(relative.toLowerCase());
    offset += 512;
    if (offset + size > tar.length) throw new Error('Truncated archive.');
    if (type !== '5') files.set(relative, { bytes: tar.subarray(offset, offset + size), mode: octal(100, 8) });
    else if (size !== 0) throw new Error('Invalid archive directory.');
    offset += Math.ceil(size / 512) * 512;
  }
  if (!ended) throw new Error('Missing archive terminator.');
  const pkg = JSON.parse(files.get('package.json')?.bytes.toString('utf8') ?? 'null');
  if (pkg?.name !== 'mcp-pacemaker' ||
      pkg.version !== version ||
      pkg.bin?.['mcp-pacemaker'] !== 'bin/cli.mjs' ||
      pkg.bin?.['mcp-bridge'] !== 'bin/mcp-bridge.mjs' ||
      typeof pkg.engines?.node !== 'string' ||
      !semver.satisfies(nodeVersion, pkg.engines.node)) throw new Error('Package name, exact version or Node engine mismatch.');
  for (const path of required) {
    if (!files.get(path)?.bytes.length) throw new Error(`Target lacks managed upgrade capability: ${path}. No service was stopped.`);
  }
  const capability = JSON.parse(files.get('bin/upgrade-capability.json').bytes.toString('utf8'));
  if (capability.protocol !== 1 ||
      capability.portZero !== true ||
      capability.admission !== true ||
      capability.cli !== true) throw new Error('Target does not support managed readiness/admission/port allocation/CLI dispatch.');
  for (const file of files.values()) {
    if (![0o644, 0o755].includes(file.mode)) throw new Error('Unexpected package file mode.');
  }
  for (const [path, file] of files) {
    if (!path.endsWith('.exe')) continue;
    if (file.bytes[0] !== 0x4d ||
        file.bytes[1] !== 0x5a) throw new Error('Invalid packaged native binary.');
  }
  const native = ['bin/windows/PoolingSecurityHelper', 'bin/windows-lifetime/ProcessLifetimeHelper'];
  if (capability.legacyRestartProtocol === 1) {
    for (const path of [
      'bin/legacy-upgrade.mjs', 'bin/legacy-installation.mjs', 'bin/legacy-task.mjs', 'bin/legacy-1.3.json',
      'bin/windows-legacy-process.mjs', 'autostart/windows/legacy-task.ps1',
    ]) {
      if (!files.get(path)?.bytes.length) throw new Error(`Target legacy recovery dependency is missing: ${path}.`);
    }
    native.push('bin/windows-legacy/LegacyProcessBroker');
  }
  if (capability.accountWorkerProtocol === 1) {
    for (const path of [
      'bin/account-upgrade-controller.mjs', 'bin/account-upgrade-worker.mjs', 'bin/account-worker-session.mjs',
      'bin/account-task-adapter.mjs', 'bin/task-only-controller.mjs', 'bin/task-scope.mjs',
      'bin/task-transaction-protocol.mjs', 'bin/windows-task-channel.mjs', 'autostart/windows/account-task.ps1',
      'autostart/windows/inspect-worker-process-sessions.ps1',
    ]) {
      if (!files.get(path)?.bytes.length) throw new Error(`Target account worker dependency is missing: ${path}.`);
    }
    native.push('bin/windows-task-channel/TaskChannelGuard');
  }
  for (const base of native) {
    const binary = files.get(`${base}.exe`);
    const metadata = files.get(`${base}.build.json`);
    if (!binary ||
        !metadata) throw new Error('Missing packaged native binary identity.');
    const build = JSON.parse(metadata.bytes.toString('utf8'));
    if (createHash('sha256').update(binary.bytes).digest('hex') !== build.binarySha256) {
      throw new Error('Packaged native binary hash mismatch.');
    }
  }
  if (readdirSync(destination).length) throw new Error('Package destination is not empty.');
  for (const [path, file] of files) {
    const output = join(destination, path);
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    writeFileSync(output, file.bytes, { flag: 'wx', mode: file.mode });
  }
  return { version, files: [...files].map(([path, file]) => ({
    path, sha256: createHash('sha256').update(file.bytes).digest('hex'),
  })) };
}

export async function acquireUpgrade(version, directory, { registry, run = runFile } = {}) {
  exactVersion(version);
  registry = validateRegistry(registry);
  const cache = join(directory, 'cache');
  const metadata = await readNpmMetadata(`mcp-pacemaker@${version}`, undefined, { registry, cache, run });
  if (metadata.name !== 'mcp-pacemaker' ||
      metadata.version !== version ||
      metadata.deprecated) throw new Error('Exact target metadata was not verified.');
  const args = [npmCliPath(), 'pack', `mcp-pacemaker@${version}`, '--json', '--ignore-scripts',
    '--pack-destination', directory, '--cache', cache];
  if (registry !== undefined) args.push('--registry', registry);
  let stdout;
  try {
    ({ stdout } = await run(process.execPath, args, {
      cwd: process.cwd(), encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 4 * 1024 * 1024,
    }));
  } catch {
    throw new Error('Package acquisition failed under the configured npm policy. No registry or policy fallback was attempted.');
  }
  const result = normalizePackResult(JSON.parse(stdout), version);
  const bytes = readFileSync(join(directory, result.filename));
  verifyArchive(bytes, metadata.dist?.integrity);
  return { bytes, integrity: metadata.dist.integrity };
}

export function normalizePackResult(value, version) {
  let result;
  if (Array.isArray(value) &&
      value.length === 1) result = value[0];
  else if (value &&
      typeof value === 'object' &&
      Object.keys(value).length === 1 &&
      Object.hasOwn(value, 'mcp-pacemaker')) result = value['mcp-pacemaker'];
  if (!result ||
      Array.isArray(result) ||
      result.name !== 'mcp-pacemaker' ||
      result.version !== version ||
      result.filename !== `mcp-pacemaker-${version}.tgz`) throw new Error('Unexpected npm pack result.');
  return result;
}

export async function configuredRegistry(registry) {
  if (registry !== undefined) return validateRegistry(registry);
  try {
    const { stdout } = await runFile(process.execPath, [
      npmCliPath(), 'config', 'get', 'registry', '--logs-max=0', '--update-notifier=false',
    ], {
      encoding: 'utf8', windowsHide: true, timeout: 10000, maxBuffer: 16384,
    });
    return validateRegistry(stdout.trim());
  } catch {
    throw new Error('Effective npm registry could not be read. Set --registry explicitly; no fallback selected.');
  }
}
