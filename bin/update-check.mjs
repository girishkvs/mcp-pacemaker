import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { dirname, join, resolve, delimiter } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import semver from 'semver';

const runFile = promisify(execFile);

export function updateChannel(pkg) {
  if (typeof pkg.name !== 'string' ||
      !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(pkg.name)) {
    throw new Error('Invalid installed package name.');
  }
  if (typeof pkg.version !== 'string' ||
      !semver.valid(pkg.version) ||
      semver.prerelease(pkg.version)) {
    throw new Error('The installed CLI must have a stable SemVer version.');
  }
  const major = semver.major(pkg.version);
  if (major !== 1 &&
      major !== 2) {
    throw new Error(`No update channel is defined for major ${major}.`);
  }
  return major === 1 ? 'legacy' : 'latest';
}

export function channelTarget(pkg, tags) {
  const channel = updateChannel(pkg);
  const target = tags?.[channel];
  if (typeof target !== 'string' ||
      semver.valid(target) !== target ||
      semver.prerelease(target) ||
      semver.major(target) !== semver.major(pkg.version)) {
    throw new Error(`Channel "${channel}" has no valid stable same-major target. No fallback selected.`);
  }
  return target;
}

export function selectUpdate(pkg, tags, release) {
  const channel = updateChannel(pkg);
  const target = channelTarget(pkg, tags);
  if (!release ||
      Array.isArray(release) ||
      release.name !== pkg.name ||
      release.version !== target) {
    throw new Error(`The exact "${channel}" target could not be verified.`);
  }
  if (release.deprecated !== undefined &&
      release.deprecated !== '') {
    throw new Error(`The "${channel}" target is deprecated. No fallback selected.`);
  }
  const order = semver.compare(target, pkg.version);
  return {
    name: pkg.name,
    current: pkg.version,
    channel,
    target,
    status: order > 0 ? 'update-available' : order < 0 ? 'installed-ahead' : 'current',
    updateAvailable: order > 0,
    rollbackRequired: order < 0,
  };
}

export function validateRegistry(registry) {
  if (registry === undefined) return undefined;
  const url = new URL(registry);
  if (!['https:', 'http:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash) {
    throw new Error('Registry must be an HTTP(S) URL without credentials, query, or fragment. Use npm configuration for authentication.');
  }
  return url.href;
}

function npmCliPath() {
  const candidates = [];
  if (process.env.npm_execpath) candidates.push(process.env.npm_execpath);
  candidates.push(join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'));
  for (const directory of (process.env.PATH || '').split(delimiter)) {
    if (!directory) continue;
    candidates.push(join(directory, 'node_modules', 'npm', 'bin', 'npm-cli.js'));
    const launcher = join(directory, 'npm');
    if (existsSync(launcher)) candidates.push(realpathSync(launcher));
  }
  const path = candidates.find((candidate) => candidate.endsWith('npm-cli.js') && existsSync(candidate));
  if (!path) throw new Error('npm CLI not found. Install npm with Node.js or run through npm; no registry fallback was attempted.');
  return resolve(path);
}

export async function readNpmMetadata(spec, field, { registry, cache, run = runFile } = {}) {
  const args = [npmCliPath(), 'view', spec];
  if (field) args.push(field);
  args.push('--json', '--prefer-online', '--ignore-scripts', '--fetch-retries=0', '--fetch-timeout=8000', '--cache', cache);
  if (registry !== undefined) args.push('--registry', validateRegistry(registry));
  let stdout;
  try {
    ({ stdout } = await run(process.execPath, args, {
      encoding: 'utf8', timeout: 12000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
    }));
  } catch {
    // npm's diagnostics can contain private registry URLs and authentication details.
    throw new Error('Registry metadata unavailable (offline, denied, missing, or npm failed). Check your approved npm configuration; no fallback selected.');
  }
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error('npm returned invalid metadata. No fallback selected.');
  }
}

export async function checkForUpdate(pkg, { registry, read = readNpmMetadata } = {}) {
  updateChannel(pkg);
  registry = validateRegistry(registry);
  // An empty cache prevents an offline/stale response from certifying channel state.
  const cache = mkdtempSync(join(tmpdir(), 'mcp-update-'));
  try {
    const options = { registry, cache };
    const tags = await read(pkg.name, 'dist-tags', options);
    const target = channelTarget(pkg, tags);
    const release = await read(`${pkg.name}@${target}`, undefined, options);
    return selectUpdate(pkg, tags, release);
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
}

export function updateGuidance(result, { registry, platform = process.platform } = {}) {
  const quote = (value) => platform === 'win32'
    ? `'${value.replaceAll("'", "''")}'`
    : `'${value.replaceAll("'", "'\\''")}'`;
  const registryOption = registry === undefined ? '' : ` --registry ${quote(validateRegistry(registry))}`;
  const action = result.rollbackRequired
    ? 'Installed CLI is ahead of its channel. This is a deliberate rollback, NOT a normal update.'
    : result.updateAvailable ? 'A same-major CLI update is available.' : 'Installed CLI matches its channel.';
  return [
    `${result.name}: installed CLI ${result.current}; ${result.channel} -> ${result.target}. ${action}`,
    'Guidance only: no package, service, autostart, or host configuration was changed.',
    'Before replacement: identify every service using the installation root, its supervisor, autostart, port and config directory.',
    'For a 2.x downgrade, settle/cancel batches and recover interrupted transactions with 2.x first. Keep protected backups; never delete transaction files.',
    'Use the matching installation CLI to stop the selected managed service: mcp-pacemaker stop --port <port>.',
    'A successful managed stop holds its supervisor/autostart until an explicit start. Older/unmanaged supervisors require separately verified OS-service shutdown and disabled autostart.',
    'Do not overwrite ANY root still used by a bridge or supervisor: workers, helpers and UI load files later.',
    'Only after shutdown is verified, and after a deliberate rollback decision if installed-ahead:',
    `  npm install --global ${result.name}@${result.target}${registryOption}`,
    'Use the same approved npm registry configuration. Prefer a separate durable version root; one global prefix replaces the shared CLI bins.',
    'Re-register the intended durable autostart path if it changed, start deliberately, and verify backend version and a new instance ID. Refresh dashboard tabs and check active config, permissions and tool calls.',
    'Moving to another major is a separate migration; no cross-major target was selected.',
    'Side-by-side services need separate durable roots, config directories, HOME/host state and ports. import/init --config is an input host config, not a runtime profile.',
  ].join('\n');
}
