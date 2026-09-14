import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, lstatSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { TOOL_PINS } from '../publication-scanners/index.mjs';

// Official release API asset digests and independently read release checksum files, 2026-09-13.
export const SCANNER_RELEASES = Object.freeze({
  gitleaks: Object.freeze({
    version: '8.30.1', repository: 'gitleaks/gitleaks',
    archive: 'gitleaks_8.30.1_linux_x64.tar.gz',
    sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
    checksums: 'gitleaks_8.30.1_checksums.txt',
    checksumsSha256: '061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae',
  }),
  trufflehog: Object.freeze({
    version: '3.97.1', repository: 'trufflesecurity/trufflehog',
    archive: 'trufflehog_3.97.1_linux_amd64.tar.gz',
    sha256: 'f863ea3a8d786f7d097870496c977944cce7372a2fe1e56707d965016e543ece',
    checksums: 'trufflehog_3.97.1_checksums.txt',
    checksumsSha256: 'a48f30708a533e13e95f6c72e7f6e375d489aa70d0802bf4beee9be5dad962f1',
  }),
});
export const GITLEAKS_CONFIG_URL = 'https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const requireValue = (condition, message) => { if (!condition) throw new Error(message); };

export function assertHostedScannerContext(env, runtime = process) {
  requireValue(runtime.platform === 'linux' &&
    runtime.arch === 'x64' &&
    env.GITHUB_ACTIONS === 'true' &&
    env.RUNNER_ENVIRONMENT === 'github-hosted' &&
    env.RUNNER_OS === 'Linux' &&
    env.RUNNER_ARCH === 'X64' &&
    env.ImageOS === 'ubuntu24' &&
    env.GITHUB_REPOSITORY === 'girishkvs/mcp-pacemaker', 'Scanner bootstrap requires the approved hosted Ubuntu 24.04 x64 job');
  for (const name of ['RUNNER_TEMP', 'GITHUB_ENV']) {
    requireValue(typeof env[name] === 'string' &&
      isAbsolute(env[name]) &&
      !/[\r\n]/.test(env[name]), `Hosted ${name} absolute path required`);
  }
}

async function download(url) {
  const approved = candidate => candidate.protocol === 'https:' &&
    ['github.com', 'release-assets.githubusercontent.com', 'raw.githubusercontent.com'].includes(candidate.hostname) &&
    !candidate.username &&
    !candidate.password;
  for (let redirects = 0; redirects < 4; redirects++) {
    requireValue(approved(new URL(url)), 'Unexpected scanner download host');
    const response = await fetch(url, {
      redirect: 'manual', credentials: 'omit', signal: AbortSignal.timeout(120_000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      url = new URL(response.headers.get('location'), url).href;
      continue;
    }
    requireValue(response.status === 200, 'Official scanner download denied or failed; no fallback');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      requireValue(size <= 256 * 1024 * 1024, 'Scanner download exceeds limit');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
  throw new Error('Too many official scanner download redirects');
}

export function releaseExecutable(archive, executable) {
  const tar = gunzipSync(archive, { maxOutputLength: 768 * 1024 * 1024 });
  let offset = 0;
  let result;
  let ended = false;
  const seen = new Set();
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      requireValue(tar.subarray(offset).every(byte => byte === 0), 'Data after release tar terminator');
      ended = true;
      break;
    }
    const text = (start, size) => header.subarray(start, start + size).toString().replace(/\0.*$/s, '');
    const octal = (start, size) => {
      const value = text(start, size).trim();
      requireValue(/^[0-7]+$/.test(value), 'Unsupported release tar number');
      return Number.parseInt(value, 8);
    };
    const sum = [...header].reduce((total, byte, index) => total + (index >= 148 && index < 156 ? 32 : byte), 0);
    requireValue(sum === octal(148, 8), 'Release tar header checksum mismatch');
    const name = `${text(345, 155) ? `${text(345, 155)}/` : ''}${text(0, 100)}`;
    const safeRelativePath = name.split('/').every(segment =>
      /^[A-Za-z0-9_.+-]+$/.test(segment) &&
      segment !== '.' &&
      segment !== '..');
    requireValue(safeRelativePath &&
      !seen.has(name) &&
      ['', '0'].includes(text(156, 1)), 'Unreviewed release archive entry');
    seen.add(name);
    const size = octal(124, 12);
    offset += 512;
    requireValue(size > 0 &&
      offset + size <= tar.length, 'Truncated or empty release entry');
    if (name === executable) result = Buffer.from(tar.subarray(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
  }
  requireValue(ended &&
    result?.length > 0, 'Pinned release executable missing');
  return result;
}

function execute(file, args, options) {
  const result = spawnSync(file, args, { ...options, encoding: 'utf8', shell: false,
    timeout: 30_000, maxBuffer: 1024 * 1024 });
  requireValue(!result.error &&
    result.status === 0, 'Pinned scanner version command failed');
  return `${result.stdout}${result.stderr}`.trim();
}

export async function installScanners({
  env = process.env, runtime = process, fetchBytes = download, run = execute,
} = {}) {
  assertHostedScannerContext(env, runtime);
  requireValue(realpathSync(env.RUNNER_TEMP) === resolve(env.RUNNER_TEMP) &&
    lstatSync(env.RUNNER_TEMP).isDirectory() &&
    lstatSync(env.GITHUB_ENV).isFile() &&
    !lstatSync(env.GITHUB_ENV).isSymbolicLink(), 'Hosted scanner paths must be real local files/directories');
  const root = mkdtempSync(join(env.RUNNER_TEMP, 'publication-scanners-'));
  const values = {};
  const provenance = [];
  for (const [name, pin] of Object.entries(SCANNER_RELEASES)) {
    requireValue(TOOL_PINS[name].version === pin.version, 'Scanner adapter/bootstrap pins differ');
    const base = `https://github.com/${pin.repository}/releases/download/v${pin.version}/`;
    const checksums = await fetchBytes(`${base}${pin.checksums}`);
    requireValue(hash(checksums) === pin.checksumsSha256, 'Official release checksum file changed');
    const entries = checksums.toString('utf8').trim().split(/\r?\n/).map(line => line.split(/\s+/));
    const entry = entries.filter(fields => fields[1] === pin.archive);
    requireValue(entry.length === 1 &&
      entry[0][0] === pin.sha256, 'Official release checksum does not match fixed archive pin');
    const archive = await fetchBytes(`${base}${pin.archive}`);
    requireValue(hash(archive) === pin.sha256, 'Scanner release archive digest mismatch');
    const binary = releaseExecutable(archive, name);
    const path = join(root, name);
    writeFileSync(path, binary, { flag: 'wx', mode: 0o700 });
    chmodSync(path, 0o700);
    const args = name === 'gitleaks' ? ['version'] : ['--no-update', '--no-verification', '--version'];
    const text = await run(path, args, {
      cwd: root, env: { PATH: env.PATH, HOME: root, TMPDIR: root, GIT_TERMINAL_PROMPT: '0' },
    });
    requireValue(name === 'gitleaks' ? [pin.version, `v${pin.version}`].includes(text)
      : text === `trufflehog ${pin.version}`, 'Pinned release reports wrong scanner version');
    const prefix = `MCP_${name.toUpperCase()}`;
    values[`${prefix}_BIN`] = path;
    values[`${prefix}_SHA256`] = hash(binary);
    provenance.push({ name, version: pin.version, archiveSha256: pin.sha256,
      checksumsSha256: pin.checksumsSha256, executableSha256: hash(binary),
      digestBasis: 'Executable extracted from independently pinned official release archive; not a separate upstream executable checksum' });
  }
  const config = await fetchBytes(GITLEAKS_CONFIG_URL);
  requireValue(hash(config) === TOOL_PINS.gitleaks.configSha256, 'Gitleaks upstream configuration digest mismatch');
  values.MCP_GITLEAKS_CONFIG = join(root, 'gitleaks.toml');
  writeFileSync(values.MCP_GITLEAKS_CONFIG, config, { flag: 'wx', mode: 0o600 });
  appendFileSync(env.GITHUB_ENV, Object.entries(values).map(([key, value]) => `${key}=${value}\n`).join(''));
  return { schemaVersion: 1, platform: 'linux-x64', tools: provenance,
    configSha256: hash(config), environmentKeys: Object.keys(values),
    cleanup: 'Owned RUNNER_TEMP directory retained for following source/finalizer steps; runner teardown removes it' };
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    requireValue(process.argv.length === 2, 'Scanner bootstrap accepts no arguments');
    console.log(JSON.stringify(await installScanners(), null, 2));
  } catch {
    console.error('Pinned hosted scanner bootstrap failed; no fallback or environment export on failure.');
    process.exitCode = 1;
  }
}
