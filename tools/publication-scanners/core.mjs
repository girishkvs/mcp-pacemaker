import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants, createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';

export const LIMITS = Object.freeze({
  timeoutMs: 600_000, outputBytes: 32 * 1024 * 1024,
  fileBytes: 256 * 1024 * 1024, treeBytes: 1024 * 1024 * 1024, files: 200_000,
  archiveDepth: 20, decodeDepth: 5,
});

export class ScannerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ScannerError';
    this.code = code;
  }
}

export function requireCondition(condition, code) {
  if (!condition) throw new ScannerError(code);
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function fileDigest(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}

export function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new ScannerError('invalid-json');
  }
}

export async function readJson(path) {
  const info = await lstat(path);
  requireCondition(info.isFile() && info.size <= LIMITS.outputBytes, 'invalid-input-file');
  const bytes = await readFile(path);
  return { value: parseJson(bytes.toString('utf8')), sha256: sha256(bytes) };
}

export async function guarded(kind, action) {
  const startedAt = new Date().toISOString();
  try {
    return { schemaVersion: 1, kind, startedAt, ...await action(), completedAt: new Date().toISOString() };
  } catch (error) {
    // Never serialize child output, native errors, paths, matches or error causes.
    return {
      schemaVersion: 1, kind, startedAt, completedAt: new Date().toISOString(), status: 'error',
      error: error instanceof ScannerError ? error.code : 'scanner-operation-failed',
    };
  }
}

export async function workspace(action) {
  // Only owned scratch creation resolves temp aliases; external scan roots retain their strict guards.
  const root = await mkdtemp(join(await realpath(tmpdir()), 'publication-scanners-'));
  const identity = await lstat(root, { bigint: true });
  requireCondition(identity.isDirectory() && !identity.isSymbolicLink(), 'temporary-directory-identity-changed');
  try {
    await mkdir(join(root, 'home'));
    await writeFile(join(root, 'gitconfig'), '');
    return await action(root);
  } finally {
    const current = await lstat(root, { bigint: true });
    requireCondition(current.isDirectory() && !current.isSymbolicLink() && current.ino === identity.ino &&
      current.dev === identity.dev, 'temporary-directory-identity-changed');
    await rm(root, { recursive: true, force: false });
  }
}

export function isolatedEnvironment(root) {
  const env = {};
  // No inherited scanner settings, tokens, proxies, SSH agents, npm config or Git credentials.
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT']) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return {
    ...env, HOME: join(root, 'home'), USERPROFILE: join(root, 'home'),
    XDG_CONFIG_HOME: join(root, 'home'), XDG_CACHE_HOME: join(root, 'home'),
    TMP: root, TEMP: root, TMPDIR: root, NO_COLOR: '1', TERM: 'dumb',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(root, 'gitconfig'),
    GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.bareRepository', GIT_CONFIG_VALUE_0: 'explicit',
    GIT_TERMINAL_PROMPT: '0', GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: 'file',
    GIT_NO_REPLACE_OBJECTS: '1', GIT_GRAFT_FILE: join(root, 'no-grafts'),
    GIT_OPTIONAL_LOCKS: '0', GOPROXY: 'off', GOTOOLCHAIN: 'local', GOTELEMETRY: 'off',
  };
}

export async function runBounded(file, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? LIMITS.timeoutMs;
  const maxOutputBytes = options.maxOutputBytes ?? LIMITS.outputBytes;
  requireCondition(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 &&
    timeoutMs <= LIMITS.timeoutMs, 'invalid-process-timeout');
  requireCondition(Number.isSafeInteger(maxOutputBytes) && maxOutputBytes > 0 &&
    maxOutputBytes <= LIMITS.treeBytes + LIMITS.files * 128, 'invalid-process-output-limit');
  requireCondition(options.input === undefined ||
    (Buffer.isBuffer(options.input) && options.input.length <= LIMITS.outputBytes), 'invalid-process-input');
  return new Promise((resolveResult, reject) => {
    const stdout = [];
    const stderr = [];
    let size = 0;
    let failure;
    let settled = false;
    const child = spawn(file, args, {
      cwd: options.cwd, env: options.env, shell: false, windowsHide: true,
      detached: process.platform !== 'win32', stdio: [options.input ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    });
    const stop = code => {
      if (failure) return;
      failure = code;
      if (!Number.isSafeInteger(child.pid)) {
        finish();
        return;
      }
      if (process.platform === 'win32') {
        // /PID targets only this owned process tree, never a process name.
        const killer = spawn(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'),
          ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
        killer.on('error', () => child.kill());
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
      setTimeout(() => finish(), 2000).unref();
    };
    const finish = (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (failure) {
        reject(new ScannerError(failure));
      } else if (signal) {
        reject(new ScannerError('scanner-terminated'));
      } else {
        const output = Buffer.concat(stdout);
        resolveResult({ code, stdout: options.binaryOutput ? output : output.toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8') });
      }
    };
    const collect = target => bytes => {
      size += bytes.length;
      if (size > maxOutputBytes) {
        stop('scanner-output-limit');
      } else if (!failure) {
        target.push(bytes);
      }
    };
    const timer = setTimeout(() => stop('scanner-timeout'), timeoutMs);
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.on('error', () => {
      failure = 'scanner-start-failed';
      finish();
    });
    child.on('close', finish);
    if (options.input) {
      child.stdin.on('error', () => {
        if (!settled &&
            !failure) stop('scanner-input-failed');
      });
      child.stdin.end(options.input);
    }
  });
}

export async function inventory(root, { source = false, copyTo, trackedPaths = [] } = {}) {
  requireCondition(typeof root === 'string' && isAbsolute(root), 'absolute-root-required');
  const rootInfo = await lstat(root);
  requireCondition(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(), 'invalid-root');
  const canonical = await realpath(root);
  const samePath = process.platform === 'win32'
    ? resolve(root).toLowerCase() === canonical.toLowerCase()
    : resolve(root) === canonical;
  requireCondition(samePath, 'root-link-not-supported');
  const entries = [];
  let bytes = 0;
  const visit = async (directory, relative = '') => {
    const names = (await readdir(directory)).sort();
    for (const name of names) {
      const path = join(directory, name);
      const local = relative ? `${relative}/${name}` : name;
      const info = await lstat(path);
      const generatedDependency = name === 'node_modules' && info.isDirectory() &&
        !trackedPaths.some(tracked => tracked.startsWith(`${local}/`));
      if (source &&
          (name === '.git' || generatedDependency)) continue;
      requireCondition(!info.isSymbolicLink(), 'symlink-scope-not-supported');
      if (info.isDirectory()) {
        await visit(path, local);
      } else {
        requireCondition(info.isFile(), 'special-file-not-supported');
        bytes += info.size;
        requireCondition(info.size <= LIMITS.fileBytes && bytes <= LIMITS.treeBytes &&
          entries.length < LIMITS.files, 'input-size-limit');
        entries.push({ path: local, size: info.size, mode: info.mode & 0o777, sha256: await fileDigest(path) });
        if (copyTo) {
          const target = join(copyTo, local);
          await mkdir(dirname(target), { recursive: true });
          await copyFile(path, target, constants.COPYFILE_EXCL);
          requireCondition(await fileDigest(target) === entries.at(-1).sha256, 'source-changed-during-copy');
        }
      }
    }
  };
  await visit(root);
  requireCondition(entries.length > 0, 'empty-scan-scope');
  return { entries, evidence: { files: entries.length, bytes, sha256: sha256(JSON.stringify(entries)) } };
}

export function validateBinding(binding, artifactRequired = false) {
  requireCondition(binding && /^[a-f0-9]{40,64}$/.test(binding.commit), 'commit-binding-required');
  if (artifactRequired ||
      binding.artifactSha256 !== undefined) {
    requireCondition(/^[a-f0-9]{64}$/.test(binding.artifactSha256), 'artifact-binding-required');
  }
  return { commit: binding.commit, ...(binding.artifactSha256 ? { artifactSha256: binding.artifactSha256 } : {}) };
}
