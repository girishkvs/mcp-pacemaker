import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import { POLICY, digest, publicationTagName, sameDigests, validatePackage, validateSource } from './policy.mjs';
import { inspectTarball } from './tarball.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const LIMIT = 128 * 1024 * 1024;
const MODES = ['npm-default', 'disabled'];
export const MATRIX = Object.freeze(['linux', 'win32', 'darwin'].flatMap(platform =>
  [{ node: '22.23.2', npm: '11.6.1' }, { node: '24.21.0', npm: '12.0.2' }]
    .map(pair => Object.freeze({
      platform, ...pair,
      os: { linux: 'Linux', win32: 'Windows', darwin: 'macOS' }[platform],
      image: { linux: 'ubuntu-24.04', win32: 'windows-2025', darwin: 'macos-15' }[platform],
      jobName: `consumer (${platform}, ${pair.npm})`,
    }))));

const json = path => JSON.parse(readFileSync(path, 'utf8'));
const sha256 = bytes => digest(bytes).sha256;
const sourceTuple = approval => Object.fromEntries(['ref', 'tagObject', 'commit', 'tree']
  .map(key => [key, approval[key]]));
const artifactName = (env, lane) => `npm-consumer-${env.GITHUB_RUN_ID}-1-${lane.platform}-${lane.npm}`;
const sha = value => assert.match(value ?? '', /^[a-f0-9]{64}$/, 'Invalid SHA256');
const id = value => {
  assert.match(String(value ?? ''), /^[1-9][0-9]*$/, 'Invalid GitHub ID');
  return String(value);
};
const archiveDigest = value => {
  const hex = (value ?? '').replace(/^sha256:/, '');
  sha(hex);
  return `sha256:${hex}`;
};

export function validateMatrixContext(env, approval, event) {
  assert.equal(env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.ok(['Linux', 'Windows', 'macOS'].includes(env.RUNNER_OS));
  assert.ok(['X64', 'ARM64'].includes(env.RUNNER_ARCH));
  assert.ok(env.RUNNER_NAME);
  for (const [key, value] of Object.entries({
    GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_API_URL: 'https://api.github.com', GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REPOSITORY: POLICY.repository, GITHUB_REPOSITORY_OWNER: POLICY.owner,
    GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner, GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF: approval.ref, GITHUB_SHA: approval.commit, GITHUB_WORKFLOW_SHA: approval.commit,
    GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`,
  })) assert.equal(env[key], value, `Wrong ${key}`);
  id(env.GITHUB_RUN_ID);
  id(env.GITHUB_REPOSITORY_ID);
  assert.equal(approval.schemaVersion, 1);
  assert.equal(approval.scope, 'prepare');
  assert.equal(approval.approver, POLICY.owner);
  assert.equal(approval.name, POLICY.name);
  assert.ok(['1.3.1', '2.0.1'].includes(approval.version));
  publicationTagName(approval.ref, approval.version);
  for (const key of ['tagObject', 'commit', 'tree']) assert.match(approval[key] ?? '', /^[a-f0-9]{40}$/);
  // Source preparation checks freshness once. Long-running gates do not spend another approval.
  if (event) {
    assert.equal(event.inputs?.action, 'prepare');
    assert.deepEqual(JSON.parse(event.inputs.approval), approval, 'Approval is not the actual dispatch input');
    assert.equal(event.repository?.full_name, POLICY.repository);
    assert.equal(event.repository.private, false);
    assert.equal(event.repository.fork, false);
    assert.equal(event.sender?.login, POLICY.owner);
  }
}

export function matrixLane(env, runtime = process) {
  const lane = MATRIX.find(item => item.platform === env.MATRIX_PLATFORM &&
    item.node === env.MATRIX_NODE &&
    item.npm === env.MATRIX_NPM);
  assert.ok(lane, 'Unsupported consumer lane');
  assert.equal(env.RUNNER_OS, lane.os);
  assert.equal(runtime.platform, lane.platform);
  assert.equal(runtime.versions.node, lane.node);
  assert.equal(runtime.arch, { X64: 'x64', ARM64: 'arm64' }[env.RUNNER_ARCH]);
  return lane;
}

export function isolatedConsumerEnvironment(env, home, node = process.execPath) {
  const child = {};
  for (const key of ['SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'COMSPEC', 'PATHEXT']) {
    if (env[key]) child[key] = env[key];
  }
  for (const dir of ['tmp', 'prefix', 'cache', 'config', 'data', 'AppData/Roaming', 'AppData/Local']) {
    mkdirSync(join(home, dir), { recursive: true });
  }
  for (const file of ['user.npmrc', 'global.npmrc']) {
    writeFileSync(join(home, file), '', { flag: 'wx', mode: 0o600 });
  }
  return {
    ...child, PATH: `${dirname(node)}${delimiter}${env.PATH ?? env.Path ?? ''}`,
    HOME: home, USERPROFILE: home, APPDATA: join(home, 'AppData/Roaming'),
    LOCALAPPDATA: join(home, 'AppData/Local'), TMP: join(home, 'tmp'),
    TEMP: join(home, 'tmp'), TMPDIR: join(home, 'tmp'), XDG_CONFIG_HOME: join(home, 'config'),
    XDG_DATA_HOME: join(home, 'data'), XDG_STATE_HOME: join(home, 'data'),
    XDG_CACHE_HOME: join(home, 'cache'), CI: 'true', NO_COLOR: '1',
    npm_config_userconfig: join(home, 'user.npmrc'), npm_config_globalconfig: join(home, 'global.npmrc'),
    npm_config_cache: join(home, 'cache'), npm_config_prefix: join(home, 'prefix'),
    npm_config_registry: POLICY.registry, npm_config_audit: 'false', npm_config_fund: 'false',
  };
}

export function execute(command, args, options) {
  const result = spawnSync(command, args, {
    encoding: 'utf8', shell: false, windowsHide: true, maxBuffer: LIMIT,
    timeout: 15 * 60 * 1000, ...options,
  });
  assert.equal(result.error, undefined, 'Command failed to start; no retry');
  assert.equal(result.signal, null, 'Command terminated; no retry');
  assert.equal(result.status, 0, 'Command failed; no report generated');
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

// Bind downloaded files to the SHA256 of the actual API archive, not an action warning.
// Only small, ordinary stored/deflated ZIPs are accepted; no links, ZIP64 or path overrides.
export function zipFiles(bytes) {
  assert.ok(Buffer.isBuffer(bytes) &&
    bytes.length <= LIMIT);
  let end = bytes.length - 22;
  const first = Math.max(0, end - 65535);
  while (end >= first &&
    bytes.readUInt32LE(end) !== 0x06054b50) end--;
  assert.ok(end >= first, 'Missing ZIP end record');
  assert.equal(end + 22 + bytes.readUInt16LE(end + 20), bytes.length);
  assert.equal(bytes.readUInt16LE(end + 4), 0);
  assert.equal(bytes.readUInt16LE(end + 6), 0);
  const count = bytes.readUInt16LE(end + 10);
  assert.ok(count > 0 &&
    count < 10000);
  assert.equal(bytes.readUInt16LE(end + 8), count);
  let cursor = bytes.readUInt32LE(end + 16);
  const centralEnd = cursor + bytes.readUInt32LE(end + 12);
  assert.equal(centralEnd, end, 'Unsupported ZIP layout');
  const files = new Map();
  const names = new Set();
  let total = 0;
  for (let index = 0; index < count; index++) {
    assert.ok(cursor + 46 <= centralEnd);
    assert.equal(bytes.readUInt32LE(cursor), 0x02014b50);
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    assert.equal(flags & ~0x080e, 0, 'Encrypted or unsupported ZIP entry');
    assert.ok([0, 8].includes(method));
    const compressed = bytes.readUInt32LE(cursor + 20);
    const size = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8');
    assert.match(name, /^[A-Za-z0-9_./@+-]+$/, 'Unsafe archive path');
    assert.ok(!name.startsWith('/') &&
      name.replace(/\/$/, '').split('/').every(part => part !== '' &&
        part !== '.' &&
        part !== '..'), 'Archive path traversal');
    assert.ok(!names.has(name.toLowerCase()), 'Duplicate archive member');
    names.add(name.toLowerCase());
    const kind = (bytes.readUInt32LE(cursor + 38) >>> 16) & 0o170000;
    assert.ok([0, 0o100000, 0o040000].includes(kind), 'Archive links/special files are forbidden');
    assert.equal(bytes.readUInt16LE(cursor + 34), 0);
    const local = bytes.readUInt32LE(cursor + 42);
    assert.ok(local + 30 <= bytes.readUInt32LE(end + 16));
    assert.equal(bytes.readUInt32LE(local), 0x04034b50);
    assert.equal(bytes.readUInt16LE(local + 6), flags);
    assert.equal(bytes.readUInt16LE(local + 8), method);
    const localNameLength = bytes.readUInt16LE(local + 26);
    assert.equal(bytes.subarray(local + 30, local + 30 + localNameLength).toString('utf8'), name);
    const start = local + 30 + localNameLength + bytes.readUInt16LE(local + 28);
    assert.ok(start + compressed <= bytes.readUInt32LE(end + 16));
    total += size;
    assert.ok(total <= LIMIT, 'Archive expands beyond limit');
    const packed = bytes.subarray(start, start + compressed);
    const data = method === 0 ? packed : inflateRawSync(packed, { maxOutputLength: LIMIT });
    assert.equal(data.length, size);
    if (name.endsWith('/')) assert.equal(size, 0);
    else files.set(name, data);
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  assert.equal(cursor, centralEnd);
  return files;
}

function localFiles(directory, prefix = '') {
  const stat = lstatSync(directory);
  assert.ok(stat.isDirectory() &&
    !stat.isSymbolicLink(), 'Expected a real artifact directory');
  const files = new Map();
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    assert.ok(!entry.isSymbolicLink(), 'Local artifact links are forbidden');
    const name = `${prefix}${entry.name}`;
    if (entry.isDirectory()) {
      for (const [key, value] of localFiles(join(directory, entry.name), `${name}/`)) files.set(key, value);
    } else {
      assert.ok(entry.isFile());
      assert.ok(lstatSync(join(directory, entry.name)).size <= LIMIT);
      files.set(name, readFileSync(join(directory, entry.name)));
    }
  }
  return files;
}

export function githubReaders(env, { fetcher = fetch } = {}) {
  const api = async path => {
    assert.ok(env.GITHUB_TOKEN, 'Read-only artifact/job token required');
    const response = await fetcher(`https://api.github.com/repos/${POLICY.repository}/${path}`, {
      headers: { authorization: `Bearer ${env.GITHUB_TOKEN}`, accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28' },
      redirect: 'manual', signal: AbortSignal.timeout(30_000),
    });
    return response;
  };
  const get = async path => {
    const response = await api(path);
    assert.equal(response.status, 200, 'GitHub read failed; no fallback');
    return response.json();
  };
  const pages = async (path, key) => {
    const all = [];
    for (let page = 1; page <= 20; page++) {
      const result = await get(`${path}?per_page=100&page=${page}`);
      assert.ok(Array.isArray(result[key]));
      all.push(...result[key]);
      if (all.length === result.total_count) return all;
      assert.ok(result[key].length > 0, 'Incomplete GitHub pagination');
    }
    throw new Error('Unexpected GitHub result count');
  };
  return {
    readArtifactMetadata: artifactId => get(`actions/artifacts/${id(artifactId)}`),
    readArtifacts: runId => pages(`actions/runs/${id(runId)}/artifacts`, 'artifacts'),
    readJobs: (runId, attempt) => pages(`actions/runs/${id(runId)}/attempts/${id(attempt)}/jobs`, 'jobs'),
    readArtifactArchive: async artifactId => {
      const response = await api(`actions/artifacts/${id(artifactId)}/zip`);
      assert.equal(response.status, 302, 'Expected official artifact download redirect');
      const location = new URL(response.headers.get('location'));
      assert.equal(location.protocol, 'https:');
      assert.equal(location.username, '');
      assert.equal(location.password, '');
      // Follow only the signed location returned by the authenticated GitHub API, without its token.
      const archive = await fetcher(location, { redirect: 'error', signal: AbortSignal.timeout(120_000) });
      assert.equal(archive.status, 200, 'Artifact download failed; no fallback');
      const chunks = [];
      let length = 0;
      for await (const chunk of archive.body) {
        length += chunk.length;
        assert.ok(length <= LIMIT, 'Artifact archive too large');
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    },
  };
}

function metadataBinding(metadata, env, name, expectedId, expectedDigest) {
  assert.equal(id(metadata.id), id(expectedId));
  assert.equal(metadata.name, name);
  assert.equal(metadata.expired, false);
  assert.match(metadata.digest ?? '', /^sha256:[a-f0-9]{64}$/);
  if (expectedDigest) assert.equal(metadata.digest, archiveDigest(expectedDigest));
  assert.equal(id(metadata.workflow_run?.id), id(env.GITHUB_RUN_ID));
  assert.equal(metadata.workflow_run.head_sha, env.GITHUB_SHA);
  for (const key of ['repository_id', 'head_repository_id']) {
    assert.equal(id(metadata.workflow_run[key]), id(env.GITHUB_REPOSITORY_ID));
  }
}

async function verifiedArchive(metadata, readers, directory) {
  const archive = await readers.readArtifactArchive(metadata.id);
  assert.equal(`sha256:${sha256(archive)}`, metadata.digest, 'Artifact API archive digest mismatch');
  const files = zipFiles(archive);
  const local = localFiles(directory);
  assert.deepEqual([...local.keys()].sort(), [...files.keys()].sort(), 'Downloaded artifact file set mismatch');
  for (const [name, bytes] of files) {
    assert.equal(sha256(local.get(name)), sha256(bytes), 'Downloaded artifact bytes differ from API archive');
  }
  return files;
}

export async function verifyPreparedBundle({
  directory, approval, env, readArtifactMetadata, readArtifactArchive,
}) {
  validateMatrixContext(env, approval);
  const readers = { ...githubReaders(env), ...Object.fromEntries(Object.entries({
    readArtifactMetadata, readArtifactArchive,
  }).filter(([, value]) => value)) };
  const metadata = await readers.readArtifactMetadata(id(env.PREPARED_ARTIFACT_ID));
  metadataBinding(metadata, env, `npm-prepared-${env.GITHUB_RUN_ID}-1`,
    env.PREPARED_ARTIFACT_ID, archiveDigest(env.PREPARED_ARTIFACT_DIGEST));
  const files = await verifiedArchive(metadata, readers, directory);
  sha(env.PREPARED_MANIFEST_SHA256);
  assert.ok(files.has('prepared.json') &&
    files.has('candidate.tgz') &&
    files.has('source-gates.json'), 'Incomplete prepared bundle');
  assert.equal(sha256(files.get('prepared.json')), env.PREPARED_MANIFEST_SHA256);
  const prepared = JSON.parse(files.get('prepared.json').toString('utf8'));
  assert.equal(prepared.schemaVersion, 1);
  assert.equal(prepared.status, 'prepared-awaiting-platform-gates');
  assert.equal(prepared.name, POLICY.name);
  assert.equal(prepared.version, approval.version);
  assert.deepEqual(prepared.source, sourceTuple(approval));
  assert.deepEqual(prepared.toolchain, { node: POLICY.node, npm: POLICY.npm });
  assert.equal(prepared.artifact.filename, 'candidate.tgz');
  const artifact = digest(files.get('candidate.tgz'));
  sameDigests(artifact, prepared.artifact);
  sameDigests(artifact, {
    sha256: env.PREPARED_TARBALL_SHA256, sha512: env.PREPARED_TARBALL_SHA512,
    integrity: env.PREPARED_TARBALL_INTEGRITY,
  });
  assert.equal(sha256(files.get('source-gates.json')), prepared.sourceReportSha256);
  const inspection = inspectTarball(files.get('candidate.tgz'), approval);
  assert.deepEqual(inspection.files, prepared.artifact.files, 'Prepared file manifest differs from actual tarball');
  return { prepared, inspection, sourceArtifact: {
    id: id(metadata.id), digest: metadata.digest, preparedSha256: env.PREPARED_MANIFEST_SHA256,
    sourceReportSha256: prepared.sourceReportSha256,
  } };
}

function requireJob(jobs, lane, env) {
  const matches = jobs.filter(job => job.name === lane.jobName);
  assert.equal(matches.length, 1, `Missing/duplicate current-run job: ${lane.jobName}`);
  const job = matches[0];
  id(job.id);
  id(job.runner_id);
  assert.ok(job.runner_name);
  assert.equal(id(job.run_id), id(env.GITHUB_RUN_ID));
  assert.equal(job.run_attempt, 1);
  assert.equal(job.head_sha, env.GITHUB_SHA);
  assert.equal(job.status, 'completed');
  assert.equal(job.conclusion, 'success', `Consumer job did not succeed: ${lane.jobName}`);
  assert.ok(job.labels?.includes(lane.image), 'Consumer ran on a different image');
  for (const name of ['Require supported hosted runner', 'Verify source transfer and run real consumers',
    'Upload one consumer report']) {
    const steps = job.steps?.filter(step => step.name === name);
    assert.equal(steps?.length, 1, `Missing consumer step: ${name}`);
    assert.equal(steps[0].status, 'completed');
    assert.equal(steps[0].conclusion, 'success', `Skipped/failed consumer step: ${name}`);
  }
  return job;
}

export async function selectMatrixArtifacts({ approval, env, ...injected }) {
  validateMatrixContext(env, approval);
  const readers = { ...githubReaders(env), ...injected };
  const artifacts = await readers.readArtifacts(env.GITHUB_RUN_ID);
  const jobs = await readers.readJobs(env.GITHUB_RUN_ID, 1);
  const matching = artifacts.filter(item => item.name.startsWith(`npm-consumer-${env.GITHUB_RUN_ID}-`));
  assert.equal(matching.length, MATRIX.length, 'Expected exactly six current-run consumer artifacts');
  const selected = [];
  const ids = new Set();
  for (const lane of MATRIX) {
    const candidates = matching.filter(item => item.name === artifactName(env, lane));
    assert.equal(candidates.length, 1, `Missing/duplicate artifact for ${lane.jobName}`);
    const metadata = await readers.readArtifactMetadata(candidates[0].id);
    metadataBinding(metadata, env, artifactName(env, lane), candidates[0].id, candidates[0].digest);
    assert.ok(!ids.has(id(metadata.id)), 'Reused matrix artifact ID');
    ids.add(id(metadata.id));
    selected.push({ lane, metadata, job: requireJob(jobs, lane, env) });
  }
  return selected;
}

function workflowBinding(env) {
  return { repository: POLICY.repository, path: POLICY.workflow, ref: env.GITHUB_WORKFLOW_REF,
    commit: env.GITHUB_SHA, runId: env.GITHUB_RUN_ID, attempt: 1 };
}

function commandEvidence(command, result) {
  return { command, commandSha256: sha256(JSON.stringify(command)),
    stdoutSha256: sha256(result.stdout), stderrSha256: sha256(result.stderr), exitCode: 0 };
}

function checkEvidence(evidence, expected, stdout) {
  assert.equal(evidence.exitCode, 0);
  assert.deepEqual(evidence.command, expected, 'Unexpected executed command');
  assert.equal(evidence.commandSha256, sha256(JSON.stringify(expected)));
  sha(evidence.stdoutSha256);
  sha(evidence.stderrSha256);
  if (stdout !== undefined) assert.equal(evidence.stdoutSha256, sha256(stdout));
}

function consumerArgs(paths, approval, mode) {
  return [paths.cli, '--silent', 'run', 'consumer:check', '--', '--tarball', paths.tarball,
    '--sha256', paths.sha256, '--version', approval.version, '--name', POLICY.name,
    ...(mode === 'disabled' ? ['--ignore-scripts'] : [])];
}

function checkConsumer(result, lane, approval, hash, mode) {
  assert.equal(result.name, POLICY.name);
  assert.equal(result.version, approval.version);
  assert.equal(result.sha256, hash);
  assert.equal(result.node, `v${lane.node}`);
  assert.equal(result.npm, lane.npm);
  assert.equal(result.platform, lane.platform);
  assert.equal(result.installScripts, mode);
  assert.equal(result.producerLockCopied, false);
  assert.equal(result.installedBin, true);
  assert.equal(result.bridgeAndUi, true);
  assert.equal(result.registrySignature, 'pending-publication');
  assert.equal(result.provenance, 'not-verified-by-consumer-smoke');
  assert.ok(Array.isArray(result.dependencies) &&
    result.dependencies.length > 0);
  for (const dependency of result.dependencies) {
    assert.match(dependency.name ?? '', /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/);
    assert.match(dependency.version ?? '', /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/);
    assert.ok(dependency.integrity === null ||
      typeof dependency.integrity === 'string' &&
      /^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(dependency.integrity),
    'Integrity must be an actual SRI or explicit unavailable value');
  }
}

function nativeTap(stdout) {
  const counts = Object.fromEntries(['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'].map(key => {
    const matches = [...stdout.matchAll(new RegExp(`^# ${key} (\\d+)\\r?$`, 'gm'))];
    assert.equal(matches.length, 1, `Missing native TAP ${key}`);
    return [key, Number(matches[0][1])];
  }));
  assert.ok(counts.tests >= 9);
  assert.equal(counts.pass, counts.tests);
  for (const key of ['fail', 'cancelled', 'skipped', 'todo']) assert.equal(counts[key], 0);
  assert.ok(!/^(?:not ok\b|ok .+# (?:SKIP|TODO)\b)/im.test(stdout));
  for (const name of ['real helper inspection emits only one fingerprint and does not change file contents',
    'real helper prepares both files with matching security without writing config data',
    'real helper refuses a stale fingerprint without writing config data']) {
    assert.ok(stdout.split(/\r?\n/).some(line => /^ok \d+ - /.test(line) &&
      line.endsWith(name)), `Missing actual Windows helper execution: ${name}`);
  }
  return counts;
}

function helperFiles(inspection) {
  const files = inspection.files.filter(file => file.path.startsWith('bin/windows/'));
  assert.ok(files.some(file => file.path === 'bin/windows/PoolingSecurityHelper.exe'));
  assert.ok(files.some(file => file.path === 'bin/windows/PoolingSecurityHelper.build.json'));
  assert.ok(files.length >= 6);
  return files.map(({ path, sha256: hash }) => ({ path, sha256: hash }));
}

export async function runMatrix({
  approval, env, event, root = ROOT, runtime = process, executor = execute, ...readers
}) {
  validateMatrixContext(env, approval, event);
  const lane = matrixLane(env, runtime);
  assert.equal(env.GITHUB_JOB, 'consumers');
  const sourceDirectory = join(env.RUNNER_TEMP, 'npm-prepared');
  const bundle = await verifyPreparedBundle({ directory: sourceDirectory, approval, env, ...readers });
  const cli = resolve(env.NPM_CONSUMER_CLI ?? '');
  assert.match(relative(resolve(env.RUNNER_TEMP), cli).replaceAll('\\', '/'),
    /^npm-consumer-toolchain-[A-Za-z0-9]+\/prefix\/node_modules\/npm\/bin\/npm-cli\.js$/,
    'Use only the owned consumer npm CLI');
  assert.equal(json(resolve(dirname(cli), '../package.json')).name, 'npm');
  assert.equal(json(resolve(dirname(cli), '../package.json')).version, lane.npm);
  const home = mkdtempSync(join(env.RUNNER_TEMP, 'npm-consumer-home-'));
  const childEnv = isolatedConsumerEnvironment(env, home, runtime.execPath);
  const invoke = (file, args) => executor(file, args, { cwd: root, env: childEnv });
  const git = (...args) => invoke('git', ['-c', 'core.autocrlf=false', ...args]).stdout.trim();
  validateSource({
    tagType: git('cat-file', '-t', approval.ref), tagObject: git('rev-parse', approval.ref),
    tagCommit: git('rev-parse', `${approval.ref}^{commit}`), tagTree: git('rev-parse', `${approval.ref}^{tree}`),
    head: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}'),
    status: git('status', '--porcelain', '--untracked-files=all'),
    workflowMatches: git('hash-object', POLICY.workflow) === git('rev-parse', `${approval.commit}:${POLICY.workflow}`),
  }, approval);
  validatePackage(json(join(root, 'package.json')), approval);
  assert.ok(!existsSync(join(root, '.npmrc')), 'Project npm config is not allowed in the isolated runner');
  assert.equal(invoke(runtime.execPath, [cli, '--version']).stdout.trim(), lane.npm);
  const paths = { node: runtime.execPath, cli, root, tarball: join(sourceDirectory, 'candidate.tgz'),
    sha256: bundle.prepared.artifact.sha256 };
  const command = args => ({ file: paths.node, args, cwd: root });
  const ciArgs = [cli, 'ci', '--ignore-scripts'];
  const lockHash = sha256(readFileSync(join(root, 'package-lock.json')));
  const rootCi = commandEvidence(command(ciArgs), invoke(paths.node, ciArgs));
  const consumers = MODES.map(mode => {
    const args = consumerArgs(paths, approval, mode);
    const output = invoke(paths.node, args);
    const result = JSON.parse(output.stdout);
    checkConsumer(result, lane, approval, paths.sha256, mode);
    return { mode, result, stdout: output.stdout, evidence: commandEvidence(command(args), output) };
  });
  let nativeWindows = { status: 'not-applicable', reason: 'Not a Windows runner' };
  if (lane.platform === 'win32') {
    const files = helperFiles(bundle.inspection);
    for (const file of files) {
      assert.equal(sha256(readFileSync(join(root, file.path))), file.sha256,
        'Checkout helper bytes differ from the tarball');
    }
    const args = ['--test', '--test-reporter=tap', 'test/windows-security-helper.test.mjs'];
    const output = invoke(paths.node, args);
    nativeWindows = {
      status: 'actual-windows-execution', files, counts: nativeTap(output.stdout), stdout: output.stdout,
      evidence: commandEvidence(command(args), output), rebuild: 'not-performed',
      ordinaryDesktopToken: 'not-proven', inheritedBaseline: 'not-verified-by-matrix',
    };
  }
  assert.equal(sha256(readFileSync(join(root, 'package-lock.json'))), lockHash, 'Producer lock changed');
  sameDigests(digest(readFileSync(paths.tarball)), bundle.prepared.artifact);
  const report = {
    schemaVersion: 1, phase: 'consumer-matrix', name: POLICY.name, version: approval.version,
    source: sourceTuple(approval), sourceArtifact: bundle.sourceArtifact,
    artifact: digest(readFileSync(paths.tarball)), workflow: workflowBinding(env),
    job: { key: 'consumers', name: lane.jobName },
    runner: { environment: env.RUNNER_ENVIRONMENT, os: env.RUNNER_OS, arch: env.RUNNER_ARCH, name: env.RUNNER_NAME },
    toolchain: { node: lane.node, npm: lane.npm }, platform: lane.platform,
    paths, rootCi, consumers, nativeWindows,
  };
  const output = join(env.RUNNER_TEMP, 'npm-consumer-report');
  mkdirSync(output);
  writeFileSync(join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  return report;
}

export async function verifyMatrixReports({ directory, approval, prepared, env, ...injected }) {
  validateMatrixContext(env, approval);
  const readers = { ...githubReaders(env), ...injected };
  const bundle = await verifyPreparedBundle({
    directory: join(env.RUNNER_TEMP, 'npm-prepared'), approval, env, ...readers,
  });
  assert.deepEqual(prepared, bundle.prepared, 'Finalizer supplied different prepared bytes');
  const selected = await selectMatrixArtifacts({ approval, env, ...readers });
  assert.deepEqual(readdirSync(directory).sort(), selected.map(item => item.metadata.name).sort(),
    'Expected exactly the six immutable report directories');
  const consumerLanes = [];
  const nativeWindowsEvidence = [];
  const artifactEvidence = [];
  for (const { lane, metadata, job } of selected) {
    const files = await verifiedArchive(metadata, readers, join(directory, metadata.name));
    assert.deepEqual([...files.keys()], ['report.json'], 'Each matrix artifact must contain exactly one report');
    const report = JSON.parse(files.get('report.json').toString('utf8'));
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.phase, 'consumer-matrix');
    assert.equal(report.name, POLICY.name);
    assert.equal(report.version, approval.version);
    assert.deepEqual(report.source, sourceTuple(approval));
    assert.deepEqual(report.sourceArtifact, bundle.sourceArtifact);
    sameDigests(report.artifact, prepared.artifact);
    assert.deepEqual(report.workflow, workflowBinding(env));
    assert.deepEqual(report.job, { key: 'consumers', name: lane.jobName });
    assert.equal(report.platform, lane.platform);
    assert.deepEqual(report.toolchain, { node: lane.node, npm: lane.npm });
    assert.equal(report.runner.environment, 'github-hosted');
    assert.equal(report.runner.os, lane.os);
    assert.ok(['X64', 'ARM64'].includes(report.runner.arch));
    assert.equal(report.runner.name, job.runner_name);
    const paths = report.paths;
    assert.equal(paths.sha256, prepared.artifact.sha256);
    for (const key of ['node', 'cli', 'root', 'tarball']) {
      assert.equal(typeof paths[key], 'string');
      assert.ok(/^(?:[A-Za-z]:[\\/]|\/)/.test(paths[key]), 'Evidence path must be absolute');
    }
    const command = args => ({ file: paths.node, args, cwd: paths.root });
    checkEvidence(report.rootCi, command([paths.cli, 'ci', '--ignore-scripts']));
    assert.deepEqual(report.consumers.map(item => item.mode), MODES, 'Both consumer modes are required');
    for (const consumer of report.consumers) {
      assert.deepEqual(JSON.parse(consumer.stdout), consumer.result);
      checkConsumer(consumer.result, lane, approval, prepared.artifact.sha256, consumer.mode);
      checkEvidence(consumer.evidence, command(consumerArgs(paths, approval, consumer.mode)), consumer.stdout);
      consumerLanes.push({ platform: lane.platform, node: lane.node, npm: lane.npm,
        mode: consumer.mode, result: consumer.result, evidence: consumer.evidence,
        artifactId: id(metadata.id), jobId: id(job.id) });
    }
    if (lane.platform === 'win32') {
      const native = report.nativeWindows;
      assert.equal(native.status, 'actual-windows-execution');
      assert.deepEqual(native.files, helperFiles(bundle.inspection));
      assert.equal(native.rebuild, 'not-performed');
      assert.equal(native.ordinaryDesktopToken, 'not-proven');
      assert.equal(native.inheritedBaseline, 'not-verified-by-matrix');
      assert.deepEqual(native.counts, nativeTap(native.stdout));
      checkEvidence(native.evidence,
        command(['--test', '--test-reporter=tap', 'test/windows-security-helper.test.mjs']), native.stdout);
      nativeWindowsEvidence.push({ platform: lane.platform, node: lane.node, npm: lane.npm,
        ...native, artifactId: id(metadata.id), jobId: id(job.id) });
    } else {
      assert.deepEqual(report.nativeWindows, { status: 'not-applicable', reason: 'Not a Windows runner' });
    }
    artifactEvidence.push({ id: id(metadata.id), name: metadata.name, digest: metadata.digest,
      reportSha256: sha256(files.get('report.json')), runId: env.GITHUB_RUN_ID, attempt: 1,
      jobId: id(job.id), jobName: job.name });
  }
  return { consumerLanes, nativeWindowsEvidence, artifactEvidence };
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const env = process.env;
  const event = json(env.GITHUB_EVENT_PATH);
  const approval = JSON.parse(event.inputs.approval);
  validateMatrixContext(env, approval, event);
  assert.ok(isAbsolute(env.RUNNER_TEMP));
  if (process.argv.length === 3 &&
      process.argv[2] === 'run') {
    await runMatrix({ approval, env, event });
  } else if (process.argv.length === 3 &&
      process.argv[2] === 'select') {
    const selected = await selectMatrixArtifacts({ approval, env });
    writeFileSync(env.GITHUB_OUTPUT,
      `matrix-artifact-ids=${selected.map(item => id(item.metadata.id)).join(',')}\n`, { flag: 'a' });
  } else {
    throw new Error('Usage: node tools/npm-publication/matrix.mjs run|select');
  }
}
