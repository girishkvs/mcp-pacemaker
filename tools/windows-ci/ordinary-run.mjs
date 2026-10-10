import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdtempSync, openSync, closeSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { queryCliCallerContext, requireOrdinaryUpgradeCaller } from '../../bin/windows-task-channel.mjs';
import { ensureWindowsProcessLifetime, observeWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const ENVIRONMENT = ['PATH', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'OS', 'ProgramFiles',
  'ProgramFiles(x86)', 'ProgramData', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
  'MCP_NATIVE_COMPILER', 'MCP_NATIVE_REFERENCES', 'MCP_POOLING_TRACE_RUN_FAULTS'];
const OPERATIONS = ['test', 'pooling-diagnostics', 'compat:prepare', 'test:compat', 'compat:clean',
  'probe', 'probe-npm', 'probe-exit', 'probe-error', 'probe-hang'];

function read(directory, name) {
  const path = join(directory, name);
  const stat = lstatSync(path);
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65536, 'Invalid ordinary-launch receipt');
  return JSON.parse(readFileSync(path, 'utf8'));
}

function write(directory, name, value) {
  const path = join(directory, name);
  writeFileSync(`${path}.tmp`, JSON.stringify(value), { flag: 'wx' });
  renameSync(`${path}.tmp`, path);
}

async function waitFor(directory, name, deadline) {
  while (!existsSync(join(directory, name))) {
    if (Date.now() > deadline) throw new Error(`Ordinary launch deadline waiting for ${name}`);
    if (name !== 'bootstrap.json' &&
        existsSync(join(directory, 'bootstrap.json'))) throw new Error('Desktop bootstrap exited before its required receipt');
    await delay(100);
  }
  return read(directory, name);
}

function argumentsFor(input) {
  assert.ok(OPERATIONS.includes(input.operation), 'Unsupported ordinary CI operation');
  if (input.operation === 'probe-npm') return [input.npm, '--version'];
  if (input.operation.startsWith('probe')) return [join(HERE, 'ordinary-probe.mjs'), input.operation, input.directory];
  if (input.operation === 'pooling-diagnostics') {
    return ['--test', '--test-concurrency=1', '--test-reporter=tap',
      '--test-name-pattern=real deadline diagnostics', 'test/pooling-api.test.mjs'];
  }
  return [input.npm, ...(input.operation === 'test' ? ['test'] : ['run', input.operation])];
}

export function operationBudgetMs(operation) {
  return operation === 'test' ? 3600000 : 2700000;
}

export async function prepare(operation, parentDirectory, timeoutMs = 2700000) {
  assert.equal(process.platform, 'win32');
  assert.ok(OPERATIONS.includes(operation), 'Unsupported ordinary CI operation');
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 3600000, 'Invalid bounded test deadline');
  const node = process.execPath;
  const npm = resolve(process.env.MCP_CI_NPM_CLI ?? join(dirname(node), 'node_modules/npm/bin/npm-cli.js'));
  assert.ok(existsSync(npm) && lstatSync(npm).isFile(), 'Explicit npm CLI is unavailable; supply MCP_CI_NPM_CLI, no fallback is selected');
  assert.equal(JSON.parse(readFileSync(join(dirname(npm), '../package.json'), 'utf8')).name, 'npm');
  const npmSha256 = createHash('sha256').update(readFileSync(npm)).digest('hex');
  const context = await queryCliCallerContext();
  const owner = await ensureWindowsProcessLifetime();
  const directory = mkdtempSync(join(parentDirectory, 'pacemaker-ordinary-'));
  const environment = { CI: 'true' };
  for (const key of ENVIRONMENT) {
    const entry = Object.entries(process.env).find(([name]) => name.toLowerCase() === key.toLowerCase());
    if (entry) environment[key] = entry[1];
  }
  environment.PATH = `${dirname(node)};${environment.PATH ?? ''}`;
  const input = { runId: randomUUID(), directory, operation, node, npm, npmSha256, cwd: ROOT, environment,
    owner, expectedSid: context.identity.ownerSid, expectedSession: context.identity.sessionId,
    startDeadline: Date.now() + 45000, deadline: Date.now() + timeoutMs };
  write(directory, 'input.json', input);
  return input;
}

export function launchDesktop(input) {
  const powershell = join(input.environment.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  return spawn(powershell, ['-NoProfile', '-NonInteractive', '-File',
    join(HERE, 'ordinary-desktop.ps1'), '-InputDirectory', input.directory],
  { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
}

export async function collect(input) {
  const directory = input.directory;
  const started = await waitFor(directory, 'started.json', input.startDeadline);
  assert.equal(started.runId, input.runId, 'Ordinary worker run identity differs');
  const observer = await observeWindowsProcessLifetime(started.owner);
  write(directory, 'armed.json', { runId: input.runId });
  let result;
  try {
    while (!existsSync(join(directory, 'context.json')) &&
        !existsSync(join(directory, 'result.json'))) {
      assert.ok(Date.now() <= input.startDeadline, 'Ordinary caller verification startup deadline exceeded');
      await delay(100);
    }
    if (existsSync(join(directory, 'context.json'))) {
      const context = read(directory, 'context.json');
      console.log(JSON.stringify({ node: context.nodeVersion,
        ordinaryEligible: context.context.ordinaryEligible, reason: context.context.reason,
        elevated: context.context.actorFacts?.elevated, enabledAdministrator: context.context.actorFacts?.enabledAdministrator,
        sameSid: context.context.identity.ownerSid === input.expectedSid,
        sameSession: context.context.identity.sessionId === input.expectedSession }));
    }
    result = await waitFor(directory, 'result.json', input.deadline + 5000);
    assert.equal(result.runId, input.runId);
  } finally {
    if (!existsSync(join(directory, 'cancel.json'))) write(directory, 'cancel.json', { runId: input.runId });
    await Promise.race([observer.done, delay(15000, undefined, { ref: false }).then(() => { throw new Error('Ordinary job cleanup unverified'); })]);
  }
  const bootstrap = await waitFor(directory, 'bootstrap.json', Date.now() + 15000);
  assert.equal(bootstrap.runId, input.runId);
  assert.equal(bootstrap.error, null, 'Ordinary bootstrap failed');
  assert.equal(bootstrap.exitCode, result.exitCode, 'Ordinary worker exit receipt differs');
  for (const [name, stream] of [['stdout.log', process.stdout], ['stderr.log', process.stderr]]) {
    if (existsSync(join(directory, name))) {
      await new Promise((resolveWrite, reject) => stream.write(readFileSync(join(directory, name)),
        error => error ? reject(error) : resolveWrite()));
    }
  }
  write(directory, 'verified.json', { runId: input.runId, exitCode: result.exitCode, activeProcesses: 0 });
  return result;
}

async function worker(directory) {
  let exitCode = 1;
  let input;
  let timer;
  let cancellation;
  const handles = [];
  try {
    input = read(directory, 'input.json');
    assert.equal(input.directory, resolve(directory));
    assert.equal(input.node.toLowerCase(), process.execPath.toLowerCase(), 'Matrix Node executable changed');
    assert.equal(input.cwd, ROOT);
    assert.equal(createHash('sha256').update(readFileSync(input.npm)).digest('hex'), input.npmSha256,
      'Explicit npm CLI changed before ordinary launch');
    assert.ok(Date.now() <= input.startDeadline && input.deadline <= Date.now() + 3600000, 'Expired or invalid run deadline');
    for (const name of Object.keys(input.environment)) assert.ok([...ENVIRONMENT, 'CI'].includes(name), 'Unexpected child environment');
    for (const name of Object.keys(process.env)) delete process.env[name];
    Object.assign(process.env, input.environment);
    process.chdir(input.cwd);
    const finish = (code, error) => {
      if (!existsSync(join(directory, 'result.json'))) write(directory, 'result.json', { runId: input.runId, exitCode: code, error });
      process.exit(code);
    };
    timer = setTimeout(() => finish(124, 'Ordinary test deadline exceeded'), Math.max(1, input.deadline - Date.now()));
    cancellation = setInterval(() => {
      if (existsSync(join(directory, 'cancel.json'))) finish(125, 'Ordinary controller cancelled');
    }, 100);
    const owner = await ensureWindowsProcessLifetime();
    write(directory, 'started.json', { runId: input.runId, owner });
    const armed = await waitFor(directory, 'armed.json', input.startDeadline);
    assert.equal(armed.runId, input.runId);
    const parent = await observeWindowsProcessLifetime(input.owner);
    parent.done.then(() => finish(125, 'Ordinary controller exited'), () => finish(125, 'Ordinary controller lifetime unverified'));
    const context = await queryCliCallerContext();
    write(directory, 'context.json', { runId: input.runId, context, node: process.execPath,
      nodeVersion: process.version, npm: input.npm, cwd: process.cwd() });
    const hasBinding = typeof input.expectedSid === 'string' &&
      input.expectedSid.length > 0 &&
      Number.isInteger(input.expectedSession);
    if (!hasBinding) throw new Error('Ordinary caller identity binding is unavailable');
    if (context.identity.ownerSid !== input.expectedSid ||
        context.identity.sessionId !== input.expectedSession) throw new Error('Ordinary worker SID/session differs');
    await requireOrdinaryUpgradeCaller();
    const stdout = openSync(join(directory, 'stdout.log'), 'wx');
    const stderr = openSync(join(directory, 'stderr.log'), 'wx');
    handles.push(stdout, stderr);
    const child = spawn(process.execPath, argumentsFor(input), {
      cwd: input.cwd, env: process.env, windowsHide: true, stdio: ['ignore', stdout, stderr],
    });
    exitCode = await new Promise((resolveExit, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => {
        if (signal ||
            !Number.isInteger(code)) reject(new Error('Ordinary test did not return an exit code'));
        else resolveExit(code);
      });
    });
    write(directory, 'result.json', { runId: input.runId, exitCode, error: null });
  } catch (error) {
    exitCode = 1;
    write(directory, 'result.json', { runId: input?.runId, exitCode: 1, error: error.message });
  } finally {
    clearTimeout(timer);
    clearInterval(cancellation);
    for (const handle of handles) closeSync(handle);
    process.exit(exitCode);
  }
}

async function main() {
  if (process.argv[2] === '--worker') return worker(resolve(process.argv[3]));
  const input = await prepare(process.argv[2], process.env.RUNNER_TEMP ?? tmpdir(), operationBudgetMs(process.argv[2]));
  setTimeout(() => process.exit(124), Math.max(1, input.deadline - Date.now() + 30000)).unref();
  console.log(`Ordinary CI evidence: ${input.directory}`);
  const cancel = () => {
    if (!existsSync(join(input.directory, 'cancel.json'))) write(input.directory, 'cancel.json', { runId: input.runId });
  };
  process.once('SIGINT', cancel);
  process.once('SIGTERM', cancel);
  const broker = launchDesktop(input);
  let brokerError = '';
  broker.stderr.on('data', bytes => { brokerError = (brokerError + bytes).slice(-4096); });
  broker.stdout.resume();
  broker.once('error', cancel);
  const result = await collect(input).catch(error => {
    cancel();
    if (existsSync(join(input.directory, 'result.json'))) {
      const failure = read(input.directory, 'result.json');
      if (failure.error) console.error(failure.error);
    }
    if (existsSync(join(input.directory, 'bootstrap.json'))) {
      const bootstrap = read(input.directory, 'bootstrap.json');
      if (bootstrap.error) console.error(bootstrap.error);
      for (const name of ['bootstrap.stdout', 'bootstrap.stderr']) {
        if (existsSync(join(input.directory, name))) process.stderr.write(readFileSync(join(input.directory, name)));
      }
    }
    throw new Error(`${error.message}; ${brokerError}`);
  });
  if (result.error) console.error(result.error);
  process.exit(result.exitCode);
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    setTimeout(() => process.exit(1), 1000).unref();
    process.stderr.write(`${error.message}\n`, () => process.exit(1));
  });
}
