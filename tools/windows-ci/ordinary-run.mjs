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
const GUARDIAN_CLEANUP_GRACE_MS = 30000;
const GUARDIAN_CHILD_STOP_MS = 10000;
const ENVIRONMENT = ['PATH', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'OS', 'ProgramFiles',
  'ProgramFiles(x86)', 'ProgramData', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
  'MCP_NATIVE_COMPILER', 'MCP_NATIVE_REFERENCES', 'MCP_POOLING_TRACE_RUN_FAULTS'];
const OPERATIONS = ['test', 'session-required', 'pooling-diagnostics', 'compat:prepare', 'test:compat', 'compat:clean',
  'probe', 'probe-npm', 'probe-exit', 'probe-error', 'probe-hang', 'probe-before-registration',
  'probe-after-registration', 'probe-after-run', 'probe-registration-uncertain',
  'probe-collision', 'probe-mismatch', 'probe-input-change', 'probe-stop-failure', 'probe-delete-failure',
  'probe-guardian-startup-stall', 'probe-guardian-operation-stall'];

function readBytes(directory, name) {
  const path = join(directory, name);
  const stat = lstatSync(path);
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65536, 'Invalid ordinary-launch receipt');
  return readFileSync(path);
}

function read(directory, name) {
  return JSON.parse(readBytes(directory, name).toString('utf8'));
}

function write(directory, name, value) {
  const path = join(directory, name);
  writeFileSync(`${path}.tmp`, JSON.stringify(value), { flag: 'wx' });
  renameSync(`${path}.tmp`, path);
}

async function waitFor(directory, name, deadline) {
  while (!existsSync(join(directory, name))) {
    if (Date.now() > deadline) throw new Error(`Ordinary launch deadline waiting for ${name}`);
    if (!['bootstrap.json', 'guardian.json'].includes(name) &&
        existsSync(join(directory, 'bootstrap.json'))) throw new Error('Task bootstrap exited before its required receipt');
    if (name !== 'guardian.json' &&
        existsSync(join(directory, 'guardian.json'))) {
      const guardian = read(directory, 'guardian.json');
      if (guardian.error ||
          guardian.cleanupError) throw new Error(guardian.cleanupError ?? guardian.error);
    }
    if (existsSync(join(directory, 'guardian-exit.json'))) {
      const exit = read(directory, 'guardian-exit.json');
      if (exit.code !== 0) throw new Error('Task guardian exited before completing its recorded contract');
    }
    await delay(100);
  }
  return read(directory, name);
}

function argumentsFor(input) {
  assert.ok(OPERATIONS.includes(input.operation), 'Unsupported ordinary CI operation');
  if (input.operation === 'probe-npm') return [input.npm, '--version'];
  if (input.operation.startsWith('probe')) return [join(HERE, 'ordinary-probe.mjs'), input.operation, input.directory];
  if (input.operation === 'session-required') {
    return [join(HERE, '../ci/run-tests.mjs'), 'session-required'];
  }
  if (input.operation === 'pooling-diagnostics') {
    return ['--test', '--test-concurrency=1', '--test-reporter=tap',
      '--test-name-pattern=real deadline diagnostics', 'test/pooling-api.test.mjs'];
  }
  return [input.npm, ...(input.operation === 'test' ? ['test'] : ['run', input.operation])];
}

export function operationBudgetMs(operation) {
  if (operation === 'test') return 3600000;
  return operation === 'session-required' ? 1800000 : 2700000;
}

export function guardianStartupInTime(input, receipt) {
  assert.equal(receipt.runId, input.runId, 'Guardian startup receipt binding differs');
  assert.ok(Number.isSafeInteger(receipt.armedAt) &&
    receipt.armedAt > 0, 'Guardian startup time is unverified');
  return receipt.armedAt <= input.startDeadline;
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
  const directory = mkdtempSync(join(parentDirectory, 'pacemaker-ordinary-'));
  const environment = { CI: 'true' };
  for (const key of ENVIRONMENT) {
    const entry = Object.entries(process.env).find(([name]) => name.toLowerCase() === key.toLowerCase());
    if (entry) environment[key] = entry[1];
  }
  environment.PATH = `${dirname(node)};${environment.PATH ?? ''}`;
  const runId = randomUUID();
  const input = { runId, taskName: `mcp-pacemaker-ci-${runId}`, createdAt: new Date().toISOString(),
    timeoutMs, directory, operation, node, npm, npmSha256, cwd: ROOT, environment,
    expectedSid: context.identity.ownerSid, expectedSession: context.identity.sessionId,
    startDeadline: Date.now() + 45000, deadline: Date.now() + timeoutMs };
  write(directory, 'task-request.json', input);
  return input;
}

export async function bindController(input) {
  input.owner = await ensureWindowsProcessLifetime();
  write(input.directory, 'input.json', input);
}

export async function launchTask(input) {
  const stdout = openSync(join(input.directory, 'guardian.stdout'), 'wx');
  const stderr = openSync(join(input.directory, 'guardian.stderr'), 'wx');
  const guardian = spawn(process.execPath, [fileURLToPath(import.meta.url), '--guardian', input.directory],
  { stdio: ['ignore', stdout, stderr], windowsHide: true, detached: true, env: input.environment });
  closeSync(stdout);
  closeSync(stderr);
  guardian.unref();
  guardian.on('error', error => write(input.directory, 'guardian-launch-error.json', { error: error.code }));
  guardian.on('close', (code, signal) => write(input.directory, 'guardian-exit.json', { code, signal }));
  const started = await waitFor(input.directory, 'guardian-started.json', input.startDeadline);
  assert.equal(started.pid, guardian.pid, 'Guardian process binding differs');
  await bindController(input);
  const ready = await waitFor(input.directory, 'guardian-ready.json', input.startDeadline);
  assert.equal(ready.runId, input.runId);
  write(input.directory, 'registration-go.json', { runId: input.runId });
}

export async function verifyTaskAbsent(input) {
  const powershell = join(input.environment.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-File',
    join(HERE, 'ordinary-task.ps1'), '-InputDirectory', input.directory, '-CheckOnly'],
  { env: input.environment, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let error = '';
  child.stdout.on('data', bytes => { output += bytes; });
  child.stderr.on('data', bytes => { error = (error + bytes).slice(-4096); });
  const completion = new Promise((resolveExit, reject) => {
    child.once('error', reject);
    child.once('close', resolveExit);
  });
  const code = await Promise.race([completion, delay(10000, undefined, { ref: false }).then(() => {
    throw new Error('Task absence query exceeded its deadline');
  })]);
  assert.equal(code, 0, error);
  assert.equal(JSON.parse(output).taskAbsent, true);
  return true;
}

export async function collectWorker(input) {
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
  } catch (error) {
    if (!existsSync(join(directory, 'cancel.json'))) write(directory, 'cancel.json', { runId: input.runId });
    throw error;
  } finally {
    const drain = await Promise.race([observer.done, delay(15000, undefined, { ref: false }).then(() => { throw new Error('Ordinary job cleanup unverified'); })]);
    write(directory, 'drain.json', drain);
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
  return result;
}

export async function collect(input) {
  let result;
  let failure;
  try { result = await collectWorker(input); } catch (error) { failure = error; }
  const guardian = await waitFor(input.directory, 'guardian.json', Math.min(input.deadline + 30000, Date.now() + 30000));
  await verifyTaskAbsent(input);
  if (guardian.cleanupError) throw new Error(guardian.cleanupError);
  if (guardian.error) throw new Error(guardian.error);
  if (failure) throw failure;
  assert.equal(guardian.taskAbsent, true);
  assert.equal(guardian.instanceCompleted, true);
  assert.equal(guardian.nativeDrain?.activeProcesses, 0);
  const instance = read(input.directory, 'task-instance.json');
  assert.equal(instance.lastTaskResult, result.exitCode, 'Task action exit differs from command/bootstrap exits');
  write(input.directory, 'verified.json', { runId: input.runId, exitCode: result.exitCode,
    ...read(input.directory, 'drain.json'), taskAbsent: true, taskInstanceCompleted: true });
  return result;
}

async function worker(directory) {
  let exitCode = 1;
  let input;
  let timer;
  let cancellation;
  const handles = [];
  try {
    const inputBytes = readBytes(directory, 'input.json');
    input = JSON.parse(inputBytes.toString('utf8'));
    const inputSha256 = createHash('sha256').update(inputBytes).digest('hex');
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
    const guardian = await waitFor(directory, 'guardian-armed.json', input.startDeadline);
    assert.equal(guardian.runId, input.runId);
    assert.equal(guardian.taskName, input.taskName);
    assert.equal(guardian.inputSha256, inputSha256, 'Worker input changed after registration');
    assert.deepEqual(guardian.owner, owner, 'Guardian observed a different worker lifetime owner');
    assert.ok(guardianStartupInTime(input, guardian) &&
      Date.now() <= input.startDeadline, 'Ordinary worker verification exceeded its startup deadline');
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
  if (process.argv[2] === '--guardian') {
    const directory = resolve(process.argv[3]);
    const request = read(directory, 'task-request.json');
    assert.ok(Number.isSafeInteger(request.startDeadline) &&
      request.startDeadline <= Date.now() + 45000);
    assert.ok(Number.isSafeInteger(request.deadline) &&
      request.deadline <= Date.now() + 3600000);
    const startupDeadline = request.startDeadline + GUARDIAN_CLEANUP_GRACE_MS;
    const operationDeadline = request.deadline + GUARDIAN_CLEANUP_GRACE_MS;
    let child;
    let timingOut = false;
    let resolveChildExit;
    const childExit = new Promise(resolveExit => { resolveChildExit = resolveExit; });
    let startupTimer;
    let operationTimer;
    let progressTimer;
    const expire = async (phase, deadline) => {
      if (timingOut) return;
      timingOut = true;
      clearTimeout(startupTimer);
      clearTimeout(operationTimer);
      clearInterval(progressTimer);
      const receipt = { runId: request.runId, taskName: request.taskName, phase, deadline,
        expiredAt: Date.now(), childPid: child?.pid ?? null, taskCleanupVerified: false,
        childTerminationVerified: false, cancellationWritten: false };
      const finish = () => {
        try {
          if (!existsSync(join(directory, 'guardian-host-result.json'))) {
            write(directory, 'guardian-host-result.json', { ...receipt, finishedAt: Date.now() });
          }
        } finally { process.exit(124); }
      };
      setTimeout(finish, GUARDIAN_CHILD_STOP_MS + 1000);
      try {
        const binding = existsSync(join(directory, 'task-binding.json')) ? read(directory, 'task-binding.json') : null;
        receipt.inputSha256 = binding?.inputSha256 ?? null;
        if (existsSync(join(directory, 'result.json'))) {
          const bytes = readBytes(directory, 'result.json');
          receipt.originalResultSha256 = createHash('sha256').update(bytes).digest('hex');
          receipt.originalResultExitCode = JSON.parse(bytes.toString('utf8')).exitCode;
        }
        write(directory, 'guardian-host-deadline.json', receipt);
        if (!existsSync(join(directory, 'cancel.json'))) write(directory, 'cancel.json', { runId: request.runId });
        receipt.cancellationWritten = read(directory, 'cancel.json').runId === request.runId;
      } catch (error) { receipt.cancellationError = error.code ?? 'receipt-unavailable'; }
      try {
        if (child &&
            child.exitCode === null &&
            child.signalCode === null) receipt.killRequested = child.kill();
        const suppressObservation = request.operation === 'probe-guardian-operation-stall';
        receipt.terminationObservationSuppressedForControl = suppressObservation;
        const stopped = await Promise.race([
          suppressObservation ? new Promise(() => {}) : childExit,
          delay(GUARDIAN_CHILD_STOP_MS).then(() => null),
        ]);
        receipt.childTerminationVerified = stopped !== null;
        if (stopped) receipt.childExit = stopped;
      } catch (error) { receipt.terminationError = error.code ?? 'termination-unverified'; }
      finish();
    };
    const observeStartup = () => {
      if (timingOut) return false;
      if (!existsSync(join(directory, 'guardian-armed.json'))) return false;
      try {
        if (guardianStartupInTime(request, read(directory, 'guardian-armed.json'))) {
          clearTimeout(startupTimer);
          clearInterval(progressTimer);
          return true;
        }
      } catch (error) {
        process.stderr.write(`Guardian startup observation failed: ${error.code ?? 'invalid-receipt'}\n`);
        void expire('startup-observation', Date.now());
      }
      return false;
    };
    // Host timers precede the child; synchronous COM calls cannot block them.
    startupTimer = setTimeout(() => {
      if (!observeStartup()) void expire('startup', startupDeadline);
    }, Math.max(1, startupDeadline - Date.now()));
    operationTimer = setTimeout(() => { void expire('operation', operationDeadline); }, Math.max(1, operationDeadline - Date.now()));
    progressTimer = setInterval(observeStartup, 100);
    write(directory, 'guardian-started.json', { pid: process.pid });
    const powershell = join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
    child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-File',
      join(HERE, 'ordinary-task.ps1'), '-InputDirectory', directory],
    { stdio: ['ignore', 'inherit', 'inherit'], windowsHide: true });
    child.once('error', error => resolveChildExit({ code: null, signal: null, error: error.code }));
    child.once('close', (code, signal) => {
      const result = { pid: child.pid, code, signal };
      write(directory, 'guardian-child-exit.json', result);
      resolveChildExit(result);
    });
    const ended = await childExit;
    if (timingOut) return;
    clearTimeout(startupTimer);
    clearTimeout(operationTimer);
    clearInterval(progressTimer);
    process.exit(ended.code ?? 1);
  }
  if (process.argv[2] === '--worker') return worker(resolve(process.argv[3]));
  const input = await prepare(process.argv[2], process.env.RUNNER_TEMP ?? tmpdir(), operationBudgetMs(process.argv[2]));
  setTimeout(() => process.exit(124), Math.max(1, input.deadline - Date.now() + GUARDIAN_CLEANUP_GRACE_MS)).unref();
  console.log(`Ordinary CI evidence: ${input.directory}`);
  const cancel = () => {
    if (!existsSync(join(input.directory, 'cancel.json'))) write(input.directory, 'cancel.json', { runId: input.runId });
  };
  process.once('SIGINT', cancel);
  process.once('SIGTERM', cancel);
  let result;
  try {
    await launchTask(input);
    result = await collect(input);
  } catch (error) {
    cancel();
    if (existsSync(join(input.directory, 'guardian.json'))) {
      const guardian = read(input.directory, 'guardian.json');
      console.error(JSON.stringify({ taskAbsent: guardian.taskAbsent, collision: guardian.collision,
        cleanupError: guardian.cleanupError, error: guardian.error }));
    }
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
    throw error;
  }
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
