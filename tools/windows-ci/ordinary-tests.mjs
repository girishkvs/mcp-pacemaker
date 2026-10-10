import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { prepare, bindController, launchTask, collect, collectWorker, verifyTaskAbsent, operationBudgetMs, guardianStartupInTime } from './ordinary-run.mjs';
import { ensureWindowsProcessLifetime, observeWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';
import { queryCliCallerContext } from '../../bin/windows-task-channel.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const [role, directory, mode] = process.argv.slice(2);
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const POWERSHELL = join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
const CASES = {
  positive: 'probe', npm: 'probe-npm', privileged: 'probe', unknown: 'probe', 'wrong-session': 'probe',
  exit: 'probe-exit', error: 'probe-error', timeout: 'probe-hang', cancel: 'probe-hang',
  'before-registration': 'probe-before-registration', 'after-registration': 'probe-after-registration',
  'after-run': 'probe-after-run', uncertain: 'probe-registration-uncertain',
  collision: 'probe-collision', mismatch: 'probe-mismatch', 'input-change': 'probe-input-change',
  'stop-failure': 'probe-stop-failure', 'delete-failure': 'probe-delete-failure',
  'guardian-startup-stall': 'probe-guardian-startup-stall',
  'guardian-operation-stall': 'probe-guardian-operation-stall',
};

async function wait(path, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (!existsSync(path)) {
    assert.ok(Date.now() < deadline, `Missing owned test receipt: ${path}`);
    await delay(100);
  }
  return json(path);
}

function fixture(run, action) {
  execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-File', join(HERE, 'task-fixture.ps1'),
    '-InputDirectory', run, '-Mode', action], { windowsHide: true, timeout: 15000, stdio: 'pipe' });
}

if (role === '--controller') {
  const input = await prepare(CASES[mode], directory,
    ['timeout', 'stop-failure', 'guardian-operation-stall'].includes(mode) ? 10000 : 60000);
  if (mode === 'guardian-startup-stall') {
    input.startDeadline = Date.now() + 10000;
    writeFileSync(join(input.directory, 'task-request.json'), JSON.stringify(input));
  }
  writeFileSync(join(directory, 'controller.json'), JSON.stringify({ directory: input.directory }));
  if (mode === 'privileged') {
    const context = await queryCliCallerContext();
    assert.ok(context.actorFacts.elevated || context.actorFacts.enabledAdministrator,
      'Actual privileged control requires an already privileged controller; no elevation attempted');
    await bindController(input);
    const child = spawn(process.execPath, [join(HERE, 'ordinary-run.mjs'), '--worker', input.directory],
      { env: input.environment, windowsHide: true, stdio: 'ignore' });
    child.once('close', (code, signal) => writeFileSync(join(input.directory, 'bootstrap.json'),
      JSON.stringify({ runId: input.runId, childStarted: true, exitCode: code, error: signal })));
    const result = await collectWorker(input);
    await verifyTaskAbsent(input);
    writeFileSync(join(input.directory, 'negative-verified.json'), JSON.stringify({
      taskAbsent: true, ...json(join(input.directory, 'drain.json')),
    }));
    process.exitCode = result.exitCode;
  } else {
    if (mode === 'unknown') delete input.expectedSid;
    if (mode === 'wrong-session') input.expectedSession++;
    if (mode === 'collision') fixture(input.directory, 'Collision');
    try {
      await launchTask(input);
      const result = await collect(input);
      assert.equal(mode.startsWith('guardian-'), false, 'Blocked guardian unexpectedly succeeded');
      process.exitCode = result.exitCode;
    } catch (error) {
      if (!mode.startsWith('guardian-')) throw error;
      const host = await wait(join(input.directory, 'guardian-host-result.json'), 90000);
      const ended = await wait(join(input.directory, 'guardian-exit.json'), 15000);
      assert.equal(ended.code, 124);
      writeFileSync(join(input.directory, 'guardian-watchdog-control.json'),
        JSON.stringify({ originalFailure: error.message, guardianExitCode: ended.code, host }));
      process.exitCode = 1;
    }
  }
} else {
  assert.equal(role, '--output');
  mkdirSync(directory);
  const policy = `
    $ErrorActionPreference = 'Stop'
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
      '${join(HERE, 'ordinary-task.ps1').replaceAll("'", "''")}', [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Bootstrap policy syntax is invalid.' }
    $guards = @($ast.FindAll({
      param($node)
      $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text.Contains('$diagnostic.positiveSession')
    }, $true))
    if ($guards.Count -ne 1) { throw 'Expected one actual bootstrap precondition.' }
    $refuses = [ScriptBlock]::Create($guards[0].Clauses[0].Item1.Extent.Text)
    $sid = 'S-1-5-21-1-2-3-500'
    $session = 1
    $inputRecord = @{ expectedSid = $sid; expectedSession = $session }
    foreach ($builtin in @($false, $true)) {
      $diagnostic = @{ isBuiltinAdministrator = $builtin; positiveSession = $true;
        registryAccess = 'read'; EnableLUA = 1; FilterAdministratorToken = $null }
      if (& $refuses) { throw 'Account category alone must not reject the CI controller.' }
      $invalid = @{ positiveSession = $false; registryAccess = 'denied'; EnableLUA = 0 }
      foreach ($key in $invalid.Keys) {
        $original = $diagnostic[$key]
        $diagnostic[$key] = $invalid[$key]
        if (-not (& $refuses)) { throw "Missing prerequisite was accepted: $key" }
        $diagnostic[$key] = $original
      }
      $inputRecord.expectedSid = 'S-1-5-21-1-2-3-1000'
      if (-not (& $refuses)) { throw 'Mismatched caller SID was accepted.' }
      $inputRecord.expectedSid = $sid
      $inputRecord.expectedSession = 2
      if (-not (& $refuses)) { throw 'Mismatched caller session was accepted.' }
      $inputRecord.expectedSession = $session
    }
    'PASS: bootstrap predicate with synthetic policy inputs'
  `;
  const policyResult = execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-Command', policy],
    { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(policyResult.trim(), 'PASS: bootstrap predicate with synthetic policy inputs');
  console.log(policyResult.trim());
  assert.equal(operationBudgetMs('test'), 3600000);
  for (const operation of ['pooling-diagnostics', 'compat:prepare', 'test:compat', 'compat:clean']) {
    assert.equal(operationBudgetMs(operation), 2700000);
  }
  const startup = { runId: 'startup-boundary', startDeadline: 100 };
  assert.equal(guardianStartupInTime(startup, { runId: startup.runId, armedAt: 99 }), true);
  assert.equal(guardianStartupInTime(startup, { runId: startup.runId, armedAt: 100 }), true);
  assert.equal(guardianStartupInTime(startup, { runId: startup.runId, armedAt: 101 }), false);
  assert.throws(() => guardianStartupInTime(startup, { runId: 'wrong-run', armedAt: 99 }));
  assert.throws(() => guardianStartupInTime(startup, { runId: startup.runId }));
  await ensureWindowsProcessLifetime();
  const selected = mode ? mode.split(',') : Object.keys(CASES);
  assert.ok(selected.length > 0 && selected.every(name => Object.hasOwn(CASES, name)));
  for (const testCase of selected) {
    const output = join(directory, testCase);
    mkdirSync(output);
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--controller', output, testCase],
      { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let text = '';
    child.stdout.on('data', bytes => { text += bytes; });
    child.stderr.on('data', bytes => { text += bytes; });
    const completion = new Promise((resolveExit, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolveExit({ code, signal }));
    });
    const run = await Promise.race([wait(join(output, 'controller.json')), completion.then(ended => {
      if (existsSync(join(output, 'controller.json'))) return json(join(output, 'controller.json'));
      throw new Error(`Owned controller failed before input (${ended.code}): ${text}`);
    })]);
    if (['before-registration', 'after-registration', 'after-run', 'cancel'].includes(testCase)) {
      const barrier = { 'before-registration': 'before-registration.json', 'after-registration': 'after-registration.json',
        'after-run': 'worker-bootstrap-entered.json', cancel: 'probe-descendant.json' }[testCase];
      await wait(join(run.directory, barrier));
      const controllerObserver = await observeWindowsProcessLifetime(json(join(run.directory, 'input.json')).owner);
      let observer;
      if (testCase === 'cancel') {
        observer = await observeWindowsProcessLifetime(json(join(run.directory, 'started.json')).owner);
      }
      child.kill();
      const guardian = await wait(join(run.directory, 'guardian.json'), 45000);
      assert.equal(guardian.cleanupError, null, JSON.stringify(guardian));
      assert.equal(guardian.taskAbsent, true);
      const controllerDrain = await Promise.race([controllerObserver.done,
        delay(15000, undefined, { ref: false }).then(() => { throw new Error('Controller job drain unverified'); })]);
      assert.equal(controllerDrain.activeProcesses, 0);
      if (observer) {
        const workerDrain = await Promise.race([observer.done,
          delay(15000, undefined, { ref: false }).then(() => { throw new Error('Worker job drain unverified'); })]);
        assert.equal(workerDrain.activeProcesses, 0);
      }
      writeFileSync(join(output, 'cancellation-verified.json'), JSON.stringify({
        phase: testCase, controllerDrain, workerDrain: guardian.nativeDrain,
      }));
    } else {
      if (testCase === 'mismatch') {
        await wait(join(run.directory, 'after-registration.json'));
        fixture(run.directory, 'Mismatch');
        writeFileSync(join(run.directory, 'continue.json'), '{}');
      } else if (testCase === 'input-change') {
        await wait(join(run.directory, 'after-registration.json'));
        const input = json(join(run.directory, 'input.json'));
        input.operation = 'probe';
        writeFileSync(join(run.directory, 'input.json'), JSON.stringify(input));
        writeFileSync(join(run.directory, 'continue.json'), '{}');
      }
      const ended = await Promise.race([completion, delay(100000, undefined, { ref: false }).then(() => {
        throw new Error(`Owned task test exceeded deadline: ${testCase}`);
      })]);
      const expected = { positive: 0, npm: 0, exit: 23, error: 1, timeout: 124 }[testCase] ?? 1;
      assert.equal(ended.code, expected, text);
      if (testCase.startsWith('guardian-')) {
        const input = json(join(run.directory, 'input.json'));
        const host = json(join(run.directory, 'guardian-host-result.json'));
        const entered = json(join(run.directory, 'guardian-stall-entered.json'));
        const childExit = json(join(run.directory, 'guardian-child-exit.json'));
        assert.equal(host.phase, entered.phase);
        assert.equal(host.taskCleanupVerified, false);
        assert.equal(Object.hasOwn(host, 'taskAbsent'), false);
        assert.equal(host.cancellationWritten, true);
        assert.equal(host.childPid, childExit.pid);
        assert.ok(childExit.code !== null || childExit.signal !== null);
        assert.ok(host.expiredAt >= host.deadline);
        assert.ok(host.finishedAt <= host.deadline + 13000, 'Guardian host exceeded its hard exit bound');
        if (testCase === 'guardian-operation-stall') {
          assert.equal(host.childTerminationVerified, false);
          assert.equal(host.terminationObservationSuppressedForControl, true);
          const original = readFileSync(join(run.directory, 'result.json'));
          assert.equal(createHash('sha256').update(original).digest('hex'), host.originalResultSha256);
          assert.equal(JSON.parse(original).exitCode, 0);
          assert.equal(json(join(run.directory, 'drain.json')).activeProcesses, 0);
          await assert.rejects(verifyTaskAbsent(input), /registration remains/);
          execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-File', join(HERE, 'ordinary-task.ps1'),
            '-InputDirectory', run.directory, '-Recover'], { windowsHide: true, timeout: 30000, stdio: 'pipe' });
          assert.equal(json(join(run.directory, 'guardian-recovered.json')).taskAbsent, true);
        } else {
          assert.equal(host.childTerminationVerified, true);
          assert.equal(existsSync(join(run.directory, 'task-created.json')), false);
        }
      } else if (testCase === 'privileged') {
        const context = json(join(run.directory, 'context.json')).context;
        assert.equal(context.ordinaryEligible, false);
        assert.equal(context.reason, 'PRIMARY_CONTEXT_PRIVILEGED');
        assert.equal(json(join(run.directory, 'negative-verified.json')).activeProcesses, 0);
        assert.equal(existsSync(join(run.directory, 'probe-ran.json')), false);
      } else {
        const guardian = json(join(run.directory, 'guardian.json'));
        if (testCase === 'collision') {
          assert.equal(guardian.collision, true);
          assert.equal(guardian.registrationAttempted, false);
          fixture(run.directory, 'Cleanup');
        } else if (testCase === 'mismatch') {
          assert.match(guardian.cleanupError, /definition changed/);
          assert.equal(guardian.taskAbsent, false);
          fixture(run.directory, 'Cleanup');
        } else if (['stop-failure', 'delete-failure'].includes(testCase)) {
          assert.match(guardian.cleanupError, /Owned (stop|delete) failure control/);
          assert.equal(guardian.taskAbsent, false);
          execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-File', join(HERE, 'ordinary-task.ps1'),
            '-InputDirectory', run.directory, '-Recover'], { windowsHide: true, timeout: 30000, stdio: 'pipe' });
          assert.equal(json(join(run.directory, 'guardian-recovered.json')).taskAbsent, true);
        } else {
          assert.equal(guardian.cleanupError, null);
          assert.equal(guardian.taskAbsent, true);
        }
        if (['positive', 'npm', 'exit', 'error', 'timeout', 'delete-failure'].includes(testCase)) {
          assert.equal(guardian.nativeDrain?.activeProcesses, 0);
          assert.equal(json(join(run.directory, 'context.json')).context.ordinaryEligible, true);
        }
        if (['unknown', 'wrong-session', 'uncertain', 'collision', 'mismatch', 'input-change'].includes(testCase)) {
          assert.equal(existsSync(join(run.directory, 'probe-ran.json')), false);
        }
        if (testCase === 'input-change') {
          const bootstrap = json(join(run.directory, 'bootstrap.json'));
          assert.equal(bootstrap.childStarted, false);
          assert.match(bootstrap.error, /input changed after registration/);
        }
      }
    }
    await completion;
    await verifyTaskAbsent(json(join(run.directory, 'input.json')));
    console.log(`PASS: ${testCase}; bound task absent; native drain verified where a worker started`);
  }
}
