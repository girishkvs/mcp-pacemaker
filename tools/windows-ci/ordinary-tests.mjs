import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { prepare, launchDesktop, collect, operationBudgetMs } from './ordinary-run.mjs';
import { ensureWindowsProcessLifetime, observeWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';
import { queryCliCallerContext } from '../../bin/windows-task-channel.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const [role, directory, mode] = process.argv.slice(2);
const json = path => JSON.parse(readFileSync(path, 'utf8'));

async function wait(path, timeout = 45000) {
  const deadline = Date.now() + timeout;
  while (!existsSync(path)) {
    assert.ok(Date.now() < deadline, `Missing owned test receipt: ${path}`);
    await delay(100);
  }
  return json(path);
}

if (role === '--controller') {
  const operation = mode === 'timeout' || mode === 'cancel' ? 'probe-hang'
    : mode === 'exit' ? 'probe-exit' : mode === 'error' ? 'probe-error' : mode === 'npm' ? 'probe-npm' : 'probe';
  const input = await prepare(operation, directory, mode === 'timeout' ? 10000 : 60000);
  if (mode === 'unknown') {
    delete input.expectedSid;
    writeFileSync(join(input.directory, 'input.json'), JSON.stringify(input));
  }
  writeFileSync(join(directory, 'controller.json'), JSON.stringify({ directory: input.directory }));
  let bootstrap;
  if (mode === 'privileged') {
    const context = await queryCliCallerContext();
    assert.ok(context.actorFacts.elevated || context.actorFacts.enabledAdministrator,
      'Real privileged refusal requires an already privileged test controller; no elevation is attempted');
    bootstrap = spawn(join(input.environment.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-File', join(HERE, 'ordinary-desktop.ps1'),
        '-InputDirectory', input.directory, '-Worker'], { stdio: 'ignore', windowsHide: true });
  } else bootstrap = launchDesktop(input);
  bootstrap.stdout?.resume();
  let brokerError = '';
  bootstrap.stderr?.on('data', bytes => { brokerError = (brokerError + bytes).slice(-4096); });
  const result = await collect(input).catch(error => { throw new Error(`${error.message}; ${brokerError}`); });
  process.exitCode = result.exitCode;
} else {
  assert.equal(role, '--output');
  assert.ok(directory, 'A new private test output directory is required');
  assert.equal(operationBudgetMs('test'), 3600000);
  for (const operation of ['pooling-diagnostics', 'compat:prepare', 'test:compat', 'compat:clean', 'probe-hang']) {
    assert.equal(operationBudgetMs(operation), 2700000);
  }
  console.log('PASS: full test selects 60 minutes; other operation budgets remain 45 minutes.');
  mkdirSync(directory);
  await ensureWindowsProcessLifetime();
  for (const testCase of ['positive', 'npm', 'privileged', 'unknown', 'exit', 'error', 'timeout', 'cancel']) {
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
      throw new Error(`Owned controller exited before its input receipt (${ended.code}): ${text}`);
    })]);
    if (testCase === 'cancel') {
      await wait(join(run.directory, 'probe-descendant.json'));
      const started = json(join(run.directory, 'started.json'));
      const observer = await observeWindowsProcessLifetime(started.owner);
      child.kill();
      await Promise.race([observer.done, delay(15000, undefined, { ref: false }).then(() => {
        throw new Error('Owned ordinary descendants did not drain after controller loss');
      })]);
      await wait(join(run.directory, 'bootstrap.json'), 15000);
      assert.equal(json(join(run.directory, 'result.json')).exitCode, 125);
    } else {
      const ended = await Promise.race([completion, delay(75000, undefined, { ref: false }).then(() => {
        throw new Error(`Owned launcher test exceeded deadline: ${testCase}`);
      })]);
      const expected = { positive: 0, npm: 0, privileged: 1, unknown: 1, exit: 23, error: 1, timeout: 124 }[testCase];
      assert.equal(ended.code, expected, text);
      const verified = json(join(run.directory, 'verified.json'));
      assert.equal(verified.activeProcesses, 0);
      assert.equal(verified.exitCode, expected);
      if (testCase === 'privileged' ||
          testCase === 'unknown') {
        assert.equal(existsSync(join(run.directory, 'probe-ran.json')), false);
        const context = json(join(run.directory, 'context.json')).context;
        if (testCase === 'privileged') {
          assert.equal(context.ordinaryEligible, false);
          assert.equal(context.reason, 'PRIMARY_CONTEXT_PRIVILEGED');
        } else assert.equal(context.ordinaryEligible, true);
      } else {
        const context = json(join(run.directory, 'context.json'));
        assert.equal(context.context.ordinaryEligible, true);
        assert.equal(context.node, process.execPath);
        if (testCase === 'npm') {
          const expectedNpm = json(join(dirname(context.npm), '../package.json')).version;
          assert.equal(readFileSync(join(run.directory, 'stdout.log'), 'utf8').trim(), expectedNpm);
        } else {
          assert.match(text, /ordinary probe stdout/);
          assert.match(text, /ordinary probe stderr/);
        }
        if (testCase === 'error') assert.match(text, /owned ordinary probe error/);
      }
    }
    await completion;
    const input = json(join(run.directory, 'input.json'));
    assert.equal(input.environment.GITHUB_TOKEN, undefined);
    assert.equal(input.environment.NODE_OPTIONS, undefined);
    console.log(`PASS: ${testCase}; actual context enforced and owned job drained`);
  }
}
