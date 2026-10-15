import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { EventEmitter } from 'node:events';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ExecutionContext } from '../tools/ci/execution-context.mjs';
import { TestProcess } from '../tools/ci/test-process.mjs';
import { nodeTestArguments, qualificationPlan, testContract, SESSION_REQUIRED_TESTS } from '../tools/ci/test-contracts.mjs';

test('the CI ordinary-account lane stays inside Windows account limits and removes what it creates', () => {
  const script = readFileSync(new URL('../tools/windows-ci/ci-ordinary-user.ps1', import.meta.url), 'utf8');
  const literal = pattern => {
    const found = pattern.exec(script);
    assert.ok(found, `The ordinary-account lane no longer declares ${pattern}`);
    return found[1];
  };
  // Windows rejects these at parameter binding, which would otherwise only surface on a runner.
  assert.ok(literal(/\$account = '([^']+)'/).length <= 20, 'Local account names are limited to 20 characters');
  assert.ok(literal(/-Description '([^']+)'/).length <= 48, 'Local account descriptions are limited to 48 characters');
  assert.ok(literal(/-FullName '([^']+)'/).length <= 256, 'Local account full names are limited to 256 characters');
  // The lane must never run outside a hosted runner, never gain administrator rights, and must
  // always remove the account it created.
  assert.match(script, /GITHUB_ACTIONS -ne 'true'/);
  assert.match(script, /RUNNER_ENVIRONMENT -ne 'github-hosted'/);
  assert.match(script, /S-1-5-21-\(\?:\[0-9\]\+-\)\{3\}500/);
  assert.doesNotMatch(script, /Add-LocalGroupMember[^\n]*Administrators/);
  assert.match(script, /The CI account must never be an administrator/);
  assert.match(script, /^finally \{/m);
  assert.match(script, /Remove-OwnedAccount -Name \$account/);
  assert.match(script, /The disposable CI account was not removed/);
  // The worker must get a private home it can write, not the administrator's profile, and must
  // report its own identity. Anchored on the opening quote so each name is checked on its own
  // rather than being satisfied by a longer variable that merely contains it.
  for (const name of ['USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP',
    'USERNAME', 'USERDOMAIN']) {
    assert.match(script, new RegExp(`set [\`"]*${name}=`), `The ordinary worker must pin ${name}`);
  }
  // -Wait also waits for descendants, and this suite leaves detached native helpers running.
  assert.doesNotMatch(script, /Start-Process[^\n]*-Wait/);
  assert.match(script, /\$process\.WaitForExit\(\)/);
  assert.match(script, /ValidateSet\('source-ordinary', 'compatibility'\)/);
  // Compatibility fixtures record the temp root that owns them, so the worker must prepare and
  // remove its own pair; an administrator-prepared pair is refused at load. Preparation reads npm
  // configuration through npm_execpath, so it must run as an npm script, not bare node.
  assert.match(script, /run compat:prepare/);
  assert.match(script, /run compat:clean/);
  assert.match(script, /exit \/b %CONTRACT_RESULT%/);
  // PowerShell variable names are case-insensitive, so a local named like a parameter silently
  // overwrites it and re-runs that parameter's validation attributes mid-lane.
  const parameters = /param\(([\s\S]*?)\n\)/.exec(script);
  assert.ok(parameters, 'The lane must declare a parameter block');
  const names = [...parameters[1].matchAll(/\$(\w+)\s*(?:,|$)/gm)].map(found => found[1].toLowerCase());
  assert.ok(names.length >= 3, 'The lane parameters were not recognized');
  const body = script.slice(parameters.index + parameters[0].length);
  for (const name of names) {
    assert.doesNotMatch(body, new RegExp(`\\$${name}\\s*=[^=]`, 'i'),
      `A local variable shadows the ${name} parameter and re-triggers its validation`);
  }
});

test('the Windows lanes together cover every registered file exactly once', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const complete = testContract(root, 'source', 'win32');
  const ordinary = testContract(root, 'source-ordinary', 'win32');
  const files = args => args.filter(value => value.startsWith('test/'));
  assert.equal(ordinary.role, 'user-runtime');
  assert.equal(ordinary.session, false, 'A provisioned CI account has no interactive logon session');
  assert.equal(complete.session, true);
  assert.equal(ordinary.timeoutMs, 60 * 60 * 1000);
  assert.equal(new Set(SESSION_REQUIRED_TESTS).size, SESSION_REQUIRED_TESTS.length);
  assert.deepEqual(files(ordinary.args).filter(file => SESSION_REQUIRED_TESTS.includes(file)), []);
  assert.deepEqual([...files(ordinary.args), ...SESSION_REQUIRED_TESTS].sort(), files(complete.args).sort());
  // The bound is part of the declared contract and must survive into the ordinary lane.
  assert.deepEqual(ordinary.args.filter(value => !value.startsWith('test/')),
    complete.args.filter(value => !value.startsWith('test/')));
  assert.throws(() => testContract(root, 'source-ordinary', 'linux'), /only for Windows/);
  const session = testContract(root, 'session-required', 'win32');
  assert.equal(session.role, 'user-runtime');
  assert.equal(session.session, true, 'The session lane must observe a real interactive logon session');
  assert.deepEqual(files(session.args), [...SESSION_REQUIRED_TESTS]);
  assert.ok(session.args.includes('--test-reporter=tap'), 'The receipt totals parser requires TAP output');
  assert.deepEqual([...files(ordinary.args), ...files(session.args)].sort(), files(complete.args).sort());
  assert.throws(() => testContract(root, 'session-required', 'linux'), /only for Windows/);
});

test('source contract includes every registered source file without changing concurrency', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  for (const platform of ['win32', 'linux', 'darwin']) {
    const source = testContract(root, 'source', platform);
    assert.equal(source.role, 'user-runtime');
    assert.equal(source.session, platform === 'win32');
    assert.equal(testContract(root, 'service-context', platform).checkOnly, true);
    assert.equal(source.args.includes('--test-concurrency=1'), false);
    assert.equal(testContract(root, 'compatibility', platform).args.includes('--test-concurrency=1'), true);
  }
  const plan = qualificationPlan(root);
  assert.equal(plan.filter(item => item.name === 'source').length, 9);
  assert.equal(plan.filter(item => item.name === 'audit').length, 3);
  assert.deepEqual(plan.filter(item => item.name === 'browser').map(({ platform, node }) => ({ platform, node })),
    [{ platform: 'linux', node: 22 }]);
  assert.equal(plan.some(item => item.name === 'service-context'), false);
  // Hosted runners have no interactive logon session, so the session lane is host-only by design.
  assert.equal(plan.some(item => item.name === 'session-required'), false);
  assert.throws(() => testContract(root, 'audit', 'linux'));
});

test('contract CLI rejects extra arguments before any context observation', () => {
  const script = fileURLToPath(new URL('../tools/ci/run-tests.mjs', import.meta.url));
  for (const args of [[], ['source', '--check', 'ignored'], ['plan', 'ignored'], ['unknown'], ['source', '--unknown']]) {
    const child = spawnSync(process.execPath, [script, ...args],
      { encoding: 'utf8', timeout: 10000, windowsHide: true });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 1);
    assert.equal(child.stdout, '');
    assert.match(child.stderr, /Use CONTRACT|Unknown test contract/);
  }
  const plan = spawnSync(process.execPath, [script, 'plan'],
    { encoding: 'utf8', timeout: 10000, windowsHide: true });
  assert.equal(plan.error, undefined);
  assert.equal(plan.status, 0);
  assert.equal(JSON.parse(plan.stdout).executionPerformed, false);
});

test('contract selection rejects shell commands, filters, traversal and unregistered files', t => {
  for (const value of ['npm test', 'node --test', 'node --test --test-name-pattern=none test/a.test.mjs',
    'node --test test/../a.test.mjs', 'node --test test/a.test.mjs test/a.test.mjs',
    'node --test --test-concurrency=6', 'node --test --test-concurrency=0 test/a.test.mjs',
    'node --test --test-concurrency=100 test/a.test.mjs', 'node --test --concurrency=6 test/a.test.mjs']) {
    assert.throws(() => nodeTestArguments(value));
  }
  assert.deepEqual(nodeTestArguments('node --test --test-concurrency=6 test/a.test.mjs'),
    ['--test', '--test-concurrency=6', 'test/a.test.mjs']);
  const root = mkdtempSync(join(tmpdir(), 'ci-contract-'));
  t.after(() => rmSync(root, { recursive: true }));
  mkdirSync(join(root, 'test'));
  writeFileSync(join(root, 'test', 'missing.test.mjs'), '');
  writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test test/a.test.mjs' } }));
  assert.throws(() => testContract(root, 'source', 'linux'));
});

test('ordinary-context refusal stops session probing and is not repaired', async () => {
  const failure = new Error('ordinary context unavailable');
  const context = new ExecutionContext({
    platform: 'linux',
    ordinary: async () => { throw failure; },
    run: async () => assert.fail('No service-manager call after caller refusal'),
    inspect: () => assert.fail('No filesystem probe after caller refusal'),
  });
  await assert.rejects(context.require({ platform: 'linux', role: 'user-runtime', session: true }),
    error => error === failure);
});

test('Linux observes the owned user manager with a fixed bus path and no state-changing command', async () => {
  const calls = [];
  const context = new ExecutionContext({
    platform: 'linux',
    ordinary: async () => ({ platform: 'linux', ordinary: true, identity: { euid: 1000 } }),
    inspect: path => ({
      uid: 1000, mode: 0o700, isDirectory: () => path === '/run/user/1000',
      isSymbolicLink: () => false, isSocket: () => path === '/run/user/1000/bus',
    }),
    canonical: path => path,
    run: async (file, args, options) => {
      calls.push({ file, args });
      assert.equal(options.env.XDG_RUNTIME_DIR, '/run/user/1000');
      assert.equal(options.env.DBUS_SESSION_BUS_ADDRESS, 'unix:path=/run/user/1000/bus');
      return { stdout: '255\n' };
    },
  });
  assert.equal((await context.require({ platform: 'linux', role: 'user-runtime', session: true })).sessionVerified, true);
  assert.deepEqual(calls, [{ file: '/usr/bin/systemctl', args: ['--user', 'show', '--property=Version', '--value'] }]);
  context.run = async () => { throw new Error('No user manager'); };
  await assert.rejects(context.require({ platform: 'linux', role: 'user-runtime', session: true }),
    { code: 'CI_CONTEXT_UNAVAILABLE' });
});

test('macOS queries only the actual caller user domain and rejects absence', async () => {
  const context = new ExecutionContext({
    platform: 'darwin',
    ordinary: async () => ({ platform: 'darwin', ordinary: true, identity: { euid: 501 } }),
    run: async (file, args) => {
      assert.equal(file, '/bin/launchctl');
      assert.deepEqual(args, ['print', 'gui/501']);
      return { stdout: '' };
    },
  });
  const contract = { platform: 'darwin', role: 'user-runtime', session: true };
  assert.equal((await context.require(contract)).sessionVerified, true);
  context.run = async () => { throw new Error('Missing login domain'); };
  await assert.rejects(context.require(contract), { code: 'CI_CONTEXT_UNAVAILABLE' });
});

test('Windows session proof must match the ordinary caller and a real logon observation', async () => {
  const identity = { pid: 42, creationTime: '123', ownerSid: 'S-1-5-21-1-2-3-1000', sessionId: 1 };
  const session = { ownerSid: identity.ownerSid, sessionId: 1, state: 'active', logonTime: '1234' };
  const proof = { proofScope: 'current-user-session-snapshot', identity, session };
  const context = new ExecutionContext({
    platform: 'win32',
    ordinary: async () => ({ platform: 'win32', ordinary: true, native: { identity } }),
    windowsSession: async () => proof,
  });
  const contract = { platform: 'win32', role: 'user-runtime', session: true };
  assert.equal((await context.require(contract)).sessionVerified, true);
  for (const changed of [
    { ...proof, identity: { ...identity, ownerSid: 'S-1-5-21-9-8-7-1000' } },
    { ...proof, identity: { ...identity, creationTime: '124' } },
    { ...proof, session: { ...session, logonTime: '' } },
    { ...proof, session: { ...session, state: 'logged-off' } },
  ]) {
    context.windowsSession = async () => changed;
    await assert.rejects(context.require(contract), { code: 'CI_CONTEXT_UNAVAILABLE' });
  }
});

test('privileged fixtures require an actual verified privileged caller', async () => {
  const context = new ExecutionContext({
    platform: 'win32',
    privileged: async () => ({ actorFacts: { elevated: true, enabledAdministrator: true, restricted: false,
      appContainer: false, guardThreadImpersonating: false, parentThreadImpersonation: 'observed-none' },
    helperExit: { code: 0, signal: null } }),
  });
  const contract = { platform: 'win32', role: 'privileged-fixture', session: false };
  assert.equal((await context.require(contract)).verified, true);
  context.privileged = async () => ({ actorFacts: { elevated: true } });
  await assert.rejects(context.require(contract), { code: 'CI_CONTEXT_UNAVAILABLE' });
});

test('test process preserves actual exits and rejects nonzero child completion', async () => {
  const output = [];
  const stdout = new Writable({ write(chunk, _encoding, next) { output.push(chunk.toString()); next(); } });
  const runner = new TestProcess({ stdout, stderr: stdout });
  const listeners = process.listenerCount('SIGTERM');
  const contract = { name: 'source', timeoutMs: 10000, args: ['-e', "process.stdout.write('child-output')"] };
  const result = await runner.run(contract);
  assert.equal(result.code, 0);
  assert.equal(output.join(''), 'child-output');
  await assert.rejects(runner.run({ ...contract, args: ['-e', 'process.exit(7)'] }), /failed \(7\)/);
  assert.equal(process.listenerCount('SIGTERM'), listeners);
});

test('test process cancellation and deadline wait for the actual child to close', async () => {
  for (const mode of ['abort', 'deadline']) {
    let childPid;
    let output = '';
    const cancellation = new AbortController();
    const stdout = new Writable({
      write(chunk, _encoding, next) {
        output += chunk.toString();
        if (/^\d+\r?\n/.test(output)) {
          childPid = Number(output.trim());
          if (mode === 'abort') cancellation.abort(new Error('requested cancellation'));
        }
        next();
      },
    });
    const runner = new TestProcess({ stdout, stderr: stdout });
    await assert.rejects(runner.run({
      name: 'source', timeoutMs: mode === 'abort' ? 10000 : 1500,
      args: ['-e', "console.log(process.pid); process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"],
    }, { signal: cancellation.signal }), mode === 'abort' ? /requested cancellation/ : /exceeded 1500 ms/);
    assert.ok(Number.isSafeInteger(childPid));
    assert.throws(() => process.kill(childPid, 0), { code: 'ESRCH' });
  }
});

test('audit capture enforces the actual 16 MiB boundary and never treats overflow as success', async () => {
  const stdout = new Writable({ write(_chunk, _encoding, next) { next(); } });
  const runner = new TestProcess({ stdout, stderr: stdout });
  const contract = { name: 'audit', timeoutMs: 10000,
    args: ['-e', 'process.stdout.write(Buffer.alloc(16 * 1024 * 1024, 120))'] };
  assert.equal((await runner.run(contract)).stdout.length, 16 * 1024 * 1024);
  await assert.rejects(runner.run({ ...contract,
    args: ['-e', 'process.stdout.write(Buffer.alloc(16 * 1024 * 1024 + 1, 120))'] }), /exceeded 16 MiB/);
});

test('wrapper forwards cancellation and repeated POSIX signals through child cleanup', async t => {
  const root = mkdtempSync(join(tmpdir(), 'ci-signal-'));
  const script = join(root, 'wrapper.mjs');
  writeFileSync(script, `
import { TestProcess } from ${JSON.stringify(new URL('../tools/ci/test-process.mjs', import.meta.url).href)};
import { ensureWindowsProcessLifetime } from ${JSON.stringify(new URL('../bin/windows-process-lifetime.mjs', import.meta.url).href)};
await ensureWindowsProcessLifetime();
process.on('message', () => process.emit('SIGTERM'));
try {
  await new TestProcess().run({ name: 'source', timeoutMs: 15000,
    args: ['-e', "process.on('SIGTERM', () => console.log('IGNORED')); console.log(process.pid); setTimeout(() => process.exit(0), 15000); setInterval(() => {}, 1000)"] });
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally { if (process.connected) process.disconnect(); }
`);
  const wrapper = spawn(process.execPath, [script], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  const closed = new Promise((resolve, reject) => {
    wrapper.once('error', reject);
    wrapper.once('close', (code, signal) => resolve({ code, signal }));
  });
  let output = '';
  let errors = '';
  wrapper.stderr.on('data', chunk => { errors += chunk; });
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Signal fixture deadline')), 20000); });
  t.after(async () => {
    clearTimeout(timer);
    if (wrapper.exitCode === null &&
        wrapper.signalCode === null) wrapper.kill('SIGKILL');
    await closed;
    rmSync(root, { recursive: true });
  });
  const ready = new Promise(resolve => wrapper.stdout.on('data', chunk => {
    output += chunk;
    const match = /^(\d+)\r?\n/.exec(output);
    if (match) resolve(Number(match[1]));
  }));
  const ignored = new Promise(resolve => wrapper.stdout.on('data', () => {
    if (output.includes('IGNORED')) resolve();
  }));
  const pid = await Promise.race([ready, deadline]);
  if (process.platform === 'win32') wrapper.send('deliver-SIGTERM');
  else {
    wrapper.kill('SIGTERM');
    await Promise.race([ignored, deadline]);
    wrapper.kill('SIGTERM');
  }
  assert.deepEqual(await Promise.race([closed, deadline]), { code: 1, signal: null });
  assert.match(errors, /cancelled by SIGTERM/);
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
});

test('unverified termination is an error and releases wrapper handles at the cleanup bound', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const child = Object.assign(new EventEmitter(), { pid: 42,
    stdout: new PassThrough(), stderr: new PassThrough() });
  const signals = [];
  let unreferenced = false;
  child.kill = signal => { signals.push(signal); return false; };
  child.unref = () => { unreferenced = true; };
  const stdout = new Writable({ write(_chunk, _encoding, next) { next(); } });
  const runner = new TestProcess({ stdout, stderr: stdout, launch: () => child });
  const listeners = process.listenerCount('SIGTERM');
  const rejected = assert.rejects(runner.run({ name: 'source', args: [], timeoutMs: 1000 }),
    /shutdown or output closure is unverified/);
  t.mock.timers.tick(1000);
  t.mock.timers.tick(5000);
  t.mock.timers.tick(5000);
  await rejected;
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(unreferenced, true);
  assert.equal(child.stdout.destroyed, true);
  assert.equal(child.stderr.destroyed, true);
  assert.equal(process.listenerCount('SIGTERM'), listeners);
});
