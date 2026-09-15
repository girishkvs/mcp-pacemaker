import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fork, spawn } from 'node:child_process';
import { once } from 'node:events';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { exactKeys } from './policy.mjs';
import { githubReaders } from './matrix.mjs';
import { readSignedArtifact } from './bootstrap-readers.mjs';
import { createHostedBootstrapVerifier } from './verify-bootstrap.mjs';
import { ownerEnvironment, validateOwnerContext } from './owner-bootstrap.mjs';
import { ownerState, atomicJson, readJsonFile } from './owner-state.mjs';

const entry = fileURLToPath(import.meta.url);

export function validateVerificationRequest(message, binding, nextId) {
  exactKeys(message, ['type', 'requestId', 'binding'], 'owner verification request');
  assert.equal(message.type, 'revalidate');
  assert.equal(message.requestId, nextId);
  assert.deepEqual(message.binding, binding);
}

function inputs(cleanupOnly = false) {
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const approval = JSON.parse(event.inputs.approval);
  validateOwnerContext({ env: process.env, event, approval,
    ...(cleanupOnly ? { approvalTime: Date.parse(approval.approvedAt) } : {}) });
  return approval;
}

async function start(approval) {
  const state = ownerState(process.env, approval, true);
  state.write('ledger', 'preflight-starting.json', { schemaVersion: 1, binding: state.binding,
    status: 'verification-pending', ownerSession: 'not-created' });
  const signed = await readSignedArtifact(approval, githubReaders(process.env));
  for (const [name, bytes] of signed.files) {
    fs.writeFileSync(join(state.directory, 'signed', name), bytes, { flag: 'wx', mode: 0o600 });
  }
  const verifier = await createHostedBootstrapVerifier({ approval, directory: join(state.directory, 'signed') });
  try {
    const receipt = await verifier.verify();
    state.write('ledger', 'verification-before-owner.json', receipt);
  } finally { verifier.close(); }
  state.check();
  const env = { ...ownerEnvironment(process.env, join(state.directory, 'home')),
    GITHUB_TOKEN: process.env.GITHUB_TOKEN, RUNNER_TRACKING_ID: process.env.RUNNER_TRACKING_ID };
  const child = spawn(process.execPath, [entry, 'supervise'], {
    cwd: resolve(dirname(entry), '../..'), env, detached: true, stdio: 'ignore', shell: false,
  });
  await once(child, 'spawn');
  atomicJson(state.directory, 'process.json', { pid: child.pid, binding: state.binding });
  child.unref();
  console.log('Verified owner bootstrap started. Only encrypted challenges and safe receipts are exported.');
}

async function supervise(approval) {
  const state = ownerState(process.env, approval);
  const markerPath = join(state.directory, 'process.json');
  for (let n = 0; !fs.existsSync(markerPath) && n < 100; n++) await delay(100);
  const marker = readJsonFile(markerPath);
  assert.equal(marker.pid, process.pid);
  assert.deepEqual(marker.binding, state.binding);
  const verifier = await createHostedBootstrapVerifier({ approval, directory: join(state.directory, 'signed') });
  let child;
  let killTimer;
  let stopRequested = false;
  let poll;
  const stop = () => {
    if (stopRequested) return;
    stopRequested = true;
    if (child) {
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 65_000);
    }
  };
  const deadline = setTimeout(stop, 30 * 60 * 1000);
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  let nextId = 1;
  let verifying = false;
  try {
    await verifier.verify();
    assert.equal(stopRequested, false);
    child = fork(join(dirname(entry), 'owner-process.mjs'), [], {
      cwd: join(state.directory, 'home'),
      env: ownerEnvironment(process.env, join(state.directory, 'home')),
      execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    atomicJson(state.directory, 'owner-process.json', { pid: child.pid, binding: state.binding });
    child.on('message', async message => {
      try {
        assert.equal(verifying, false, 'Concurrent owner verification request');
        validateVerificationRequest(message, state.binding, nextId++);
        verifying = true;
        const receipt = await verifier.verify();
        state.write('ledger', `verification-${message.requestId}.json`, receipt);
        assert.equal(stopRequested, false);
        child.send({ type: 'verified', requestId: message.requestId, binding: state.binding, ok: true });
      } catch {
        stop();
      } finally { verifying = false; }
    });
    poll = setInterval(() => {
      try {
        state.check();
        if (fs.existsSync(join(state.directory, 'cancel.json'))) stop();
      } catch { stop(); }
    }, 500);
    const [code, signal] = await once(child, 'exit');
    state.write('ledger', 'supervisor.json', { schemaVersion: 1, binding: state.binding,
      status: code === 0 ? 'completed' : 'stopped', childExitCode: code, childSignal: signal,
      recordedAt: new Date().toISOString() });
  } finally {
    clearTimeout(deadline);
    clearTimeout(killTimer);
    clearInterval(poll);
    if (child?.exitCode === null &&
        child.signalCode === null) stop();
    verifier.close();
  }
}

async function waitFor(approval, target) {
  const state = ownerState(process.env, approval);
  const limits = { login: 10, publication: 15, completion: 10, cleanup: 2 };
  assert.ok(Object.hasOwn(limits, target));
  const end = Date.now() + limits[target] * 60_000;
  while (Date.now() < end) {
    state.check();
    const sequence = target === 'login' ? 1 : 2;
    const challenge = join(state.directory, 'challenges', `challenge-${sequence}.json`);
    if (['login', 'publication'].includes(target) &&
        fs.existsSync(challenge)) {
      readJsonFile(challenge);
      fs.appendFileSync(process.env.GITHUB_OUTPUT, 'ready=true\n');
      return;
    }
    const completed = join(state.directory, 'ledger', 'supervisor.json');
    if (fs.existsSync(completed)) {
      const supervisor = readJsonFile(completed);
      assert.deepEqual(supervisor.binding, state.binding);
      if (target === 'cleanup') {
        const markers = ['process.json', 'owner-process.json']
          .filter(name => fs.existsSync(join(state.directory, name)))
          .map(name => readJsonFile(join(state.directory, name)));
        for (const marker of markers) {
          assert.deepEqual(marker.binding, state.binding);
          assert.ok(Number.isInteger(marker.pid) &&
            marker.pid > 1);
        }
        if (markers.every(marker => !fs.existsSync(`/proc/${marker.pid}`))) return;
        await delay(500);
        continue;
      }
      const result = readJsonFile(join(state.directory, 'ledger', 'done.json'));
      assert.deepEqual(result.binding, state.binding);
      assert.equal(supervisor.status, 'completed', 'Owner process stopped; inspect safe ledger, never retry');
      assert.equal(result.success, true, 'Publication/readback/session cleanup did not all complete');
      assert.notEqual(target, 'login', 'Missing encrypted login challenge');
      if (target === 'publication') fs.appendFileSync(process.env.GITHUB_OUTPUT, 'ready=false\n');
      return;
    }
    await delay(500);
  }
  throw new Error('Bounded owner wait expired; inspect safe ledger, never retry');
}

async function cleanup(approval) {
  const directory = join(fs.realpathSync.native(process.env.RUNNER_TEMP), 'npm-owner-bootstrap');
  if (!fs.existsSync(directory)) return;
  const state = ownerState(process.env, approval);
  if (!fs.existsSync(join(directory, 'process.json'))) return;
  if (!fs.existsSync(join(directory, 'cancel.json'))) atomicJson(directory, 'cancel.json', { binding: state.binding });
  try {
    await waitFor(approval, 'cleanup');
  } catch {
    // The cancellation request already allowed two minutes for finally/logout.
    for (const [name, expected] of [
      ['owner-process.json', [process.execPath, join(dirname(entry), 'owner-process.mjs')]],
      ['process.json', [process.execPath, entry, 'supervise']],
    ]) {
      if (!fs.existsSync(join(directory, name))) continue;
      const marker = readJsonFile(join(directory, name));
      assert.deepEqual(marker.binding, state.binding);
      assert.ok(Number.isInteger(marker.pid) &&
        marker.pid > 1);
      const commandPath = `/proc/${marker.pid}/cmdline`;
      if (fs.existsSync(commandPath)) {
        const args = fs.readFileSync(commandPath, 'utf8').split('\0').filter(Boolean);
        assert.deepEqual(args, expected, 'Refuse to signal a reused or unrelated PID');
        process.kill(marker.pid, 'SIGKILL');
      }
    }
    state.write('ledger', 'cleanup-incomplete.json', { schemaVersion: 1, binding: state.binding,
      status: 'process-or-session-cleanup-unconfirmed', instruction: 'Owner reconciliation required; no retry' });
    throw new Error('Owner cleanup not confirmed');
  }
}

export async function main(args) {
  const approval = inputs(args[0] === 'cleanup');
  assert.ok(['start', 'supervise', 'wait', 'cleanup'].includes(args[0]));
  assert.equal(args.length, args[0] === 'wait' ? 2 : 1);
  if (args[0] === 'start') await start(approval);
  if (args[0] === 'supervise') await supervise(approval);
  if (args[0] === 'wait') await waitFor(approval, args[1]);
  if (args[0] === 'cleanup') await cleanup(approval);
}

if (process.argv[1] &&
    resolve(process.argv[1]) === entry) {
  main(process.argv.slice(2)).catch(() => {
    if (process.argv[2] === 'supervise') {
      try {
        const approval = inputs(true);
        const state = ownerState(process.env, approval);
        const output = join(state.directory, 'ledger', 'supervisor.json');
        if (!fs.existsSync(output)) state.write('ledger', 'supervisor.json', {
          schemaVersion: 1, binding: state.binding, status: 'stopped', cleanup: 'unconfirmed',
        });
      } catch { /* Never turn a scratch/identity failure into an invented completion. */ }
    }
    console.error('Owner bootstrap stopped. Inspect the safe ledger; no automatic retry or credential fallback.');
    process.exitCode = 1;
  });
}
