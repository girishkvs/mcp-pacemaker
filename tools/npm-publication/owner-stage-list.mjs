import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstatSync, mkdirSync, realpathSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OWNER_LIST_LIMITS, OWNER_LIST_REGISTRY, boundedOwnerJson, ownerListHash, StageListAudit } from './owner-stage-list-audit.mjs';
import { createOwnerListDirectory, ownerListSourceBinding, publishOwnerListJson,
  readOwnerListJson, removeOwnerListDirectory, writeOwnerListBytes, ownerListExecutableHash } from './owner-stage-list-io.mjs';

export async function runOwnerStageList({ cli, directory, env = process.env, cwd = process.cwd(),
  timeoutMs = OWNER_LIST_LIMITS.commandMs, outputFd = 1 }) {
  assert.equal(process.versions.node, '24.21.0', 'Owner stage-list requires pinned Node24.21.0');
  assert.ok(isAbsolute(cli) &&
    isAbsolute(directory), 'Absolute npm CLI and new output directory required');
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= OWNER_LIST_LIMITS.commandMs);
  for (const [name, value] of Object.entries(env)) {
    assert.ok(!/^(NODE_OPTIONS|NODE_PATH)$/i.test(name) ||
      !value, 'Owner stage-list forbids runtime module injection');
  }
  const started = new Date().toISOString();
  const deadline = performance.now() + timeoutMs;
  const checkDeadline = () => assert.ok(performance.now() < deadline, 'Owner stage-list whole-command deadline');
  let owned;
  let privateOwned;
  let child;
  let timer;
  let outputOverflow = false;
  let timedOut = false;
  let exitCode;
  let signal;
  const streams = { stdout: [], stderr: [] };
  const lengths = { stdout: 0, stderr: 0 };
  const source = ownerListSourceBinding();
  let success = false;
  let receipt;
  let failure;
  try {
    cli = realpathSync.native(cli);
    owned = createOwnerListDirectory(directory);
    const scratch = join(owned.path, 'private');
    mkdirSync(scratch, { mode: 0o700 });
    const privateStat = lstatSync(scratch);
    privateOwned = { path: scratch, dev: privateStat.dev, ino: privateStat.ino };
    const request = { requestId: randomUUID(), cli, scratch, source, timeoutMs };
    publishOwnerListJson(scratch, 'request.json', request);
    checkDeadline();
    const childPath = join(dirname(fileURLToPath(import.meta.url)), 'owner-stage-list-child.mjs');
    const args = [childPath, join(scratch, 'request.json')];
    child = spawn(process.execPath, args, {
      cwd, env: { ...env }, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const kill = () => child.kill('SIGKILL');
    timer = setTimeout(() => { timedOut = true; kill(); }, Math.max(1, deadline - performance.now()));
    for (const name of ['stdout', 'stderr']) {
      child[name].on('data', (chunk) => {
        lengths[name] += chunk.length;
        const limit = name === 'stdout' ? OWNER_LIST_LIMITS.stdoutBytes : OWNER_LIST_LIMITS.stderrBytes;
        if (lengths[name] > limit) {
          outputOverflow = true;
          kill();
        } else {
          streams[name].push(Buffer.from(chunk));
        }
      });
    }
    const ended = await new Promise((resolveChild) => {
      child.once('error', error => resolveChild({ error: error.code ?? 'START_FAILED' }));
      child.once('close', (code, childSignal) => resolveChild({ code, signal: childSignal }));
    });
    exitCode = ended.code;
    signal = ended.signal;
    assert.equal(ended.error, undefined);
    assert.equal(timedOut, false);
    assert.equal(outputOverflow, false);
    assert.equal(exitCode, 0);
    assert.equal(signal, null);
    checkDeadline();
    const stdout = Buffer.concat(streams.stdout);
    const observed = readOwnerListJson(join(scratch, 'observation.json'));
    assert.equal(observed.kind, 'owner-stage-list-unaccepted-observation');
    assert.equal(observed.requestId, request.requestId);
    assert.equal(observed.cli, cli);
    assert.deepEqual(observed.source, source);
    assert.deepEqual(ownerListSourceBinding(), source);
    assert.equal(observed.expectedStdout.bytes, stdout.length);
    assert.equal(observed.expectedStdout.sha256, ownerListHash(stdout));
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(stdout));
    boundedOwnerJson(parsed, OWNER_LIST_LIMITS.stdoutBytes);
    const replay = new StageListAudit();
    for (const page of observed.audit.pages) {
      replay.begin('/-/stage', { registry: OWNER_LIST_REGISTRY, query: page.query });
      replay.accept(page.response);
    }
    const projection = parsed.map(({ id, packageName }) => ({ id, packageName }));
    const checked = replay.finish(JSON.stringify(projection));
    assert.equal(checked.total, observed.audit.total);
    assert.equal(observed.physicalRequests, observed.audit.pages.length);
    assert.ok(observed.responseBytes <= OWNER_LIST_LIMITS.responseTotalBytes);
    receipt = {
      schemaVersion: 1, kind: 'owner-stage-list-read-evidence',
      packageName: 'mcp-pacemaker', registry: OWNER_LIST_REGISTRY,
      startedAt: started, completedAt: new Date().toISOString(),
      total: checked.total, pendingAssessment: checked.total === 0 ? 'none' : 'requires-owner-review',
      ownerAuthentication: 'existing-context-not-authenticated-by-this-receipt', mutationAuthorized: false,
      command: { node: process.version, executable: realpathSync.native(process.execPath),
        nodeSha256: ownerListExecutableHash(process.execPath),
        cli, cliSha256: ownerListHash(readFileSync(cli)),
        argv: ['stage', 'list', 'mcp-pacemaker', '--json', `--registry=${OWNER_LIST_REGISTRY}`],
        operationalOptions: 'Private npm cache; logs/timing/update notification disabled; owner auth/config preserved.',
        exitCode, signal, source, loader: observed.loader },
      observation: observed.audit, responseBytes: observed.responseBytes,
      stdout: { bytes: stdout.length, sha256: ownerListHash(stdout), rawRetained: false },
      stderr: { bytes: lengths.stderr, sha256: ownerListHash(Buffer.concat(streams.stderr)), rawRetained: false },
    };
    boundedOwnerJson(receipt, OWNER_LIST_LIMITS.receiptBytes);
    removeOwnerListDirectory(privateOwned);
    privateOwned = undefined;
    checkDeadline();
    const persisted = publishOwnerListJson(owned.path, 'receipt.json', receipt);
    checkDeadline();
    writeOwnerListBytes(outputFd, Buffer.from(`${JSON.stringify({
      receipt: persisted.path, sha256: persisted.sha256, total: receipt.total,
      pendingAssessment: receipt.pendingAssessment, mutationAuthorized: false,
    })}\n`));
    checkDeadline();
    success = true;
    return receipt;
  } catch (error) {
    failure = Object.assign(new Error('Owner stage-list read rejected; no accepted empty-list evidence.'), {
      code: 'OWNER_STAGE_LIST_REJECTED', details: {
        exitCode, signal, timedOut, outputOverflow,
        stdoutBytes: lengths.stdout, stderrBytes: lengths.stderr,
        stdoutSha256: ownerListHash(Buffer.concat(streams.stdout)),
        stderrSha256: ownerListHash(Buffer.concat(streams.stderr)),
        outputHashScope: outputOverflow ? 'bounded captured prefixes, not complete streams' : 'complete captured streams',
        reasonCode: error.code ?? 'VALIDATION_FAILED',
      },
    });
    throw failure;
  } finally {
    clearTimeout(timer);
    try {
      if (owned) {
        if (success) {
          if (privateOwned) removeOwnerListDirectory(privateOwned);
        } else {
          removeOwnerListDirectory(owned);
        }
      }
    } catch {
      if (failure) failure.details.cleanupFailed = true;
      else throw new Error('Owner stage-list cleanup failed; receipt is not accepted without successful command completion.');
    }
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.equal(process.argv.length, 4, 'Usage: node owner-stage-list.mjs /physical/npm/bin/npm-cli.js /new/private/output-directory');
    await runOwnerStageList({ cli: resolve(process.argv[2]), directory: resolve(process.argv[3]) });
  } catch {
    console.error('Owner stage-list read rejected; no accepted empty-list evidence.');
    process.exitCode = 1;
  }
}
