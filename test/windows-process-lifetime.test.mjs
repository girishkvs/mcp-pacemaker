import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyProcessLifetimeAssets, requiresProcessLifetime } from '../tools/windows-process-lifetime/inventory.mjs';
import { lifetimeFixtureFiles } from './helpers/lifetime-package-fixture.mjs';

test('packaged lifetime helper has exact source, build and binary inventory', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
  assert.equal(verifyProcessLifetimeAssets(root, version).status, 'source-and-binary-hashes-verified');
  assert.equal(requiresProcessLifetime('1.3.1'), false);
  assert.equal(requiresProcessLifetime('2.0.0'), false);
});

test('lifetime inventory rejects missing, changed and extra native assets', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-lifetime-inventory-'));
  t.after(() => rmSync(directory, { recursive: true }));
  const files = lifetimeFixtureFiles('2.0.2');
  for (const [path, bytes] of Object.entries(files)) {
    mkdirSync(dirname(join(directory, path)), { recursive: true });
    writeFileSync(join(directory, path), bytes);
  }
  const check = () => verifyProcessLifetimeAssets(directory, '2.0.2');
  check();
  for (const path of ['bin/windows-lifetime/ProcessLifetimeHelper.exe',
    'bin/windows-lifetime/src/ProcessLifetimeHelper.cs', 'tools/windows-process-lifetime/build.ps1']) {
    rmSync(join(directory, path));
    assert.throws(check);
    writeFileSync(join(directory, path), Buffer.concat([files[path], Buffer.from('tampered')]));
    assert.throws(check);
    writeFileSync(join(directory, path), files[path]);
  }
  writeFileSync(join(directory, 'bin/windows-lifetime/unapproved.exe'), 'not an admitted native asset');
  assert.throws(check);
  rmSync(join(directory, 'bin/windows-lifetime/unapproved.exe'));
  const metadataPath = 'bin/windows-lifetime/ProcessLifetimeHelper.build.json';
  const metadata = JSON.parse(files[metadataPath]);
  metadata.inputs.compilerArguments.push('/define:TEST');
  writeFileSync(join(directory, metadataPath), JSON.stringify(metadata));
  assert.throws(check);
});

test('a started lifetime helper never holds the caller working directory open', {
  skip: process.platform !== 'win32', timeout: 60_000,
}, async (t) => {
  const parent = mkdtempSync(join(tmpdir(), 'mcp-lifetime-cwd-'));
  let holder;
  let holderClosed;
  let blocker;
  let blockerClosed;
  t.after(async () => {
    for (const [child, closed] of [[blocker, blockerClosed], [holder, holderClosed]]) {
      if (!child) continue;
      if (child.exitCode == null &&
          child.signalCode == null) child.kill();
      if (closed) await closed;
    }
    rmSync(parent, { recursive: true, force: true, maxRetries: 50, retryDelay: 100 });
  });

  // Control: a process whose working directory is the owned directory really does block its
  // removal on Windows, so the helper assertion below is an observation, not an unconditional pass.
  const control = join(parent, 'control');
  mkdirSync(control);
  blocker = spawn(process.execPath, ['-e', 'process.stdout.write("held\\n"); setInterval(() => {}, 1000);'],
    { cwd: control, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
  blockerClosed = once(blocker, 'close');
  const controlExited = blockerClosed.then(() => {
    throw new Error('Owned control process exited before holding its directory');
  });
  controlExited.catch(() => {});
  await Promise.race([once(blocker.stdout, 'data'), controlExited]);
  assert.throws(() => rmSync(control, { recursive: true }),
    error => ['EPERM', 'EBUSY', 'ENOTEMPTY'].includes(error.code));
  blocker.kill();
  await blockerClosed;
  rmSync(control, { recursive: true, maxRetries: 50, retryDelay: 100 });

  const owned = join(parent, 'owned');
  mkdirSync(owned);
  holder = fork(fileURLToPath(new URL('./fixtures/windows-process-lifetime/cwd-holder.mjs', import.meta.url)),
    [owned, tmpdir()], { execArgv: [], windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let diagnostics = '';
  for (const stream of [holder.stdout, holder.stderr]) stream.on('data', bytes => { diagnostics += bytes; });
  const closed = once(holder, 'close');
  holderClosed = closed;
  const holderExited = closed.then(() => {
    throw new Error(`Owned holder exited early: ${diagnostics}`);
  });
  holderExited.catch(() => {});
  const [ready] = await Promise.race([once(holder, 'message'), holderExited]);
  assert.equal(ready.type, 'ready', diagnostics);
  assert.notEqual(ready.cwd, owned);
  assert.ok(Number.isSafeInteger(ready.lifetime?.ownerPid) &&
    ready.lifetime.ownerPid > 0, diagnostics);
  // The helper must still be running, or a removal that succeeds would prove nothing.
  process.kill(ready.lifetime.ownerPid, 0);
  rmSync(owned, { recursive: true });
  assert.equal(existsSync(owned), false);
});

class LifetimeFixture {
  run(mode, t) {
    const directory = mkdtempSync(join(process.env.MCP_LIFETIME_TEST_EVIDENCE || tmpdir(), 'mcp-lifetime-'));
    const script = fileURLToPath(new URL('./fixtures/windows-process-lifetime/run.ps1', import.meta.url));
    const args = ['-NoProfile', '-NonInteractive', '-File', script,
      '-Node', process.execPath, '-Evidence', directory, '-Mode', mode];
    const output = spawnSync('pwsh.exe', args, {
      windowsHide: true, encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    });
    writeFileSync(join(directory, 'runner.stdout.txt'), output.stdout || '');
    writeFileSync(join(directory, 'runner.stderr.txt'), output.stderr || '');
    writeFileSync(join(directory, 'command.json'), JSON.stringify({
      node: process.version, executable: process.execPath, command: 'pwsh.exe', args,
    }, null, 2));
    t.diagnostic(`Owned lifetime evidence: ${directory}`);
    assert.equal(output.error, undefined, output.stderr);
    assert.equal(output.status, 0, `${output.stdout}\n${output.stderr}`);
    const result = JSON.parse(output.stdout.trim());
    assert.equal(result.cleanup.allCapturedIdentitiesGone, true);
    assert.deepEqual(result.cleanup.errors, []);
    assert.equal(result.cleanup.heartbeatListenerStopped, true);
    assert.equal(result.survivingDescendants, 0,
      `Nested descendants survived: ${JSON.stringify(result.heartbeatEvidence)}`);
    assert.equal(result.nativeOwners.length, 1, 'One native job owner per bridge, not per session');
    return result;
  }
}

for (const mode of ['normal-delete', 'recycle', 'abrupt-root-loss', 'shared-abrupt',
  'concurrent-abrupt', 'pool-abrupt', 'auth-abrupt', 'owner-loss', 'supervisor-restart']) {
  test(`Windows lifetime: ${mode} leaves no nested descendants`,
    { skip: process.platform !== 'win32', timeout: 130_000 }, (t) => {
      const result = new LifetimeFixture().run(mode, t);
      const normal = mode === 'normal-delete' || mode === 'recycle';
      assert.equal(result.nativeOwners[0].alive, normal);
      const multiple = ['concurrent-abrupt', 'pool-abrupt', 'auth-abrupt'].includes(mode);
      assert.equal(Object.keys(result.heartbeatEvidence).length, multiple ? 4 : 2);
      for (const role of Object.keys(result.heartbeatEvidence)) {
        assert.equal(result.heartbeatEvidence[role].alive, false);
        assert.equal(result.heartbeatEvidence[role].advancedAfterAction, false);
      }
      if (mode === 'supervisor-restart') {
        assert.deepEqual(result.replacement, { instanceChanged: true, sessions: 0, responsive: true });
      }
    });
}
