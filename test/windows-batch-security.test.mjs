import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NativeFixture, originalBytes, editedBytes, expected,
} from './fixtures/windows-batch-security/driver.mjs';
import {
  AUDIT_DIAGNOSTIC, AUDIT_MODE, AUDIT_MODE_VARIABLE, AUDIT_PROCESS_TIMEOUT_MS, AUDIT_TEST_NAME, auditReport,
} from '../tools/npm-publication/local-audit-report.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HELPER = join(ROOT, 'bin', 'windows', 'PoolingSecurityHelper.exe');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'windows-batch-security');
const WINDOWS = { skip: process.platform !== 'win32' };

function fixture(t) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'mcp native batch \u03bb '));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const value = new NativeFixture(HELPER, directory);
  fs.writeFileSync(value.source, originalBytes);
  return value;
}

function oracleUnavailable(report) {
  assert.ok(report &&
    typeof report === 'object', 'Invalid oracle report');
  if (!Object.hasOwn(report, 'unavailable')) return false;
  if (report.unavailable === 'TEST-SETUP full audit oracle token unavailable' ||
      report.unavailable === 'TEST-SETUP full audit oracle access unavailable') {
    assert.deepEqual(Object.keys(report), ['unavailable']);
    return report.unavailable;
  }
  assert.equal(report.unavailable, 'TEST-SETUP existing ordinary Explorer context unavailable');
  assert.deepEqual(Object.keys(report).sort(), ['capability', 'unavailable']);
  const capability = report.capability;
  assert.deepEqual(Object.keys(capability).sort(), ['explorerPids', 'policyChanged', 'sessionId', 'stage']);
  assert.equal(capability.policyChanged, false);
  assert.ok(Number.isSafeInteger(capability.sessionId) &&
    capability.sessionId >= 0);
  assert.ok(Array.isArray(capability.explorerPids) &&
    capability.explorerPids.every(pid => Number.isSafeInteger(pid) && pid > 0));
  if (capability.stage === 'explorer-process-discovery') assert.equal(capability.explorerPids.length, 0);
  else {
    assert.equal(capability.stage, 'explorer-window-discovery');
    assert.ok(capability.explorerPids.length > 0);
  }
  return report.unavailable;
}

function verifyRestrictedCleanup(t, shell) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'mcp-batch-audit-oracle-control-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const worker = join(directory, 'normal-worker.mjs');
  const tree = join(directory, 'tree.json');
  const heartbeat = join(directory, 'heartbeat.json');
  fs.writeFileSync(worker, `
    import { spawn } from 'node:child_process';
    import { writeFileSync } from 'node:fs';
    const child = spawn(process.execPath, ['-e',
      "const fs=require('node:fs');const path=process.argv[1];let count=0;setInterval(()=>{fs.writeFileSync(path+'.tmp',JSON.stringify({pid:process.pid,count:++count}),{flush:true});fs.renameSync(path+'.tmp',path)},50)",
      ${JSON.stringify(heartbeat)}], { windowsHide: true, stdio: 'ignore' });
    writeFileSync(${JSON.stringify(tree)}, JSON.stringify({ root: process.pid, child: child.pid }), { flush: true });
    setInterval(() => {}, 100);
  `, { flag: 'wx' });
  const script = `
    $ErrorActionPreference='Stop'
    Add-Type -Path $env:MCP_AUDIT_CONTROL_LAUNCHER
    $launcher=New-Object RestrictedWorker
    try {
      $launcher.Run($env:MCP_AUDIT_CONTROL_NODE,$env:MCP_AUDIT_CONTROL_WORKER,
        $env:MCP_AUDIT_CONTROL_ROOT,$env:MCP_AUDIT_CONTROL_HELPER,4000)|Out-Null
      throw 'Expected restricted worker timeout'
    } catch {
      if ($_.Exception.InnerException -isnot [TimeoutException]) { throw }
    }
    [IO.File]::WriteAllText($env:MCP_AUDIT_CONTROL_WORKER,'process.exit(17)')
    $code=$launcher.Run($env:MCP_AUDIT_CONTROL_NODE,$env:MCP_AUDIT_CONTROL_WORKER,
      $env:MCP_AUDIT_CONTROL_ROOT,$env:MCP_AUDIT_CONTROL_HELPER,4000)
    if ($code -ne 17) { throw 'Worker exit code was lost' }
    '{"timeout":true,"nonzeroExit":17}'
  `;
  const result = spawnSync(shell, [
    '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
  ], {
    encoding: 'utf8', windowsHide: true, timeout: 30000, maxBuffer: 1024 * 1024,
    env: { ...process.env, MCP_AUDIT_CONTROL_LAUNCHER: join(FIXTURES, 'RestrictedWorker.cs'),
      MCP_AUDIT_CONTROL_NODE: process.execPath, MCP_AUDIT_CONTROL_WORKER: worker,
      MCP_AUDIT_CONTROL_ROOT: directory, MCP_AUDIT_CONTROL_HELPER: HELPER },
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { timeout: true, nonzeroExit: 17 });
  const pids = JSON.parse(fs.readFileSync(tree, 'utf8'));
  const progress = JSON.parse(fs.readFileSync(heartbeat, 'utf8'));
  assert.ok(Number.isSafeInteger(pids.root) &&
    Number.isSafeInteger(pids.child) &&
    pids.root > 0 &&
    pids.child > 0 &&
    pids.root !== pids.child);
  assert.equal(progress.pid, pids.child);
  assert.ok(progress.count >= 2, 'Owned descendant did not make progress before timeout');
  for (const pid of [pids.root, pids.child]) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
}

test('oracle unavailable reports require known pre-policy capability evidence', () => {
  const valid = {
    unavailable: 'TEST-SETUP existing ordinary Explorer context unavailable',
    capability: { stage: 'explorer-process-discovery', sessionId: 0, explorerPids: [], policyChanged: false },
  };
  assert.equal(oracleUnavailable(valid), valid.unavailable);
  assert.equal(oracleUnavailable({ normal: {} }), false);
  for (const mutate of [
    report => { report.unavailable = 'worker failed'; },
    report => { delete report.capability; },
    report => { report.capability.policyChanged = true; },
    report => { report.capability.stage = 'worker'; },
    report => { report.capability.explorerPids = [42]; },
    report => { report.capability.sessionId = -1; },
  ]) {
    const report = structuredClone(valid);
    mutate(report);
    assert.throws(() => oracleUnavailable(report));
  }
});

test('oracle Explorer capability controls never activate a real shell or suppress discovery and worker errors', WINDOWS, () => {
  const shell = join(process.env.WINDIR, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const prefix = `
    $ErrorActionPreference = 'Stop'
    . $env:MCP_TEST_EXPLORER_CONTEXT
    $Find = { [pscustomobject]@{Id=42;SessionId=7} }
  `;
  const cases = [
    {
      script: '$c=Get-OracleExplorerContext -SessionId 7 -FindProcesses { @() } -CreateShell { throw "Must not create shell" }; $c.Report|ConvertTo-Json -Depth 4 -Compress',
      unavailable: true,
    },
    {
      script: '$c=Get-OracleExplorerContext -SessionId 8 -FindProcesses $Find -CreateShell { throw "Must not create shell" }; $c.Report|ConvertTo-Json -Depth 4 -Compress',
      unavailable: true,
    },
    {
      script: `$c=Get-OracleExplorerContext -SessionId 7 -FindProcesses $Find -CreateShell {
        $s=New-Object PSObject; $s|Add-Member ScriptMethod Windows { @() }; $s
      }; $c.Report|ConvertTo-Json -Depth 4 -Compress`,
      unavailable: true,
    },
    ...[-2147023888, -2147467259].map(hresult => ({
      script: `Get-OracleExplorerContext -SessionId 7 -FindProcesses $Find -CreateShell {
        throw [Runtime.InteropServices.COMException]::new('Owned discovery failure', ${hresult})
      }`,
      error: 'Owned discovery failure',
    })),
    ...['SessionId', 'Id'].map(property => ({
      script: `$p=[pscustomobject]@{Id=42;SessionId=7}
        $p|Add-Member -Force ScriptProperty ${property} { throw 'Owned ${property} getter failure' }
        $c=Get-OracleExplorerContext -SessionId 7 -FindProcesses { $p } -CreateShell {
          $s=New-Object PSObject; $s|Add-Member ScriptMethod Windows { @() }; $s
        }; $c.Report|ConvertTo-Json -Depth 4 -Compress`,
      error: `Owned ${property} getter failure`,
    })),
    {
      script: `$c=Get-OracleExplorerContext -SessionId 7 -FindProcesses $Find -CreateShell {
        $s=New-Object PSObject
        $s|Add-Member ScriptMethod Windows {
          $e=New-Object PSObject
          $e|Add-Member ScriptProperty FullName { throw 'Owned FullName getter failure' }; $e
        }; $s
      }; $c.Report|ConvertTo-Json -Depth 4 -Compress`,
      error: 'Owned FullName getter failure',
    },
    {
      script: `Get-OracleExplorerContext -SessionId 7 -FindProcesses $Find -CreateShell {
        $s=New-Object PSObject; $s|Add-Member ScriptMethod Windows { throw 'Owned Windows method failure' }; $s
      }`,
      error: 'Owned Windows method failure',
    },
    {
      script: `$c=Get-OracleExplorerContext -SessionId 7 -FindProcesses $Find -CreateShell {
        $s=New-Object PSObject
        $s|Add-Member ScriptMethod Windows {
          $e=[pscustomobject]@{FullName='C:\\Windows\\explorer.exe'}
          $e|Add-Member ScriptMethod ShellExecute {
            throw [Runtime.InteropServices.COMException]::new('Owned post-discovery failure', -2147023888)
          }; $e
        }; $s
      }
      if ($null -ne $c.Report) { throw 'Unexpected unavailable report' }
      $c.Explorer.ShellExecute()`,
      error: 'Owned post-discovery failure',
    },
  ];
  for (const item of cases) {
    const script = `try { ${prefix}${item.script} }
      catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }`;
    const result = spawnSync(shell, [
      '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
    ], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
      env: { ...process.env, MCP_TEST_EXPLORER_CONTEXT: join(FIXTURES, 'explorer-context.ps1') },
    });
    assert.equal(result.error, undefined);
    if (item.unavailable) {
      assert.equal(result.status, 0, result.stderr);
      assert.equal(typeof oracleUnavailable(JSON.parse(result.stdout)), 'string');
    } else {
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout.trim(), '');
      assert.ok(result.stderr.includes(item.error), result.stderr);
    }
  }
});

test('inspect-access returns a stable held-object descriptor and content revision', WINDOWS, (t) => {
  const value = fixture(t);
  const first = value.inspect();
  assert.deepEqual(value.inspect(), first);
  fs.writeFileSync(value.source, editedBytes);
  const changed = value.inspect();
  assert.equal(changed.identity, first.identity);
  assert.equal(changed.security, first.security);
  assert.notEqual(changed.revision, first.revision);
});

test('stage creates a complete candidate and no-replace moves retain both objects', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const candidate = value.success(value.stage(source), editedBytes);
  assert.notEqual(candidate.identity, source.identity);
  assert.deepEqual(value.inspect(), source);
  assert.deepEqual(value.inspect(value.candidate), candidate);
  assert.deepEqual(value.success(value.move(value.source, value.previous, source)), source);
  assert.equal(fs.existsSync(value.source), false);
  assert.deepEqual(value.inspect(value.previous), source);
  assert.deepEqual(value.success(value.move(value.candidate, value.source, candidate)), candidate);
  assert.deepEqual(value.inspect(), candidate);
  assert.deepEqual(fs.readFileSync(value.previous), originalBytes);
});

for (const field of ['identity', 'revision', 'security']) {
  test(`stage and move refuse stale ${field} without any byte/security change`, WINDOWS, (t) => {
    const value = fixture(t);
    const before = value.inspect();
    const stale = { ...before, [field]: field === 'identity' ? 'stale' : '0'.repeat(64) };
    value.failure(value.stage(stale), 3, 'PoolingConflictException');
    value.failure(value.move(value.source, value.previous, stale), 3, 'PoolingConflictException');
    assert.equal(fs.existsSync(value.candidate), false);
    assert.equal(fs.existsSync(value.previous), false);
    assert.deepEqual(value.inspect(), before);
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  });
}

test('CREATE_NEW collision and no-replace collision preserve existing candidate/previous', WINDOWS, (t) => {
  const value = fixture(t);
  fs.writeFileSync(value.candidate, 'external candidate');
  fs.writeFileSync(value.previous, 'external previous');
  const before = value.inspect();
  const candidate = value.inspect(value.candidate);
  const previous = value.inspect(value.previous);
  value.failure(value.stage(before), 3, 'Win32Exception', 80);
  value.failure(value.move(value.source, value.previous, before), 3, 'Win32Exception', 183);
  assert.deepEqual(value.inspect(), before);
  assert.deepEqual(value.inspect(value.candidate), candidate);
  assert.deepEqual(value.inspect(value.previous), previous);
});

test('a contender after the first move cannot be overwritten by candidate placement', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const candidate = value.success(value.stage(source), editedBytes);
  value.success(value.move(value.source, value.previous, source));
  fs.writeFileSync(value.source, 'external active');
  const contender = value.inspect();
  value.failure(value.move(value.candidate, value.source, candidate), 3, 'Win32Exception', 183);
  assert.deepEqual(value.inspect(), contender);
  assert.deepEqual(value.inspect(value.previous), source);
  assert.deepEqual(value.inspect(value.candidate), candidate);
});

test('bounded strict UTF8 requests and base64 refuse malformed input without creating files', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const inputs = [
    Buffer.from([0xff]),
    Buffer.alloc(1400001, 0x20),
    Buffer.from('{'),
    {},
    { expected: expected(before) },
    { expected: { ...expected(before), extra: 'x' }, bytes: '' },
    { expected: expected(before), bytes: '!!!!' },
    { expected: expected(before), bytes: 'YQ==\n' },
    { expected: expected(before), bytes: Buffer.from([0xff]).toString('base64') },
    { expected: expected(before), bytes: Buffer.alloc(1048577).toString('base64') },
  ];
  for (const input of inputs) {
    const result = value.run('stage', value.source, value.candidate, input);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(result.stderr.startsWith('MCPERR type='));
    assert.equal(fs.existsSync(value.candidate), false);
    assert.deepEqual(value.inspect(), before);
  }
});

test('single-link and 1MiB bounds apply to inspect, stage, and move', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const link = join(value.directory, 'hard-link.json');
  fs.linkSync(value.source, link);
  for (const result of [
    value.run('inspect-access'),
    value.stage(before),
    value.move(value.source, value.previous, before),
  ]) {
    value.failure(result, 1, 'PoolingPolicyException');
  }
  assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  assert.deepEqual(fs.readFileSync(link), originalBytes);
  fs.unlinkSync(link);
  fs.writeFileSync(value.source, Buffer.alloc(1048577, 0x20));
  value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
  value.failure(value.stage(before), 1, 'PoolingPolicyException');
  value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
  assert.equal(fs.statSync(value.source).size, 1048577);
  assert.equal(fs.existsSync(value.candidate), false);
  assert.equal(fs.existsSync(value.previous), false);
  fs.writeFileSync(value.source, Buffer.alloc(1048576, 0x20));
  const maximum = value.inspect();
  value.success(value.stage(maximum, Buffer.alloc(1048576, 0x20)), Buffer.alloc(1048576, 0x20));
});

test('existing data writer blocks staging without a candidate or source mutation', WINDOWS, (t) => {
  const value = fixture(t);
  const source = value.inspect();
  const writer = fs.openSync(value.source, 'r+');
  try {
    value.failure(value.stage(source), 1, 'Win32Exception', 32);
    assert.equal(fs.existsSync(value.candidate), false);
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
  } finally {
    fs.closeSync(writer);
  }
  assert.deepEqual(value.inspect(), source);
});

test('read-only attributes refuse staging without using parent replacement rights', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  fs.chmodSync(value.source, 0o444);
  try {
    value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
    value.failure(value.stage(before), 1, 'Win32Exception', 5);
    value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
    assert.deepEqual(fs.readFileSync(value.source), originalBytes);
    assert.equal(fs.existsSync(value.candidate), false);
    assert.equal(fs.existsSync(value.previous), false);
  } finally {
    fs.chmodSync(value.source, 0o600);
  }
  assert.deepEqual(value.inspect(), before);
});

test('final-component file reparse points never expose or mutate their target', WINDOWS, (t) => {
  const value = fixture(t);
  const before = value.inspect();
  const target = join(value.directory, 'target.json');
  fs.renameSync(value.source, target);
  try {
    fs.symlinkSync(target, value.source, 'file');
  } catch (error) {
    if (error.code === 'EPERM') {
      t.skip('TEST-SETUP symbolic-link creation is not permitted by this token');
      return;
    }
    throw error;
  }
  value.failure(value.run('inspect-access'), 1, 'PoolingPolicyException');
  value.failure(value.stage(before), 1, 'PoolingPolicyException');
  value.failure(value.move(value.source, value.previous, before), 1, 'PoolingPolicyException');
  assert.equal(fs.lstatSync(value.source).isSymbolicLink(), true);
  assert.deepEqual(value.inspect(target), before);
  assert.deepEqual(fs.readFileSync(target), originalBytes);
  assert.equal(fs.existsSync(value.candidate), false);
  assert.equal(fs.existsSync(value.previous), false);
});

test(AUDIT_TEST_NAME, WINDOWS, (t) => {
  const mode = process.env[AUDIT_MODE_VARIABLE];
  assert.ok(mode === undefined ||
    mode === AUDIT_MODE, 'Unsupported audit worker mode');
  const required = mode === AUDIT_MODE;
  const directory = fs.mkdtempSync(join(tmpdir(), 'mcp-batch-audit-oracle-'));
  const shell = join(process.env.WINDIR, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  t.after(() => {
    const readonly = join(directory, 'readonly', 'active.json');
    if (fs.existsSync(readonly)) {
      const cleanup = spawnSync(shell, [
        '-NoProfile', '-NonInteractive', '-Command', '[IO.File]::Delete($env:MCP_TEST_READONLY)',
      ], {
        encoding: 'utf8', windowsHide: true, timeout: 10000,
        env: { ...process.env, MCP_TEST_READONLY: readonly },
      });
      assert.equal(cleanup.status, 0, cleanup.stderr);
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  if (required) verifyRestrictedCleanup(t, shell);
  const result = spawnSync(shell, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', join(FIXTURES, 'oracle.ps1'),
    '-Root', directory, '-Helper', HELPER, '-Node', process.execPath,
    ...(required ? ['-WorkerMode', 'RestrictedToken'] : []),
  ], { encoding: 'utf8', windowsHide: true, timeout: required ? AUDIT_PROCESS_TIMEOUT_MS : 30000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  const unavailable = oracleUnavailable(report);
  if (unavailable) {
    assert.equal(required, false, 'Required ordinary-token audit cannot be skipped');
    t.diagnostic(JSON.stringify(report));
    t.skip(unavailable);
    return;
  }
  assert.equal(report.normal.medium, true);
  assert.equal(report.normal.securityPrivilegeAbsent, true);
  assert.equal(report.normal.nodeVersion, process.version);
  assert.equal(report.normal.cases, 19);
  assert.equal(report.audit.sourceExplicit, 1);
  assert.equal(report.audit.sourceInherited, 1);
  assert.equal(report.audit.candidateExplicit, 0);
  assert.equal(report.audit.candidateInherited, 1);
  assert.equal(report.audit.previousExact, true);
  assert.equal(report.securityVerified, true);
  if (required) {
    report.worker.cleanupVerified = true;
    auditReport(report, process.version);
    t.diagnostic(`${AUDIT_DIAGNOSTIC}${JSON.stringify(report)}`);
  }
});
