import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { availableParallelism, networkInterfaces, release } from 'node:os';
import { cpSync, mkdirSync, readFileSync, readdirSync, statfsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, verifyManifest } from './local-inputs.mjs';
import { bindGuestIdentity, windowsSystemEnvironment } from './local-environment.mjs';

mkdirSync('C:\\output');
const [mode, owner, manifestSha256, nodeSha256, publisherSha256] = process.argv.slice(2);
assert.match(owner, /^[a-f0-9-]{36}$/);
assert.equal(sha256(readFileSync(process.execPath)), nodeSha256, 'Guest Node bytes differ');
if (mode === 'gate') assert.equal(sha256(readFileSync('C:\\publisher-node.exe')), publisherSha256);
const runtime = {
  platform: process.platform, os: release(), node: process.version, cpu: availableParallelism(),
  network: networkInterfaces(), pid: process.pid, owner, manifestSha256, nodeSha256, publisherSha256,
  disk: (() => {
    const value = statfsSync('C:\\');
    return { totalBytes: value.blocks * value.bsize, freeBytes: value.bavail * value.bsize };
  })(),
};
assert.equal(runtime.cpu, 4);
for (const addresses of Object.values(runtime.network)) assert.ok(addresses.every(address => address.internal));
const bootstrap = 'C:\\bootstrap';
mkdirSync(bootstrap);
const system = windowsSystemEnvironment(process.env);
for (const key of Object.keys(process.env)) delete process.env[key];
Object.assign(process.env, system, {
  PATH: 'C:\\;C:\\input\\git\\cmd;C:\\input\\pwsh;C:\\input\\npm\\bin;C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
  HOME: bootstrap, USERPROFILE: bootstrap, APPDATA: bootstrap, LOCALAPPDATA: bootstrap,
  TEMP: bootstrap, TMP: bootstrap, TMPDIR: bootstrap,
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: 'NUL', GIT_ATTR_NOSYSTEM: '1',
  GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never',
});
runtime.directories = Object.fromEntries(['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR']
  .map(key => [key, process.env[key]]));
writeFileSync('C:\\output\\runtime.json', JSON.stringify(runtime), { flush: true });
try {
if (mode === 'fail') {
  try {
    assert.equal(1, 2, 'Deliberate isolated assertion failure');
  } catch (error) {
    writeFileSync('C:\\output\\control.json', JSON.stringify({
      owner, error: { code: error.code, message: error.message, actual: error.actual, expected: error.expected },
    }), { flush: true });
    throw error;
  }
} else if (mode === 'timeout' ||
    mode === 'timeout-early-exit') {
  const child = spawn(process.execPath, ['-e', `
    const { spawn } = require('node:child_process');
    const { writeFileSync } = require('node:fs');
    const grandchild = spawn(process.execPath, ['-e', \`
      const { writeFileSync, renameSync } = require('node:fs');
      let count = 0;
      process.send({ ready: true, pid: process.pid });
      setInterval(() => {
        writeFileSync('C:\\\\\\\\output\\\\\\\\heartbeat.tmp', JSON.stringify({pid:process.pid,count:++count}), {flush:true});
        renameSync('C:\\\\\\\\output\\\\\\\\heartbeat.tmp', 'C:\\\\\\\\output\\\\\\\\heartbeat.json');
        if (${mode === 'timeout-early-exit'} && count === 2) process.exit(0);
      }, 100);
    \`], {
      detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    grandchild.on('message', value => {
      if (value.ready !== true || value.pid !== grandchild.pid) process.exit(9);
      writeFileSync('C:\\\\output\\\\tree.json', JSON.stringify({
        owner: ${JSON.stringify(owner)}, root: process.ppid, child: process.pid, grandchild: grandchild.pid
      }), {flush:true});
    });
    setInterval(() => {}, 1000);
  `], { detached: true, stdio: 'ignore' });
  assert.ok(child.pid > 0);
  setInterval(() => {}, 1000);
} else {
  assert.equal(mode, 'gate');
  const manifestBytes = readFileSync('C:\\input\\manifest.json');
  assert.equal(sha256(manifestBytes), manifestSha256, 'Host-to-guest manifest changed');
  const manifest = JSON.parse(manifestBytes);
  verifyManifest('C:\\input', manifest);
  const preflight = [];
  const identityArgs = ['-NoProfile', '-NonInteractive', '-Command',
    '$i=[Security.Principal.WindowsIdentity]::GetCurrent(); @{name=$i.Name;sid=$i.User.Value}|ConvertTo-Json -Compress'];
  const identity = spawnSync('powershell.exe', identityArgs, {
    encoding: 'utf8', shell: false, windowsHide: true, timeout: 60_000,
  });
  preflight.push({ file: 'powershell.exe', args: identityArgs, status: identity.status, signal: identity.signal,
    error: identity.error?.code, stdout: identity.stdout, stderr: identity.stderr });
  writeFileSync('C:\\output\\prerequisites.json', JSON.stringify(preflight), { flush: true });
  assert.equal(identity.error, undefined, 'Guest token lookup failed or timed out');
  assert.equal(identity.signal, null);
  assert.equal(identity.status, 0, 'Guest token lookup failed');
  runtime.identity = bindGuestIdentity(process.env, JSON.parse(identity.stdout));
  writeFileSync('C:\\output\\runtime.json', JSON.stringify(runtime), { flush: true });
  for (const [file, args] of [
    ['git', ['--version']],
    ['powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      'Add-Type -AssemblyName System.Web.Extensions; $PSVersionTable.PSVersion.ToString()']],
    ['pwsh.exe', ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()']],
    ['C:\\publisher-node.exe', ['C:\\input\\npm\\bin\\npm-cli.js', '--version']],
    ['git', ['-c', 'core.hooksPath=', 'clone', '--quiet', '--no-checkout', 'C:\\input\\history.bundle', 'C:\\source']],
    ['git', ['-C', 'C:\\source', 'read-tree', 'HEAD']],
  ]) {
    const value = spawnSync(file, args, { encoding: 'utf8', shell: false, windowsHide: true, timeout: 60_000 });
    preflight.push({ file, args, status: value.status, signal: value.signal,
      error: value.error?.code, stdout: value.stdout, stderr: value.stderr });
    writeFileSync('C:\\output\\prerequisites.json', JSON.stringify(preflight), { flush: true });
    assert.equal(value.error, undefined, `Missing or timed-out prerequisite: ${file}`);
    assert.equal(value.status, 0, `Failed prerequisite: ${file}`);
  }
  for (const name of readdirSync('C:\\input\\source')) {
    cpSync(join('C:\\input\\source', name), join('C:\\source', name), { recursive: true, dereference: false });
  }
  process.chdir('C:\\source');
  const { LocalGate } = await import('file:///C:/source/tools/npm-publication/local-gate.mjs');
  const gate = new LocalGate({
    root: 'C:\\source', npmCli: 'C:\\input\\npm\\bin\\npm-cli.js', output: 'C:\\output\\gate',
    publisherNode: 'C:\\publisher-node.exe',
    workRoot: 'C:\\work',
    containment: { kind: 'hyperv-network-none', root: 'C:\\source', output: 'C:\\output', manifestSha256 },
  });
  try {
    await gate.run();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
} catch (error) {
  writeFileSync('C:\\output\\entry-failure.json', JSON.stringify({
    owner, mode, error: { code: error.code, message: error.message, stack: error.stack },
  }), { flush: true });
  throw error;
}
