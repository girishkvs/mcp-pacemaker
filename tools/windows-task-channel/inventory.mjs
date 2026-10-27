import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const TASK_CHANNEL_FILES = Object.freeze([
  'bin/windows-task-channel.mjs',
  'bin/windows-task-channel/TaskChannelGuard.exe',
  'bin/windows-task-channel/TaskChannelGuard.build.json',
  'bin/windows-task-channel/src/AssemblyInfo.cs',
  'bin/windows-task-channel/src/ChannelCliContext.cs',
  'bin/windows-task-channel/src/ChannelFiles.cs',
  'bin/windows-task-channel/src/ChannelNative.cs',
  'bin/windows-task-channel/src/ChannelSession.cs',
  'bin/windows-task-channel/src/TaskChannelGuard.cs',
  'tools/windows-task-channel/build.ps1',
  'tools/windows-task-channel/inventory.mjs',
  'tools/windows-task-channel/README.md',
]);
export const TASK_CHANNEL_TEST = 'test/windows-task-channel.test.mjs';
export const TASK_CHANNEL_REQUIRED_TESTS = Object.freeze([
  ...['invalid UTF8', 'invalid JSON', 'nonobject'].map(name =>
    `task channel rejects completed ${name} before authorization acknowledgement`),
  ...['prepeer', 'postpeer'].flatMap(phase => ['close', 'EOF'].map(action =>
    `task channel ${phase} ${action} cancels blocked authorization`)),
  'task channel preserves valid opaque frames and FIFO commands across authorization',
  ...['close', 'EOF'].map(action => `task channel ${action} stays observable behind a queued authorization`),
  ...['duplicate sequence', 'queue overflow'].map(fault =>
    `task channel refuses ${fault} while authorization is blocked`),
  'task channel observes its actual caller token and held parent identity',
  'task channel binds direct Node peer and preserves identity across bidirectional frames',
  'task channel refuses another SID without actual elevated token despite supplied admin flags',
  'task channel refuses wrong peer generation without stopping the worker',
  'task channel refuses an unavailable bound session before creating bootstrap resources',
  'task channel refuses extra worker argv without stopping the worker',
  'task channel rejects changed bootstrap bytes before creating operation resources',
  'task channel accepts only its first connection and cannot reconnect after close',
  ...['disconnect', 'exit'].map(action => `task channel invalidates held connection on worker ${action}`),
  ...['exit', 'disconnect'].map(action =>
    `task channel refuses authorization when peer ${action} occurs during token observation`),
  ...['nonobject', 'invalid json', 'invalid UTF8', 'oversize', 'CR framing', 'incomplete frame timeout']
    .map(name => `task channel refuses ${name} without terminating its peer`),
  'task channel processes fragmented UTF8 and multiple complete frames on the same peer',
  'task channel handshake deadline releases its resources without adopting a peer',
  'task channel rejects unsupported role and never uses claimed parent or admin identity',
  'task channel admin policy requires all actual token and parent-thread facts',
  'task channel session policy refuses unavailable owner state and logon-generation ambiguity',
  'task channel trusted-root inspection refuses a reparse path and does not import files',
  'task channel parent exit releases native proof without stopping the direct worker',
  'task channel manifest reader rejects wrong operation and a caller that is not its bootstrap',
  'task channel refuses a newly created untrusted-writer code file without repairing its ACL',
  'task channel inventories exact packaged native bytes and rejects source metadata or binary drift',
  'task channel checks helper hashes before every native role and refuses missing helpers',
  'task channel stdin cancellation ends a blocked query with its early owned identity',
  'task channel parent loss ends a blocked query without waiting for its root walk',
  'task channel blocked query deadline reports verified native exit without a surviving helper',
  'task channel preserves exit-unverified evidence when a test-only native watchdog is blocked',
  'task channel ordinary context proves the actual owned caller through complete held PSS threads',
  'task channel ordinary eligibility refuses incomplete ambiguous or privileged policy facts',
  ...['denied', 'token', 'churn', 'layout', 'binding'].map(variant =>
    `task channel ordinary context refuses owned ${variant} fault without relaxing authority`),
  ...['query-denied', 'denied', 'token', 'churn', 'reuse', 'layout', 'no-info', 'walk',
    'marker-free', 'snapshot-free', 'duplicate', 'empty', 'count',
    'owner', 'birth', 'exit-zero', 'exit-future', 'missing-flag', 'unknown-flags',
    'changed-exit', 'classification', 'thread-denied', 'no-live'].map(variant =>
    `task channel full facts refuses owned ${variant} fault without fallback`),
  'task channel full facts repeats PSS per authorization and keeps peer and reader limited',
  ...['caller', 'cli-context'].flatMap(role => [
    `task channel ${role} accepts proven already-ended held thread`,
    `task channel ${role} refuses live thread ending after first snapshot`,
  ]),
]);

export function verifyTaskChannelAssets(root) {
  for (const path of ['bin', 'bin/windows-task-channel', 'bin/windows-task-channel/src',
    'tools', 'tools/windows-task-channel']) {
    const stat = lstatSync(join(root, path));
    assert.ok(stat.isDirectory() &&
      !stat.isSymbolicLink(), `Invalid task channel directory: ${path}`);
  }
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const files = TASK_CHANNEL_FILES.map(path => {
    const full = join(root, path);
    const stat = lstatSync(full);
    assert.ok(stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0, `Invalid task channel asset: ${path}`);
    return { path, sha256: hash(readFileSync(full)) };
  });
  assert.deepEqual(readdirSync(join(root, 'bin/windows-task-channel')).sort(),
    ['TaskChannelGuard.build.json', 'TaskChannelGuard.exe', 'src']);
  const sources = ['AssemblyInfo.cs', 'ChannelCliContext.cs', 'ChannelFiles.cs', 'ChannelNative.cs', 'ChannelSession.cs', 'TaskChannelGuard.cs'];
  assert.deepEqual(readdirSync(join(root, 'bin/windows-task-channel/src')).sort(), sources);
  const metadata = JSON.parse(readFileSync(join(root, 'bin/windows-task-channel/TaskChannelGuard.build.json')));
  assert.equal(metadata.schemaVersion, 1);
  assert.equal(metadata.binary, 'TaskChannelGuard.exe');
  assert.equal(metadata.inputs.targetFramework, '.NETFramework,Version=v4.6.2');
  assert.equal(metadata.inputs.platform, 'AnyCPU');
  assert.equal(metadata.inputs.pathMap, '/_/mcp-pacemaker/windows-task-channel');
  assert.deepEqual(Object.keys(metadata.inputs.sourceSha256).sort(), sources);
  assert.deepEqual(Object.keys(metadata.inputs.referenceSha256).sort(),
    ['System.Core.dll', 'System.Management.dll', 'System.Web.Extensions.dll', 'System.dll', 'mscorlib.dll']);
  assert.match(metadata.inputs.compilerSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(metadata.inputs.compilerArguments, [
    '/nologo', '/noconfig', '/nostdlib+', '/target:exe', '/platform:anycpu', '/langversion:7.3',
    '/optimize+', '/debug-', '/deterministic+', '/checked-', '/unsafe-', '/warn:4', '/warnaserror+', '/utf8output',
  ]);
  assert.equal(files.find(file => file.path.endsWith('.exe')).sha256, metadata.binarySha256);
  const inputs = sources.map(name => [`bin/windows-task-channel/src/${name}`, metadata.inputs.sourceSha256[name]]);
  inputs.push(['tools/windows-task-channel/build.ps1', metadata.inputs.buildScriptSha256]);
  for (const [path, expected] of inputs) {
    assert.equal(hash(readFileSync(join(root, path), 'utf8').replaceAll('\r\n', '\n')), expected,
      `Changed task channel build input: ${path}`);
  }
  return { status: 'source-and-binary-hashes-verified', files, binarySha256: metadata.binarySha256,
    compilerSha256: metadata.inputs.compilerSha256, reproducibilityBuild: 'requires-recorded-toolchain-verify' };
}
