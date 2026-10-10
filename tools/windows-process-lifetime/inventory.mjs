import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const LIFETIME_FILES = Object.freeze([
  'bin/windows-process-lifetime.mjs',
  'bin/windows-lifetime/ProcessLifetimeHelper.exe',
  'bin/windows-lifetime/ProcessLifetimeHelper.build.json',
  'bin/windows-lifetime/src/AssemblyInfo.cs',
  'bin/windows-lifetime/src/ProcessLifetimeHelper.cs',
  'tools/windows-process-lifetime/build.ps1',
  'tools/windows-process-lifetime/inventory.mjs',
  'tools/windows-process-lifetime/README.md',
]);
export const LIFETIME_TEST = 'test/windows-process-lifetime.test.mjs';
export const LIFETIME_STARTUP_TEST = 'test/windows-lifetime-startup.test.mjs';
export const LIFETIME_IDENTITY_TEST = 'test/windows-lifetime-identity.test.mjs';
export const LIFETIME_REQUIRED_TESTS = Object.freeze([
  ...['normal-delete', 'recycle', 'abrupt-root-loss', 'shared-abrupt', 'concurrent-abrupt',
    'pool-abrupt', 'auth-abrupt', 'owner-loss', 'supervisor-restart']
    .map((mode) => `Windows lifetime: ${mode} leaves no nested descendants`),
  ...['gated-success', 'missing', 'invalid', 'assignment-failure', 'observer-owner-loss',
    'observer-stale', 'observer-wrong-image', 'observer-parent-loss', 'observer-zero-exit']
    .map((mode) => `Windows lifetime startup: ${mode}`),
  'lifetime helper bare or unrelated-parent invocation cannot assign the caller',
  ...['missing', 'altered', 'stale', 'protocol'].flatMap((kind) =>
    ['owner', 'observer'].map((action) => `packaged helper identity rejects ${kind} before ${action} spawn`)),
]);

export function requiresProcessLifetime(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  assert.ok(match, 'Lifetime gate requires a canonical stable version');
  return Number(match[1]) > 2 ||
    Number(match[1]) === 2 &&
    (Number(match[2]) > 0 || Number(match[3]) >= 2);
}

export function verifyProcessLifetimeAssets(root, version) {
  if (!requiresProcessLifetime(version)) return { status: 'not-required-for-historical-version' };
  for (const path of ['bin', 'bin/windows-lifetime', 'bin/windows-lifetime/src',
    'tools', 'tools/windows-process-lifetime']) {
    const stat = lstatSync(join(root, path));
    assert.ok(stat.isDirectory() &&
      !stat.isSymbolicLink(), `Linked or invalid lifetime asset directory: ${path}`);
  }
  const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const files = LIFETIME_FILES.map((path) => {
    const full = join(root, path);
    const stat = lstatSync(full);
    assert.ok(stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0, `Invalid lifetime package asset: ${path}`);
    return { path, sha256: hash(readFileSync(full)) };
  });
  assert.deepEqual(readdirSync(join(root, 'bin/windows-lifetime')).sort(), [
    'ProcessLifetimeHelper.build.json', 'ProcessLifetimeHelper.exe', 'src',
  ]);
  assert.deepEqual(readdirSync(join(root, 'bin/windows-lifetime/src')).sort(), [
    'AssemblyInfo.cs', 'ProcessLifetimeHelper.cs',
  ]);
  const metadata = JSON.parse(readFileSync(join(root, 'bin/windows-lifetime/ProcessLifetimeHelper.build.json')));
  assert.equal(metadata.schemaVersion, 1);
  assert.equal(metadata.binary, 'ProcessLifetimeHelper.exe');
  assert.equal(metadata.inputs.targetFramework, '.NETFramework,Version=v4.6.2');
  assert.equal(metadata.inputs.platform, 'AnyCPU');
  assert.deepEqual(Object.keys(metadata.inputs.sourceSha256).sort(), ['AssemblyInfo.cs', 'ProcessLifetimeHelper.cs']);
  assert.deepEqual(Object.keys(metadata.inputs.referenceSha256).sort(), ['System.dll', 'mscorlib.dll']);
  assert.match(metadata.inputs.compilerSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(metadata.inputs.compilerArguments, [
    '/nologo', '/noconfig', '/nostdlib+', '/target:exe', '/platform:anycpu',
    '/langversion:7.3', '/optimize+', '/debug-', '/deterministic+', '/checked-',
    '/unsafe-', '/warn:4', '/warnaserror+', '/utf8output',
  ]);
  assert.equal(files.find((file) => file.path.endsWith('.exe')).sha256, metadata.binarySha256);
  const sources = Object.entries(metadata.inputs.sourceSha256)
    .map(([name, expected]) => [`bin/windows-lifetime/src/${name}`, expected]);
  sources.push(['tools/windows-process-lifetime/build.ps1', metadata.inputs.buildScriptSha256]);
  for (const [path, expected] of sources) {
    assert.equal(hash(readFileSync(join(root, path), 'utf8').replaceAll('\r\n', '\n')), expected,
      `Lifetime helper build input changed: ${path}`);
  }
  return { status: 'source-and-binary-hashes-verified', files,
    compilerSha256: metadata.inputs.compilerSha256, binarySha256: metadata.binarySha256,
    reproducibilityBuild: 'requires-recorded-toolchain-verify' };
}
