import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const LEGACY_BROKER_FILES = Object.freeze([
  'bin/windows-legacy-process.mjs',
  'bin/windows-legacy/LegacyProcessBroker.exe',
  'bin/windows-legacy/LegacyProcessBroker.build.json',
  'bin/windows-legacy/src/AssemblyInfo.cs',
  'bin/windows-legacy/src/LegacyNative.cs',
  'bin/windows-legacy/src/LegacyProcessBroker.cs',
  'tools/windows-legacy/build.ps1',
  'tools/windows-legacy/inventory.mjs',
  'tools/windows-legacy/README.md',
]);
export const LEGACY_BROKER_TEST = 'test/windows-legacy-process.test.mjs';
export const LEGACY_BROKER_REQUIRED_TESTS = Object.freeze([
  'legacy API denials preserve refusal and bounded stored-only failure diagnostics',
  'legacy failure metadata cannot mask errors or cross concurrent operation identities',
  'legacy cached selected-root creator-PID reuse skips only the older edge and retains strict refusals',
  'legacy protected-plan model enforces 512 combined identities and UTF8 byte bounds without process queries',
  'legacy expected request refuses oversized UTF8 framing before native discovery',
  ...['relative', 'drive-relative', 'root-relative'].flatMap((spelling) =>
    ['bridge', 'supervisor'].map((affected) =>
      `legacy script identity rejects ${affected} ${spelling} argv without stopping targets`)),
  'legacy script identity accepts fully qualified Unicode and space paths',
  'legacy script qualification recognizes drive and UNC forms without cwd resolution',
  'legacy script identity preserves fully qualified short-path handling',
  'legacy script identity does not equate a junction spelling with a different canonical root',
  'legacy broker captures held roots and stops only its observed set with partial receipt',
  'legacy broker close is read-only and an identical expected plan can be reopened',
  'legacy broker preserves an already-exited captured descendant without adopting a replacement PID',
  'legacy broker rejects stale generation or expanded observed plan without stopping roots',
  'legacy broker rejects wrong root and malformed protected verification plan',
  'legacy broker refuses extra supervisor argv and a foreign listener without process mutation',
  'legacy read-only recovery does not stop an unrelated process reusing the endpoint',
  'legacy native inventory rejects changed executable, source and build metadata',
  'legacy prepare and recovery verify refuse wrong-hash packaged helper before any discovery',
  'legacy broker parent loss releases read-only capture without stopping legacy roots',
  'legacy broker reports captured descendant termination failure without certifying stop',
  'legacy broker preserves Unicode plan identity across fragmented UTF8 pipe messages',
  'legacy broker excludes a proven older nonmember without terminating or verifying its exit',
]);

export function verifyLegacyBrokerAssets(root) {
  for (const path of ['bin', 'bin/windows-legacy', 'bin/windows-legacy/src',
    'tools', 'tools/windows-legacy']) {
    const stat = lstatSync(join(root, path));
    assert.ok(stat.isDirectory() &&
      !stat.isSymbolicLink(), `Linked or invalid legacy broker directory: ${path}`);
  }
  const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const files = LEGACY_BROKER_FILES.map((path) => {
    const full = join(root, path);
    const stat = lstatSync(full);
    assert.ok(stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0, `Invalid legacy broker asset: ${path}`);
    return { path, sha256: hash(readFileSync(full)) };
  });
  assert.deepEqual(readdirSync(join(root, 'bin/windows-legacy')).sort(), [
    'LegacyProcessBroker.build.json', 'LegacyProcessBroker.exe', 'src',
  ]);
  const sources = ['AssemblyInfo.cs', 'LegacyNative.cs', 'LegacyProcessBroker.cs'];
  assert.deepEqual(readdirSync(join(root, 'bin/windows-legacy/src')).sort(), sources);
  const metadata = JSON.parse(readFileSync(join(root, 'bin/windows-legacy/LegacyProcessBroker.build.json')));
  assert.equal(metadata.schemaVersion, 1);
  assert.equal(metadata.binary, 'LegacyProcessBroker.exe');
  assert.equal(metadata.inputs.targetFramework, '.NETFramework,Version=v4.6.2');
  assert.equal(metadata.inputs.platform, 'AnyCPU');
  assert.deepEqual(Object.keys(metadata.inputs.sourceSha256).sort(), sources);
  assert.deepEqual(Object.keys(metadata.inputs.referenceSha256).sort(),
    ['System.Core.dll', 'System.Management.dll', 'System.Web.Extensions.dll', 'System.dll', 'mscorlib.dll']);
  assert.match(metadata.inputs.compilerSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(metadata.inputs.compilerArguments, [
    '/nologo', '/noconfig', '/nostdlib+', '/target:exe', '/platform:anycpu', '/langversion:7.3',
    '/optimize+', '/debug-', '/deterministic+', '/checked-', '/unsafe-', '/warn:4', '/warnaserror+', '/utf8output',
  ]);
  assert.equal(files.find((file) => file.path.endsWith('.exe')).sha256, metadata.binarySha256);
  const inputs = sources.map((name) => [`bin/windows-legacy/src/${name}`, metadata.inputs.sourceSha256[name]]);
  inputs.push(['tools/windows-legacy/build.ps1', metadata.inputs.buildScriptSha256]);
  for (const [path, expected] of inputs) {
    assert.equal(hash(readFileSync(join(root, path), 'utf8').replaceAll('\r\n', '\n')), expected,
      `Changed legacy broker input: ${path}`);
  }
  return { status: 'source-and-binary-hashes-verified', files,
    binarySha256: metadata.binarySha256, compilerSha256: metadata.inputs.compilerSha256,
    reproducibilityBuild: 'requires-recorded-toolchain-verify' };
}
