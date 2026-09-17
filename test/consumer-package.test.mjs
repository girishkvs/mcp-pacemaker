import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { consumerGraph, consumerNoticeVersions, consumerOptions } from '../tools/npm-consumer/check.mjs';
import { captureConsumerLicenseEvidence, validateConsumerLicenseEvidence } from '../tools/npm-consumer/license-evidence.mjs';
import { fixtureFile, fixtureIntegrity, fixtureLicenseEvidence, fixtureMit } from './fixtures/consumer-license-evidence.mjs';

const args = ['--tarball', 'candidate.tgz', '--sha256', 'a'.repeat(64),
  '--version', '2.0.1', '--name', 'mcp-pacemaker'];

test('fresh resolution cannot reuse a runtime supplement for an unreviewed dependency version', () => {
  const manifest = { runtimeNotices: [{ name: 'yoga-layout', version: '3.2.1' }] };
  assert.doesNotThrow(() => consumerNoticeVersions([{ name: 'yoga-layout', version: '3.2.1' }], manifest));
  assert.throws(() => consumerNoticeVersions([], manifest), /Missing installed runtime/);
  assert.throws(() => consumerNoticeVersions([{ name: 'yoga-layout', version: '3.2.2' }], manifest),
    /Fresh resolution requires a notice review/);
});

test('license capture reads exact fresh nested/scoped installed bytes, not a producer version', t => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'consumer-license-test-')));
  t.after(() => rmSync(root, { recursive: true }));
  const path = 'node_modules/fixture-parent/node_modules/@alcalzone/ansi-tokenize';
  const dependencies = [{ path, name: '@alcalzone/ansi-tokenize', version: '0.3.1', integrity: fixtureIntegrity }];
  const packageRoot = join(root, path);
  mkdirSync(packageRoot, { recursive: true });
  const metadata = JSON.stringify({ name: dependencies[0].name, version: '0.3.1', license: 'MIT' });
  writeFileSync(join(packageRoot, 'package.json'), metadata);
  writeFileSync(join(packageRoot, 'LICENSE'), fixtureMit);
  const evidence = captureConsumerLicenseEvidence(root, dependencies);
  assert.deepEqual(evidence.packages[0].packageJson, fixtureFile('package.json', metadata));
  assert.deepEqual(evidence.packages[0].files, [fixtureFile('LICENSE', fixtureMit)]);
  assert.equal(evidence.packages[0].integrity, fixtureIntegrity);
  assert.equal(evidence.packages[0].path, path);
  writeFileSync(join(packageRoot, 'package.json'), JSON.stringify({ name: dependencies[0].name, version: '0.3.0' }));
  assert.throws(() => captureConsumerLicenseEvidence(root, dependencies), /package identity mismatch/);
  writeFileSync(join(packageRoot, 'package.json'), metadata);
  writeFileSync(join(packageRoot, 'LICENSE'), Buffer.from([0xff]));
  assert.throws(() => captureConsumerLicenseEvidence(root, dependencies), /encoded data/);
  rmSync(join(packageRoot, 'LICENSE'));
  mkdirSync(join(packageRoot, 'LICENSE'));
  assert.throws(() => captureConsumerLicenseEvidence(root, dependencies), /Non-file/);
  rmSync(join(packageRoot, 'LICENSE'), { recursive: true });
  const retained = join(root, 'retained');
  renameSync(packageRoot, retained);
  symlinkSync(retained, packageRoot, process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => captureConsumerLicenseEvidence(root, dependencies), /Linked consumer/);
  rmSync(packageRoot);
  renameSync(retained, packageRoot);
  const source = join(root, 'outside-source');
  mkdirSync(source);
  writeFileSync(join(source, 'index.ts'), fixtureMit);
  symlinkSync(source, join(packageRoot, 'LICENSE'), process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => captureConsumerLicenseEvidence(root, dependencies), /Linked consumer/);
  assert.equal(dirname(packageRoot).endsWith('@alcalzone'), true);
});

for (const [name, change] of [
  ['old schema', value => { value.schemaVersion = 1; }],
  ['missing evidence', value => { delete value.licenseEvidence; }],
  ['missing package', value => { value.licenseEvidence.packages.pop(); }],
  ['older version text', value => { value.licenseEvidence.packages[0].version = '0.3.0'; }],
  ['unbound integrity', value => { value.licenseEvidence.packages[0].integrity = null; }],
  ['missing dependency integrity', value => { value.dependencies[0].integrity = null; }],
  ['line-terminated path', value => { value.dependencies[0].path += '\n'; }],
  ['line-terminated version', value => { value.dependencies[0].version += '\n'; }],
  ['line-terminated name', value => { value.dependencies[0].name += '\n'; }],
  ['line-terminated integrity', value => { value.dependencies[0].integrity += '\n'; }],
  ['metadata identity', value => { value.licenseEvidence.packages[0].packageJson = fixtureFile('package.json',
    JSON.stringify({ name: '@alcalzone/ansi-tokenize', version: '0.3.0', license: 'MIT' })); }],
  ['metadata hash', value => { value.licenseEvidence.packages[0].packageJson.text += ' '; }],
  ['license hash', value => { value.licenseEvidence.packages[0].files[0].text += 'tampered'; }],
  ['duplicate path', value => {
    value.dependencies.push(structuredClone(value.dependencies[0]));
    value.licenseEvidence.packages.push(structuredClone(value.licenseEvidence.packages[0]));
  }],
  ['duplicate license', value => { value.licenseEvidence.packages[0].files.push(value.licenseEvidence.packages[0].files[0]); }],
  ['license path traversal', value => { value.licenseEvidence.packages[0].files[0].path = '../LICENSE'; }],
  ['unexpected evidence field', value => { value.licenseEvidence.approved = true; }],
  ['oversized text', value => { value.licenseEvidence.packages[0].files[0] = fixtureFile('LICENSE', 'a'.repeat(1024 * 1024 + 1)); }],
]) {
  test(`consumer evidence rejects ${name} without installs or network`, () => {
    const dependencies = [{ path: 'node_modules/@alcalzone/ansi-tokenize',
      name: '@alcalzone/ansi-tokenize', version: '0.3.1', integrity: fixtureIntegrity }];
    const value = { schemaVersion: 2, dependencies, licenseEvidence: fixtureLicenseEvidence(dependencies) };
    validateConsumerLicenseEvidence(value);
    change(value);
    assert.throws(() => validateConsumerLicenseEvidence(value));
  });
}

test('consumer package paths reject traversal, absolute paths, backslashes and aliases before file reads', () => {
  for (const path of ['../outside', '/node_modules/unit', 'C:/node_modules/unit',
    'node_modules/../unit', 'node_modules\\unit', 'node_modules/unit/../../outside',
    'node_modules/@scope/../unit', 'node_modules/other', 'node_modules/unit\n']) {
    assert.throws(() => validateConsumerLicenseEvidence({
      schemaVersion: 2, dependencies: [{ path, name: 'unit', version: '1.0.0', integrity: fixtureIntegrity }],
      licenseEvidence: fixtureLicenseEvidence([{ path, name: 'unit', version: '1.0.0', integrity: fixtureIntegrity }]),
    }));
  }
});

test('consumer validation requires an exact version and digest before installing anything', () => {
  const options = consumerOptions(args);
  assert.equal(options.version, '2.0.1');
  assert.equal(options.ignoreScripts, false);
  assert.equal(consumerOptions([...args, '--ignore-scripts']).ignoreScripts, true);
  for (const invalid of [
    [], args.slice(2), [...args, '--name', 'other'], [...args, '--unknown'],
    args.map((value) => value === '2.0.1' ? 'latest' : value),
    args.map((value) => value === '2.0.1' ? '2.0.2' : value),
    args.map((value) => value === 'a'.repeat(64) ? 'bad-hash' : value),
    args.map((value) => value === 'mcp-pacemaker' ? '../outside' : value),
  ]) assert.throws(() => consumerOptions(invalid));
});

test('the fresh consumer graph records the installed candidate and dependencies, not a source link', () => {
  const lock = {
    packages: {
      '': { name: 'private-consumer' },
      'node_modules/mcp-pacemaker': { version: '1.3.1', integrity: 'sha512-candidate' },
      'node_modules/smol-toml': { version: '1.8.0', integrity: 'sha512-parser' },
    },
  };
  assert.deepEqual(consumerGraph(lock, 'mcp-pacemaker', '1.3.1'), [
    { path: 'node_modules/mcp-pacemaker', name: 'mcp-pacemaker', version: '1.3.1', integrity: 'sha512-candidate' },
    { path: 'node_modules/smol-toml', name: 'smol-toml', version: '1.8.0', integrity: 'sha512-parser' },
  ]);
  assert.throws(() => consumerGraph(lock, 'mcp-pacemaker', '2.0.1'));
  lock.packages['node_modules/mcp-pacemaker'].link = true;
  assert.throws(() => consumerGraph(lock, 'mcp-pacemaker', '1.3.1'), /not a source-directory link/);
});
