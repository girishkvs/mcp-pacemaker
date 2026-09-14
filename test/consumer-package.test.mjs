import assert from 'node:assert/strict';
import { test } from 'node:test';
import { consumerGraph, consumerNoticeVersions, consumerOptions } from '../tools/npm-consumer/check.mjs';

const args = ['--tarball', 'candidate.tgz', '--sha256', 'a'.repeat(64),
  '--version', '2.0.1', '--name', 'mcp-pacemaker'];

test('fresh resolution cannot reuse a runtime supplement for an unreviewed dependency version', () => {
  const manifest = { runtimeNotices: [{ name: 'yoga-layout', version: '3.2.1' }] };
  assert.doesNotThrow(() => consumerNoticeVersions([{ name: 'yoga-layout', version: '3.2.1' }], manifest));
  assert.throws(() => consumerNoticeVersions([], manifest), /Missing installed runtime/);
  assert.throws(() => consumerNoticeVersions([{ name: 'yoga-layout', version: '3.2.2' }], manifest),
    /Fresh resolution requires a notice review/);
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
    { name: 'mcp-pacemaker', version: '1.3.1', integrity: 'sha512-candidate' },
    { name: 'smol-toml', version: '1.8.0', integrity: 'sha512-parser' },
  ]);
  assert.throws(() => consumerGraph(lock, 'mcp-pacemaker', '2.0.1'));
  lock.packages['node_modules/mcp-pacemaker'].link = true;
  assert.throws(() => consumerGraph(lock, 'mcp-pacemaker', '1.3.1'), /not a source-directory link/);
});
