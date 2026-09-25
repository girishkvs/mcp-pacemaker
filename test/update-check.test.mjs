import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkForUpdate, selectUpdate, updateGuidance, validateRegistry, readNpmMetadata } from '../bin/update-check.mjs';

const name = 'mcp-pacemaker';
const release = (version, extra = {}) => ({ name, version, ...extra });

for (const major of [1, 2]) {
  const channel = major === 1 ? 'legacy' : 'latest';
  for (const { current, target, status } of [
    { current: `${major}.0.1`, target: `${major}.0.2`, status: 'update-available' },
    { current: `${major}.0.2`, target: `${major}.0.2`, status: 'current' },
    { current: `${major}.0.3`, target: `${major}.0.2`, status: 'installed-ahead' },
    { current: `${major}.0.9`, target: `${major}.0.10`, status: 'update-available' },
  ]) {
    test(`T29/T41 major ${major}: ${current} vs channel ${target} = ${status}`, () => {
      const result = selectUpdate({ name, version: current }, { [channel]: target }, release(target));
      assert.equal(result.status, status);
      assert.equal(result.updateAvailable, status === 'update-available');
      assert.equal(result.rollbackRequired, status === 'installed-ahead');
      const guidance = updateGuidance(result);
      assert.match(guidance, new RegExp(`${name}@${target.replaceAll('.', '\\.')}`));
      assert.doesNotMatch(guidance, /@latest|@legacy|github:|git .*pull/);
      assert.match(guidance, /Guidance only/);
      if (status === 'installed-ahead') assert.match(guidance, /deliberate rollback, NOT a normal update/);
    });
  }

  for (const { label, target, metadata } of [
    { label: 'missing channel' },
    { label: 'wrong major', target: `${major + 1}.0.1` },
    { label: 'prerelease', target: `${major}.0.1-rc.1` },
    { label: 'range', target: `^${major}.0.1` },
    { label: 'version alias', target: `v${major}.0.1` },
    { label: 'missing exact release', target: `${major}.0.1`, metadata: null },
    { label: 'wrong release', target: `${major}.0.1`, metadata: release(`${major}.0.2`) },
    { label: 'wrong identity', target: `${major}.0.1`, metadata: release(`${major}.0.1`, { name: 'other' }) },
    { label: 'deprecated release', target: `${major}.0.1`, metadata: release(`${major}.0.1`, { deprecated: 'withdrawn' }) },
    { label: 'unexpected array', target: `${major}.0.1`, metadata: [release(`${major}.0.1`)] },
  ]) {
    test(`T30/T43 major ${major}: rejects ${label} without fallback`, () => {
      assert.throws(() => selectUpdate(
        { name, version: `${major}.0.0` },
        { [channel]: target },
        metadata === undefined ? release(target) : metadata,
      ));
    });
  }

  test(`T43 major ${major}: only the approved channel and exact release are read`, async () => {
    const target = `${major}.3.1`;
    const calls = [];
    const result = await checkForUpdate({ name, version: `${major}.3.2` }, {
      registry: 'https://approved-registry.example.test/npm/',
      read: async (spec, field, options) => {
        calls.push({ spec, field, options });
        assert.equal(options.registry, 'https://approved-registry.example.test/npm/');
        assert.equal(existsSync(options.cache), true);
        if (field === 'dist-tags') {
          return { legacy: '1.3.1', latest: major === 2 ? target : '2.9.9', withdrawn: `${major}.3.2` };
        }
        assert.equal(spec, `${name}@${target}`);
        return release(target);
      },
    });
    assert.equal(result.target, target);
    assert.equal(result.status, 'installed-ahead');
    assert.equal(calls.length, 2);
    assert.equal(existsSync(calls[0].options.cache), false);
  });
}

test('T30 offline is unknown/error and cleans its empty cache; it is not current', async () => {
  let cache;
  let calls = 0;
  await assert.rejects(checkForUpdate({ name, version: '2.0.1' }, {
    read: async (_spec, _field, options) => {
      calls++;
      cache = options.cache;
      throw new Error('offline');
    },
  }), /offline/);
  assert.equal(calls, 1);
  assert.equal(existsSync(cache), false);
});

test('missing channel stops before requesting an exact release', async () => {
  let calls = 0;
  await assert.rejects(checkForUpdate({ name, version: '1.3.1' }, {
    read: async () => { calls++; return { latest: '2.0.1' }; },
  }), /No fallback selected/);
  assert.equal(calls, 1);
});

test('package identity is supplied by the manifest, including an approved scope', () => {
  const pkg = { name: '@example/pacemaker', version: '1.3.1' };
  const result = selectUpdate(pkg, { legacy: '1.3.2', latest: '2.0.1' }, { ...pkg, version: '1.3.2' });
  assert.match(updateGuidance(result), /@example\/pacemaker@1\.3\.2/);
  for (const version of ['3.0.0', '1.3.1-rc.1', 'bad']) {
    assert.throws(() => selectUpdate({ name, version }, {}, null));
  }
});

test('explicit registry selection is preserved; credentials are not embedded in guidance', () => {
  const credentialedRegistry = [
    'https://',
    String.fromCharCode(117, 115, 101, 114, 58, 115, 101, 99, 114, 101, 116),
    '@',
    'example.test/',
  ].join('');
  const queryRegistry = [
    'https://example.test/',
    '?',
    String.fromCharCode(116, 111, 107, 101, 110, 61, 115, 101, 99, 114, 101, 116),
  ].join('');
  for (const url of ['file:///tmp/registry', credentialedRegistry, queryRegistry]) {
    assert.throws(() => validateRegistry(url));
  }
  assert.equal(validateRegistry(undefined), undefined);
  const result = selectUpdate({ name, version: '2.0.1' }, { latest: '2.0.2' }, release('2.0.2'));
  assert.match(updateGuidance(result, { registry: 'https://approved-registry.example.test/npm/' }),
    /--registry 'https:\/\/approved-registry\.example\.test\/npm\/'/);
  assert.doesNotMatch(updateGuidance(result), /--registry|registry\.npmjs\.org/);
});

test('npm invocation is read-only, bounded, shell-free and preserves inherited npm policy', async () => {
  const cache = mkdtempSync(join(tmpdir(), 'mcp-update-test-'));
  try {
    const result = await readNpmMetadata(`${name}@1.3.1`, undefined, {
      cache, registry: 'https://approved-registry.example.test/npm/',
      run: async (command, args, options) => {
        assert.equal(command, process.execPath);
        assert.equal(args[1], 'view');
        assert.equal(args[2], `${name}@1.3.1`);
        assert.equal(args.includes('--ignore-scripts'), true);
        assert.equal(args.includes('--prefer-online'), true);
        assert.equal(args.includes('--fetch-retries=0'), true);
        assert.equal(args[args.indexOf('--cache') + 1], cache);
        assert.equal(options.shell, undefined);
        assert.equal(options.env, undefined);
        return { stdout: JSON.stringify(release('1.3.1')) };
      },
    });
    assert.equal(result.version, '1.3.1');
    await assert.rejects(readNpmMetadata(name, 'dist-tags', {
      cache, run: async () => { throw new Error('private registry diagnostic'); },
    }), (error) => {
      assert.doesNotMatch(error.message, /private registry diagnostic/);
      return /No fallback|no fallback/.test(error.message);
    });
    await assert.rejects(readNpmMetadata(name, 'dist-tags', {
      cache, run: async () => ({ stdout: '{bad-json' }),
    }), /invalid metadata/);
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
});

test('regression controls: isolated copies fail the legacy-channel and rollback assertions', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-update-regression-'));
  const require = createRequire(import.meta.url);
  const source = readFileSync(new URL('../bin/update-check.mjs', import.meta.url), 'utf8')
    .replace("'semver'", JSON.stringify(pathToFileURL(require.resolve('semver')).href));
  try {
    for (const [label, before, after, check] of [
      ['channel', 'const target = tags?.[channel];', 'const target = tags?.latest;', (module) => {
        const result = module.selectUpdate({ name, version: '1.3.1' }, { legacy: '1.3.2', latest: '2.0.1' }, release('1.3.2'));
        assert.equal(result.target, '1.3.2');
      }],
      ['rollback', 'semver.compare(target, pkg.version)', 'Number(target !== pkg.version)', (module) => {
        const result = module.selectUpdate({ name, version: '2.0.2' }, { latest: '2.0.1' }, release('2.0.1'));
        assert.equal(result.status, 'installed-ahead');
      }],
    ]) {
      assert.equal(source.includes(before), true, 'control must change the intended production code');
      const path = join(directory, `${label}.mjs`);
      writeFileSync(path, source.replace(before, after));
      const changed = await import(pathToFileURL(path));
      assert.throws(() => check(changed), `${label} regression must fail its assertion`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
