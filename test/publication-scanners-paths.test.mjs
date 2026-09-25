import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, relative } from 'node:path';
import { inventory, isolatedEnvironment, workspace } from '../tools/publication-scanners/core.mjs';
import { diagnosticOutputPath } from '../tools/publication-scanners/diagnose.mjs';
import { diagnosticLocations, isForeignWindowsPath } from '../tools/publication-scanners/locations.mjs';

async function fixture(action) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'scanner-paths-'));
  try {
    return await action(root);
  } finally {
    await rm(root, { recursive: true, force: false });
  }
}

async function withTempParent(parent, action) {
  const names = ['TMP', 'TEMP', 'TMPDIR'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  try {
    for (const name of names) process.env[name] = parent;
    return await action();
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
}

async function directoryAlias(target, path) {
  await symlink(target, path, process.platform === 'win32' ? 'junction' : 'dir');
}

function shortPath(path, root) {
  const output = execFileSync(join(process.env.SystemRoot, 'System32/cmd.exe'),
    ['/d', '/v:off', '/u', '/s', '/c', 'for %I in ("%PUBLICATION_ALIAS_PATH%") do @echo "%~sI"'], {
      env: { ...isolatedEnvironment(root), PUBLICATION_ALIAS_PATH: path },
      encoding: 'utf16le', timeout: 10_000, maxBuffer: 64 * 1024,
      windowsHide: true, windowsVerbatimArguments: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  assert.match(output, /^"[^"\r\n]+"$/, 'Native short-path query must return one quoted path');
  return output.slice(1, -1);
}

test('T42: path-syntax classification distinguishes native POSIX roots from Windows drive and UNC roots', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const path of ['/tmp/source/file.mjs', '/private/var/tmp/file.mjs', 'test/file.mjs', './test/file.mjs']) {
      assert.equal(isForeignWindowsPath(path, platform), false, 'Native POSIX or relative syntax must not be foreign');
    }
    for (const path of ['C:\\source\\file.mjs', 'C:/source/file.mjs', 'C:file.mjs',
      '\\\\server\\share\\file.mjs', '//server/share/file.mjs', '\\rooted\\file.mjs',
      '\\\\?\\C:\\source\\file.mjs']) {
      assert.equal(isForeignWindowsPath(path, platform), true, 'Foreign Windows syntax must be rejected on POSIX');
    }
  }
  for (const path of ['C:\\source\\file.mjs', '\\\\server\\share\\file.mjs', 'test/file.mjs']) {
    assert.equal(isForeignWindowsPath(path, 'win32'), false);
  }
});

test('T42: actual native absolute and relative diagnostic locations remain inventory-bound', async () => fixture(async root => {
  const entries = [{ path: 'test/fixture.mjs' }, { path: 'test/例.mjs' }];
  for (const file of [join(root, 'test/fixture.mjs'), 'test/fixture.mjs', './test/fixture.mjs',
    join(root, 'test/例.mjs')]) {
    const output = diagnosticLocations('gitleaks', {
      stdout: JSON.stringify([{ RuleID: 'fixture-rule', File: file, StartLine: 2, Secret: 'REDACTED' }]),
    }, root, entries);
    assert.equal(output[0].path, file.endsWith('例.mjs') ? 'test/例.mjs' : 'test/fixture.mjs');
    assert.equal(output[0].line, 2);
  }
  for (const file of ['../outside.mjs', join(root, '..', 'outside.mjs'), 'unknown.mjs']) {
    assert.throws(() => diagnosticLocations('gitleaks', {
      stdout: JSON.stringify([{ RuleID: 'fixture-rule', File: file, StartLine: 2, Secret: 'REDACTED' }]),
    }, root, entries), /diagnostic-path-outside-snapshot/);
  }
}));

test('T42: foreign Windows locations cannot pass a POSIX inventory lookup', {
  skip: process.platform === 'win32' ? 'Native POSIX locator execution requires Linux/macOS' : false,
}, () => {
  for (const file of ['C:/source/file.mjs', 'C:relative.mjs', '\\\\server\\share\\file.mjs',
    '//server/share/file.mjs', '\\rooted\\file.mjs']) {
    assert.throws(() => diagnosticLocations('gitleaks', {
      stdout: JSON.stringify([{ RuleID: 'fixture-rule', File: file, StartLine: 1, Secret: 'REDACTED' }]),
    }, '/tmp/source', [{ path: file.replaceAll('\\', '/') }]), /diagnostic-path-outside-snapshot/);
  }
  assert.throws(() => diagnosticLocations('gitleaks', {
    stdout: JSON.stringify([{ RuleID: 'fixture-rule', File: 'test\\fixture.mjs', StartLine: 1, Secret: 'REDACTED' }]),
  }, '/tmp/source', [{ path: 'test/fixture.mjs' }]), /diagnostic-path-outside-snapshot/);
});

test('T42: canonical owned workspaces support inventory and outside-root reports, then remove only themselves',
  async () => fixture(async parent => withTempParent(parent, async () => {
    let owned;
    await workspace(async root => {
      owned = root;
      assert.ok(root === await realpath(root), 'Workspace must expose its canonical path');
      assert.ok(!(await lstat(root)).isSymbolicLink());
      assert.ok((await inventory(root)).entries.some(entry => entry.path === 'gitconfig'));
      assert.equal(await diagnosticOutputPath(join(parent, 'report.json'), root), join(parent, 'report.json'));
    });
    await assert.rejects(() => lstat(owned), { code: 'ENOENT' });
    assert.ok((await lstat(parent)).isDirectory());
  })));

test('T42: real NTFS short temp aliases produce canonical owned workspaces without relaxing external inventory',
  { skip: process.platform !== 'win32' ? 'NTFS short names are Windows-specific' : false },
  async t => fixture(async parent => {
    const longParent = join(parent, 'long alias 例 & % !');
    await mkdir(longParent);
    const alias = shortPath(longParent, parent);
    assert.ok((await lstat(alias)).isDirectory());
    assert.ok(!(await lstat(alias)).isSymbolicLink(), 'This control must use a short name, not a link');
    if (alias.toLowerCase() === (await realpath(alias)).toLowerCase()) {
      t.skip('This filesystem does not expose an 8.3 alias');
      return;
    }
    await withTempParent(alias, async () => {
      assert.ok((await realpath(tmpdir())).toLowerCase() === longParent.toLowerCase());
      await workspace(async root => {
        assert.ok(root === await realpath(root), 'Workspace must not expose its short-name spelling');
        assert.ok((await inventory(root)).entries.length > 0);
      });
    });
    await assert.rejects(() => inventory(alias), /root-link-not-supported/);
  }));

test('T42: actual aliased temp parents are canonicalized only for owned creation', async () => fixture(async parent => {
  const physical = join(parent, 'physical');
  const alias = join(parent, 'alias');
  await mkdir(physical);
  await directoryAlias(physical, alias);
  await withTempParent(alias, async () => workspace(async root => {
    assert.ok(root === await realpath(root), 'Owned path must not retain an aliased ancestor');
    assert.ok(!relative(physical, root).startsWith('..'));
    assert.ok((await inventory(root)).entries.length > 0);
  }));
  await mkdir(join(physical, 'external-source'));
  await writeFile(join(physical, 'external-source', 'fixture.txt'), 'fixture');
  await assert.rejects(() => inventory(join(alias, 'external-source')), /root-link-not-supported/);
  await assert.rejects(() => inventory(alias), /invalid-root/);
}));

test('T42: retargeting a temp-parent alias cannot redirect owned workspace cleanup', async () => fixture(async parent => {
  const first = join(parent, 'first');
  const second = join(parent, 'second');
  const alias = join(parent, 'alias');
  await mkdir(first);
  await mkdir(second);
  await directoryAlias(first, alias);
  let owned;
  let replacement;
  await withTempParent(alias, async () => workspace(async root => {
    owned = join(first, basename(root));
    replacement = join(second, basename(root));
    await rm(alias);
    await directoryAlias(second, alias);
    await mkdir(replacement);
    await writeFile(join(replacement, 'sentinel'), 'preserve replacement');
  }));
  await assert.rejects(() => lstat(owned), { code: 'ENOENT' });
  assert.equal(await readFile(join(replacement, 'sentinel'), 'utf8'), 'preserve replacement');
}));

test('T42: inventory still rejects actual nested filesystem links', async () => fixture(async parent => {
  const source = join(parent, 'source');
  const target = join(parent, 'target');
  await mkdir(source);
  await mkdir(target);
  await writeFile(join(target, 'sentinel'), 'outside source');
  await directoryAlias(target, join(source, 'linked'));
  await assert.rejects(() => inventory(source), /symlink-scope-not-supported/);
  assert.equal(await readFile(join(target, 'sentinel'), 'utf8'), 'outside source');
}));

test('T42: replacement directories are refused rather than recursively removed', async () => fixture(async parent => {
  let replacement;
  const moved = join(parent, 'moved-owned-directory');
  await withTempParent(parent, async () => assert.rejects(() => workspace(async root => {
    replacement = root;
    await rename(root, moved);
    await mkdir(root);
    await writeFile(join(root, 'sentinel'), 'preserve replacement');
  }), /temporary-directory-identity-changed/));
  assert.equal(await readFile(join(replacement, 'sentinel'), 'utf8'), 'preserve replacement');
  assert.ok((await lstat(moved)).isDirectory());
}));

test('T42: replacement links are refused and their target is preserved', async () => fixture(async parent => {
  let replacement;
  const target = join(parent, 'target');
  await mkdir(target);
  await writeFile(join(target, 'sentinel'), 'preserve target');
  await withTempParent(parent, async () => assert.rejects(() => workspace(async root => {
    replacement = root;
    await rm(root, { recursive: true, force: false });
    await directoryAlias(target, root);
  }), /temporary-directory-identity-changed/));
  assert.equal(await readFile(join(target, 'sentinel'), 'utf8'), 'preserve target');
  assert.ok((await lstat(replacement)).isSymbolicLink());
}));

test('T42: callback errors still clean the original owned directory', async () => fixture(async parent => {
  let owned;
  const failure = new Error('fixture callback failure');
  await withTempParent(parent, async () => assert.rejects(() => workspace(async root => {
    owned = root;
    throw failure;
  }), error => error === failure));
  await assert.rejects(() => lstat(owned), { code: 'ENOENT' });
  assert.ok((await lstat(parent)).isDirectory());
}));
