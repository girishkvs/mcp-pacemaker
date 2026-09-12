import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { CleanupFileSystem } from './cleanup-filesystem.mjs';
import {
  ROOT, MANIFEST, assertCandidateInputs, candidateInputs, checkLockfile, isolatedEnvironment,
  npmRestoreArguments, ownedDirectory, ownedFixtureManifest, readJson, removeFixtureManifest,
  removeOwnedDirectory, writeFixtureManifest,
} from '../../tools/compatibility/fixtures.mjs';

test('every compatibility test is registered and both gates are explicit CI steps', () => {
  const scripts = readJson(join(ROOT, 'package.json')).scripts;
  const listed = [scripts['test:compat'], scripts['test:compat:browser']].join(' ');
  for (const file of readdirSync(join(ROOT, 'test', 'compat')).filter((name) => name.endsWith('.test.mjs'))) {
    assert.ok(listed.includes(`test/compat/${file}`), `Unregistered compatibility test: ${file}`);
  }
  const workflow = readFileSync(join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.match(workflow, /os: \[ubuntu-latest, windows-latest, macos-latest\]/);
  assert.match(workflow, /node: \[20, 22\]/);
  for (const name of ['test:compat', 'test:compat:browser']) {
    assert.match(workflow, new RegExp(`- name: [^\\n]+\\n +run: npm run ${name}\\r?\\n`));
  }
  assert.equal((workflow.match(/run: npm run compat:prepare/g) ?? []).length, 2);
  assert.match(workflow, /playwright install --with-deps chromium/);
});

test('owned fixture cleanup does not follow a directory link or remove another fixture', () => {
  const owned = ownedDirectory();
  const other = ownedDirectory();
  try {
    const sentinel = join(other.dir, 'keep.txt');
    writeFileSync(sentinel, 'keep');
    mkdirSync(join(owned.dir, 'nested'));
    writeFileSync(join(owned.dir, 'nested', 'remove.txt'), 'remove');
    symlinkSync(other.dir, join(owned.dir, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    removeOwnedDirectory(owned);
    assert.equal(existsSync(owned.dir), false);
    assert.equal(readFileSync(sentinel, 'utf8'), 'keep');
  } finally {
    if (existsSync(owned.dir)) removeOwnedDirectory(owned);
    removeOwnedDirectory(other);
  }
});

test('fixture ownership mismatch fails without removing its contents', () => {
  const owned = ownedDirectory();
  try {
    assert.throws(() => removeOwnedDirectory({ ...owned, owner: 'not-the-owner' }), /Fixture ownership changed/);
    assert.equal(existsSync(owned.dir), true);
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('compatibility subprocesses use private HOME, state and temporary directories', () => {
  const owned = ownedDirectory();
  try {
    const env = isolatedEnvironment(owned.dir);
    assert.equal(env.HOME, join(owned.dir, 'home'));
    assert.equal(env.USERPROFILE, env.HOME);
    assert.equal(env.XDG_CONFIG_HOME, env.HOME);
    assert.equal(env.TEMP, join(owned.dir, 'tmp'));
    assert.equal(env.MCP_CONFIG_WATCH, '0');
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('public lockfile check rejects other registries and non-HTTPS resolutions', () => {
  const owned = ownedDirectory();
  try {
    const file = join(owned.dir, 'package-lock.json');
    for (const resolved of ['https://private.invalid/a.tgz', 'http://registry.npmjs.org/a.tgz', 'file:../a']) {
      writeFileSync(file, JSON.stringify({ packages: { a: { resolved } } }));
      assert.throws(() => checkLockfile(file), /does not resolve to the public registry/);
    }
    writeFileSync(file, JSON.stringify({ packages: { a: { resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' } } }));
    checkLockfile(file);
    checkLockfile(join(ROOT, 'package-lock.json'));
    checkLockfile(join(ROOT, 'ui', 'package-lock.json'));
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('candidate freshness includes changed, added and removed package inputs', () => {
  const inputs = candidateInputs();
  assertCandidateInputs(inputs);
  assert.throws(() => assertCandidateInputs({ ...inputs, 'package.json': 'old-hash' }), /Candidate inputs changed/);
  assert.throws(() => assertCandidateInputs({ ...inputs, 'bin/removed.mjs': 'old-hash' }), /Candidate inputs changed/);
  const missing = { ...inputs };
  delete missing['package.json'];
  assert.throws(() => assertCandidateInputs(missing), /Candidate inputs changed/);
});

test('isolated npm restore honors resolved caller registry settings, including the public default', async () => {
  for (const registry of ['https://registry.npmjs.org/', 'https://approved-registry.example.test/npm/']) {
    const cache = join(ROOT, 'node_modules', '.cache', 'npm');
    const calls = [];
    const settings = { cache, registry, 'replace-registry-host': 'npmjs' };
    const args = await npmRestoreArguments(async (args, options) => {
      calls.push(args);
      assert.equal(options.cwd, ROOT);
      assert.deepEqual(args.slice(0, 2), ['config', 'get']);
      return `${settings[args[2]]}\n`;
    });
    assert.deepEqual(calls.map((args) => args[2]), ['cache', 'registry', 'replace-registry-host']);
    assert.deepEqual(args, ['--cache', cache, '--registry', registry, '--replace-registry-host', 'npmjs']);
  }
});

test('npm configuration errors propagate without a registry fallback', async () => {
  const rejected = new Error('Approved registry configuration rejected');
  await assert.rejects(npmRestoreArguments(async () => { throw rejected; }), (error) => error === rejected);
});

test('partial cleanup EPERM retains ownership and safely retries', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedDirectory(fs);
  fs.writeFileSync(join(owned.dir, 'first.txt'), 'first');
  const blocked = join(owned.dir, 'last.txt');
  fs.writeFileSync(blocked, 'last');
  const marker = `${owned.dir}.compat-owner`;
  const authority = { ...fs.entry(marker) };
  fs.failOnce('unlinkSync', blocked);
  assert.throws(() => removeOwnedDirectory(owned, fs), { code: 'EPERM' });
  assert.ok(fs.removals.includes(join(owned.dir, 'first.txt')));
  assert.equal(fs.readFileSync(blocked), 'last');
  assert.deepEqual(fs.entry(marker), authority);
  assert.doesNotThrow(() => removeOwnedDirectory(owned, fs));
  assert.deepEqual([...fs.entries], []);
});

test('final directory removal EPERM retains ownership and safely retries', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedDirectory(fs);
  fs.writeFileSync(join(owned.dir, 'payload.txt'), 'payload');
  const marker = `${owned.dir}.compat-owner`;
  const authority = { ...fs.entry(marker) };
  fs.failOnce('rmdirSync', owned.dir);
  assert.throws(() => removeOwnedDirectory(owned, fs), { code: 'EPERM' });
  assert.deepEqual(fs.entry(marker), authority);
  assert.doesNotThrow(() => removeOwnedDirectory(owned, fs));
  assert.deepEqual([...fs.entries], []);
});

test('ownership marker unlink EPERM safely retries after the directory is gone', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedDirectory(fs);
  const marker = `${owned.dir}.compat-owner`;
  const authority = { ...fs.entry(marker) };
  fs.failOnce('unlinkSync', marker);
  assert.throws(() => removeOwnedDirectory(owned, fs), { code: 'EPERM' });
  assert.equal(fs.entries.has(owned.dir), false);
  assert.deepEqual(fs.entry(marker), authority);
  assert.doesNotThrow(() => removeOwnedDirectory(owned, fs));
  assert.deepEqual([...fs.entries], []);
});

test('prepared manifest unlink EPERM remains retryable through the cleanup entry point', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedFixtureManifest(fs);
  fs.writeFileSync(join(owned.dir, 'payload.txt'), 'payload');
  const manifest = { ...fs.entry(MANIFEST) };
  fs.failOnce('unlinkSync', MANIFEST);
  assert.throws(() => removeFixtureManifest(fs), { code: 'EPERM' });
  assert.equal(fs.entries.has(owned.dir), false);
  assert.deepEqual(fs.entry(MANIFEST), manifest);
  assert.doesNotThrow(() => removeFixtureManifest(fs));
  assert.deepEqual([...fs.entries], []);
});

test('prepared manifest remains authoritative through partial unlink and final rmdir failures', () => {
  for (const operation of ['unlinkSync', 'rmdirSync']) {
    const fs = new CleanupFileSystem();
    const owned = ownedFixtureManifest(fs);
    fs.writeFileSync(join(owned.dir, 'first.txt'), 'first');
    const last = join(owned.dir, 'last.txt');
    fs.writeFileSync(last, 'last');
    const authority = { ...fs.entry(MANIFEST) };
    fs.failOnce(operation, operation === 'unlinkSync' ? last : owned.dir);
    assert.throws(() => removeFixtureManifest(fs), { code: 'EPERM' });
    assert.ok(fs.removals.includes(join(owned.dir, 'first.txt')));
    assert.deepEqual(fs.entry(MANIFEST), authority);
    assert.doesNotThrow(() => removeFixtureManifest(fs));
    assert.deepEqual([...fs.entries], []);
  }
});

test('prepared cleanup rejects missing, linked, replaced or redirected authority and replaced roots', () => {
  for (const kind of ['missing', 'link', 'replacement', 'redirect', 'root-replacement']) {
    const fs = new CleanupFileSystem();
    const owned = ownedFixtureManifest(fs);
    fs.writeFileSync(join(owned.dir, 'keep.txt'), 'keep');
    const bytes = fs.readFileSync(MANIFEST);
    if (kind === 'missing') fs.entries.delete(MANIFEST);
    if (kind === 'link') fs.create(MANIFEST, 'link', '/unowned');
    if (kind === 'replacement') fs.create(MANIFEST, 'file', bytes);
    if (kind === 'redirect') fs.writeFileSync(MANIFEST, JSON.stringify({ ...owned, marker: '/unowned' }));
    if (kind === 'root-replacement') fs.create(owned.dir, 'directory');
    const before = structuredClone([...fs.entries]);
    assert.throws(() => removeFixtureManifest(fs));
    assert.deepEqual([...fs.entries], before);
    assert.deepEqual(fs.removals, []);
  }
});

test('prepared cleanup retry refuses a root recreated after manifest unlink fails', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedFixtureManifest(fs);
  fs.failOnce('unlinkSync', MANIFEST);
  assert.throws(() => removeFixtureManifest(fs), { code: 'EPERM' });
  fs.create(owned.dir, 'directory');
  fs.writeFileSync(join(owned.dir, 'keep.txt'), 'keep');
  const before = structuredClone([...fs.entries]);
  const removals = [...fs.removals];
  assert.throws(() => removeFixtureManifest(fs), /Fixture directory identity changed/);
  assert.deepEqual([...fs.entries], before);
  assert.deepEqual(fs.removals, removals);
});

test('manifest publication preserves authority identity and cleanup uses that one marker', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedFixtureManifest(fs);
  const markerId = fs.entry(MANIFEST).id;
  assert.equal(owned.marker, MANIFEST);
  assert.equal(fs.entries.has(`${owned.dir}.compat-owner`), false);
  const published = { ...owned, fixtureDetails: 'longer payload'.repeat(100) };
  writeFixtureManifest(published, fs);
  assert.equal(fs.entry(MANIFEST).id, markerId);
  assert.deepEqual(JSON.parse(fs.readFileSync(MANIFEST)), published);
  writeFixtureManifest(owned, fs);
  assert.deepEqual(JSON.parse(fs.readFileSync(MANIFEST)), owned);
  assert.equal(fs.entry(MANIFEST).id, markerId);
  removeFixtureManifest(fs);
  assert.deepEqual([...fs.entries], []);
});

for (const aliased of [false, true]) {
  test(`manifest creation, publication and cleanup work in ${aliased ? 'an aliased' : 'an isolated'} root`, async (t) => {
    const sandbox = ownedDirectory();
    let local;
    t.after(() => {
      if (local &&
          existsSync(local.MANIFEST)) local.removeFixtureManifest();
      removeOwnedDirectory(sandbox);
    });
    let isolatedRoot = sandbox.dir;
    if (aliased) {
      const target = join(sandbox.dir, 'checkout');
      mkdirSync(target);
      isolatedRoot = join(sandbox.dir, 'alias');
      symlinkSync(target, isolatedRoot, process.platform === 'win32' ? 'junction' : 'dir');
    }
    const helper = join(isolatedRoot, 'tools', 'compatibility', 'fixtures.mjs');
    mkdirSync(join(isolatedRoot, 'tools', 'compatibility'), { recursive: true });
    mkdirSync(join(isolatedRoot, 'node_modules', '.cache'), { recursive: true });
    writeFileSync(helper, readFileSync(join(ROOT, 'tools', 'compatibility', 'fixtures.mjs')));
    local = await import(pathToFileURL(helper).href);
    assert.equal(local.MANIFEST, join(realpathSync(isolatedRoot), 'node_modules', '.cache', 'pacemaker-compat.json'));
    const owned = local.ownedFixtureManifest();
    writeFileSync(join(owned.dir, 'payload.txt'), 'payload');
    const manifest = { ...owned, fixtureDetails: 'prepared' };
    local.writeFixtureManifest(manifest);
    assert.deepEqual(readJson(local.MANIFEST), manifest);
    local.removeFixtureManifest();
    assert.equal(existsSync(owned.dir), false);
    assert.equal(existsSync(local.MANIFEST), false);
  });
}

test('manifest publication refuses missing markers and replaced or missing directories', () => {
  for (const kind of ['missing-marker', 'missing-root', 'replacement-root']) {
    const fs = new CleanupFileSystem();
    const owned = ownedFixtureManifest(fs);
    if (kind === 'missing-marker') fs.entries.delete(MANIFEST);
    if (kind === 'missing-root') fs.entries.delete(owned.dir);
    if (kind === 'replacement-root') fs.create(owned.dir, 'directory');
    const before = structuredClone([...fs.entries]);
    assert.throws(() => writeFixtureManifest({ ...owned, ready: true }, fs));
    assert.deepEqual([...fs.entries], before);
    assert.deepEqual(fs.removals, []);
  }
});

test('manifest publication pins the opened file and does not recreate a removed marker', () => {
  for (const kind of ['replace', 'remove']) {
    const fs = new CleanupFileSystem();
    const owned = ownedFixtureManifest(fs);
    fs.beforeOpen = (path) => {
      if (path !== MANIFEST) return;
      if (kind === 'replace') fs.create(path, 'file', 'not-ours');
      else fs.entries.delete(path);
    };
    assert.throws(() => writeFixtureManifest({ ...owned, ready: true }, fs),
      /Ownership marker identity changed|ENOENT/);
    if (kind === 'replace') assert.equal(fs.readFileSync(MANIFEST), 'not-ours');
    else assert.equal(fs.entries.has(MANIFEST), false);
    assert.equal(fs.entries.has(owned.dir), true);
    assert.deepEqual(fs.removals, []);
  }
});

test('cleanup never ignores a missing authoritative marker', () => {
  for (const rootPresent of [true, false]) {
    const fs = new CleanupFileSystem();
    const owned = ownedDirectory(fs);
    fs.entries.delete(`${owned.dir}.compat-owner`);
    if (!rootPresent) fs.entries.delete(owned.dir);
    const before = [...fs.entries];
    assert.throws(() => removeOwnedDirectory(owned, fs), { code: 'ENOENT' });
    assert.deepEqual([...fs.entries], before);
    assert.deepEqual(fs.removals, []);
  }
});

test('cleanup rejects linked roots and linked or replaced ownership markers', () => {
  for (const kind of ['root-link', 'marker-link', 'marker-replaced', 'marker-tampered']) {
    const fs = new CleanupFileSystem();
    const owned = ownedDirectory(fs);
    const marker = `${owned.dir}.compat-owner`;
    const bytes = fs.readFileSync(marker);
    if (kind === 'root-link') fs.create(owned.dir, 'link', '/unowned');
    if (kind === 'marker-link') fs.create(marker, 'link', '/unowned');
    if (kind === 'marker-replaced') fs.create(marker, 'file', bytes);
    if (kind === 'marker-tampered') fs.writeFileSync(marker, JSON.stringify({ ...owned, owner: 'wrong-owner' }));
    const before = [...fs.entries];
    assert.throws(() => removeOwnedDirectory(owned, fs), /Refusing a linked|marker identity changed|Fixture ownership changed/);
    assert.deepEqual([...fs.entries], before);
    assert.deepEqual(fs.removals, []);
  }
});

test('cleanup retry rejects a replacement directory instead of claiming it', () => {
  for (const failedOperation of ['rmdirSync', 'unlinkSync']) {
    const fs = new CleanupFileSystem();
    const owned = ownedDirectory(fs);
    const marker = `${owned.dir}.compat-owner`;
    const authority = { ...fs.entry(marker) };
    fs.failOnce(failedOperation, failedOperation === 'rmdirSync' ? owned.dir : marker);
    assert.throws(() => removeOwnedDirectory(owned, fs), { code: 'EPERM' });
    if (fs.entries.has(owned.dir)) fs.renameSync(owned.dir, `${owned.dir}-original`);
    fs.create(owned.dir, 'directory');
    const sentinel = join(owned.dir, 'not-ours.txt');
    fs.writeFileSync(sentinel, 'keep');
    const removals = [...fs.removals];
    assert.throws(() => removeOwnedDirectory(owned, fs), /Fixture directory identity changed/);
    assert.equal(fs.readFileSync(sentinel), 'keep');
    assert.deepEqual(fs.entry(marker), authority);
    assert.deepEqual(fs.removals, removals);
  }
});

test('a root recreated after final rmdir does not receive or retire ownership', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedDirectory(fs);
  const marker = `${owned.dir}.compat-owner`;
  const authority = { ...fs.entry(marker) };
  fs.afterRemoval = (path) => {
    if (path === owned.dir) fs.create(owned.dir, 'directory');
  };
  assert.throws(() => removeOwnedDirectory(owned, fs), /Fixture directory reappeared/);
  assert.deepEqual(fs.entry(marker), authority);
  const removals = [...fs.removals];
  assert.throws(() => removeOwnedDirectory(owned, fs), /Fixture directory identity changed/);
  assert.deepEqual(fs.removals, removals);
});

test('a fixture root replaced by a link after preflight is not unlinked as a child', () => {
  const fs = new CleanupFileSystem();
  const owned = ownedDirectory(fs);
  let rootReads = 0;
  fs.beforeStat = (path) => {
    if (path !== owned.dir) return;
    rootReads++;
    if (rootReads === 3) {
      fs.renameSync(owned.dir, `${owned.dir}-original`);
      fs.create(owned.dir, 'link', '/unowned');
    }
  };
  assert.throws(() => removeOwnedDirectory(owned, fs), /Refusing a linked/);
  assert.equal(fs.entry(owned.dir).type, 'link');
  assert.deepEqual(fs.removals, []);
});
