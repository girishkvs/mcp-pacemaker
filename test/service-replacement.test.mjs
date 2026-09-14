// Guard-only tests. No bridge, supervisor, native helper or npm command is launched.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import {
  assertReplacementState, assertSettled, checkReplacement, processRecords, readArtifact,
  replacementOptions, replaceStoppedRoot, withCleanup,
} from '../tools/service-replacement/check.mjs';

const digest = 'a'.repeat(64);
const args = [
  '--legacy-tarball', 'legacy.tgz', '--legacy-sha256', digest,
  '--current-tarball', 'current.tgz', '--current-sha256', digest,
];
const stopped = () => ({
  started: true, settled: true, stopped: true, held: true,
  bridgePids: [123], livePids: [], listenerOpen: false,
});

test('T32 requires two explicit exact patch artifacts and normalizes their digests', () => {
  const options = replacementOptions(args.map((value) => value === digest ? value.toUpperCase() : value));
  assert.deepEqual(options, {
    legacy: { version: '1.3.1', tarball: resolve('legacy.tgz'), sha256: digest },
    current: { version: '2.0.1', tarball: resolve('current.tgz'), sha256: digest },
  });
});

for (const [name, input] of [
  ['no artifacts', []],
  ['no current artifact', args.slice(0, 4)],
  ['no legacy artifact', args.slice(4)],
  ['missing value', ['--legacy-tarball']],
  ['option in place of value', ['--legacy-tarball', '--current-tarball']],
  ['duplicate option', [...args, '--legacy-tarball', 'other.tgz']],
  ['unknown source-root fallback', [...args, '--source-root', '.']],
  ['unknown version override', [...args, '--version', '2.0.0']],
  ['directory instead of tarball', args.map((value) => value === 'current.tgz' ? '.' : value)],
  ['bad digest', args.map((value) => value === digest ? 'not-a-digest' : value)],
]) {
  test(`T32 rejects ${name}`, () => assert.throws(() => replacementOptions(input)));
}

test('missing/directory/corrupt/digest-mismatched artifacts fail before any service exists', async () => {
  const owned = ownedDirectory();
  try {
    const missing = join(owned.dir, 'missing.tgz');
    const spec = { tarball: missing, sha256: digest, version: '1.3.1' };
    assert.throws(() => readArtifact(spec, '1.3.1'), { code: 'ENOENT' });
    const directory = join(owned.dir, 'directory.tgz');
    mkdirSync(directory);
    assert.throws(() => readArtifact({ ...spec, tarball: directory }, '1.3.1'), /regular .tgz file/);
    const corrupt = join(owned.dir, 'corrupt.tgz');
    writeFileSync(corrupt, 'not an archive');
    assert.throws(() => readArtifact({ ...spec, tarball: corrupt }, '1.3.1'), /SHA-256 mismatch/);
    assert.throws(() => readArtifact({ ...spec, version: '1.3.0' }, '1.3.1'), /exact selected patch/);
    await assert.rejects(checkReplacement({
      legacy: spec, current: { ...spec, version: '2.0.1' },
    }), { code: 'ENOENT' });
  } finally {
    removeOwnedDirectory(owned);
  }
});

function roots(owned, name) {
  const directory = join(owned.dir, name);
  mkdirSync(directory);
  const root = join(directory, 'install');
  const staged = join(directory, 'staged');
  const retired = join(directory, 'retired');
  mkdirSync(root);
  mkdirSync(staged);
  writeFileSync(join(root, 'identity'), 'old');
  writeFileSync(join(staged, 'identity'), 'new');
  return { root, staged, retired };
}

for (const [key, value] of [
  ['started', false], ['settled', false], ['stopped', false], ['held', false],
  ['listenerOpen', true], ['bridgePids', []], ['livePids', [123]],
]) {
  test(`replacement refuses ${key} without touching the owned roots`, () => {
    const owned = ownedDirectory();
    try {
      const paths = roots(owned, 'guard');
      assert.throws(() => replaceStoppedRoot(paths.root, paths.staged, paths.retired, {
        ...stopped(), [key]: value,
      }));
      assert.equal(readFileSync(join(paths.root, 'identity'), 'utf8'), 'old');
      assert.equal(readFileSync(join(paths.staged, 'identity'), 'utf8'), 'new');
      assert.equal(existsSync(paths.retired), false);
    } finally {
      removeOwnedDirectory(owned);
    }
  });
}

test('verified replacement moves only the owned stopped root and preserves old bytes', () => {
  const owned = ownedDirectory();
  try {
    const paths = roots(owned, 'valid');
    replaceStoppedRoot(paths.root, paths.staged, paths.retired, stopped());
    assert.equal(readFileSync(join(paths.root, 'identity'), 'utf8'), 'new');
    assert.equal(readFileSync(join(paths.retired, 'identity'), 'utf8'), 'old');
    assert.equal(existsSync(paths.staged), false);
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('regression control: removing the actual replacement guard fails the no-overwrite oracle', async () => {
  const owned = ownedDirectory();
  try {
    const source = replaceStoppedRoot.toString();
    const guard = 'assertReplacementState(state);';
    assert.equal(source.includes(guard), true, 'Mutate the real root replacement function');
    const mutantPath = join(owned.dir, 'without-stop-guard.mjs');
    writeFileSync(mutantPath, [
      "import assert from 'node:assert/strict';",
      "import { renameSync } from 'node:fs';",
      `export ${assertReplacementState.toString()}`,
      `export ${source.replace(guard, '')}`,
    ].join('\n'));
    const mutant = await import(pathToFileURL(mutantPath).href);
    const oracle = (replace, name) => {
      const paths = roots(owned, name);
      assert.throws(() => replace(paths.root, paths.staged, paths.retired, {
        ...stopped(), stopped: false,
      }), /stop receipt/);
      assert.equal(readFileSync(join(paths.root, 'identity'), 'utf8'), 'old');
    };
    oracle(replaceStoppedRoot, 'fixed');
    assert.throws(() => oracle(mutant.replaceStoppedRoot, 'mutated'), { code: 'ERR_ASSERTION' });
    assert.equal(readFileSync(join(owned.dir, 'mutated', 'install', 'identity'), 'utf8'), 'new',
      'The isolated mutant really overwrote its synthetic root; no production source was reverted');
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('pending, applying, failed and unknown batches block replacement', () => {
  for (const status of ['pending', 'applying', 'failed', 'unknown']) {
    assert.throws(() => assertSettled({ prewarm: { batches: [{ id: 'test', status }] } }), /blocks replacement/);
  }
  assertSettled({ prewarm: {} });
  assertSettled({ prewarm: { batches: [{ status: 'applied' }, { status: 'cancelled' }] } });
});

test('missing, malformed and invalid PID evidence fails closed', () => {
  const owned = ownedDirectory();
  try {
    const path = join(owned.dir, 'processes.jsonl');
    assert.throws(() => processRecords(path), { code: 'ENOENT' });
    writeFileSync(path, '{incomplete\n');
    assert.throws(() => processRecords(path), SyntaxError);
    for (const pid of [0, -1, null, '123']) {
      writeFileSync(path, JSON.stringify({ pid, entry: 'fixture', worker: false }) + '\n');
      assert.throws(() => processRecords(path), /Invalid process observation/);
    }
    const record = { pid: process.pid, entry: 'fixture', worker: false };
    writeFileSync(path, JSON.stringify(record) + '\n');
    assert.deepEqual(processRecords(path), [record]);
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('cleanup preserves the original failure, attempts every fixture and reports retained evidence', async () => {
  const original = new Error('original gate failure');
  const diagnostics = [];
  let attempts = 0;
  const fixtures = [
    { cleanup: async () => { attempts++; throw new Error('retain unverified root'); } },
    { cleanup: async () => { attempts++; } },
  ];
  await assert.rejects(withCleanup(fixtures, async () => { throw original; }, (line) => diagnostics.push(line)),
    (error) => error === original);
  assert.equal(attempts, 2);
  assert.match(diagnostics.join('\n'), /retain unverified root/);
  await assert.rejects(withCleanup(fixtures, async () => 'not success', () => {}), AggregateError);
  assert.equal(await withCleanup([], async () => 'success'), 'success');
});
