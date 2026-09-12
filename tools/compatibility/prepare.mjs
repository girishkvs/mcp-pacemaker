import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  ROOT, LEGACY_REF, MANIFEST, assertCandidateInputs, candidateInputs, checkLockfile, isolatedEnvironment, npm,
  npmRestoreArguments, ownedFixtureManifest, readJson, removeFixtureManifest, removeOwnedDirectory,
  run, sha256, writeFixtureManifest,
} from './fixtures.mjs';

assert.ok(process.argv.slice(2).every((arg) => arg === '--clean'), 'Only --clean is supported');
if (process.argv.includes('--clean')) {
  if (existsSync(MANIFEST)) {
    const dir = removeFixtureManifest();
    console.log(`Removed owned compatibility fixture: ${dir}`);
  } else {
    console.log('No prepared compatibility fixture to clean.');
  }
} else {
  assert.equal(existsSync(MANIFEST), false, 'Fixtures already prepared. Run "npm run compat:clean" before rebuilding.');
  assert.equal(readJson(join(ROOT, 'package.json')).version, '2.0.0', 'This gate covers only 1.3.0 and 2.0.0');
  mkdirSync(join(ROOT, 'node_modules', '.cache'), { recursive: true });
  const owned = ownedFixtureManifest();
  const { dir } = owned;
  try {
    const env = isolatedEnvironment(dir);
    const restoreArguments = await npmRestoreArguments();
    const legacy = join(dir, 'legacy');
    const candidate = join(dir, 'candidate');
    mkdirSync(legacy);
    mkdirSync(candidate);
    let gitArgs = ['-C', ROOT];
    try {
      await run('git', [...gitArgs, 'cat-file', '-e', `${LEGACY_REF}^{commit}`]);
    } catch {
      // A shallow CI checkout may not contain the release. Fetch only the immutable SHA
      // into a private repository, never a moving tag or the working checkout.
      const repo = join(dir, 'baseline.git');
      await run('git', ['init', '--bare', repo], { env });
      gitArgs = ['--git-dir', repo];
      await run('git', [...gitArgs, '-c', 'credential.helper=', 'fetch', '--no-tags', '--depth=1',
        'https://github.com/girishkvs/mcp-pacemaker.git', LEGACY_REF], {
        env: { ...env, GIT_TERMINAL_PROMPT: '0' },
      });
    }
    assert.equal((await run('git', [...gitArgs, 'rev-parse', `${LEGACY_REF}^{commit}`])).trim(), LEGACY_REF);
    const archive = join(dir, 'legacy.tar');
    await run('git', [...gitArgs, 'archive', '--format=tar', `--output=${archive}`, LEGACY_REF]);
    await run('tar', ['-xf', archive, '-C', legacy]);
    assert.equal(readJson(join(legacy, 'package.json')).version, '1.3.0');

    const candidateLockSha256 = sha256(join(ROOT, 'package-lock.json'));
    const inputs = candidateInputs();
    checkLockfile(join(ROOT, 'package-lock.json'));
    checkLockfile(join(ROOT, 'ui', 'package-lock.json'));
    checkLockfile(join(legacy, 'package-lock.json'));
    const packed = JSON.parse(await npm(['pack', '--ignore-scripts', '--json', '--pack-destination', dir], { cwd: ROOT }))[0];
    const tarball = join(dir, packed.filename);
    await run('tar', ['-xzf', tarball, '-C', candidate, '--strip-components=1']);
    copyFileSync(join(ROOT, 'package-lock.json'), join(candidate, 'package-lock.json'));
    const candidateFiles = Object.fromEntries(packed.files.map(({ path }) => [path, sha256(join(candidate, path))]));
    const legacyFiles = {};
    const record = (relative) => {
      for (const entry of readdirSync(join(legacy, relative), { withFileTypes: true })) {
        const path = join(relative, entry.name);
        if (entry.isDirectory()) record(path);
        else legacyFiles[path] = sha256(join(legacy, path));
      }
    };
    record('bin');
    record(join('ui', 'dist'));
    for (const path of ['package.json', 'package-lock.json']) legacyFiles[path] = sha256(join(legacy, path));

    for (const cwd of [legacy, candidate]) {
      const lockfile = join(cwd, 'package-lock.json');
      const lockHash = sha256(lockfile);
      const output = await npm(['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund',
        '--prefer-offline', ...restoreArguments], { cwd, env });
      assert.equal(sha256(lockfile), lockHash, 'npm ci changed the fixture lockfile');
      checkLockfile(lockfile);
      console.log(output.trim());
    }
    const manifest = {
      ...owned, legacyRef: LEGACY_REF, runtimeMajor: process.versions.node.split('.')[0],
      legacy, candidate, tarball, tarballSha256: sha256(tarball), candidateLockSha256,
      candidateFiles, legacyFiles, candidateInputs: inputs,
    };
    assertCandidateInputs(inputs);
    writeFixtureManifest(manifest);
    console.log(`Prepared 1.3.0 @ ${LEGACY_REF} and packed 2.0.0\n${MANIFEST}\nCandidate SHA-256: ${manifest.tarballSha256}`);
  } catch (error) {
    console.error(`Compatibility preparation failed: ${error.stack}`);
    try { removeOwnedDirectory(owned); }
    catch (cleanupError) { console.error(`Fixture cleanup failed: ${cleanupError.stack}`); }
    throw error;
  }
}
