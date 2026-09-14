import assert from 'node:assert/strict';
import { constants, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  ROOT, MANIFEST, assertCandidateInputs, candidateInputs, checkLockfile, fixturePlan,
  isolatedEnvironment, npm, npmRestoreArguments, ownedFixtureManifest, packedPackage, preparationOptions,
  readJson, removeFixtureManifest, removeOwnedDirectory, run, sha256, writeFixtureManifest,
} from './fixtures.mjs';
import { extractTarball } from '../npm-publication/tarball.mjs';

const options = preparationOptions(process.argv.slice(2));

async function releaseArchive(ref, dir, role, env) {
  let gitArgs = ['-C', ROOT];
  try {
    assert.equal((await run('git', [...gitArgs, 'rev-parse', '--verify', '--quiet', `${ref}^{commit}`])).trim(), ref);
  } catch (error) {
    if (error.exitCode !== 1) throw error;
    const repo = join(dir, `${role}-baseline.git`);
    await run('git', ['init', '--bare', repo], { env });
    gitArgs = ['--git-dir', repo];
    await run('git', [...gitArgs, '-c', 'credential.helper=', 'fetch', '--no-tags', '--depth=1',
      'https://github.com/girishkvs/mcp-pacemaker.git', ref], {
      env: { ...env, GIT_TERMINAL_PROMPT: '0' },
    });
  }
  assert.equal((await run('git', [...gitArgs, 'rev-parse', `${ref}^{commit}`])).trim(), ref);
  const archive = join(dir, `${role}.tar`);
  await run('git', [...gitArgs, '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
    '-c', `core.attributesFile=${process.platform === 'win32' ? 'NUL' : '/dev/null'}`,
    'archive', '--format=tar', `--output=${archive}`, ref], {
    env: { ...env, GIT_ATTR_NOSYSTEM: '1' },
  });
  return archive;
}

function fileManifest(root) {
  const files = {};
  const visit = (relative) => {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      assert.equal(entry.isSymbolicLink(), false, `Linked fixture input: ${path}`);
      if (entry.isDirectory()) visit(path);
      else files[path] = sha256(join(root, path));
    }
  };
  visit('');
  return files;
}

async function prepareSource(spec, role, dir, env) {
  const destination = join(dir, role);
  mkdirSync(destination);
  let archive;
  let inputs;
  let lockSha256;
  if (spec.source === 'release') {
    archive = await releaseArchive(spec.ref, dir, role, env);
    await run('tar', ['-xf', archive, '-C', destination]);
  } else {
    const source = spec.source === 'root' ? ROOT : options.peerRoot;
    assert.equal(readJson(join(source, 'package.json')).version, spec.version);
    checkLockfile(join(source, 'package-lock.json'));
    checkLockfile(join(source, 'ui', 'package-lock.json'));
    inputs = candidateInputs(source);
    lockSha256 = sha256(join(source, 'package-lock.json'));
    let files;
    if (spec.source === 'root' &&
        options.candidateTarball) {
      assert.equal(sha256(options.candidateTarball), options.candidateSha256, 'Supplied candidate digest differs');
      archive = join(dir, 'supplied-candidate.tgz');
      copyFileSync(options.candidateTarball, archive, constants.COPYFILE_EXCL);
      assert.equal(sha256(archive), options.candidateSha256, 'Supplied candidate changed while copying');
      const commit = (await run('git', ['-C', source, 'rev-parse', 'HEAD'])).trim();
      files = extractTarball(readFileSync(archive), { version: spec.version, commit }, destination).files;
    } else {
      const result = JSON.parse(await npm(['pack', '--ignore-scripts', '--json', '--pack-destination', dir],
        { cwd: source }));
      const packed = packedPackage(result, readJson(join(source, 'package.json')).name, spec.version);
      archive = join(dir, packed.filename);
      await run('tar', ['-xzf', archive, '-C', destination, '--strip-components=1']);
      files = packed.files;
    }
    assert.deepEqual(files.map(({ path }) => path).sort(),
      Object.keys(inputs).filter((path) => path !== 'package-lock.json').sort(),
      'Packed files must cover exactly the candidate package inputs');
    copyFileSync(join(source, 'package-lock.json'), join(destination, 'package-lock.json'));
    for (const { path } of files) {
      assert.equal(sha256(join(destination, path)), sha256(join(source, path)), `Packed source differs: ${path}`);
    }
    assertCandidateInputs(inputs, source);
  }
  assert.equal(readJson(join(destination, 'package.json')).version, spec.version);
  checkLockfile(join(destination, 'package-lock.json'));
  return {
    archive, archiveSha256: sha256(archive), files: fileManifest(destination),
    ...(inputs ? { inputs, lockSha256 } : {}),
  };
}

if (options.clean) {
  if (existsSync(MANIFEST)) {
    console.log(`Removed owned compatibility fixture: ${removeFixtureManifest()}`);
  } else {
    console.log('No prepared compatibility fixture to clean.');
  }
} else {
  assert.equal(existsSync(MANIFEST), false, 'Fixtures already prepared. Run "npm run compat:clean" before rebuilding.');
  const plan = fixturePlan(readJson(join(ROOT, 'package.json')).version, {
    historical: options.historical,
    peerVersion: options.peerRoot && readJson(join(options.peerRoot, 'package.json')).version,
  });
  mkdirSync(join(ROOT, 'node_modules', '.cache'), { recursive: true });
  const owned = ownedFixtureManifest();
  const { dir } = owned;
  try {
    const env = isolatedEnvironment(dir);
    const restoreArguments = await npmRestoreArguments();
    const inputs = candidateInputs();
    const sources = {};
    for (const role of ['legacy', 'candidate']) {
      sources[role] = await prepareSource(plan[role], role, dir, env);
      const cwd = join(dir, role);
      const lockfile = join(cwd, 'package-lock.json');
      const before = sha256(lockfile);
      const output = await npm(['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund',
        '--prefer-offline', ...restoreArguments], { cwd, env });
      assert.equal(sha256(lockfile), before, 'npm ci changed the fixture lockfile');
      checkLockfile(lockfile);
      console.log(output.trim());
    }
    const manifest = {
      ...owned, schemaVersion: 2, plan, runtimeMajor: process.versions.node.split('.')[0],
      npmVersion: (await npm(['--version'])).trim(),
      legacy: join(dir, 'legacy'), candidate: join(dir, 'candidate'),
      peerRoot: options.peerRoot, sources, candidateInputs: inputs,
    };
    assertCandidateInputs(inputs);
    writeFixtureManifest(manifest);
    console.log(`Prepared ${plan.mode}: ${plan.legacy.version} / ${plan.candidate.version}\n${MANIFEST}`);
    for (const role of ['legacy', 'candidate']) {
      console.log(`${role}: ${plan[role].source}; ${plan[role].ref ?? 'local packed inputs'}; SHA-256 ${sources[role].archiveSha256}`);
    }
  } catch (error) {
    console.error(`Compatibility preparation failed: ${error.stack}`);
    try { removeOwnedDirectory(owned); }
    catch (cleanupError) { console.error(`Fixture cleanup failed: ${cleanupError.stack}`); }
    throw error;
  }
}
