import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  isolatedEnvironment, npm, ownedDirectory, readJson,
  removeOwnedDirectory, run, sha256,
} from '../compatibility/fixtures.mjs';
import { CompatibilityBridge } from '../../test/compat/bridge.mjs';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { configurationText, consumerEnvironment, readConsumerConfiguration } from './environment.mjs';
import { captureConsumerLicenseEvidence } from './license-evidence.mjs';

export function consumerOptions(args) {
  const values = {};
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    assert.ok(['--tarball', '--sha256', '--version', '--name', '--ignore-scripts'].includes(key),
      `Unknown consumer-check option: ${key}`);
    assert.equal(Object.hasOwn(values, key), false, `Repeated consumer-check option: ${key}`);
    if (key === '--ignore-scripts') {
      values[key] = true;
    } else {
      const value = args[++index];
      assert.ok(value &&
        !value.startsWith('--'), `Missing value for ${key}`);
      values[key] = value;
    }
  }
  assert.ok(values['--tarball'], '--tarball is required');
  assert.match(values['--sha256'] ?? '', /^[a-f0-9]{64}$/, 'A SHA-256 digest is required');
  assert.ok(['1.3.1', '2.0.1'].includes(values['--version']), 'An explicitly supported patch version is required');
  assert.match(values['--name'] ?? '', /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/,
    'A package name is required');
  return {
    tarball: resolve(values['--tarball']), sha256: values['--sha256'],
    version: values['--version'], name: values['--name'], ignoreScripts: values['--ignore-scripts'] === true,
  };
}

export function consumerGraph(lock, name, version) {
  assert.ok(lock.packages, 'The fresh consumer lock must record its installed packages');
  const candidate = lock.packages[`node_modules/${name}`];
  assert.ok(candidate, 'The consumer did not install the candidate');
  assert.equal(candidate.version, version);
  assert.notEqual(candidate.link, true, 'The consumer must install package bytes, not a source-directory link');
  return Object.entries(lock.packages)
    .filter(([path]) => path.startsWith('node_modules/'))
    .map(([path, entry]) => ({
      path, name: path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length),
      version: entry.version, integrity: entry.integrity ?? null,
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

export function consumerNoticeVersions(graph, manifest) {
  for (const supplement of manifest.runtimeNotices) {
    const installed = graph.filter((entry) => entry.name === supplement.name);
    assert.ok(installed.length > 0, `Missing installed runtime supplement target: ${supplement.name}`);
    for (const entry of installed) {
      assert.equal(entry.version, supplement.version,
        `Fresh resolution requires a notice review for ${supplement.name}`);
    }
  }
}

export async function checkConsumer(options) {
  assert.equal(sha256(options.tarball), options.sha256, 'Candidate tarball digest mismatch');
  const configuration = await readConsumerConfiguration();
  const owned = ownedDirectory();
  let failed = false;
  try {
    const env = isolatedEnvironment(owned.dir, consumerEnvironment());
    for (const name of Object.keys(env)) {
      if (/^npm_config_/i.test(name) ||
          /^(NODE_AUTH_TOKEN|NPM_TOKEN|INIT_CWD)$/i.test(name) ||
          name.toLowerCase() === 'path') delete env[name];
    }
    env.PATH = `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? process.env.Path ?? ''}`;
    const userconfig = join(owned.dir, 'user.npmrc');
    const globalconfig = join(owned.dir, 'global.npmrc');
    writeFileSync(userconfig, configurationText(configuration), { mode: 0o600, flag: 'wx' });
    writeFileSync(globalconfig, '', { mode: 0o600, flag: 'wx' });
    env.npm_config_userconfig = userconfig;
    env.npm_config_globalconfig = globalconfig;
    const flags = [
      '--userconfig', userconfig, '--globalconfig', globalconfig, '--no-audit', '--no-fund',
      ...(options.ignoreScripts ? ['--ignore-scripts'] : []),
    ];
    const project = join(owned.dir, 'consumer');
    const prefix = join(owned.dir, 'global-prefix');
    mkdirSync(project);
    mkdirSync(prefix);
    writeFileSync(join(project, 'package.json'), JSON.stringify({
      name: 'pacemaker-private-consumer-check', version: '0.0.0', private: true,
    }) + '\n');
    assert.equal(existsSync(join(project, 'package-lock.json')), false);
    await npm(['install', options.tarball, ...flags], { cwd: project, env });
    assert.equal(readJson(join(project, 'package.json')).private, true);
    const lock = readJson(join(project, 'package-lock.json'));
    const graph = consumerGraph(lock, options.name, options.version);
    const licenseEvidence = captureConsumerLicenseEvidence(project, graph);
    const localRoot = join(project, 'node_modules', options.name);
    assert.equal(readJson(join(localRoot, 'package.json')).name, options.name);
    consumerNoticeVersions(graph, verifyArtifacts(localRoot));
    assert.equal(existsSync(join(localRoot, 'package-lock.json')), false,
      'The packed dependency must not carry the producer lock');

    await npm(['install', '--global', '--prefix', prefix, options.tarball, ...flags], { cwd: project, env });
    const globalModules = (await npm(['root', '--global', '--prefix', prefix,
      '--userconfig', userconfig, '--globalconfig', globalconfig], { cwd: project, env })).trim();
    const installed = join(globalModules, options.name);
    const packageJson = readJson(join(installed, 'package.json'));
    assert.equal(packageJson.name, options.name);
    assert.equal(packageJson.version, options.version);
    assert.deepEqual(packageJson.bin, {
      'mcp-pacemaker': 'bin/cli.mjs', 'mcp-bridge': 'bin/mcp-bridge.mjs',
    });
    const shim = join(prefix, ...(process.platform === 'win32' ? [] : ['bin']),
      process.platform === 'win32' ? 'mcp-pacemaker.cmd' : 'mcp-pacemaker');
    const output = process.platform === 'win32'
      ? await run(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `""${shim}" --version"`],
        { cwd: project, env, windowsVerbatimArguments: true, timeout: 20000 })
      : await run(shim, ['--version'], { cwd: project, env, timeout: 20000 });
    assert.equal(output.trim(), options.version, 'The installed npm bin shim must run the selected version');

    await new CompatibilityBridge({ env }).run({ diagnostic: (line) => console.error(line) }, async (bridge) => {
      await bridge.start(installed, options.version);
      await bridge.seedAdvice();
      const ui = await bridge.request('GET', '/ui');
      assert.equal(ui.status, 200, ui.text);
      const assets = [...ui.text.matchAll(/(?:src|href)="(\/ui\/assets\/[^"]+)"/g)].map((match) => match[1]);
      assert.ok(assets.length > 0, 'The packaged dashboard must reference built assets');
      for (const asset of assets) {
        const response = await bridge.request('GET', asset);
        assert.equal(response.status, 200, `Missing dashboard asset: ${asset}`);
        assert.equal(response.text, readFileSync(join(installed, 'ui', 'dist', asset.slice('/ui/'.length)), 'utf8'));
      }
      const status = JSON.parse((await bridge.cli(installed, ['--json'])).stdout);
      assert.equal(status.service, 'mcp-pacemaker');
      assert.equal(status.version, options.version);
      await bridge.assertUnchanged();
    });
    assert.equal(sha256(options.tarball), options.sha256, 'Candidate bytes changed during consumer validation');
    return {
      schemaVersion: 2, name: options.name, version: options.version, sha256: options.sha256,
      node: process.version, npm: (await npm(['--version'], { env })).trim(), platform: process.platform,
      installScripts: options.ignoreScripts ? 'disabled' : 'npm-default',
      producerLockCopied: false, installedBin: true, bridgeAndUi: true, dependencies: graph, licenseEvidence,
      registrySignature: 'pending-publication', provenance: 'not-verified-by-consumer-smoke',
    };
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    try { removeOwnedDirectory(owned); }
    catch (error) {
      if (!failed) throw error;
      console.error(`Consumer cleanup also failed: ${error.message}`);
    }
  }
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(await checkConsumer(consumerOptions(process.argv.slice(2))), null, 2));
}
