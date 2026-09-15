import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { POLICY, digest, sameDigests } from './policy.mjs';
import { execute, isolatedConsumerEnvironment } from './matrix.mjs';
import { registryResource, JSON_LIMIT } from './published-proof.mjs';
import { inspectTarball } from './tarball.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../compatibility/fixtures.mjs';
import { consumerGraph, consumerNoticeVersions } from '../npm-consumer/check.mjs';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { CompatibilityBridge } from '../../test/compat/bridge.mjs';

export function requireAnonymousHosted(env, runtime = process) {
  assert.equal(runtime.platform, 'linux');
  assert.equal(runtime.arch, 'x64');
  assert.equal(runtime.versions.node, POLICY.node);
  assert.equal(env.GITHUB_ACTIONS, 'true');
  assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  for (const [key, value] of Object.entries(env)) {
    assert.ok(!/^(?:GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN|NODE_OPTIONS|NPM_ID_TOKEN|SIGSTORE_ID_TOKEN|ACTIONS_ID_TOKEN.*|npm_config_.*)$/i.test(key) ||
      !value, 'Anonymous verification cannot inherit credentials or npm/Node overrides');
  }
}

export function registryInstallArguments(record) {
  assert.equal(record.name, POLICY.name);
  assert.ok(['1.3.1', '2.0.1'].includes(record.version));
  return ['install', `${record.name}@${record.version}`, '--save-exact', '--ignore-scripts',
    '--package-lock=true', '--no-audit', '--no-fund', `--registry=${POLICY.registry}`,
    '--strict-ssl=true', '--fetch-retries=0', '--fetch-timeout=30000'];
}

export function publishedConsumerGraph(lock, record) {
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages?.['']?.dependencies, { [record.name]: record.version });
  const target = lock.packages[`node_modules/${record.name}`];
  assert.equal(target?.version, record.version);
  assert.equal(target.integrity, record.artifact.integrity);
  assert.equal(target.resolved, `${POLICY.registry}${record.name}/-/${record.name}-${record.version}.tgz`);
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue;
    assert.ok(path.startsWith('node_modules/'));
    assert.notEqual(entry.link, true, 'Registry consumers cannot contain source links');
    registryResource(entry.resolved);
    assert.ok(typeof entry.integrity === 'string' &&
      entry.integrity.length > 0);
  }
  return consumerGraph(lock, record.name, record.version);
}

export function exactInstalledFiles(installed, tarball, record) {
  sameDigests(digest(tarball), record.artifact);
  const { files } = inspectTarball(tarball, record);
  for (const file of files) {
    const path = join(installed, file.path);
    const stat = fs.lstatSync(path);
    assert.ok(stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.nlink === 1);
    assert.equal(fs.realpathSync.native(path), path, 'Installed payload path was replaced or linked');
    assert.equal(stat.size, file.size);
    assert.equal(digest(fs.readFileSync(path)).sha256, file.sha256,
      'Installed bytes differ from the approved published payload');
  }
  assert.equal(fs.existsSync(join(installed, 'package-lock.json')), false, 'Producer lock must not be packed');
  return files.length;
}

export async function smokePublishedConsumer({ project, installed, record, env, executor = execute,
  bridgeFactory = options => new CompatibilityBridge(options), realpath = fs.realpathSync.native }) {
  const manifest = JSON.parse(fs.readFileSync(join(installed, 'package.json'), 'utf8'));
  assert.equal(manifest.name, record.name);
  assert.equal(manifest.version, record.version);
  assert.deepEqual(manifest.bin, { 'mcp-pacemaker': 'bin/cli.mjs', 'mcp-bridge': 'bin/mcp-bridge.mjs' });
  const shim = join(project, 'node_modules', '.bin', 'mcp-pacemaker');
  assert.equal(realpath(shim), join(installed, 'bin', 'cli.mjs'));
  const result = executor(shim, ['--version'], { cwd: project, env, timeout: 20_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.stdout.trim(), record.version);
  let assetsChecked = 0;
  await bridgeFactory({ env }).run({ diagnostic: () => {} }, async bridge => {
    await bridge.start(installed, record.version);
    await bridge.seedAdvice();
    const ui = await bridge.request('GET', '/ui');
    assert.equal(ui.status, 200);
    const assets = [...ui.text.matchAll(/(?:src|href)="(\/ui\/assets\/[^"]+)"/g)].map(match => match[1]);
    assert.ok(assets.length > 0);
    for (const asset of assets) {
      assert.match(asset, /^\/ui\/assets\/[a-zA-Z0-9_.-]+$/);
      const response = await bridge.request('GET', asset);
      assert.equal(response.status, 200);
      assert.equal(response.text, fs.readFileSync(join(installed, 'ui', 'dist', asset.slice('/ui/'.length)), 'utf8'));
      assetsChecked++;
    }
    const status = JSON.parse((await bridge.cli(installed, ['--json'])).stdout);
    assert.equal(status.service, record.name);
    assert.equal(status.version, record.version);
    await bridge.assertUnchanged();
  });
  return { installedBin: true, bridgeAndUi: true, assetsChecked };
}

export async function withPublishedConsumer({
  record, tarball, cli, env = process.env, executor = execute, verifyAudit, smoke = smokePublishedConsumer,
  inspectNotices = verifyArtifacts,
}) {
  if (executor === execute) requireAnonymousHosted(env);
  const owned = ownedDirectory();
  try {
    const directory = fs.realpathSync.native(owned.dir);
    fs.chmodSync(directory, 0o700);
    const project = join(directory, 'consumer');
    const home = join(directory, 'home');
    fs.mkdirSync(project, { mode: 0o700 });
    fs.mkdirSync(home, { mode: 0o700 });
    assert.deepEqual(fs.readdirSync(project), []);
    const child = isolatedConsumerEnvironment(env, home);
    if (env.RUNNER_TRACKING_ID) child.RUNNER_TRACKING_ID = env.RUNNER_TRACKING_ID;
    const options = { cwd: project, env: child, timeout: 6 * 60_000, maxBuffer: JSON_LIMIT };
    assert.equal(executor(process.execPath, [cli, '--version'], options).stdout.trim(), POLICY.npm);
    fs.writeFileSync(join(project, 'package.json'), JSON.stringify({
      name: 'pacemaker-private-registry-consumer', version: '0.0.0', private: true,
    }) + '\n', { flag: 'wx', mode: 0o600 });
    assert.equal(fs.existsSync(join(project, 'package-lock.json')), false);
    executor(process.execPath, [cli, ...registryInstallArguments(record)], options);
    const lockBytes = fs.readFileSync(join(project, 'package-lock.json'));
    assert.ok(lockBytes.length <= JSON_LIMIT);
    const graph = publishedConsumerGraph(JSON.parse(lockBytes), record);
    const installed = join(project, 'node_modules', record.name);
    const fileCount = exactInstalledFiles(installed, tarball, record);
    consumerNoticeVersions(graph, inspectNotices(installed));
    const report = executor(process.execPath, [cli, 'audit', 'signatures', '--json', '--include-attestations',
      '--ignore-scripts', `--registry=${POLICY.registry}`, '--strict-ssl=true',
      '--fetch-retries=0', '--fetch-timeout=30000'], options);
    assert.ok(Buffer.byteLength(report.stdout) <= JSON_LIMIT);
    const audit = JSON.parse(report.stdout);
    // Package code runs only after actual target coverage, signatures and provenance pass.
    const evidence = await verifyAudit(audit, join(home, 'tuf'));
    const consumer = await smoke({ project, installed, record, env: child, executor });
    assert.deepEqual(fs.readFileSync(join(project, 'package-lock.json')), lockBytes);
    exactInstalledFiles(installed, tarball, record);
    return { evidence, consumer: {
      ...consumer, spec: `${record.name}@${record.version}`, registry: POLICY.registry,
      node: process.versions.node, npm: POLICY.npm, platform: process.platform,
      producerLockCopied: false, installScripts: 'disabled', fileCount,
      consumerLockSha256: digest(lockBytes).sha256, dependencyCount: graph.length,
    } };
  } finally {
    removeOwnedDirectory(owned);
  }
}
