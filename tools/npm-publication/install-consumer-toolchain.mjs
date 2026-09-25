import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { POLICY } from './policy.mjs';
import { execute, isolatedConsumerEnvironment, matrixLane, validateMatrixContext } from './matrix.mjs';

export function bootstrapNpmCli(node, platform) {
  return platform === 'win32'
    ? join(dirname(node), 'node_modules/npm/bin/npm-cli.js')
    : resolve(dirname(node), '../lib/node_modules/npm/bin/npm-cli.js');
}

export function installConsumerToolchain({
  env, approval, event, runtime = process, executor = execute,
}) {
  validateMatrixContext(env, approval, event);
  const lane = matrixLane(env, runtime);
  const home = mkdtempSync(join(env.RUNNER_TEMP, 'npm-consumer-toolchain-'));
  const childEnv = isolatedConsumerEnvironment(env, home, runtime.execPath);
  const bootstrap = bootstrapNpmCli(runtime.execPath, runtime.platform);
  assert.equal(JSON.parse(readFileSync(resolve(dirname(bootstrap), '../package.json'), 'utf8')).name, 'npm');
  const prefix = join(home, 'prefix');
  executor(runtime.execPath, [bootstrap, 'install', '--prefix', prefix, `npm@${lane.npm}`,
    '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock',
    `--registry=${POLICY.registry}`,
    `--userconfig=${childEnv.npm_config_userconfig}`, `--globalconfig=${childEnv.npm_config_globalconfig}`], {
    cwd: home, env: childEnv,
  });
  const cli = join(prefix, 'node_modules/npm/bin/npm-cli.js');
  const pkg = JSON.parse(readFileSync(join(prefix, 'node_modules/npm/package.json'), 'utf8'));
  assert.equal(pkg.name, 'npm');
  assert.equal(pkg.version, lane.npm, 'Pinned consumer npm was not installed');
  assert.equal(executor(runtime.execPath, [cli, '--version'], {
    cwd: home, env: childEnv,
  }).stdout.trim(), lane.npm);
  assert.ok(!/[\r\n]/.test(cli), 'Unsafe workflow environment value');
  writeFileSync(env.GITHUB_ENV, `NPM_CONSUMER_CLI=${cli}\n`, { flag: 'a' });
  return { cli, node: lane.node, npm: lane.npm };
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  assert.equal(process.argv.length, 2);
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  installConsumerToolchain({
    env: process.env, event, approval: JSON.parse(event.inputs.approval),
  });
}
