import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { POLICY, validateApproval, validateContext } from './policy.mjs';
import { cleanNpmEnvironment } from './run.mjs';

// Hosted workflow only. This is never part of the local unit tests.
const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
const approval = JSON.parse(event.inputs.approval);
validateApproval(approval, event.inputs.action);
validateContext(process.env, event, approval);
assert.equal(process.versions.node, POLICY.node);
const home = join(process.env.RUNNER_TEMP, 'npm-toolchain-home');
const prefix = join(process.env.RUNNER_TEMP, 'npm-toolchain');
mkdirSync(home);
const user = join(home, 'user.npmrc');
const global = join(home, 'global.npmrc');
writeFileSync(user, '', { flag: 'wx', mode: 0o600 });
writeFileSync(global, '', { flag: 'wx', mode: 0o600 });
const result = spawnSync('npm', ['install', '--prefix', prefix, `npm@${POLICY.npm}`,
  '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock',
  `--registry=${POLICY.registry}`, `--userconfig=${user}`, `--globalconfig=${global}`], {
  cwd: home, env: cleanNpmEnvironment(process.env, home), shell: false, encoding: 'utf8',
});
assert.equal(result.status, 0, 'Isolated pinned npm restore failed; no registry fallback');
assert.equal(JSON.parse(readFileSync(join(prefix, 'node_modules/npm/package.json'), 'utf8')).version, POLICY.npm);
writeFileSync(process.env.GITHUB_ENV,
  `NPM_PUBLICATION_CLI=${join(prefix, 'node_modules/npm/bin/npm-cli.js')}\n`, { flag: 'a' });
