import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { queryCliCallerContext, requireOrdinaryUpgradeCaller } from '../../bin/windows-task-channel.mjs';

const [mode, directory] = process.argv.slice(2);
await requireOrdinaryUpgradeCaller();
const context = await queryCliCallerContext();
assert.equal(context.ordinaryEligible, true);
if (mode === 'descendant') {
  writeFileSync(join(directory, 'probe-descendant.json'), JSON.stringify(context.identity), { flag: 'wx' });
  setInterval(() => {}, 1000);
  setTimeout(() => process.exit(99), 120000);
} else {
  const input = JSON.parse(readFileSync(join(directory, 'input.json'), 'utf8'));
  assert.equal(process.env.GITHUB_TOKEN, undefined);
  assert.equal(process.env.NODE_OPTIONS, undefined);
  for (const name of ['PATH', 'MCP_NATIVE_COMPILER', 'MCP_NATIVE_REFERENCES', 'MCP_POOLING_TRACE_RUN_FAULTS']) {
    assert.equal(process.env[name], input.environment[name], `Explicit environment differs: ${name}`);
  }
  assert.equal(process.execPath, input.node);
  assert.equal(process.cwd(), input.cwd);
  const selectedNode = spawnSync('node', ['--version'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(selectedNode.status, 0);
  assert.equal(selectedNode.stdout.trim(), process.version, 'PATH selected a different matrix Node');
  writeFileSync(join(directory, 'probe-ran.json'), JSON.stringify({ node: process.execPath,
    ordinaryEligible: context.ordinaryEligible }), { flag: 'wx' });
  console.log('ordinary probe stdout');
  console.error('ordinary probe stderr');
  if (mode === 'probe-exit') process.exit(23);
  if (mode === 'probe-error') throw new Error('owned ordinary probe error');
  if (mode === 'probe-hang') {
    spawn(process.execPath, [process.argv[1], 'descendant', directory], { stdio: 'ignore', windowsHide: true });
    setInterval(() => {}, 1000);
  }
}
