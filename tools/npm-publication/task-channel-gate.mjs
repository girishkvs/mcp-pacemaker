import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { TASK_CHANNEL_FILES, TASK_CHANNEL_TEST, TASK_CHANNEL_REQUIRED_TESTS, verifyTaskChannelAssets } from '../windows-task-channel/inventory.mjs';

export function taskChannelRequired(files) {
  return files.some(file => file.path === 'bin/account-upgrade-worker.mjs');
}

export function verifyTaskChannelFeature(root) {
  if (!existsSync(join(root, 'bin', 'account-upgrade-worker.mjs'))) return undefined;
  const capability = JSON.parse(readFileSync(join(root, 'bin', 'upgrade-capability.json'), 'utf8'));
  assert.equal(capability.accountWorkerProtocol, 1);
  return verifyTaskChannelAssets(root);
}

export function verifyTaskChannelExecution(report, inspection) {
  if (!taskChannelRequired(inspection.files)) {
    assert.equal(report.taskChannel, undefined);
    return;
  }
  assert.equal(report.taskChannel?.status, 'source-and-binary-hashes-verified');
  assert.deepEqual(report.taskChannel.files.map(file => file.path), [...TASK_CHANNEL_FILES]);
  for (const file of report.taskChannel.files) {
    assert.equal(inspection.files.find(item => item.path === file.path)?.sha256, file.sha256);
  }
  assert.ok(report.evidence.command.args.includes(TASK_CHANNEL_TEST), 'Actual task-channel tests must execute.');
  for (const name of TASK_CHANNEL_REQUIRED_TESTS) {
    assert.ok(report.stdout.split(/\r?\n/).some(line => /^ok \d+ - /.test(line) && line.endsWith(name)),
      `Missing executed task channel test: ${name}`);
  }
}
