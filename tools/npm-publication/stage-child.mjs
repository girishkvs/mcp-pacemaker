import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, sameDigests, stageArguments, validateApproval, validateContext } from './policy.mjs';
import { validateLocalApproval } from './local-regression.mjs';
import { captureSubject } from './stage-capture.mjs';
import { installStageCapture } from './stage-sdk.mjs';

export function startStageChild() {
  assert.equal(process.argv.length, 6, 'Private stage child expects context, tarball, capture directory and npm CLI');
  const [contextPath, tarball, directory, cli] = process.argv.slice(2).map(value => resolve(value));
  const context = JSON.parse(readFileSync(contextPath, 'utf8'));
  const { approval, subject, config } = context;
  validateLocalApproval(approval);
  validateApproval(approval, 'stage');
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  assert.equal(event.inputs.action, 'stage');
  assert.deepEqual(JSON.parse(event.inputs.approval), approval);
  validateContext(process.env, event, approval);
  assert.equal(process.env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(process.env.GITHUB_JOB, 'stage');
  assert.equal(subject.workflow.runId, process.env.GITHUB_RUN_ID);
  assert.deepEqual(captureSubject(subject), {
    name: approval.name, version: approval.version,
    channel: approval.version === '1.3.1' ? 'legacy' : 'latest',
    source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]])),
    workflow: { ref: process.env.GITHUB_WORKFLOW_REF, commit: process.env.GITHUB_WORKFLOW_SHA,
      runId: process.env.GITHUB_RUN_ID, attempt: 1 }, artifact: digest(readFileSync(tarball)),
  });
  sameDigests(subject.artifact, approval.artifact);
  for (const path of [config.user, config.global]) assert.equal(readFileSync(path, 'utf8'), '');
  for (const key of Object.keys(process.env)) {
    const injected = ['NODE_OPTIONS', 'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_ID_TOKEN',
      'SIGSTORE_ID_TOKEN', 'GITHUB_TOKEN'].includes(key.toUpperCase()) ||
      key.toLowerCase().startsWith('npm_config_');
    assert.ok(!injected ||
      !process.env[key], 'Inherited credentials/config are forbidden');
  }
  const { entry } = installStageCapture({ cli, expected: subject, directory,
    secrets: [process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN].filter(Boolean) });
  assert.equal(process.versions.node, POLICY.node);
  process.argv = [process.execPath, entry, ...stageArguments(tarball, subject.channel, config)];
  createRequire(entry)(entry);
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    startStageChild();
  } catch {
    console.error('Stage child stopped; no retry. Reconcile any unknown outcome.');
    process.exitCode = 1;
  }
}
