import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateLocalApproval } from './local-regression.mjs';

// The actual GitHub run and dispatch authenticate human acceptance, not local test execution.
export async function readOwnerLocalAcceptance({ approval, env, event, readers, continuing = false }) {
  validateLocalApproval(approval, { continuing });
  assert.equal(env.GITHUB_ACTIONS, 'true');
  assert.equal(env.GITHUB_SERVER_URL, 'https://github.com');
  assert.equal(env.GITHUB_API_URL, 'https://api.github.com');
  assert.equal(env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(env.GITHUB_REPOSITORY, 'girishkvs/mcp-pacemaker');
  assert.equal(env.GITHUB_SHA, approval.commit);
  assert.equal(env.GITHUB_REF, approval.ref);
  assert.equal(env.GITHUB_WORKFLOW_SHA, approval.commit);
  assert.equal(env.GITHUB_WORKFLOW_REF,
    `girishkvs/mcp-pacemaker/.github/workflows/npm-publish.yml@${approval.ref}`);
  assert.equal(env.GITHUB_RUN_ATTEMPT, '1');
  assert.deepEqual(JSON.parse(event.inputs.approval), approval);
  assert.equal(event.inputs.action, approval.scope);
  assert.equal(event.sender.login, 'girishkvs');
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID']) {
    assert.match(env[key], /^[1-9][0-9]*$/);
  }

  const run = await readers.readJson(`actions/runs/${env.GITHUB_RUN_ID}`);
  assert.equal(String(run.id), env.GITHUB_RUN_ID);
  assert.equal(run.run_attempt, 1);
  assert.equal(run.head_sha, approval.commit);
  assert.equal(run.path, '.github/workflows/npm-publish.yml');
  assert.equal(run.event, 'workflow_dispatch');
  assert.equal(run.status, 'in_progress');
  assert.equal(run.conclusion, null);
  for (const repository of [run.repository, run.head_repository, event.repository]) {
    assert.equal(repository.full_name, env.GITHUB_REPOSITORY);
    assert.equal(String(repository.id), env.GITHUB_REPOSITORY_ID);
    assert.equal(repository.private, false);
    assert.equal(repository.fork, false);
    assert.equal(repository.owner.login, 'girishkvs');
    assert.equal(String(repository.owner.id), env.GITHUB_REPOSITORY_OWNER_ID);
  }
  for (const actor of [run.actor, run.triggering_actor, event.sender]) {
    assert.equal(actor.login, 'girishkvs');
    assert.equal(String(actor.id), env.GITHUB_REPOSITORY_OWNER_ID);
  }
  assert.equal(env.GITHUB_ACTOR, 'girishkvs');
  assert.equal(env.GITHUB_TRIGGERING_ACTOR, 'girishkvs');
  return { kind: 'owner-dispatch-acceptance-not-execution-proof',
    runId: env.GITHUB_RUN_ID, commit: approval.commit };
}

export function publicationHelperEnvironment(base, parent) {
  const result = { ...base };
  for (const key of ['GITHUB_ACTIONS', 'GITHUB_SERVER_URL', 'GITHUB_API_URL', 'GITHUB_EVENT_NAME',
    'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_SHA',
    'GITHUB_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_WORKFLOW_REF', 'GITHUB_RUN_ATTEMPT',
    'GITHUB_RUN_ID', 'GITHUB_ACTOR', 'GITHUB_TRIGGERING_ACTOR', 'GITHUB_EVENT_PATH',
    'RUNNER_ENVIRONMENT', 'ACTUAL_RUNNER_ENVIRONMENT', 'GITHUB_TOKEN']) {
    assert.ok(parent[key], `Missing hosted preparation input: ${key}`);
    result[key] = parent[key];
  }
  if (parent.GITHUB_RUN_NUMBER) result.GITHUB_RUN_NUMBER = parent.GITHUB_RUN_NUMBER;
  if (parent.GITHUB_JOB) result.GITHUB_JOB = parent.GITHUB_JOB;
  return result;
}

export async function requireHostedLocalPreparation(approval) {
  assert.equal(approval?.scope, 'prepare');
  const env = process.env;
  const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
  const { githubReaders } = await import('./matrix.mjs');
  return readOwnerLocalAcceptance({ approval, env, event, readers: githubReaders(env), continuing: true });
}
