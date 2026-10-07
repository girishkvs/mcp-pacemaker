const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { SingleAuthorizationSession } = require('../session.cjs');

test('authorization retention never retries a job, unknown write or incomplete cleanup', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-session-guard-'));
  const session = new SingleAuthorizationSession();
  session.authorization.credential = { token: 'synthetic-in-memory-only' };
  session.attemptNumber = 1;
  const controller = { root, auditRecords: [] };
  const cleanup = path.join(root, 'cleanup.json');
  fs.writeFileSync(cleanup, JSON.stringify({ failures: [] }));
  try {
    const failure = new Error('RELAY_CREATION_FAILED');
    assert.equal(session.canWait(controller, failure), true);
    assert.equal(session.canWait(controller, new Error('GITHUB_WRITE_OUTCOME_UNKNOWN')), false);
    controller.auditRecords.push({ phase: 'attempt', endpoint: '/repos/example/project/git/refs' });
    assert.equal(session.canWait(controller, failure), false);
    controller.auditRecords = [{ phase: 'attempt', operation: 'execute-approved-bundle' }];
    assert.equal(session.canWait(controller, failure), false);
    controller.auditRecords = [];
    fs.writeFileSync(cleanup, JSON.stringify({ failures: ['ENVIRONMENT_CLEANUP_UNVERIFIED'] }));
    assert.equal(session.canWait(controller, failure), false);
    fs.writeFileSync(cleanup, JSON.stringify({ failures: [] }));
    session.attemptNumber = 3;
    assert.equal(session.canWait(controller, failure), false);
    session.attemptNumber = 1;
    session.authorization.credential = undefined;
    assert.equal(session.canWait(controller, failure), false);
  } finally {
    session.authorization.credential = undefined;
    fs.rmSync(root, { recursive: true });
  }
});
