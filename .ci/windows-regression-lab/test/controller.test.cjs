const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Controller } = require('../controller.cjs');
const { DeviceLogin, GitHubApi } = require('../control.cjs');

test('end-to-end controller requests exactly one device authorization', async context => {
  const requests = [];
  const scopes = ['repo', 'workflow', 'read:user'];
  context.mock.method(DeviceLogin.prototype, 'login', async (scope, label) => {
    requests.push({ scope, label });
    return { token: 'synthetic-single-login', scopes };
  });
  context.mock.method(GitHubApi.prototype, 'identity', async () => ({
    value: { login: 'girishkvs' }, scopes
  }));
  const controller = new Controller({}, {}, 'unused');
  const receipts = [];
  controller.save = (name, value) => receipts.push({ name, value });
  try {
    await controller.authenticate();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].scope, 'repo workflow read:user');
    assert.equal(controller.github.token, 'synthetic-single-login');
    assert.equal(receipts[0].value.authenticationMode, 'single-device-code');
    assert.equal(receipts[0].value.tokensSaved, false);
    assert.equal(JSON.stringify(receipts).includes('synthetic-single-login'), false);
    assert.equal('identityToken' in controller, false);
  } finally {
    controller.github?.discard();
    await controller.relay.close();
    await controller.owner.delete(() => {});
  }
});

test('a verified in-memory authorization can be reused without another device code', async context => {
  const scopes = ['repo', 'workflow', 'read:user'];
  let calls = 0;
  context.mock.method(DeviceLogin.prototype, 'login', async () => {
    calls++;
    return { token: 'synthetic-session-only', scopes };
  });
  context.mock.method(GitHubApi.prototype, 'identity', async () => ({
    value: { login: 'girishkvs' }, scopes
  }));
  const session = {};
  const first = new Controller({}, {}, 'unused', session);
  const second = new Controller({}, {}, 'unused', session);
  const receipts = [];
  first.save = (name, value) => receipts.push(value);
  second.save = (name, value) => receipts.push(value);
  try {
    await first.authenticate();
    first.github.discard();
    await second.authenticate();
    assert.equal(calls, 1);
    assert.equal(receipts[0].reusedAuthorization, false);
    assert.equal(receipts[1].reusedAuthorization, true);
    assert.equal(JSON.stringify(receipts).includes('synthetic-session-only'), false);
  } finally {
    first.github?.discard();
    second.github?.discard();
    session.credential.token = null;
    await first.relay.close();
    await first.owner.delete(() => {});
    await second.relay.close();
    await second.owner.delete(() => {});
  }
});
test('controller refuses an unapproved plan before authentication or writes', async () => {
  const controller = new Controller({}, { status: 'draft' }, 'unused');
  let authenticated = false;
  controller.authenticate = async () => { authenticated = true; };
  try {
    await assert.rejects(controller.start(), /EXACT_SETUP_APPROVAL_REQUIRED/);
    assert.equal(authenticated, false);
    assert.equal(controller.auditRecords.length, 0);
  } finally {
    await controller.relay.close();
    await controller.owner.delete(() => {});
  }
});
