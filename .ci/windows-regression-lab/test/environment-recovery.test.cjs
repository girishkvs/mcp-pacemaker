const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Controller } = require('../controller.cjs');

test('only the unchanged empty environment recreated by the known failed run is reusable', async () => {
  const createdAt = '2026-10-07T13:23:54Z';
  const plan = {
    expectedBranchSha: 'b'.repeat(40),
    recreatedEnvironment: { id: 123, createdAt, runId: 456 }
  };
  const controller = new Controller(plan, {}, 'unused');
  let secrets = 0;
  const calls = [];
  controller.github = {
    request: async (method, endpoint) => {
      calls.push(method);
      if (endpoint.includes('/actions/runs/')) {
        return { value: { id: 456, status: 'completed', head_sha: plan.expectedBranchSha, updated_at: createdAt } };
      }
      return { value: { total_count: endpoint.endsWith('/secrets') ? secrets : 0 } };
    }
  };
  controller.save = () => {};
  const environment = {
    id: 123, name: controller.environment, created_at: createdAt, updated_at: createdAt,
    protection_rules: [], deployment_branch_policy: null
  };
  try {
    await controller.verifyRecreatedEnvironment(environment);
    await assert.rejects(controller.verifyRecreatedEnvironment({ ...environment, id: 999 }), /ALREADY_EXISTS/);
    await assert.rejects(controller.verifyRecreatedEnvironment({
      ...environment, updated_at: '2026-10-07T13:24:00Z'
    }), /ALREADY_EXISTS/);
    secrets = 1;
    await assert.rejects(controller.verifyRecreatedEnvironment(environment), /IS_NOT_EMPTY/);
    assert.ok(calls.every(method => method === 'GET'));
  } finally {
    await controller.relay.close();
    await controller.owner.reader.close();
  }
});

test('environment cleanup happens only after the published job is terminal', async () => {
  const controller = new Controller({}, {}, 'unused');
  const order = [];
  controller.environmentCreated = true;
  controller.credentialsBefore = [];
  controller.credentialSnapshot = () => [];
  controller.save = () => {};
  controller.audit = () => {};
  controller.auditRecords = [{
    phase: 'attempt', method: 'PATCH',
    endpoint: '/repos/girishkvs/mcp-pacemaker/git/refs/heads/windows-regression-lab-20261006'
  }];
  controller.ssh = { close: () => order.push('ssh-close') };
  const originalClose = controller.relay.close.bind(controller.relay);
  controller.relay.close = async () => { order.push('client-close'); await originalClose(); };
  controller.owner.delete = async () => { order.push('tunnel-delete'); await controller.owner.reader.close(); };
  controller.findRun = async () => {
    order.push('job-terminal');
    return { id: 456, status: 'completed', conclusion: 'failure', head_sha: 'b'.repeat(40) };
  };
  controller.github = {
    request: async method => {
      if (method === 'DELETE') {
        assert.ok(order.includes('job-terminal'));
        order.push('environment-delete');
        return { value: null };
      }
      return null;
    },
    discard: () => {}
  };
  await controller.cleanup();
  assert.ok(order.indexOf('tunnel-delete') < order.indexOf('job-terminal'));
  assert.ok(order.indexOf('job-terminal') < order.indexOf('environment-delete'));
});
