const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Controller } = require('../controller.cjs');

test('reviewed existing branch uses a non-forced fast-forward patch', async () => {
  const head = 'b'.repeat(40);
  const next = 'c'.repeat(40);
  const controller = new Controller({
    baseSha: 'a'.repeat(40), branchAction: 'fast-forward-existing', expectedBranchSha: head
  }, {}, 'unused');
  controller.commitSha = next;
  const writes = [];
  controller.github = {
    request: async (method, endpoint, body) => {
      if (method !== 'GET') {
        writes.push({ method, endpoint, body });
        return { value: {} };
      }
      const sha = endpoint.endsWith('/heads/main') ? controller.plan.baseSha :
        writes.length ? next : head;
      return { value: { object: { sha } } };
    }
  };
  try {
    await controller.publish();
    assert.equal(writes.length, 1);
    assert.equal(writes[0].method, 'PATCH');
    assert.deepEqual(writes[0].body, { sha: next, force: false });
  } finally {
    await controller.relay.close();
    await controller.owner.reader.close();
  }
});

test('a moved lab branch is not overwritten', async () => {
  const controller = new Controller({
    baseSha: 'a'.repeat(40), branchAction: 'fast-forward-existing', expectedBranchSha: 'b'.repeat(40)
  }, {}, 'unused');
  let writes = 0;
  controller.github = {
    request: async (method, endpoint) => {
      if (method !== 'GET') writes++;
      return { value: { object: { sha: endpoint.endsWith('/heads/main') ? 'a'.repeat(40) : 'd'.repeat(40) } } };
    }
  };
  try {
    await assert.rejects(controller.publish(), /CHANGED_BEFORE_PUBLISH/);
    assert.equal(writes, 0);
  } finally {
    await controller.relay.close();
    await controller.owner.reader.close();
  }
});
