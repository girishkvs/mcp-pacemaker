const assert = require('node:assert/strict');
const { test } = require('node:test');
const { AxiosError } = require('axios');
const {
  ManagementApiVersions, TunnelManagementHttpClient
} = require('@microsoft/dev-tunnels-management');
const { Relay } = require('../relay.cjs');
const { RelayOwner } = require('../control.cjs');

test('real SDK serializes the supported auto-protocol create request exactly once', async () => {
  const owner = new RelayOwner();
  const wire = [];
  const manager = new TunnelManagementHttpClient(
    'synthetic-relay-create', ManagementApiVersions.Version20230927preview,
    undefined, undefined, undefined, async config => {
      const data = typeof config.data === 'string' ? JSON.parse(config.data) : config.data;
      wire.push({ method: config.method, url: config.url, data });
      return { status: 200, statusText: 'OK', data, headers: {}, config };
    }
  );
  manager.enableEventsReporting = false;
  try {
    const requested = owner.requestedTunnel();
    await manager.createTunnel(requested, {
      includePorts: true, includeAccessControl: true,
      tokenScopes: ['host', 'connect', 'manage']
    });
    assert.equal(wire.length, 1);
    assert.equal(wire[0].method, 'put');
    assert.equal(wire[0].data.ports[0].portNumber, 2222);
    assert.equal(wire[0].data.ports[0].protocol, 'auto');
    assert.equal(wire[0].data.customExpiration, 3600);
    assert.deepEqual(wire[0].data.accessControl, { entries: [] });
  } finally {
    await manager.dispose();
    await owner.delete(() => {});
  }
});

test('real SDK missing-tunnel 404 is distinct from denied access and transport failures', async () => {
  for (const status of [404, 401, 403, 500]) {
    const relay = new Relay();
    let requests = 0;
    const manager = new TunnelManagementHttpClient(
      'synthetic-relay-precheck', ManagementApiVersions.Version20230927preview,
      undefined, undefined, undefined, async config => {
        requests++;
        throw new AxiosError('Synthetic failure', 'ERR_BAD_RESPONSE', config, undefined, {
          status, statusText: 'Synthetic', data: {}, headers: {}, config
        });
      }
    );
    manager.enableEventsReporting = false;
    const reference = { tunnelId: 'synthetic-precheck', clusterId: 'usw2' };
    try {
      if (status === 404) {
        await assert.rejects(manager.getTunnel(reference), error => error.response.status === 404);
        assert.equal(await relay.read(reference, undefined, manager), null);
        assert.equal(requests, 2);
      } else {
        await assert.rejects(relay.read(reference, undefined, manager),
          error => error.response.status === status);
        assert.equal(requests, 1);
      }
    } finally {
      await manager.dispose();
      await relay.close();
    }
  }
});

test('a deleted relay is absence while required active relay reads still fail', async context => {
  const relay = new Relay();
  context.mock.method(relay.manager, 'getTunnel', async () => {
    const error = new Error('Synthetic missing tunnel');
    error.response = { status: 404 };
    throw error;
  });
  try {
    assert.equal(await relay.read({ tunnelId: 'synthetic' }), null);
    await assert.rejects(relay.get({ tunnelId: 'synthetic' }, 'synthetic-capability'), /RELAY_NOT_FOUND/);
  } finally {
    await relay.close();
  }
});
