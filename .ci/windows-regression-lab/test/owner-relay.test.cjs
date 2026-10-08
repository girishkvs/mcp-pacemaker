const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Relay } = require('../relay.cjs');
const { RelayOwner } = require('../control.cjs');
const { Host } = require('../host.cjs');

const reference = { tunnelId: 'synthetic-owner', clusterId: 'usw2' };
const configuration = {
  ...reference,
  accessControl: { entries: [] },
  accessTokens: { manage: 'synthetic-owner-secret' },
  ports: [{ portNumber: 2222, protocol: 'auto', accessTokens: { host: 'synthetic-port-secret' } }],
  endpoints: [{
    id: 'endpoint', hostId: 'host', connectionMode: 'TunnelRelay',
    hostPublicKeys: ['synthetic-public-key'],
    clientRelayUri: 'wss://example.invalid/client',
    accessTokens: { connect: 'synthetic-endpoint-secret' }
  }]
};

test('owner descriptor removes capabilities without weakening ACL validation', async () => {
  const relay = new Relay();
  try {
    const result = relay.descriptor(configuration, reference);
    assert.equal(JSON.stringify(result).includes('secret'), false);
    assert.deepEqual(result.accessControl, { entries: [] });
    assert.equal(result.endpoints[0].clientRelayUri, configuration.endpoints[0].clientRelayUri);
    assert.throws(() => relay.descriptor({ ...configuration, accessControl: undefined }, reference), /ACCESS_CONTROL/);
    assert.throws(() => relay.descriptor({
      ...configuration, accessControl: { entries: [{ type: 'anonymous', scopes: ['connect'] }] }
    }, reference), /ACCESS_GRANT/);
  } finally {
    await relay.close();
  }
});

test('host connects from verified owner metadata without a privileged token or limited ACL read', async context => {
  const relay = new Relay();
  let connected;
  context.mock.method(relay, 'get', async () => { throw new Error('Limited capability read must not be used'); });
  context.mock.method(relay, 'connect', async tunnel => { connected = tunnel; });
  try {
    await relay.host(reference, 'synthetic-host-capability', configuration);
    assert.deepEqual(connected.accessTokens, { host: 'synthetic-host-capability' });
    assert.equal(JSON.stringify(connected).includes('synthetic-owner-secret'), false);
    assert.match(Host.prototype.run.toString(), /this\.config\.relayConfiguration/);
  } finally {
    await relay.close();
  }
});

test('readVerified uses owner authentication and returns only sanitized configuration', async context => {
  const owner = new RelayOwner();
  owner.reference = reference;
  let ownerUsed = false;
  context.mock.method(owner.reader, 'read', async (actual, options, manager) => {
    assert.deepEqual(actual, reference);
    assert.equal(options.accessToken, undefined);
    ownerUsed = (await manager.userTokenCallback()) === 'github synthetic-owner-token';
    return configuration;
  });
  try {
    const result = await owner.readVerified('synthetic-owner-token');
    assert.equal(ownerUsed, true);
    assert.equal(JSON.stringify(result).includes('secret'), false);
  } finally {
    await owner.reader.close();
  }
});
