const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { test } = require('node:test');
const { SessionIdentity, SingleSessionServer, PinnedClient } = require('../identity.cjs');
const { Relay, connectionOptions } = require('../relay.cjs');

test('one key-authenticated SSH connection carries a private command', async () => {
  const identity = new SessionIdentity();
  const server = new SingleSessionServer({
    hostKey: identity.host.private,
    clientPublicKey: identity.client.public,
    onCommand: (command, channel) => {
      assert.equal(command, 'status');
      channel.write('synthetic-private-response');
      channel.exit(0);
      channel.end();
    }
  });
  const client = new PinnedClient(identity.client.private, identity.hostHash);
  try {
    const port = await server.listen(0);
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    await client.connect(socket);
    const channel = await client.open('status');
    let value = '';
    channel.on('data', data => { value += data.toString(); });
    const [code] = await once(channel, 'close');
    assert.equal(code, 0);
    assert.equal(value, 'synthetic-private-response');
    assert.equal(server.used, true);
    await assert.rejects(client.connect(socket), /RECONNECT/);
    await assert.rejects(client.open('powershell'), /NOT_PERMITTED/);
  } finally {
    client.close();
    server.close();
    identity.discard();
  }
});

test('incorrect host key is rejected before authentication', async () => {
  const identity = new SessionIdentity();
  const server = new SingleSessionServer({
    hostKey: identity.host.private,
    clientPublicKey: identity.client.public,
    onCommand: () => { throw new Error('Must not execute'); }
  });
  const client = new PinnedClient(identity.client.private, '0'.repeat(64));
  try {
    const port = await server.listen(0);
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    await assert.rejects(client.connect(socket), /SSH_HOST_KEY_MISMATCH/);
    assert.equal(client.hostKeyMatches, false);
    assert.equal(server.used, false);
  } finally {
    client.close();
    server.close();
    identity.discard();
  }
});

test('incorrect client key cannot start a session', async () => {
  const identity = new SessionIdentity();
  const other = new SessionIdentity();
  const server = new SingleSessionServer({
    hostKey: identity.host.private,
    clientPublicKey: identity.client.public,
    onCommand: () => { throw new Error('Must not execute'); }
  });
  const client = new PinnedClient(other.client.private, identity.hostHash);
  try {
    const port = await server.listen(0);
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    await assert.rejects(client.connect(socket), /authentication/i);
    assert.equal(server.used, false);
  } finally {
    client.close();
    server.close();
    identity.discard();
    other.discard();
  }
});

test('relay permits only the bound port and rejects anonymous access', () => {
  const relay = new Relay();
  const reference = { tunnelId: 'example', clusterId: 'usw2' };
  const tunnel = {
    ...reference,
    ports: [{ portNumber: 2222, protocol: 'auto' }],
    accessControl: { entries: [] }
  };
  assert.doesNotThrow(() => relay.validate(tunnel, reference));
  assert.throws(() => relay.validate({ ...tunnel, ports: [{ portNumber: 445, protocol: 'auto' }] }, reference));
  assert.throws(() => relay.validate({ ...tunnel, ports: [{ portNumber: 2222, protocol: 'tcp' }] }, reference));
  assert.throws(() => relay.validate({ ...tunnel, tunnelId: 'different' }, reference));
  assert.throws(() => relay.validate({
    ...tunnel, accessControl: { entries: [{ type: 'anonymous', scopes: ['connect'] }] }
  }, reference), /ACCESS_GRANT_NOT_PERMITTED/);
  assert.throws(() => relay.validate({
    ...tunnel, accessControl: { entries: [{ type: 'organizations', scopes: ['connect'] }] }
  }, reference), /ACCESS_GRANT_NOT_PERMITTED/);
  assert.throws(() => relay.validate({ ...tunnel, accessControl: undefined }, reference), /ACCESS_CONTROL_MISSING/);
  assert.equal(connectionOptions.enableRetry, false);
  assert.equal(connectionOptions.enableReconnect, false);
});
