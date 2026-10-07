const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const os = require('node:os');
const { once } = require('node:events');
const { test } = require('node:test');
const { Host, loadBootstrap } = require('../host.cjs');
const { SessionIdentity, PinnedClient } = require('../identity.cjs');

test('host binding refuses a workstation, altered commit and expired session', () => {
  const now = Date.now();
  const config = {
    repository: 'girishkvs/mcp-pacemaker',
    ref: 'refs/heads/windows-regression-lab-20261006',
    sha: 'a'.repeat(40),
    bundleSha256: 'b'.repeat(64),
    authorizationQuote: 'Synthetic unit-test approval',
    authorizedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60000).toISOString(),
    hostPrivateKey: 'test-placeholder',
    clientPublicKey: 'test-placeholder',
    hostAccessToken: 'test-placeholder',
    tunnelId: 'test-placeholder',
    clusterId: 'test-placeholder'
  };
  const environment = {
    GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted',
    RUNNER_OS: 'Windows', RUNNER_ARCH: 'X64',
    GITHUB_REPOSITORY: config.repository, GITHUB_ACTOR: 'girishkvs',
    GITHUB_EVENT_NAME: 'push', GITHUB_RUN_ATTEMPT: '1', GITHUB_RUN_ID: '123',
    GITHUB_REF: config.ref, GITHUB_SHA: config.sha,
    WINDOWS_LAB_BOOTSTRAP: JSON.stringify(config)
  };
  assert.doesNotThrow(() => loadBootstrap(environment, 'win32', now));
  assert.throws(() => loadBootstrap({}, 'win32', now), /NON_HOSTED/);
  assert.throws(() => loadBootstrap(environment, 'linux', now), /NON_HOSTED/);
  assert.throws(() => loadBootstrap({ ...environment, GITHUB_SHA: 'c'.repeat(40) }, 'win32', now), /BINDING/);
  assert.throws(() => loadBootstrap({ ...environment, GITHUB_RUN_ATTEMPT: '2' }, 'win32', now), /NON_HOSTED/);
  assert.throws(() => loadBootstrap(environment, 'win32', now + 120000), /DEADLINE/);
});

test('private upload is acknowledged only after complete digest verification', async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-upload-test-'));
  const payload = Buffer.from('synthetic bytes, not a product test');
  const identity = new SessionIdentity();
  const config = {
    hostPrivateKey: identity.host.private,
    clientPublicKey: identity.client.public,
    bundleSha256: crypto.createHash('sha256').update(payload).digest('hex')
  };
  const host = new Host(config, { RUNNER_TEMP: parent, GITHUB_RUN_ID: '123' });
  const client = new PinnedClient(identity.client.private, identity.hostHash);
  fs.mkdirSync(host.root);
  try {
    const port = await host.server.listen(0);
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    await client.connect(socket);
    const channel = await client.open('upload');
    let response = '';
    channel.on('data', data => { response += data.toString(); });
    const closed = once(channel, 'close');
    channel.end(payload);
    const [code] = await closed;
    assert.equal(code, 0);
    assert.equal(response, 'PAYLOAD_ACCEPTED');
    assert.equal(host.state, 'uploaded');
    assert.ok(fs.readFileSync(path.join(host.root, 'payload.zip')).equals(payload));
  } finally {
    client.close();
    host.server.close();
    await host.relay.close();
    identity.discard();
    fs.rmSync(parent, { recursive: true });
  }
});

test('child environment excludes credentials and redirects private output', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-env-test-'));
  const identity = new SessionIdentity();
  const host = new Host({
    hostPrivateKey: identity.host.private, clientPublicKey: identity.client.public
  }, {
    RUNNER_TEMP: root, GITHUB_RUN_ID: '123',
    GITHUB_TOKEN: 'test-placeholder', GH_TOKEN: 'test-placeholder',
    WINDOWS_LAB_BOOTSTRAP: 'test-placeholder', PRIVATE_KEY: 'test-placeholder'
  });
  fs.mkdirSync(host.root);
  try {
    const child = host.childEnvironment();
    for (const name of ['GITHUB_TOKEN', 'GH_TOKEN', 'WINDOWS_LAB_BOOTSTRAP', 'PRIVATE_KEY']) {
      assert.equal(name in child, false);
    }
    assert.ok(child.PRIVATE_RESULTS_DIR.startsWith(host.root + path.sep));
  } finally {
    host.server.close();
    identity.discard();
    fs.rmSync(root, { recursive: true });
  }
});
