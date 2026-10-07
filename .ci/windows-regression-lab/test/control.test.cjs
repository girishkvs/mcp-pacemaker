const assert = require('node:assert/strict');
const { test } = require('node:test');
const sodium = require('libsodium-wrappers');
const { GitHubApi, RelayOwner, sealSecret } = require('../control.cjs');

test('one-code identity requires exactly the approved combined scopes', async () => {
  const owner = new RelayOwner();
  try {
    assert.doesNotThrow(() => owner.validateIdentityScopes(['read:user', 'repo', 'workflow']));
    assert.doesNotThrow(() => owner.validateIdentityScopes(['workflow', 'repo', 'read:user']));
    for (const scopes of [[], ['repo'], ['read:user'], ['read:user', 'repo'], ['repo', 'workflow'], ['user'], ['read:user', 'repo', 'workflow', 'admin:org']]) {
      assert.throws(() => owner.validateIdentityScopes(scopes), /SCOPE_MISMATCH/);
    }
  } finally {
    await owner.delete(() => {});
  }
});

test('relay create uses the documented auto protocol and no anonymous grants', async () => {
  const owner = new RelayOwner();
  try {
    const request = owner.requestedTunnel();
    assert.deepEqual(request.ports, [{ portNumber: 2222, protocol: 'auto' }]);
    assert.deepEqual(request.accessControl, { entries: [] });
    assert.equal(request.customExpiration, 3600);
  } finally {
    await owner.delete(() => {});
  }
});

test('relay diagnostics preserve validation detail without request headers or token values', async () => {
  const owner = new RelayOwner();
  try {
    const token = 'synthetic-sensitive-value';
    const details = owner.diagnostics({
      code: 'ERR_BAD_REQUEST',
      message: 'Provider rejected the request',
      config: { headers: { Authorization: 'github ' + token } },
      response: {
        status: 400,
        headers: { Authorization: token },
        data: {
          title: 'Validation failed',
          detail: 'Invalid token ' + token,
          errors: { protocol: ['Use auto'] },
          echoedToken: token
        }
      }
    }, [token]);
    assert.equal(details.httpStatus, 400);
    assert.deepEqual(details.validation, [{ field: 'protocol', messages: ['Use auto'] }]);
    const encoded = JSON.stringify(details);
    assert.equal(encoded.includes(token), false);
    assert.equal(encoded.includes('headers'), false);
    assert.match(details.detail, /\[redacted\]/);
  } finally {
    await owner.delete(() => {});
  }
});

test('empty successful secret creation and cleanup responses are accepted', async () => {
  for (const status of [201, 204]) {
    const records = [];
    const api = new GitHubApi('synthetic-token', entry => records.push(entry),
      async () => new Response(null, { status }));
    const result = await api.request(status === 201 ? 'PUT' : 'DELETE', '/synthetic-test');
    assert.equal(result.value, null);
    assert.equal(records.at(-1).status, status);
    api.discard();
  }
});

test('GitHub mutation failures are not retried and audit records contain no payload', async () => {
  const audit = [];
  let attempts = 0;
  const api = new GitHubApi('synthetic-token', entry => audit.push(entry), async () => {
    attempts++;
    throw new TypeError('simulated connection loss');
  });
  await assert.rejects(api.request('PUT', '/synthetic-test', { value: 'synthetic-secret' }), /OUTCOME_UNKNOWN/);
  assert.equal(attempts, 1);
  assert.equal(audit.length, 1);
  assert.equal(JSON.stringify(audit).includes('synthetic-secret'), false);
  assert.equal(JSON.stringify(audit).includes('synthetic-token'), false);
  api.discard();
});

test('wrong GitHub account is rejected', async () => {
  const api = new GitHubApi('synthetic-token', () => {}, async () => new Response(
    JSON.stringify({ login: 'some-other-account' }),
    { status: 200, headers: { 'x-oauth-scopes': 'read:user' } }
  ));
  await assert.rejects(api.identity(), /ACCOUNT_MISMATCH/);
  api.discard();
});

test('bootstrap sealing round-trips without storing a key', async () => {
  await sodium.ready;
  const keys = sodium.crypto_box_keypair();
  const message = 'synthetic bootstrap content';
  try {
    const encrypted = await sealSecret(
      message, sodium.to_base64(keys.publicKey, sodium.base64_variants.ORIGINAL)
    );
    const opened = sodium.crypto_box_seal_open(
      sodium.from_base64(encrypted, sodium.base64_variants.ORIGINAL),
      keys.publicKey, keys.privateKey
    );
    assert.equal(sodium.to_string(opened) === message, true);
    assert.equal(encrypted.includes(message), false);
    sodium.memzero(opened);
  } finally {
    sodium.memzero(keys.privateKey);
  }
});
