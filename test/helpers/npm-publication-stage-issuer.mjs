import test from 'node:test';
import assert from 'node:assert/strict';
import { createIssuerTransport, issuerBinding, ISSUER_LIMITS } from '../../tools/npm-publication/stage-issuer.mjs';

const env = { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://issuer.fixture.invalid/token?api-version=2.0&request=original',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-request-credential' };
const options = { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }, retry: 2 };
const uri = audience => {
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  url.searchParams.append('audience', audience);
  return url.href;
};
for (const audience of ['npm:registry.npmjs.org', 'sigstore']) {
  test(`issuer guard preserves original claims/audience and bounds ${audience}`, async () => {
    let calls = 0;
    const issuer = createIssuerTransport(async (url, actual) => {
      calls++;
      assert.equal(url, uri(audience));
      assert.equal(actual.headers, options.headers);
      assert.equal(actual.redirect, 'error');
      assert.deepEqual(actual.retry, { retries: 0 });
      assert.equal(actual.timeout, ISSUER_LIMITS.timeoutMs);
      assert.equal(actual.size, ISSUER_LIMITS.responseBytes);
      assert.ok(actual.signal);
      assert.equal(actual.strictSSL, true);
      return new Response('{"value":"synthetic-return-value"}');
    }, env);
    assert.equal(issuer.handles(uri(audience), options), true);
    const result = await issuer.request(uri(audience), options);
    assert.deepEqual(await result.json(), { value: 'synthetic-return-value' });
    await assert.rejects(issuer.request(uri(audience), options), /no redirect, retry or continuation/);
    assert.equal(calls, 1);
    assert.throws(issuer.healthy, /forbids continuation/);
  });
}
for (const url of ['http://issuer.fixture.invalid/token', 'https://user:password@issuer.fixture.invalid/token',
  'https://issuer.fixture.invalid/token#fragment', 'https://issuer.fixture.invalid/token?audience=other']) {
  test(`issuer guard rejects unsafe configured URL: ${url.split(':')[0]}/${url.includes('#')}/${url.includes('@')}`, () => {
    assert.throws(() => issuerBinding({ ...env, ACTIONS_ID_TOKEN_REQUEST_URL: url }));
  });
}
for (const key of ['NPM_ID_TOKEN', 'SIGSTORE_ID_TOKEN']) {
  test(`issuer guard rejects alternate ${key}`, () => {
    assert.throws(() => issuerBinding({ ...env, [key]: 'synthetic-alternate' }));
  });
}
test('issuer guard refuses credential forwarding and unapproved audiences before transport', async () => {
  for (const target of ['http://issuer.fixture.invalid/redirected',
    'https://foreign.fixture.invalid/token', uri('other')]) {
    let calls = 0;
    const issuer = createIssuerTransport(() => { calls++; }, env);
    assert.equal(issuer.handles(target, options), true, 'Original credential must not pass through to another URL');
    await assert.rejects(issuer.request(target, options));
    assert.equal(calls, 0);
  }
});
for (const [name, response] of [
  ['redirect', () => new Response('{}', { status: 302 })],
  ['server failure', () => new Response('{}', { status: 503 })],
  ['oversize', () => new Response('x'.repeat(ISSUER_LIMITS.responseBytes + 1))],
  ['malformed JSON', () => new Response('{"value":"private-do-not-log"')],
  ['absent value', () => new Response('{}')],
]) {
  test(`issuer ${name} is terminal, sanitized and never retried`, async () => {
    let calls = 0;
    const issuer = createIssuerTransport(async () => { calls++; return response(); }, env);
    await assert.rejects(issuer.request(uri('sigstore'), options), error => {
      assert.equal(error.cause, undefined);
      assert.equal(error.message.includes('private-do-not-log'), false);
      assert.equal(error.message.includes(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN), false);
      return true;
    });
    assert.equal(calls, 1);
    assert.throws(issuer.healthy);
    await assert.rejects(issuer.request(uri('npm:registry.npmjs.org'), options));
    assert.equal(calls, 1);
  });
}
test('issuer deadline covers response body consumption and prevents late success', async () => {
  let controller;
  let signal;
  const issuer = createIssuerTransport(async (_url, options) => {
    signal = options.signal;
    return new Response(new ReadableStream({ start(value) { controller = value; } }));
  }, env, { timeoutMs: 10 });
  await assert.rejects(issuer.request(uri('sigstore'), options));
  assert.equal(signal.aborted, true);
  controller.close();
  assert.throws(issuer.healthy);
});
