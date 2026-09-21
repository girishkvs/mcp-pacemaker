import test from 'node:test';
import assert from 'node:assert/strict';
import { createFulcioTransport, fulcioExternalFetch, isFulcioRequest, FULCIO_URL,
  FULCIO_LIMITS } from '../../tools/npm-publication/stage-fulcio.mjs';
import { createIssuerTransport } from '../../tools/npm-publication/stage-issuer.mjs';

const body = { credentials: { oidcIdentityToken: 'synthetic-body-credential' },
  publicKeyRequest: { publicKey: { algorithm: 'ECDSA', content: 'synthetic-key' },
    proofOfPossession: 'synthetic-not-a-signature' } };
const options = { method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body), retry: { retries: 2 } };
const result = { signedCertificateEmbeddedSct: { chain: { certificates: ['synthetic-not-a-certificate'] } } };

test('certificate credentials are recognized in the body, not inferred absent from missing headers', () => {
  assert.equal(isFulcioRequest(FULCIO_URL, options), true);
  assert.equal(isFulcioRequest('http://fulcio.sigstore.dev/redirected', options), true);
  assert.equal(isFulcioRequest('https://foreign.invalid/elsewhere', options), true);
  assert.equal(isFulcioRequest('https://tuf-repo.fixture.invalid/metadata.json', {}), false);
});

test('Fulcio fixed destination, original body and bounded transport do not replay a certificate write', async () => {
  let calls = 0;
  const transport = createFulcioTransport(async (url, actual) => {
    calls++;
    assert.equal(url, FULCIO_URL);
    assert.equal(actual.body, options.body);
    assert.equal(actual.redirect, 'error');
    assert.deepEqual(actual.retry, { retries: 0 });
    assert.equal(actual.timeout, 30_000);
    assert.equal(actual.size, FULCIO_LIMITS.responseBytes);
    assert.ok(actual.signal);
    return new Response(JSON.stringify(result));
  });
  const response = await transport.request(FULCIO_URL, options);
  assert.deepEqual(await response.json(), result);
  await assert.rejects(transport.request(FULCIO_URL, options));
  assert.equal(calls, 1);
});

for (const uri of ['http://fulcio.sigstore.dev/api/v2/signingCert',
  'https://user:pass@fulcio.sigstore.dev/api/v2/signingCert',
  `${FULCIO_URL}#fragment`, `${FULCIO_URL}?query=wrong`,
  'https://foreign.invalid/api/v2/signingCert']) {
  test(`Fulcio rejects unsafe destination before transport: ${uri}`, async () => {
    let calls = 0;
    const transport = createFulcioTransport(() => { calls++; });
    await assert.rejects(transport.request(uri, options));
    assert.equal(calls, 0);
  });
}

for (const [name, response] of [
  ['307', () => new Response('{}', { status: 307 })],
  ['308', () => new Response('{}', { status: 308 })],
  ['503', () => new Response('{}', { status: 503 })],
  ['malformed', () => new Response('{')],
  ['oversized', () => new Response('x'.repeat(FULCIO_LIMITS.responseBytes + 1))],
  ['missing chain', () => new Response('{}')],
]) {
  test(`Fulcio ${name} failure is terminal and does not retain sensitive body/error data`, async () => {
    let calls = 0;
    const transport = createFulcioTransport(async () => { calls++; return response(); });
    await assert.rejects(transport.request(FULCIO_URL, options), error => {
      assert.equal(error.message.includes(body.credentials.oidcIdentityToken), false);
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.throws(transport.healthy);
    await assert.rejects(transport.request(FULCIO_URL, options));
    assert.equal(calls, 1);
  });
}

test('Fulcio deadline includes body consumption after response headers', async () => {
  let stream;
  let signal;
  const transport = createFulcioTransport(async (_uri, options) => {
    signal = options.signal;
    return new Response(new ReadableStream({ start(controller) { stream = controller; } }));
  }, { timeoutMs: 10 });
  await assert.rejects(transport.request(FULCIO_URL, options));
  assert.equal(signal.aborted, true);
  stream.close();
  assert.throws(transport.healthy);
});

test('Fulcio outer retry options are forced to zero independently from lower transport', async () => {
  let calls = 0;
  const external = fulcioExternalFetch(async (uri, actual) => {
    calls++;
    assert.equal(uri, FULCIO_URL);
    assert.deepEqual(actual.retry, { retries: 0 });
    assert.equal(actual.timeout, 30_000);
    assert.equal(actual.body, options.body);
    return 'fixture';
  }, () => {});
  assert.equal(await external(FULCIO_URL, options), 'fixture');
  assert.equal(calls, 1);
});

test('both issuer audiences run independently and return their own consumed JSON value', async () => {
  const env = { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://issuer.fixture.invalid/token?api-version=2.0',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-request-credential' };
  const calls = [];
  const issuer = createIssuerTransport(async (url, options) => {
    const parsed = new URL(url);
    const audience = parsed.searchParams.get('audience');
    calls.push(audience);
    assert.equal(options.redirect, 'error');
    return new Response(JSON.stringify({ value: `synthetic-for-${audience}` }));
  }, env);
  for (const audience of ['npm:registry.npmjs.org', 'sigstore']) {
    const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
    url.searchParams.append('audience', audience);
    const response = await issuer.request(url.href,
      { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
    assert.deepEqual(await response.json(), { value: `synthetic-for-${audience}` });
  }
  assert.deepEqual(calls, ['npm:registry.npmjs.org', 'sigstore']);
  issuer.healthy();
});
