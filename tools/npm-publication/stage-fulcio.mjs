import assert from 'node:assert/strict';

export const FULCIO_URL = 'https://fulcio.sigstore.dev/api/v2/signingCert';
export const FULCIO_LIMITS = Object.freeze({
  requestBytes: 64 * 1024, responseBytes: 256 * 1024, timeoutMs: 30_000,
});

export function isFulcioRequest(uri, options = {}) {
  const url = new URL(uri);
  if (url.hostname === 'fulcio.sigstore.dev' ||
      url.pathname.endsWith('/signingCert')) return true;
  if (typeof options.body !== 'string') return false;
  if (Buffer.byteLength(options.body) > FULCIO_LIMITS.requestBytes) {
    return options.body.includes('oidcIdentityToken');
  }
  try {
    const value = JSON.parse(options.body);
    return value !== null &&
      typeof value === 'object' &&
      Object.hasOwn(value, 'credentials');
  } catch {
    return options.body.includes('oidcIdentityToken');
  }
}

export function createFulcioTransport(fetcher, { timeoutMs = FULCIO_LIMITS.timeoutMs } = {}) {
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= FULCIO_LIMITS.timeoutMs);
  let spent = false;
  let failed = false;
  const healthy = () => assert.equal(failed, false, 'Fulcio failure forbids continuation');
  const request = async (uri, options = {}) => {
    healthy();
    let response;
    let timer;
    const controller = new AbortController();
    try {
      assert.equal(spent, false, 'Certificate request already attempted; never retry');
      spent = true;
      assert.equal(String(uri), FULCIO_URL, 'Token-bearing certificate request must use the fixed HTTPS endpoint');
      assert.equal(options.method, 'POST');
      assert.equal(typeof options.body, 'string');
      assert.ok(Buffer.byteLength(options.body) <= FULCIO_LIMITS.requestBytes);
      const body = JSON.parse(options.body);
      assert.deepEqual(Object.keys(body).sort(), ['credentials', 'publicKeyRequest']);
      assert.deepEqual(Object.keys(body.credentials), ['oidcIdentityToken']);
      assert.ok(typeof body.credentials.oidcIdentityToken === 'string' &&
        body.credentials.oidcIdentityToken.length > 0);
      const headers = new Headers(options.headers);
      assert.equal(headers.has('authorization'), false);
      assert.equal(headers.has('cookie'), false);
      assert.equal(headers.get('content-type'), 'application/json');
      const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
      const operation = async () => {
        signal.throwIfAborted();
        response = await fetcher(FULCIO_URL, {
          ...options, redirect: 'error', retry: { retries: 0 }, strictSSL: true,
          timeout: timeoutMs, signal, size: FULCIO_LIMITS.responseBytes,
          cache: 'no-store', cachePath: undefined, proxy: undefined, noProxy: '*',
        });
        signal.throwIfAborted();
        assert.equal(response.status, 200);
        const chunks = [];
        let size = 0;
        for await (const chunk of response.body) {
          signal.throwIfAborted();
          size += chunk.length;
          assert.ok(size <= FULCIO_LIMITS.responseBytes);
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks);
        const text = bytes.toString('utf8');
        assert.ok(Buffer.from(text).equals(bytes));
        const value = JSON.parse(text);
        const certificate = value.signedCertificateEmbeddedSct ?? value.signedCertificateDetachedSct;
        assert.ok(Array.isArray(certificate?.chain?.certificates) &&
          certificate.chain.certificates.length > 0 &&
          certificate.chain.certificates.every(item => typeof item === 'string' &&
            item.length > 0));
        signal.throwIfAborted();
        response.json = async () => structuredClone(value);
        return response;
      };
      return await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          response?.body?.destroy?.();
          reject(new Error('Certificate response deadline exceeded'));
        }, timeoutMs);
      })]);
    } catch {
      failed = true;
      controller.abort();
      response?.body?.destroy?.();
      // No token-bearing body, certificate response or underlying error is retained.
      throw new Error('Certificate request failed; no redirect, retry or continuation permitted');
    } finally {
      clearTimeout(timer);
    }
  };
  return { request, healthy };
}

// @sigstore/sign/external/fetch.js owns a second retry layer outside
// make-fetch-happen. Bind both layers, not only the lower HTTP options.
export function fulcioExternalFetch(original, healthy) {
  return (uri, options = {}) => {
    healthy();
    if (!isFulcioRequest(uri, options)) return original(uri, options);
    return original(uri, { ...options, retry: { retries: 0 }, timeout: FULCIO_LIMITS.timeoutMs });
  };
}
