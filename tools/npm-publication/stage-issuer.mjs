import assert from 'node:assert/strict';

export const ISSUER_LIMITS = Object.freeze({ timeoutMs: 30_000, responseBytes: 64 * 1024 });

export function issuerBinding(env) {
  assert.ok(typeof env.ACTIONS_ID_TOKEN_REQUEST_URL === 'string', 'Missing original issuer URL');
  assert.ok(typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN === 'string' &&
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length > 0, 'Missing original issuer credential');
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  assert.ok(url.protocol === 'https:' &&
    url.username === '' &&
    url.password === '' &&
    url.hash === '', 'Issuer must be HTTPS without userinfo or fragment');
  assert.equal(url.searchParams.has('audience'), false, 'Ambiguous configured issuer audience');
  assert.ok(!env.NPM_ID_TOKEN &&
    !env.SIGSTORE_ID_TOKEN, 'Alternate identity tokens are forbidden');
  const requests = new Map();
  for (const audience of ['npm:registry.npmjs.org', 'sigstore']) {
    const request = new URL(url.href);
    request.searchParams.append('audience', audience);
    requests.set(request.href, audience);
  }
  return { requests, origin: url.origin, pathname: url.pathname,
    authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` };
}

export function createIssuerTransport(fetcher, env, { timeoutMs = ISSUER_LIMITS.timeoutMs } = {}) {
  const binding = issuerBinding(env);
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= ISSUER_LIMITS.timeoutMs);
  let failed = false;
  const spent = new Set();
  const healthy = () => assert.equal(failed, false, 'Issuer failure forbids continuation');
  const handles = (uri, options = {}) => {
    const url = new URL(uri);
    const authorization = new Headers(options.headers).get('authorization');
    const issuerPath = url.origin === binding.origin &&
      url.pathname === binding.pathname;
    return binding.requests.has(url.href) ||
      issuerPath ||
      authorization === binding.authorization;
  };
  const request = async (uri, options = {}) => {
    healthy();
    const url = new URL(uri);
    const audience = binding.requests.get(url.href);
    let response;
    let timer;
    const controller = new AbortController();
    try {
      assert.ok(audience, 'Unexpected issuer destination or audience');
      assert.ok(new Headers(options.headers).get('authorization') === binding.authorization,
        'Issuer credential binding mismatch');
      assert.equal(options.method ?? 'GET', 'GET');
      assert.equal(options.body, undefined);
      assert.equal(spent.has(audience), false, 'Issuer audience already attempted; never retry');
      spent.add(audience);
      const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
      const operation = async () => {
        signal.throwIfAborted();
        response = await fetcher(url.href, {
          ...options, method: 'GET', redirect: 'error', retry: { retries: 0 }, strictSSL: true,
          timeout: timeoutMs, signal, size: ISSUER_LIMITS.responseBytes,
          cache: 'no-store', cachePath: undefined, proxy: undefined, noProxy: '*',
        });
        signal.throwIfAborted();
        assert.equal(response.status, 200);
        const chunks = [];
        let length = 0;
        for await (const chunk of response.body) {
          signal.throwIfAborted();
          length += chunk.length;
          assert.ok(length <= ISSUER_LIMITS.responseBytes, 'Issuer response exceeds limit');
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks);
        const text = bytes.toString('utf8');
        assert.ok(Buffer.from(text).equals(bytes), 'Issuer response is not UTF8');
        const value = JSON.parse(text);
        assert.ok(typeof value.value === 'string' &&
          value.value.length > 0, 'Issuer response has no token value');
        signal.throwIfAborted();
        response.json = async () => structuredClone(value);
        return response;
      };
      return await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          response?.body?.destroy?.();
          reject(new Error('Issuer deadline exceeded'));
        }, timeoutMs);
      })]);
    } catch {
      failed = true;
      controller.abort();
      response?.body?.destroy?.();
      // Never retain a raw response, credential, URL query or underlying error.
      throw new Error('Issuer request failed; no redirect, retry or continuation permitted');
    } finally {
      clearTimeout(timer);
    }
  };
  return { handles, request, healthy };
}
