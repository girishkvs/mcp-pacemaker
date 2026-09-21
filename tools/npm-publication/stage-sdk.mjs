import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureTransport, durableCaptureSink, sha256, STAGE_URL } from './stage-capture.mjs';
import { validateStageLoader } from './stage-loader.mjs';
import { createIssuerTransport } from './stage-issuer.mjs';
import { createFulcioTransport, isFulcioRequest, fulcioExternalFetch } from './stage-fulcio.mjs';

export function installStageCapture({ cli, expected, directory, secrets = [] }) {
  assert.equal(process.versions.node, '24.21.0', 'Actual npm12 publisher requires the pinned Node24 runtime');
  const { entry, root, require } = validateStageLoader(cli);
  const pins = JSON.parse(readFileSync(new URL('./stage-sdk-pins.json', import.meta.url)));
  for (const [path, hash] of Object.entries(pins)) {
    assert.equal(sha256(readFileSync(resolve(root, path))), hash, `Unreviewed npm source: ${path}`);
  }
  const registryPath = require.resolve('npm-registry-fetch');
  const transportPath = require.resolve('make-fetch-happen');
  // Validate the original issuer settings before loading any npm transport.
  let original;
  const issuer = createIssuerTransport((...args) => original(...args), process.env);
  const fulcio = createFulcioTransport((...args) => original(...args));
  original = require(transportPath);
  const capture = captureTransport({ fetcher: original, expected,
    save: durableCaptureSink(directory), secrets });
  const context = new AsyncLocalStorage();
  let exchangeSpent = false;
  const guarded = async (uri, options = {}) => {
    issuer.healthy();
    fulcio.healthy();
    if (issuer.handles(uri, options)) return issuer.request(uri, options);
    if (isFulcioRequest(uri, options)) return fulcio.request(uri, options);
    const url = new URL(uri);
    const isRegistry = context.getStore() ||
      url.origin === 'https://registry.npmjs.org';
    if (!isRegistry) return original(uri, options);
    assert.equal(url.origin, 'https://registry.npmjs.org');
    assert.equal(url.username, '');
    assert.equal(url.password, '');
    assert.equal(url.search, '');
    assert.equal(url.hash, '');
    if (url.href === STAGE_URL) return capture(url.href, options);
    const method = options.method ?? 'GET';
    const read = method === 'GET' &&
      ['/mcp-pacemaker', '/-/package/mcp-pacemaker/visibility'].includes(url.pathname);
    const exchange = method === 'POST' &&
      url.pathname === '/-/npm/v1/oidc/token/exchange/package/mcp-pacemaker';
    assert.ok(read ||
      exchange, 'Unapproved npm registry operation; no direct publish/approve/delete');
    if (exchange) {
      assert.equal(exchangeSpent, false, 'OIDC exchange already attempted');
      exchangeSpent = true;
    }
    return original(url.href, {
      ...options, redirect: 'error', retry: { retries: 0 }, strictSSL: true,
      timeout: 30_000, signal: options.signal ?
        AbortSignal.any([options.signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
      cache: 'no-store', cachePath: undefined, proxy: undefined, noProxy: '*',
    });
  };
  const transport = Object.assign(guarded, original);
  transport.defaults = (url, opts) => original.defaults(url, opts, guarded);
  require.cache[transportPath].exports = transport;
  const registry = require(registryPath);
  const scoped = Object.assign((uri, opts) =>
    context.run(true, () => registry(uri, opts)), registry);
  scoped.json = async (uri, opts) => (await scoped(uri, opts)).json();
  scoped.json.stream = () => { throw new Error('Stage publisher does not need registry streaming JSON'); };
  require.cache[registryPath].exports = scoped;
  const externalPath = resolve(root, 'node_modules/@sigstore/sign/dist/external/fetch.js');
  const external = require(externalPath);
  require.cache[externalPath].exports = {
    ...external, fetchWithRetry: fulcioExternalFetch(external.fetchWithRetry, () => {
      issuer.healthy();
      fulcio.healthy();
    }),
  };
  return { entry, adapter: fileURLToPath(import.meta.url) };
}
