'use strict';
const denied = require('./deny.cjs');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { createRequire } = Module;
const { mkdirSync, readFileSync, readdirSync, writeFileSync } = require('node:fs');
const { dirname, join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { fixture } = require('./fixture.cjs');
const [rootArgument, cliArgument, mode, homeArgument] = process.argv.slice(2);
const root = resolve(rootArgument);
const cli = resolve(cliArgument);
const home = resolve(homeArgument);
const requireNpm = createRequire(cli);
const npmRoot = resolve(dirname(cli), '..');
const lowPath = requireNpm.resolve('minipass-fetch');
const externalPath = join(npmRoot, 'node_modules/@sigstore/sign/dist/external/fetch.js');
const capture = join(home, 'capture');
mkdirSync(capture);
const version = JSON.parse(readFileSync(join(root, 'package.json'))).version;
Object.assign(process.env, {
  HOME: home, USERPROFILE: home, TMP: home, TEMP: home, TMPDIR: home,
  GITHUB_ACTIONS: 'true', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://offline.invalid/oidc?api-version=2.0&request=original',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-services-request-credential',
});
delete process.env.NPM_ID_TOKEN;
delete process.env.SIGSTORE_ID_TOKEN;
const requestToken = 'SYNTHETIC-FULCIO-TOKEN-NOT-REAL';
const npmToken = 'SYNTHETIC-NPM-ISSUER-NOT-REAL';
const signToken = 'SYNTHETIC-SIGSTORE-ISSUER-NOT-REAL';
const registryToken = 'SYNTHETIC-EXCHANGED-TOKEN-NOT-REAL';
const certificate = 'SYNTHETIC-NOT-A-CERTIFICATE';
const requests = [];
const outerOptions = [];
let externalObserved = false;
let low;
let certificateBody;
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const path = Module._resolveFilename(request, parent, isMain);
  const value = originalLoad.call(this, request, parent, isMain);
  if (path === lowPath) {
    low ??= value;
    const substitute = Object.assign(async (request, options) => {
      const url = new URL(request.url);
      const stream = new (requireNpm('minipass').Minipass)();
      let status = 200;
      let response;
      const headers = { 'content-type': 'application/json' };
      if (mode === 'dual-audience') {
        if (url.hostname === 'offline.invalid') {
          const audience = url.searchParams.get('audience');
          assert.ok(['npm:registry.npmjs.org', 'sigstore'].includes(audience));
          assert.equal(url.searchParams.get('api-version'), '2.0');
          assert.equal(url.searchParams.get('request'), 'original');
          response = { value: audience === 'sigstore' ? signToken : npmToken };
          requests.push({ kind: 'issuer', audience, protocol: url.protocol, method: request.method });
        } else {
          assert.equal(url.href, 'https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/mcp-pacemaker');
          assert.equal(request.headers.get('authorization'), `Bearer ${npmToken}`);
          response = { token: registryToken };
          requests.push({ kind: 'exchange', protocol: url.protocol, method: request.method });
        }
      } else {
        assert.equal(url.href, 'https://fulcio.sigstore.dev/api/v2/signingCert');
        assert.equal(request.method, 'POST');
        assert.equal(request.headers.has('authorization'), false);
        assert.equal(JSON.parse(options.body).credentials.oidcIdentityToken, requestToken);
        certificateBody ??= options.body;
        assert.equal(options.body, certificateBody);
        assert.deepEqual(options.retry, { retries: 0 });
        assert.equal(options.timeout, 30_000);
        assert.equal(options.size, 256 * 1024);
        assert.ok(options.signal);
        requests.push({ kind: 'certificate', protocol: url.protocol, method: request.method,
          identityInBody: true, authorizationHeader: false, timeoutMs: options.timeout,
          responseLimit: options.size, lowerRetries: options.retry.retries });
        if (mode.endsWith('307') ||
            mode.endsWith('308')) {
          status = Number(mode.slice(-3));
          headers.location = 'http://fulcio.sigstore.dev/redirected';
          response = {};
        } else if (mode.endsWith('503')) {
          status = 503;
          response = { message: 'synthetic service failure' };
        } else if (mode === 'fulcio-malformed') response = '{';
        else if (mode === 'fulcio-oversize') response = 'x'.repeat(256 * 1024 + 1);
        else response = { signedCertificateEmbeddedSct: { chain: { certificates: [certificate] } } };
      }
      if (mode !== 'fulcio-deadline') stream.end(typeof response === 'string' ? response : JSON.stringify(response));
      return new low.Response(stream, { url: request.url, status, headers });
    }, low);
    requireNpm.cache[path].exports = substitute;
    return substitute;
  }
  if (path === externalPath &&
      !externalObserved) {
    externalObserved = true;
    const substitute = { ...value, fetchWithRetry: (url, options) => {
      outerOptions.push({ retries: options.retry.retries, timeoutMs: options.timeout });
      return value.fetchWithRetry(url, options);
    } };
    requireNpm.cache[path].exports = substitute;
    return substitute;
  }
  return value;
};

(async () => {
  const sdk = await import(pathToFileURL(join(root, 'tools/npm-publication/stage-sdk.mjs')));
  sdk.installStageCapture({ cli, expected: fixture(version).record, directory: capture });
  const started = Date.now();
  let configuredRetries;
  let configuredTimeoutMs;
  if (mode === 'dual-audience') {
    const Config = requireNpm('@npmcli/config');
    const definitions = requireNpm('@npmcli/config/lib/definitions');
    for (const file of ['user.npmrc', 'global.npmrc']) writeFileSync(join(home, file), '', { flag: 'wx' });
    const config = new Config({ ...definitions, npmPath: npmRoot, cwd: home,
      env: { HOME: home, USERPROFILE: home },
      argv: [process.execPath, cli, '--provenance=true',
        `--userconfig=${join(home, 'user.npmrc')}`, `--globalconfig=${join(home, 'global.npmrc')}`] });
    await config.load();
    const opts = { ...config.flat, registry: 'https://registry.npmjs.org/', retry: { retries: 0 } };
    await requireNpm(join(npmRoot, 'lib/utils/oidc.js')).oidc({
      packageName: 'mcp-pacemaker', registry: opts.registry, opts, config,
    });
    assert.equal(opts['//registry.npmjs.org/:_authToken'], registryToken);
    const { CIContextProvider } = requireNpm('@sigstore/sign');
    assert.equal(await new CIContextProvider('sigstore').getToken(), signToken);
    assert.deepEqual(requests, [
      { kind: 'issuer', audience: 'npm:registry.npmjs.org', protocol: 'https:', method: 'GET' },
      { kind: 'exchange', protocol: 'https:', method: 'POST' },
      { kind: 'issuer', audience: 'sigstore', protocol: 'https:', method: 'GET' },
    ]);
    assert.equal(readFileSync(join(home, 'user.npmrc'), 'utf8'), '');
    assert.equal(outerOptions.length, 0);
  } else {
    const { flatten, definitions } = requireNpm('@npmcli/config/lib/definitions');
    const { stageArguments } = await import(pathToFileURL(join(root, 'tools/npm-publication/policy.mjs')));
    const args = stageArguments(join(home, 'fixture.tgz'), version === '1.3.1' ? 'legacy' : 'latest',
      { user: join(home, 'user.npmrc'), global: join(home, 'global.npmrc') });
    const config = {};
    flatten({ 'fetch-retries': Number(args.find(arg => arg.startsWith('--fetch-retries=')).split('=')[1]),
      'fetch-timeout': definitions['fetch-timeout'].default }, config);
    assert.equal(config.retry.retries, 0, 'Actual supported CLI already disables outer retries');
    assert.equal(config.timeout, 300_000, 'Actual CLI fetch timeout must be covered, not an SDK-default substitute');
    configuredRetries = mode.includes('default') ? 2 : config.retry.retries;
    configuredTimeoutMs = mode.includes('default') ? 5000 : config.timeout;
    const { CAClient } = requireNpm(join(npmRoot, 'node_modules/@sigstore/sign/dist/signer/fulcio/ca.js'));
    const client = new CAClient({ fulcioBaseURL: 'https://fulcio.sigstore.dev',
      retry: { retries: configuredRetries }, timeout: configuredTimeoutMs });
    const operation = client.createSigningCertificate(requestToken, 'SYNTHETIC-PUBLIC-KEY',
      Buffer.from('SYNTHETIC-NOT-A-SIGNATURE'));
    if (mode === 'fulcio-success') assert.deepEqual(await operation, [certificate]);
    else await assert.rejects(operation, error => error.code === 'CA_CREATE_SIGNING_CERTIFICATE_ERROR');
    assert.deepEqual(outerOptions, [{ retries: 0, timeoutMs: 30_000 }]);
    assert.equal(requests.length, 1, 'No second hop or outer/lower retry is allowed');
    if (mode !== 'fulcio-success') {
      await assert.rejects(requireNpm('npm-registry-fetch')('https://registry.npmjs.org/mcp-pacemaker'));
      assert.equal(requests.length, 1, 'Certificate failure blocks later registry continuation');
    }
  }
  assert.deepEqual(readdirSync(capture), []);
  assert.deepEqual(denied, []);
  console.log(JSON.stringify({ syntheticOnly: true, mode, passed: true, actualNode: process.versions.node,
    requests, outerOptions, configuredRetries, configuredTimeoutMs, elapsedMs: Date.now() - started,
    realSigning: false, realCertificateIssued: false, realTokenObtained: false,
    stageRequests: 0, deniedHostAttempts: denied }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
