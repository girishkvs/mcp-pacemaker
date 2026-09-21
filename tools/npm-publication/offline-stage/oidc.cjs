'use strict';
// Every token, ID, response and signature here is an unsigned offline fixture.
const attempts = require('./deny.cjs');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { writeFileSync } = require('node:fs');
const { join, dirname, resolve } = require('node:path');
const [cliArgument, homeArgument] = process.argv.slice(2);
const cli = resolve(cliArgument);
const req = createRequire(cli);
const home = resolve(homeArgument);
for (const name of ['user.npmrc', 'global.npmrc', 'saved.sigstore']) {
  writeFileSync(join(home, name), name.endsWith('sigstore') ? '{"fixture":"saved"}' : '', { flag: 'wx' });
}
Object.assign(process.env, {
  GITHUB_ACTIONS: 'true', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://offline.invalid/oidc',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-only',
  GITHUB_REPOSITORY: 'girishkvs/mcp-pacemaker', GITHUB_SERVER_URL: 'https://github.com',
});
delete process.env.NPM_ID_TOKEN;
const transport = req.resolve('make-fetch-happen');
const original = req(transport);
let generated = 0;
let verified = 0;
let body;
const requests = [];
const diagnostics = [];
process.on('log', (level, area, message) => {
  if (area === 'oidc') diagnostics.push({ level, message });
});
const jwt = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"repository_visibility":"public"}').toString('base64url')}.UNSIGNED`;
req.cache[transport].exports = Object.assign(async (uri, options = {}) => {
  const url = new URL(uri);
  requests.push({ path: url.pathname, method: options.method ?? 'GET' });
  let result;
  if (url.hostname === 'offline.invalid') result = { value: jwt };
  else if (url.pathname.includes('/oidc/token/exchange/')) result = { token: 'synthetic-only' };
  else if (url.pathname.endsWith('/visibility')) result = { public: true };
  else if (url.pathname === '/-/stage/package/mcp-pacemaker') {
    body = JSON.parse(options.body);
    result = { stageId: '11111111-1111-1111-1111-111111111111' };
  } else throw new Error('Unexpected fixture request');
  const stream = new (req('minipass').Minipass)();
  stream.end(JSON.stringify(result));
  return new original.Response(stream, { status: 200, url: String(uri) });
}, original);
req('sigstore');
req.cache[req.resolve('sigstore')].exports = { attest: async payload => {
  generated++;
  return { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    dsseEnvelope: { payload: payload.toString('base64'), payloadType: 'application/vnd.in-toto+json',
      signatures: [{ keyid: '', sig: 'SYNTHETIC-NOT-A-SIGNATURE' }] } };
}, verify: async () => { verified++; } };
const Config = req('@npmcli/config');
const definitions = req('@npmcli/config/lib/definitions');
const configFor = args => new Config({
  ...definitions, npmPath: dirname(dirname(cli)), cwd: home,
  env: { HOME: home, USERPROFILE: home },
  argv: [process.execPath, cli, `--userconfig=${join(home, 'user.npmrc')}`,
    `--globalconfig=${join(home, 'global.npmrc')}`, ...args],
});
(async () => {
  const saved = join(home, 'saved.sigstore');
  const config = configFor([`--provenance-file=${saved}`]);
  await config.load();
  assert.equal(config.isDefault('provenance'), true);
  const opts = { ...config.flat, stage: true, access: 'public', registry: 'https://registry.npmjs.org/',
    defaultTag: 'legacy', npmVersion: '12.0.2', fetchRetries: 0 };
  assert.equal(opts.provenanceFile, saved);
  await req(join(dirname(dirname(cli)), 'lib/utils/oidc.js')).oidc({
    packageName: 'mcp-pacemaker', registry: opts.registry, opts, config,
  });
  console.log(JSON.stringify({ syntheticOnly: true, requests, diagnostics, attempts }));
  assert.equal(opts.provenance, true, 'Actual OIDC must reproduce default-provenance replacement');
  await req('libnpmpublish').publish({ name: 'mcp-pacemaker', version: '1.3.1' },
    Buffer.from('synthetic tarball, not a publication candidate'), opts);
  assert.equal(generated, 1);
  assert.equal(verified, 0);
  const data = body._attachments['mcp-pacemaker-1.3.1.sigstore'].data;
  assert.equal(typeof data, 'string');
  assert.ok(JSON.parse(data).dsseEnvelope);
  assert.notEqual(data, '{"fixture":"saved"}');
  await assert.rejects(configFor(['--provenance=false', `--provenance-file=${saved}`]).load(),
    /cannot be provided/);
  assert.deepEqual(attempts, []);
  console.log(JSON.stringify({ syntheticOnly: true, actualNpm: '12.0.2',
    savedBundleReplaced: true, automaticAttestStubCalls: generated, savedVerifyStubCalls: verified,
    bothExplicitFlagsRejected: true, deniedHostAttempts: attempts }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
