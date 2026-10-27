import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { POLICY, digest, sameDigests, validatePackage } from './policy.mjs';
import { readBootstrapDirectory } from './verify-bootstrap.mjs';
import { officialRegistryUrl, officialWebsiteUrl, validateOwnerContext } from './owner-bootstrap.mjs';
import { npmProvenance } from './provenance.mjs';
import { validateLocalApproval, validateLocalManifest } from './local-regression.mjs';

export const PROFILE_SOURCE_SHA256 = 'ae6998f77dda9eee717e7b4b883407fe956e9d94c16e784db4943ed66a9d143e';

export function registryTransport(fetcher) {
  return (uri, options = {}) => {
    options.signal?.throwIfAborted();
    return fetcher(officialRegistryUrl(uri), {
      ...options, redirect: 'error', strictSSL: true, retry: { retries: 0 }, timeout: 30_000,
      cache: 'no-store', cachePath: undefined, proxy: undefined, noProxy: '*',
    });
  };
}

// npm-registry-fetch does not pass its caller's redirect option to make-fetch-happen.
// Bind only that library's requests to the restricted transport, before loading it.
// Sigstore's separate public trust reads do not carry owner credentials.
export function loadOwnerLibraries(cli) {
  npmProvenance(cli);
  const require = createRequire(realpathSync.native(cli));
  const registryPath = require.resolve('npm-registry-fetch');
  assert.equal(require.cache[registryPath], undefined, 'Owner SDK must load in its own fresh child');
  assert.equal(require('npm-profile/package.json').version, '13.0.1');
  assert.equal(digest(readFileSync(require.resolve('npm-profile'))).sha256, PROFILE_SOURCE_SHA256);
  const transportPath = require.resolve('make-fetch-happen');
  const originalTransport = require(transportPath);
  const context = new AsyncLocalStorage();
  const guarded = registryTransport(originalTransport);
  require.cache[transportPath].exports = Object.assign((uri, options) =>
    context.getStore() ? guarded(uri, options) : originalTransport(uri, options), originalTransport);
  const originalRegistry = require(registryPath);
  const registry = Object.assign((uri, options) =>
    context.run(true, () => originalRegistry(officialRegistryUrl(uri), options)), originalRegistry);
  registry.json = async (uri, options) => (await registry(uri, options)).json();
  registry.json.stream = () => { throw new Error('Owner SDK does not permit streaming registry operations'); };
  require.cache[registryPath].exports = registry;
  return { registry, profile: require('npm-profile'), publish: require('libnpmpublish').publish,
    pacote: require('pacote') };
}

export function createOwnerSdk({ cli, directory, approval, home, libraries }) {
  validateLocalApproval(approval);
  if (!libraries) {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    validateOwnerContext({ env: process.env, event, approval });
    libraries = loadOwnerLibraries(cli);
  }
  const original = readBootstrapDirectory(directory);
  validateLocalManifest(original.get('manifest.json'), approval,
    JSON.parse(original.get('gates.json').toString('utf8')));
  const tarball = join(directory, 'candidate.tgz');
  const provenanceFile = join(directory, 'provenance.sigstore');
  const base = { registry: POLICY.registry, authType: 'web', access: 'public', defaultTag: 'latest',
    npmVersion: POLICY.npm, provenanceFile, fetchRetries: 0, retry: { retries: 0 },
    strictSSL: true, timeout: 30_000, cache: false, ignoreScripts: true };
  const auth = token => ({ ...base, '//registry.npmjs.org/:_authToken': token });
  let manifest;
  const checkBytes = async () => {
    const files = readBootstrapDirectory(directory);
    validateLocalManifest(files.get('manifest.json'), approval, JSON.parse(files.get('gates.json').toString('utf8')));
    assert.deepEqual(files, original, 'Signed artifact changed after verification');
    sameDigests(digest(files.get('candidate.tgz')), approval.artifact);
    assert.equal(digest(files.get('provenance.sigstore')).sha256, approval.signedArtifact.bundleSha256);
    manifest = await libraries.pacote.manifest(tarball, {
      fullMetadata: true, fullReadJson: true, ignoreScripts: true, offline: true,
      cache: join(home, 'pacote-cache'), registry: POLICY.registry,
    });
    validatePackage(manifest, approval);
    assert.equal(manifest.version, '2.0.1');
    // Validate option precedence, then recheck bytes after pacote's local archive read.
    assert.deepEqual(readBootstrapDirectory(directory), original);
  };
  const json = (path, options) => libraries.registry.json(path, options);
  return {
    checkBytes,
    login: async (opener, signal) => {
      const result = await libraries.profile.loginWeb(
        async url => opener(officialWebsiteUrl(url)), { ...base, signal });
      return result.token;
    },
    whoami: async token => (await json('/-/whoami', auth(token))).username,
    profile: token => libraries.profile.get(auth(token)),
    webAuth: async (pair, opener, signal) => {
      // No owner token is needed to poll the single-use browser challenge.
      const result = await libraries.profile.webAuthOpener(async url => opener(officialWebsiteUrl(url)),
        officialWebsiteUrl(pair.authUrl), officialRegistryUrl(pair.doneUrl), { ...base, signal });
      return result.token;
    },
    publish: async (token, otp, signal) => {
      await checkBytes();
      signal?.throwIfAborted();
      const options = { ...auth(token), signal, ...(otp === undefined ? {} : { otp }) };
      assert.equal(options.stage, undefined);
      assert.equal(options.provenance, undefined);
      return libraries.publish(manifest, original.get('candidate.tgz'), options);
    },
    readback: async () => {
      const packument = await json(`/${POLICY.name}`, base);
      assert.equal(packument.name, POLICY.name);
      assert.deepEqual(Object.keys(packument.versions).sort(), ['2.0.1']);
      assert.deepEqual(packument['dist-tags'], { latest: '2.0.1' });
      const version = packument.versions['2.0.1'];
      assert.equal(version.name, POLICY.name);
      assert.equal(version.version, '2.0.1');
      assert.equal(version.dist.integrity, approval.artifact.integrity);
      const expected = `${POLICY.registry}${POLICY.name}/-/${POLICY.name}-2.0.1.tgz`;
      assert.equal(version.dist.tarball, expected);
      const response = await libraries.registry(expected, base);
      assert.equal(response.status, 200);
      sameDigests(digest(Buffer.from(await response.arrayBuffer())), approval.artifact);
    },
    logout: async token => {
      // This is npm12 logout's documented session-token DELETE, not token inventory mutation.
      await libraries.registry(`/-/user/token/${encodeURIComponent(token)}`, {
        ...auth(token), method: 'DELETE', ignoreBody: true,
      });
    },
  };
}
