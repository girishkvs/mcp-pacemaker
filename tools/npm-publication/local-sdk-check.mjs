import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import dns from 'node:dns';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { POLICY } from './policy.mjs';

export function validateSdkContract(libraries, provenance) {
  for (const name of ['registry', 'publish']) assert.equal(typeof libraries[name], 'function', name);
  assert.equal(typeof libraries.registry.json, 'function');
  assert.equal(typeof libraries.registry.json.stream, 'function');
  for (const name of ['loginWeb', 'webAuthOpener', 'get']) {
    assert.equal(typeof libraries.profile?.[name], 'function', `profile.${name}`);
  }
  assert.equal(typeof libraries.pacote?.manifest, 'function');
  for (const name of ['verifyBundle', 'generate', 'subject']) {
    assert.equal(typeof provenance[name], 'function', `provenance.${name}`);
  }
  const sha512 = 'a'.repeat(128);
  assert.deepEqual(provenance.subject(POLICY.name, '2.0.1', sha512),
    { name: `pkg:npm/${POLICY.name}@2.0.1`, digest: { sha512 } });
}

export async function loadLaneSdk(cli, version) {
  assert.ok(['1.3.1', '2.0.1'].includes(version), 'Unsupported SDK lane');
  assert.ok(isAbsolute(cli), 'An absolute pinned npm CLI path is required');
  if (version === '1.3.1') {
    // Match verify-staged.mjs's npm/sigstore loader, without running its CLI or verifying a bundle.
    const entry = realpathSync.native(cli);
    const pkg = JSON.parse(readFileSync(resolve(dirname(entry), '../package.json'), 'utf8'));
    assert.equal(pkg.name, 'npm');
    assert.equal(pkg.version, POLICY.npm);
    const require = createRequire(entry);
    assert.equal(require.cache[require.resolve('sigstore')], undefined, 'Signature SDK must load in its own fresh child');
    assert.equal(require('sigstore/package.json').version, '5.0.0');
    const { verifyStaged } = await import('./verify-staged.mjs');
    assert.equal(typeof verifyStaged, 'function', 'verify-staged.verifyStaged');
    assert.equal(typeof require('sigstore').verify, 'function', 'sigstore.verify');
    return { contract: 'legacy-staged-signature', module: 'verify-staged.mjs',
      verifier: 'sigstore@5.0.0 (npm@12.0.2)' };
  }
  const { loadOwnerLibraries, PROFILE_SOURCE_SHA256 } = await import('./owner-sdk.mjs');
  const { npmProvenance, PROVENANCE_SOURCE_SHA256 } = await import('./provenance.mjs');
  const libraries = loadOwnerLibraries(cli);
  const provenance = npmProvenance(cli);
  validateSdkContract(libraries, provenance);
  assert.match(PROFILE_SOURCE_SHA256, /^[a-f0-9]{64}$/, 'Missing reviewed profile source hash');
  assert.match(PROVENANCE_SOURCE_SHA256, /^[a-f0-9]{64}$/, 'Missing reviewed provenance source hash');
  return { contract: 'owner-sdk-and-provenance',
    profileSourceSha256: PROFILE_SOURCE_SHA256, provenanceSourceSha256: PROVENANCE_SOURCE_SHA256 };
}

// Use only in a disposable child; do not restore transports before that child exits.
export function blockSdkTransports() {
  const attempts = { network: 0, subprocess: 0 };
  const rejectNetwork = () => {
    attempts.network++;
    throw new Error('Transport is forbidden during the local SDK contract check');
  };
  const rejectProcess = () => {
    attempts.subprocess++;
    throw new Error('Subprocesses are forbidden during the local SDK contract check');
  };
  net.Socket.prototype.connect = net.Server.prototype.listen = rejectNetwork;
  net.connect = net.createConnection = tls.connect = rejectNetwork;
  http.request = http.get = https.request = https.get = rejectNetwork;
  http2.connect = rejectNetwork;
  for (const api of [dns, dns.promises]) {
    for (const name of Object.keys(api)) {
      const networkMethod = ['lookup', 'resolve', 'reverse'].some(prefix => name.startsWith(prefix));
      if (networkMethod &&
          typeof api[name] === 'function') api[name] = rejectNetwork;
    }
    for (const name of Object.getOwnPropertyNames(api.Resolver.prototype)) {
      if (name.startsWith('resolve') ||
          name.startsWith('reverse')) api.Resolver.prototype[name] = rejectNetwork;
    }
  }
  dgram.createSocket = rejectNetwork;
  for (const name of ['bind', 'connect', 'send']) dgram.Socket.prototype[name] = rejectNetwork;
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
    childProcess[name] = rejectProcess;
  }
  globalThis.fetch = rejectNetwork;
  if (globalThis.WebSocket) globalThis.WebSocket = rejectNetwork;
  syncBuiltinESMExports();
  process.on('exit', () => {
    if (attempts.network ||
        attempts.subprocess) process.exitCode = 1;
  });
  return attempts;
}

export async function main(args = process.argv.slice(2)) {
  assert.equal(args.length, 1, 'Supply the absolute retained npm CLI path');
  assert.ok(isAbsolute(args[0]));
  assert.equal(process.version, `v${POLICY.node}`, 'SDK check requires the reviewed publisher Node');
  const home = process.env.HOME;
  assert.ok(home &&
    isAbsolute(home), 'SDK check requires a fresh isolated home');
  assert.equal(realpathSync.native(home), resolve(home));
  for (const key of ['USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP']) {
    assert.equal(process.env[key], home, 'SDK home must not use owner settings');
  }
  assert.deepEqual(readdirSync(home).sort(), ['global.npmrc', 'user.npmrc'], 'SDK home is not empty');
  for (const name of ['global', 'user']) {
    assert.equal(readFileSync(join(home, `${name}.npmrc`), 'utf8'), '', 'SDK npm config is not empty');
  }
  // Drop all other inherited settings before loading npm code.
  const allowed = new Set(['path', 'home', 'userprofile', 'appdata', 'localappdata', 'temp', 'tmp', 'tmpdir',
    'systemroot', 'windir', 'comspec', 'pathext', 'no_color']);
  for (const name of Object.keys(process.env)) {
    if (!allowed.has(name.toLowerCase())) delete process.env[name];
  }
  const attempts = blockSdkTransports();
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.name, POLICY.name);
  const contract = await loadLaneSdk(args[0], pkg.version);
  assert.deepEqual(attempts, { network: 0, subprocess: 0 });
  const result = {
    status: 'passed', kind: 'fresh-child-offline-sdk-load', node: process.version, npm: POLICY.npm,
    version: pkg.version, ...contract,
    networkAttempts: attempts.network, subprocessAttempts: attempts.subprocess,
    authenticated: false, published: false, releaseReady: false, provenanceVerified: false,
    signatureVerified: false,
  };
  console.log(JSON.stringify(result));
  return result;
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
