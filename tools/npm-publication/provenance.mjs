import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, publicationTagName } from './policy.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../compatibility/fixtures.mjs';
import { stageProofEnvironment } from './local-stage-check.mjs';
import { validateStageLoader } from './stage-loader.mjs';
import { isCanonicalUnsigned } from './local-regression.mjs';

export const PROVENANCE_SOURCE_SHA256 = 'ee9b1bc8e3f636fbaf5138a3e183ce3c6d42bb5dd57ab004578e534dd08da46b';
export const PEER_PROOF_LIMITS = Object.freeze({
  bytes: 2 * 1024 * 1024, requestMs: 30_000, verificationMs: 60_000, requests: 32,
});

export function npmProvenance(cli) {
  assert.ok(typeof cli === 'string' &&
    isAbsolute(cli), 'An absolute pinned npm CLI path is required');
  const entry = realpathSync.native(cli);
  const pkg = JSON.parse(readFileSync(resolve(dirname(entry), '../package.json'), 'utf8'));
  assert.equal(pkg.name, 'npm');
  assert.equal(pkg.version, POLICY.npm);
  const require = createRequire(entry);
  assert.equal(require('sigstore/package.json').version, '5.0.0');
  assert.equal(require('libnpmpublish/package.json').version, '12.0.0');
  const path = require.resolve('libnpmpublish/lib/provenance.js');
  assert.equal(digest(readFileSync(path)).sha256, PROVENANCE_SOURCE_SHA256,
    'Installed provenance code differs from reviewed npm12.0.2 source');
  return {
    verifyBundle: require('sigstore').verify,
    generate: (...args) => require(path).generateProvenance(...args),
    subject: (name, version, sha512) => {
      const npa = require('npm-package-arg');
      return { name: npa.toPurl(npa.resolve(name, version)), digest: { sha512 } };
    },
  };
}

export async function verifyProvenance({ record, bundle, verifyBundle, cache }) {
  publicationTagName(record.source.ref, record.version);
  assert.equal(record.workflow.attempt, 1, 'Only the original signing/staging attempt is accepted');
  assert.match(String(record.workflow.runId), /^[1-9][0-9]*$/);
  assert.equal(bundle?.dsseEnvelope?.payloadType, 'application/vnd.in-toto+json');
  const encoded = bundle.dsseEnvelope.payload;
  assert.ok(typeof encoded === 'string' &&
    encoded.length > 0 &&
    encoded.length <= 1024 * 1024, 'Missing or oversized provenance payload');
  const decoded = Buffer.from(encoded, 'base64');
  assert.equal(decoded.toString('base64'), encoded, 'Noncanonical provenance encoding');
  const payload = JSON.parse(decoded.toString('utf8'));
  assert.equal(payload._type, 'https://in-toto.io/Statement/v1');
  assert.equal(payload.predicateType, 'https://slsa.dev/provenance/v1');
  assert.deepEqual(payload.subject, [{
    name: `pkg:npm/${POLICY.name}@${record.version}`, digest: { sha512: record.artifact.sha512 },
  }]);
  const build = payload.predicate.buildDefinition;
  assert.equal(build.buildType, 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1');
  assert.deepEqual(build.externalParameters.workflow, {
    ref: record.source.ref, repository: `https://github.com/${POLICY.repository}`, path: POLICY.workflow,
  });
  assert.deepEqual(build.resolvedDependencies, [{
    uri: `git+https://github.com/${POLICY.repository}@${record.source.ref}`,
    digest: { gitCommit: record.source.commit },
  }]);
  assert.equal(build.internalParameters.github.event_name, 'workflow_dispatch');
  if (record.workflow.repositoryId !== undefined) {
    assert.equal(build.internalParameters.github.repository_id, record.workflow.repositoryId);
    assert.equal(build.internalParameters.github.repository_owner_id, record.workflow.ownerId);
  }
  assert.equal(payload.predicate.runDetails.builder.id, 'https://github.com/actions/runner/github-hosted');
  assert.equal(payload.predicate.runDetails.metadata.invocationId,
    `https://github.com/${POLICY.repository}/actions/runs/${record.workflow.runId}/attempts/1`);
  const identity = `https://github.com/${POLICY.repository}/${POLICY.workflow}@${record.source.ref}`;
  const escaped = identity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  assert.equal(typeof verifyBundle, 'function', 'A real cryptographic verifier is required');
  // These hashes/claims do not authenticate the bundle. Signature, chain, issuer, SAN and logs must verify.
  await verifyBundle(bundle, {
    certificateIssuer: 'https://token.actions.githubusercontent.com',
    certificateIdentityURI: `^${escaped}$`, ctLogThreshold: 1, tlogThreshold: 1,
    ...(cache ? { tufCachePath: cache, retry: { retries: 0 } } : {}),
  });
}

export async function boundedAnonymousBytes(url, limit, fetcher, timeoutMs, notFound) {
  assert.ok(Number.isSafeInteger(limit) &&
    limit > 0 &&
    limit <= 32 * 1024 * 1024, 'Invalid anonymous read limit');
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= PEER_PROOF_LIMITS.requestMs, 'Invalid anonymous read deadline');
  const controller = new AbortController();
  let timer;
  let response;
  const operation = async () => {
    response = await fetcher(url, {
      method: 'GET', headers: { accept: 'application/json, application/octet-stream' },
      credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
    });
    controller.signal.throwIfAborted();
    assert.notEqual(response.redirected, true, 'Published peer redirect forbidden');
    if (response.url) assert.equal(response.url, url, 'Published peer response URL changed');
    if (response.status === 404 &&
        notFound) throw notFound();
    assert.equal(response.status, 200, 'Published peer read failed; no fallback');
    const length = response.headers.get('content-length');
    if (length !== null) {
      assert.match(length, /^(?:0|[1-9][0-9]{0,8})$/);
      assert.ok(Number(length) <= limit, 'Published peer response exceeds limit');
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      controller.signal.throwIfAborted();
      size += chunk.length;
      assert.ok(size <= limit, 'Published peer response exceeds limit');
      chunks.push(Buffer.from(chunk));
    }
    controller.signal.throwIfAborted();
    return Buffer.concat(chunks);
  };
  try {
    return await Promise.race([operation(), new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error('Published peer read deadline exceeded'));
      }, timeoutMs);
    })]);
  } catch (error) {
    controller.abort();
    if (!response?.body?.locked) response?.body?.cancel?.().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function peerTufUrl(url) {
  assert.equal(typeof url, 'string');
  const origin = 'https://tuf-repo-cdn.sigstore.dev';
  assert.ok(url.startsWith(`${origin}/`), 'Unapproved peer TUF origin');
  const segments = url.slice(origin.length + 1).split('/');
  const parts = segments.at(-1).split('.');
  const unversionedMetadata = parts.length === 2 &&
    ['timestamp', 'snapshot', 'targets'].includes(parts[0]);
  const versionedMetadata = parts.length === 3 &&
    ['root', 'snapshot', 'targets'].includes(parts[1]) &&
    isCanonicalUnsigned(parts[0]) &&
    Number(parts[0]) > 0;
  const metadata = segments.length === 1 &&
    (unversionedMetadata || versionedMetadata);
  const hash = parts[0];
  const hashedTarget = parts.length === 3 &&
    hash.length === 64 &&
    [...hash].every(digit => '0123456789abcdef'.includes(digit));
  const target = segments.length === 2 &&
    segments[0] === 'targets' &&
    (parts.length === 2 || hashedTarget) &&
    parts.at(-2) === 'trusted_root';
  assert.ok(parts.at(-1) === 'json' &&
    (metadata || target), 'Unapproved peer TUF resource');
  assert.equal(new URL(url).href, url, 'Noncanonical peer TUF URL');
  return url;
}

export class PeerTufTransport {
  constructor(httpError, fetcher = (...args) => globalThis.fetch(...args), timeoutMs = PEER_PROOF_LIMITS.requestMs) {
    assert.ok(Number.isSafeInteger(timeoutMs) &&
      timeoutMs > 0 &&
      timeoutMs <= PEER_PROOF_LIMITS.requestMs);
    this.httpError = httpError;
    this.fetcher = fetcher;
    this.timeoutMs = timeoutMs;
    this.requests = [];
  }

  async fetch(url) {
    peerTufUrl(url);
    assert.ok(this.requests.length < PEER_PROOF_LIMITS.requests, 'Peer TUF request budget exceeded');
    this.requests.push(url);
    const bytes = await boundedAnonymousBytes(url, PEER_PROOF_LIMITS.bytes, this.fetcher, this.timeoutMs,
      () => new this.httpError('Peer TUF resource not found', 404));
    return new Response(bytes).body;
  }
}

export function verifyRegistrySource({ record, bundle, cli, env = process.env, execute = spawnSync }) {
  assert.equal(process.versions.node, POLICY.node, 'Peer cryptography requires the pinned publisher Node');
  assert.ok(typeof cli === 'string' &&
    isAbsolute(cli), 'Pinned npm CLI is required for peer cryptography');
  const input = JSON.stringify({ record, bundle });
  assert.ok(Buffer.byteLength(input) <= PEER_PROOF_LIMITS.bytes, 'Peer proof input exceeds limit');
  const owned = ownedDirectory();
  let failure;
  try {
    const home = realpathSync.native(owned.dir);
    const result = execute(process.execPath, [fileURLToPath(import.meta.url), '--registry-peer', cli], {
      input, cwd: home, env: stageProofEnvironment(env, home, process.execPath),
      encoding: 'utf8', shell: false, windowsHide: true, timeout: PEER_PROOF_LIMITS.verificationMs,
      killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
    });
    assert.equal(result.error, undefined, 'Pinned peer verifier failed or timed out; no fallback');
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, `Pinned peer verifier failed: ${(result.stderr ?? '').slice(0, 2048)}`);
    const proof = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(proof).sort(), ['inputSha256', 'node', 'npm', 'requests', 'status']);
    assert.equal(proof.status, 'cryptographically-verified');
    assert.equal(proof.inputSha256, digest(Buffer.from(input)).sha256);
    assert.equal(proof.node, POLICY.node);
    assert.equal(proof.npm, POLICY.npm);
    assert.ok(Array.isArray(proof.requests) &&
      proof.requests.length > 0 &&
      proof.requests.length <= PEER_PROOF_LIMITS.requests);
    for (const url of proof.requests) peerTufUrl(url);
    return proof;
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    try { removeOwnedDirectory(owned); }
    catch (cleanup) {
      if (failure) throw new AggregateError([failure, cleanup],
        `${failure.message}; owned peer verifier cleanup failed`);
      throw cleanup;
    }
  }
}

export async function registrySourceMain(args = process.argv.slice(2)) {
  assert.deepEqual(args.slice(0, 1), ['--registry-peer']);
  assert.equal(args.length, 2);
  assert.equal(process.versions.node, POLICY.node);
  const home = realpathSync.native(process.env.HOME);
  assert.equal(process.cwd(), home);
  assert.deepEqual(readdirSync(home), [], 'Peer verifier requires a fresh owned home');
  for (const key of ['USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR']) {
    assert.equal(process.env[key], home);
  }
  for (const key of Object.keys(process.env)) {
    assert.doesNotMatch(key, /^(?:NODE_OPTIONS|NODE_AUTH_TOKEN|NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN|NPM_ID_TOKEN|SIGSTORE_ID_TOKEN|ACTIONS_ID_TOKEN.*|npm_config_.*)$/i);
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    assert.ok(length <= PEER_PROOF_LIMITS.bytes, 'Peer proof input exceeds limit');
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks);
  const context = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input));
  assert.deepEqual(Object.keys(context).sort(), ['bundle', 'record']);
  const { root, require } = validateStageLoader(args[1]);
  const { DefaultFetcher } = require(join(root, 'node_modules/tuf-js/dist/fetcher.js'));
  const { DownloadHTTPError } = require(join(root, 'node_modules/tuf-js/dist/error.js'));
  const fetcher = globalThis.fetch;
  const transport = new PeerTufTransport(DownloadHTTPError, (...values) => fetcher(...values));
  const original = DefaultFetcher.prototype.fetch;
  // This fresh, credential-free child is the only process whose SDK transport is changed.
  DefaultFetcher.prototype.fetch = url => transport.fetch(url);
  globalThis.fetch = () => { throw new Error('Peer verifier network must use the bounded TUF transport'); };
  try {
    const sdk = npmProvenance(args[1]);
    await verifyProvenance({ ...context, cache: join(home, 'tuf'),
      verifyBundle: (bundle, options) => sdk.verifyBundle(bundle, {
        ...options, timeout: PEER_PROOF_LIMITS.requestMs, retry: { retries: 0 },
      }) });
    assert.ok(transport.requests.length > 0, 'Peer proof must refresh TUF trust in its owned cache');
    console.log(JSON.stringify({ status: 'cryptographically-verified', inputSha256: digest(input).sha256,
      node: POLICY.node, npm: POLICY.npm, requests: transport.requests }));
  } finally {
    DefaultFetcher.prototype.fetch = original;
    globalThis.fetch = fetcher;
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  registrySourceMain().catch(error => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}
