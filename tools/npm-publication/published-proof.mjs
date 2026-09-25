import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { POLICY, channelFor, digest, exactKeys, sameDigests } from './policy.mjs';
import { verifyProvenance } from './provenance.mjs';

const SLSA = 'https://slsa.dev/provenance/v1';
export const JSON_LIMIT = 16 * 1024 * 1024;
export const TARBALL_LIMIT = 128 * 1024 * 1024;

export function registryResource(value) {
  assert.equal(typeof value, 'string');
  assert.ok(value.length <= 4096 &&
    !/[\u0000-\u0020\\]/.test(value));
  assert.match(value, /^https:\/\/registry\.npmjs\.org(?::443)?\//);
  const url = new URL(value);
  assert.equal(url.origin, 'https://registry.npmjs.org');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  return url.href;
}

export async function anonymousBytes(url, limit, fetcher = fetch) {
  const address = registryResource(url);
  assert.ok(Number.isSafeInteger(limit) &&
    limit > 0 &&
    limit <= TARBALL_LIMIT);
  const response = await fetcher(address, {
    method: 'GET', redirect: 'error', cache: 'no-store',
    headers: { accept: '*/*', 'cache-control': 'no-cache' },
    signal: AbortSignal.timeout(30_000),
  });
  const reader = response.body?.getReader();
  try {
    assert.equal(response.status, 200, 'Anonymous registry read failed; publication is not rolled back');
    if (response.url) assert.equal(response.url, address);
    const length = response.headers.get('content-length');
    if (length !== null) {
      assert.match(length, /^\d+$/);
      assert.ok(Number(length) <= limit);
    }
    assert.ok(reader, 'Missing registry response body');
    const chunks = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      assert.ok(size <= limit, 'Oversized registry response');
      chunks.push(Buffer.from(value));
    }
    assert.ok(size > 0);
    return Buffer.concat(chunks, size);
  } finally {
    if (reader) {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
}

export function publishedMetadata(packument, version, record, expectedTags) {
  assert.equal(record.name, POLICY.name);
  const channel = channelFor(record.version);
  assert.equal(expectedTags[channel], record.version);
  assert.equal(packument.name, record.name);
  assert.deepEqual(packument['dist-tags'], expectedTags, 'Published channel differs from the approved channel state');
  assert.deepEqual(packument.versions?.[record.version], version, 'Version metadata differs from the packument');
  assert.equal(version.name, record.name);
  assert.equal(version.version, record.version);
  assert.equal(version.deprecated, undefined, 'Published candidate is deprecated');
  assert.equal(version.dist?.integrity, record.artifact.integrity);
  assert.match(version.dist.shasum ?? '', /^[a-f0-9]{40}$/);
  const tarball = `${POLICY.registry}${record.name}/-/${record.name}-${record.version}.tgz`;
  assert.equal(version.dist.tarball, tarball);
  registryResource(tarball);
  assert.ok(Array.isArray(version.dist.signatures) &&
    version.dist.signatures.length > 0, 'Target package has no registry signature');
  for (const signature of version.dist.signatures) {
    assert.ok(typeof signature.keyid === 'string' &&
      signature.keyid.length > 0 &&
      typeof signature.sig === 'string' &&
      signature.sig.length > 0, 'Incomplete registry signature');
  }
  const attestations = registryResource(version.dist.attestations?.url);
  return { tarball, attestations };
}

export function attachedProvenance(document) {
  assert.ok(Array.isArray(document?.attestations) &&
    document.attestations.length > 0 &&
    document.attestations.length <= 10, 'Missing or excessive attached attestations');
  for (const entry of document.attestations) {
    assert.ok(typeof entry.predicateType === 'string' &&
      entry.bundle &&
      typeof entry.bundle === 'object');
  }
  const matching = document.attestations.filter(entry => entry.predicateType === SLSA);
  assert.equal(matching.length, 1, 'Exactly one attached SLSA v1 provenance bundle is required');
  return matching[0].bundle;
}

export function auditCoverage(report, version, document, record) {
  // npm12.0.2 VerifySignatures.run emits these arrays, not a verified-count field.
  exactKeys(report, ['invalid', 'missing', 'verified'], 'npm12 audit signatures JSON');
  assert.deepEqual(report.invalid, [], 'Registry signature/attestation verification failed');
  assert.deepEqual(report.missing, [], 'Installed registry dependencies have missing signatures');
  assert.ok(Array.isArray(report.verified) &&
    report.verified.length <= 10000);
  const targets = report.verified.filter(entry => entry.name === record.name);
  assert.equal(targets.length, 1, 'Audit did not cover exactly the installed target package');
  const target = targets[0];
  assert.equal(target.version, record.version);
  assert.equal(target.location, `node_modules/${record.name}`);
  assert.equal(target.registry, POLICY.registry);
  assert.deepEqual(target.attestations, version.dist.attestations);
  assert.deepEqual(target.attestationBundles, document.attestations,
    'Audit attestation coverage differs from the actual attached bundles');
  attachedProvenance({ attestations: target.attestationBundles });
  return { name: target.name, version: target.version, location: target.location,
    registry: target.registry, verifiedAttestationPackages: report.verified.length };
}

export function registrySignatures(version, keys, publishedAt) {
  assert.ok(Array.isArray(keys?.keys) &&
    keys.keys.length > 0 &&
    keys.keys.length <= 100);
  const time = Date.parse(publishedAt);
  assert.ok(Number.isFinite(time) &&
    time <= Date.now());
  const verified = [];
  for (const signature of version.dist.signatures) {
    const matches = keys.keys.filter(key => key.keyid === signature.keyid);
    assert.equal(matches.length, 1, 'Missing or ambiguous registry signing key');
    const key = matches[0];
    if (key.expires) {
      assert.ok(Number.isFinite(Date.parse(key.expires)) &&
        time < Date.parse(key.expires), 'Registry signing key expired before publication');
    }
    const bytes = Buffer.from(signature.sig, 'base64');
    assert.equal(bytes.toString('base64'), signature.sig);
    const publicKey = createPublicKey({ key: Buffer.from(key.key, 'base64'), type: 'spki', format: 'der' });
    // This is the registry-signature message verified by pinned pacote, independently of provenance.
    const message = `${version.name}@${version.version}:${version.dist.integrity}`;
    assert.equal(verify('sha256', Buffer.from(message), publicKey, bytes), true,
      'Published target registry signature is invalid');
    verified.push(key.keyid);
  }
  assert.ok(verified.length > 0);
  return verified;
}

export async function verifyPublishedEvidence({
  record, packument, version, tarball, attestations, audit, keys, expectedTags, expectedBundle, verifyBundle, cache,
}) {
  const urls = publishedMetadata(packument, version, record, expectedTags);
  sameDigests(digest(tarball), record.artifact);
  assert.equal(createHash('sha1').update(tarball).digest('hex'), version.dist.shasum);
  const keyIds = registrySignatures(version, keys, packument.time?.[record.version]);
  const bundle = attachedProvenance(attestations);
  if (expectedBundle) {
    assert.deepEqual(bundle, expectedBundle, 'Attached provenance differs from the approved signing bundle');
  }
  await verifyProvenance({ record, bundle, verifyBundle, cache });
  const coverage = auditCoverage(audit, version, attestations, record);
  return {
    registry: POLICY.registry, name: record.name, version: record.version, channel: channelFor(record.version),
    artifact: digest(tarball), metadataSha256: digest(Buffer.from(JSON.stringify(version))).sha256,
    attestationsUrl: urls.attestations,
    attestationsSha256: digest(Buffer.from(JSON.stringify(attestations))).sha256,
    auditSha256: digest(Buffer.from(JSON.stringify(audit))).sha256,
    auditCoverage: coverage, registrySignatures: 'verified',
    registryKeyIds: keyIds, registryKeysSha256: digest(Buffer.from(JSON.stringify(keys))).sha256,
    publishedProvenance: 'cryptographically-verified', signingWorkflow: record.workflow, source: record.source,
  };
}
