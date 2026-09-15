import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { POLICY, digest, publicationTagName } from './policy.mjs';

export const PROVENANCE_SOURCE_SHA256 = 'ee9b1bc8e3f636fbaf5138a3e183ce3c6d42bb5dd57ab004578e534dd08da46b';

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
