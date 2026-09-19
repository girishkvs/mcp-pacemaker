import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, sameDigests, channelFor } from './policy.mjs';
import { readAuthenticatedStageCapture } from './stage-capture-hosted.mjs';

export async function verifyStaged({ record, view, bytes, bundleBytes, receiptBytes, artifactId,
  currentTags, verifyBundle, readers }) {
  const capture = await readAuthenticatedStageCapture({
    record, artifactId, receiptBytes, bundleBytes, readers,
  });
  const bundle = JSON.parse(bundleBytes.toString('utf8'));
  assert.ok(['submitted-awaiting-owner-verification', 'owner-reconciled-existing-stage'].includes(record.status));
  assert.equal(view.id, record.stageId, 'Owner stage readback does not match reconciled stage ID');
  assert.equal(view.packageName, POLICY.name);
  assert.equal(view.version, record.version);
  assert.equal(view.tag, channelFor(record.version));
  assert.equal(view.shasum, createHash('sha1').update(bytes).digest('hex'));
  sameDigests(digest(bytes), record.artifact);
  assert.deepEqual(currentTags, record.ownerPreflight.expectedDistTags, 'Channel race: new owner approval required');
  assert.equal(bundle?.dsseEnvelope?.payloadType, 'application/vnd.in-toto+json');
  const payload = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
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
  assert.equal(payload.predicate.runDetails.builder.id, 'https://github.com/actions/runner/github-hosted');
  assert.equal(payload.predicate.runDetails.metadata.invocationId,
    `https://github.com/${POLICY.repository}/actions/runs/${record.workflow.runId}/attempts/${record.workflow.attempt}`);
  const identity = `https://github.com/${POLICY.repository}/${POLICY.workflow}@${record.source.ref}`;
  const escaped = identity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Hash comparison above does not authenticate anything. The verifier must verify the actual bundle.
  await verifyBundle(bundle, {
    certificateIssuer: 'https://token.actions.githubusercontent.com',
    certificateIdentityURI: `^${escaped}$`, ctLogThreshold: 1, tlogThreshold: 1,
  });
  return {
    stageId: record.stageId, artifact: digest(bytes), stagedProvenance: 'verified',
    verifier: 'sigstore@5.0.0 (npm@12.0.2)', ownerPublicationApproval: 'not-performed',
    registrySignatures: 'pending-publication',
    capture,
  };
}

async function main() {
  assert.equal(process.argv.length, 9,
    'Usage: node verify-staged.mjs stage-record.json stage-view.json downloaded.tgz bundle.sigstore current-tags.json capture-receipt.json github-artifact-id');
  assert.equal(process.versions.node, POLICY.node);
  const cli = resolve(process.env.NPM_PUBLICATION_CLI ?? '');
  const pkg = JSON.parse(readFileSync(resolve(dirname(cli), '../package.json'), 'utf8'));
  assert.equal(pkg.name, 'npm');
  assert.equal(pkg.version, POLICY.npm);
  const require = createRequire(cli);
  assert.equal(require('sigstore/package.json').version, '5.0.0');
  const read = path => JSON.parse(readFileSync(path, 'utf8'));
  const [recordPath, viewPath, tarball, bundlePath, tagsPath, receiptPath, artifactId] = process.argv.slice(2);
  const result = await verifyStaged({
    record: read(recordPath), view: read(viewPath), bytes: readFileSync(tarball),
    bundleBytes: readFileSync(bundlePath), receiptBytes: readFileSync(receiptPath), artifactId,
    currentTags: read(tagsPath), verifyBundle: require('sigstore').verify,
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(`Staged verification stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
