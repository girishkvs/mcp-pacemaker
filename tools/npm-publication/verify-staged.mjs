import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, digest, sameDigests, channelFor } from './policy.mjs';
import { verifyProvenance } from './provenance.mjs';

export async function verifyStaged({ record, view, bytes, bundle, currentTags, verifyBundle }) {
  assert.ok(['submitted-awaiting-owner-verification', 'owner-reconciled-existing-stage'].includes(record.status));
  assert.equal(view.id, record.stageId, 'Owner stage readback does not match reconciled stage ID');
  assert.equal(view.packageName, POLICY.name);
  assert.equal(view.version, record.version);
  assert.equal(view.tag, channelFor(record.version));
  assert.equal(view.shasum, createHash('sha1').update(bytes).digest('hex'));
  sameDigests(digest(bytes), record.artifact);
  assert.deepEqual(currentTags, record.ownerPreflight.expectedDistTags, 'Channel race: new owner approval required');
  await verifyProvenance({ record, bundle, verifyBundle });
  return {
    stageId: record.stageId, artifact: digest(bytes), stagedProvenance: 'verified',
    verifier: 'sigstore@5.0.0 (npm@12.0.2)', ownerPublicationApproval: 'not-performed',
    registrySignatures: 'pending-publication',
  };
}

async function main() {
  assert.equal(process.argv.length, 7,
    'Usage: node verify-staged.mjs stage-record.json stage-view.json downloaded.tgz bundle.sigstore current-tags.json');
  assert.equal(process.versions.node, POLICY.node);
  const cli = resolve(process.env.NPM_PUBLICATION_CLI ?? '');
  const pkg = JSON.parse(readFileSync(resolve(dirname(cli), '../package.json'), 'utf8'));
  assert.equal(pkg.name, 'npm');
  assert.equal(pkg.version, POLICY.npm);
  const require = createRequire(cli);
  assert.equal(require('sigstore/package.json').version, '5.0.0');
  const read = path => JSON.parse(readFileSync(path, 'utf8'));
  const [recordPath, viewPath, tarball, bundlePath, tagsPath] = process.argv.slice(2);
  const result = await verifyStaged({
    record: read(recordPath), view: read(viewPath), bytes: readFileSync(tarball),
    bundle: read(bundlePath), currentTags: read(tagsPath), verifyBundle: require('sigstore').verify,
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
