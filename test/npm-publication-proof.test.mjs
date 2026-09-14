import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { POLICY, digest } from '../tools/npm-publication/policy.mjs';
import { extractTarball, inspectTarball } from '../tools/npm-publication/tarball.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import { verifyStaged } from '../tools/npm-publication/verify-staged.mjs';

function fixture() {
  const bytes = Buffer.from('synthetic proof fixture, not a real signed npm package');
  const source = { ref: 'refs/tags/v1.3.1', commit: 'a'.repeat(40) };
  const record = {
    status: 'submitted-awaiting-owner-verification', stageId: 'b24a7be2-f726-407a-8ae3-367189f1f236',
    version: '1.3.1', source, artifact: digest(bytes), workflow: { runId: '42', attempt: 1 },
    ownerPreflight: { expectedDistTags: { latest: '2.0.1' } },
  };
  const view = { id: record.stageId, packageName: POLICY.name, version: '1.3.1', tag: 'legacy',
    shasum: createHash('sha1').update(bytes).digest('hex') };
  const payload = {
    _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: 'pkg:npm/mcp-pacemaker@1.3.1', digest: { sha512: record.artifact.sha512 } }],
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: {
          ref: source.ref, repository: `https://github.com/${POLICY.repository}`, path: POLICY.workflow,
        } },
        internalParameters: { github: { event_name: 'workflow_dispatch' } },
        resolvedDependencies: [{ uri: `git+https://github.com/${POLICY.repository}@${source.ref}`,
          digest: { gitCommit: source.commit } }],
      },
      runDetails: {
        builder: { id: 'https://github.com/actions/runner/github-hosted' },
        metadata: { invocationId: `https://github.com/${POLICY.repository}/actions/runs/42/attempts/1` },
      },
    },
  };
  const bundle = value => ({ dsseEnvelope: {
    payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(value)).toString('base64'),
  } });
  return { bytes, record, view, payload, bundle, currentTags: { latest: '2.0.1' } };
}

test('T12/T44: hashes alone never complete provenance verification or authorize owner publication', async () => {
  const f = fixture();
  let called = false;
  const result = await verifyStaged({ ...f, bundle: f.bundle(f.payload), verifyBundle: async (bundle, options) => {
    called = true;
    assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
    assert.equal(options.tlogThreshold, 1);
    assert.equal(options.ctLogThreshold, 1);
    assert.ok(new RegExp(options.certificateIdentityURI).test(
      `https://github.com/${POLICY.repository}/${POLICY.workflow}@${f.record.source.ref}`));
    assert.ok(!new RegExp(options.certificateIdentityURI).test(
      `https://github.com/${POLICY.repository}/${POLICY.workflow}@${f.record.source.ref}-evil`));
  } });
  assert.equal(called, true, 'Controlled verifier boundary must be exercised');
  assert.equal(result.registrySignatures, 'pending-publication');
  assert.equal(result.ownerPublicationApproval, 'not-performed');
});

test('T44: cryptographic verifier failure blocks matching hashes and matching metadata', async () => {
  const f = fixture();
  await assert.rejects(() => verifyStaged({ ...f, bundle: f.bundle(f.payload), verifyBundle: async () => {
    throw new Error('controlled invalid signature/chain/transparency evidence');
  } }), /invalid signature/);
});

test('T44: absent proof and wrong subject/source/workflow/run fail before cryptographic verifier', async () => {
  const f = fixture();
  const variants = [
    value => { value.subject[0].digest.sha512 = 'f'.repeat(128); },
    value => { value.subject[0].name = 'pkg:npm/mcp-pacemaker@2.0.1'; },
    value => { value.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'b'.repeat(40); },
    value => { value.predicate.buildDefinition.externalParameters.workflow.ref = 'refs/heads/main'; },
    value => { value.predicate.runDetails.builder.id = 'https://github.com/actions/runner/self-hosted'; },
    value => { value.predicate.runDetails.metadata.invocationId += '0'; },
  ];
  let calls = 0;
  for (const mutate of variants) {
    const payload = structuredClone(f.payload);
    mutate(payload);
    await assert.rejects(() => verifyStaged({ ...f, bundle: f.bundle(payload),
      verifyBundle: async () => { calls++; } }));
  }
  await assert.rejects(() => verifyStaged({ ...f, bundle: null, verifyBundle: async () => { calls++; } }));
  assert.equal(calls, 0);
});

test('T12/T19: wrong stage ID, immutable stage tag or changed channel blocks owner-verification result', async () => {
  const f = fixture();
  for (const delta of [{ view: { ...f.view, id: 'other' } }, { view: { ...f.view, tag: 'latest' } },
    { currentTags: { latest: '2.0.2' } }]) {
    await assert.rejects(() => verifyStaged({ ...f, ...delta, bundle: f.bundle(f.payload),
      verifyBundle: async () => { throw new Error('should not reach verifier'); } }));
  }
});

function tarball(entries) {
  const pieces = [];
  for (const [path, data, type = '0', mode = 0o644] of entries) {
    const content = Buffer.from(data);
    const header = Buffer.alloc(512);
    const field = (start, size, value) => header.write(value, start, size, 'ascii');
    const octal = (start, size, value) => field(start, size, `${value.toString(8).padStart(size - 1, '0')}\0`);
    field(0, 100, path);
    octal(100, 8, mode);
    octal(108, 8, 0);
    octal(116, 8, 0);
    octal(124, 12, content.length);
    octal(136, 12, 0);
    field(148, 8, '        ');
    field(156, 1, type);
    field(257, 6, 'ustar\0');
    octal(148, 8, [...header].reduce((sum, value) => sum + value, 0));
    pieces.push(header, content, Buffer.alloc((512 - content.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...pieces, Buffer.alloc(1024)]));
}

function packageEntries() {
  const pkg = {
    name: POLICY.name, version: '1.3.1',
    repository: { url: `git+https://github.com/${POLICY.repository}.git` },
    dependencies: { 'smol-toml': '^1.8.0' }, files: ['bin/', 'ui/dist/', 'LICENSE', 'THIRD_PARTY_NOTICES.txt'],
  };
  return [['package/package.json', JSON.stringify(pkg)], ['package/bin/cli.mjs', 'cli'],
    ['package/bin/mcp-bridge.mjs', 'bridge'], ['package/ui/dist/index.html', 'ui'], ['package/LICENSE', 'license'],
    ['package/THIRD_PARTY_NOTICES.txt', 'synthetic notice presence fixture'],
    ['package/ui/dist/THIRD_PARTY_NOTICES.txt', 'synthetic notice presence fixture'],
    ['package/ui/dist/third-party-manifest.json', '{"syntheticPresenceFixture":true}']];
}

test('T01/T23: actual tar headers, metadata, allowlist, modes and file hashes are inspected', () => {
  const result = inspectTarball(tarball(packageEntries()), { version: '1.3.1' });
  assert.equal(result.files.length, 8);
  assert.equal(result.files.find(file => file.path === 'bin/cli.mjs').sha256, digest(Buffer.from('cli')).sha256);
  assert.throws(() => inspectTarball(tarball(packageEntries().slice(1)), { version: '1.3.1' }), /package.json/);
  assert.throws(() => inspectTarball(tarball(packageEntries().filter(([path]) =>
    path !== 'package/ui/dist/index.html')), { version: '1.3.1' }), /Missing runtime/);
});

test('T24: both notice files and the UI manifest must be present and nonempty in actual tar bytes', () => {
  for (const required of ['THIRD_PARTY_NOTICES.txt', 'ui/dist/THIRD_PARTY_NOTICES.txt',
    'ui/dist/third-party-manifest.json']) {
    const path = `package/${required}`;
    const missing = packageEntries().filter(([name]) => name !== path);
    assert.throws(() => inspectTarball(tarball(missing), { version: '1.3.1' }), /Missing runtime or notice file/);
    const empty = packageEntries().map(entry => entry[0] === path ? [path, ''] : entry);
    assert.throws(() => inspectTarball(tarball(empty), { version: '1.3.1' }), /Empty runtime or notice file/);
  }
});

test('T22/T23: unsafe tar paths, links, modes, duplicate files and forbidden payload fail closed', () => {
  for (const entry of [['package/../escape', 'x'], ['package/bin/link', 'x', '2'],
    ['package/bin/executable', 'x', '0', 0o4777], ['package/bin/cli.mjs', 'duplicate'],
    ['package/bin/CLI.mjs', 'collision'], ['package/bin/.npmrc', 'synthetic'],
    ['package/other-file', 'outside allowlist']]) {
    assert.throws(() => inspectTarball(tarball([...packageEntries(), entry]), { version: '1.3.1' }));
  }
  assert.throws(() => inspectTarball(Buffer.from('not gzip'), { version: '1.3.1' }));
});

test('Extraction validates the entire payload before writing and never overwrites an existing tree', () => {
  const owned = ownedDirectory();
  try {
    const destination = join(owned.dir, 'package');
    mkdirSync(destination);
    const bytes = tarball(packageEntries());
    const bad = tarball([...packageEntries(), ['package/../escape', 'unsafe']]);
    assert.throws(() => extractTarball(bad, { version: '1.3.1' }, destination), /traversal/);
    assert.deepEqual(readdirSync(destination), []);
    const result = extractTarball(bytes, { version: '1.3.1' }, destination);
    assert.equal(result.files.length, 8);
    assert.equal(readFileSync(join(destination, 'bin/cli.mjs'), 'utf8'), 'cli');
    assert.throws(() => extractTarball(bytes, { version: '1.3.1' }, destination), /must be empty/);
  } finally {
    removeOwnedDirectory(owned);
  }
});
