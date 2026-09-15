import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync, linkSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { POLICY, REQUIRED_GATES, channelFor, digest, validateApproval } from '../tools/npm-publication/policy.mjs';
import { extractTarball, inspectTarball } from '../tools/npm-publication/tarball.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import { verifyStaged } from '../tools/npm-publication/verify-staged.mjs';
import { BOOTSTRAP_FILES, validateBootstrapContext, validateCandidate, signBootstrapOnce,
  verifyBootstrap } from '../tools/npm-publication/bootstrap.mjs';
import { readAbsentRegistry } from '../tools/npm-publication/bootstrap-readers.mjs';
import { readBootstrapDirectory, writeVerificationReceipt } from '../tools/npm-publication/verify-bootstrap.mjs';
import { bootstrapEnvironment } from '../tools/npm-publication/run.mjs';
import { validateOwnerContext, validateOwnerKey, ownerBinding, ownerEnvironment, officialWebsiteUrl,
  officialRegistryUrl, confirmedPublicationChallenge, publishOwnerOnce, validateOwnerReply } from '../tools/npm-publication/owner-bootstrap.mjs';
import { registryTransport, createOwnerSdk } from '../tools/npm-publication/owner-sdk.mjs';
import { ownerState, atomicJson, readJsonFile } from '../tools/npm-publication/owner-state.mjs';
import { validateVerificationRequest } from '../tools/npm-publication/publish-bootstrap.mjs';
import { verificationRequest } from '../tools/npm-publication/owner-process.mjs';
import { EventEmitter } from 'node:events';
import './helpers/npm-owner-auth-envelope-checks.mjs';
import { registryResource, anonymousBytes, verifyPublishedEvidence, auditCoverage } from '../tools/npm-publication/published-proof.mjs';
import { registryInstallArguments, publishedConsumerGraph, exactInstalledFiles, withPublishedConsumer,
  requireAnonymousHosted, smokePublishedConsumer } from '../tools/npm-publication/published-consumer.mjs';
import { acceptPublished, completedOwner, validateAcceptanceInput } from '../tools/npm-publication/post-publication.mjs';

function fixture(version = '1.3.1', namespace = '') {
  const bytes = Buffer.from('synthetic proof fixture, not a real signed npm package');
  const source = { ref: `refs/tags/${namespace}v${version}`, commit: 'a'.repeat(40) };
  const record = {
    status: 'submitted-awaiting-owner-verification', stageId: 'b24a7be2-f726-407a-8ae3-367189f1f236',
    version, source, artifact: digest(bytes), workflow: { runId: '42', attempt: 1 },
    ownerPreflight: { expectedDistTags: { latest: '2.0.1' } },
  };
  const view = { id: record.stageId, packageName: POLICY.name, version, tag: channelFor(version),
    shasum: createHash('sha1').update(bytes).digest('hex') };
  const payload = {
    _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: `pkg:npm/mcp-pacemaker@${version}`, digest: { sha512: record.artifact.sha512 } }],
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

for (const version of ['1.3.1', '2.0.1']) {
  test(`staged proof retains the complete npm publication ref for ${version}`, async () => {
    const f = fixture(version, 'npm/');
    let calls = 0;
    const verifyBundle = async (_bundle, options) => {
      calls++;
      const identity = new RegExp(options.certificateIdentityURI);
      assert.ok(identity.test(`https://github.com/${POLICY.repository}/${POLICY.workflow}@${f.record.source.ref}`));
      assert.ok(!identity.test(`https://github.com/${POLICY.repository}/${POLICY.workflow}@refs/tags/v${version}`));
    };
    await verifyStaged({ ...f, bundle: f.bundle(f.payload), verifyBundle });
    assert.equal(calls, 1);
    const differentRef = structuredClone(f.payload);
    differentRef.predicate.buildDefinition.externalParameters.workflow.ref = `refs/tags/v${version}`;
    await assert.rejects(() => verifyStaged({ ...f, bundle: f.bundle(differentRef), verifyBundle }));
    assert.equal(calls, 1, 'A ref mismatch must fail before signature verification.');
  });
}

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

function bootstrapFixture() {
  // Unit-only synthetic evidence and injected signer/verifier. Nothing here authenticates a real release.
  const f = fixture('2.0.1', 'npm/');
  const entries = packageEntries();
  const pkg = JSON.parse(entries[0][1]);
  pkg.version = '2.0.1';
  entries[0][1] = JSON.stringify(pkg);
  const bytes = tarball(entries);
  const artifact = digest(bytes);
  const source = { ...f.record.source, tagObject: 'b'.repeat(40), tree: 'c'.repeat(40) };
  const locks = { root: 'd'.repeat(64), ui: 'e'.repeat(64) };
  const sourceReportSha256 = 'f'.repeat(64);
  const gates = { schemaVersion: 1, commit: source.commit, artifact, sourceReportSha256,
    gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, {
      status: 'passed', evidence: [{ description: 'unit-only controlled evidence', sha256: 'a'.repeat(64) }],
    }])) };
  const gatesBytes = Buffer.from(JSON.stringify(gates));
  const manifest = {
    schemaVersion: 1, phase: 'prepared-not-staged', name: POLICY.name, version: '2.0.1', major: 2, channel: 'latest',
    source, workflow: { ref: `${POLICY.repository}/${POLICY.workflow}@${source.ref}`,
      commit: source.commit, runId: '44', attempt: 1 },
    ci: { runId: '43', attempt: 1, headSha: source.commit, conclusion: 'success' },
    toolchain: { node: POLICY.node, npm: POLICY.npm }, producerLocks: locks,
    artifact: { filename: 'candidate.tgz', ...artifact, files: inspectTarball(bytes, { version: '2.0.1' }).files },
    sourceReportSha256, gateReportSha256: digest(gatesBytes).sha256,
    stage: { status: 'not-submitted', stageId: null }, publicationApproval: { status: 'not-authorized' },
    registrySignatures: { status: 'pending-publication' },
    privateContentReview: { status: 'pending-owner-review', commit: source.commit, artifact },
    sourceArtifact: { unitOnly: true }, peerArtifact: { unitOnly: true },
    matrixArtifacts: Array.from({ length: 6 }, () => ({ unitOnly: true })),
  };
  const files = new Map([['candidate.tgz', bytes], ['gates.json', gatesBytes],
    ['manifest.json', Buffer.from(JSON.stringify(manifest))]]);
  const now = new Date().toISOString();
  const approval = {
    schemaVersion: 1, name: POLICY.name, version: '2.0.1', ...source,
    ciRunId: '43', ciAttempt: 1, approver: POLICY.owner, approvedAt: now, scope: 'sign-bootstrap',
    artifact: { ...artifact, manifestSha256: digest(files.get('manifest.json')).sha256, artifactId: '45',
      artifactDigest: `sha256:${'a'.repeat(64)}`, runId: '44', runAttempt: 1 },
    ownerPreflight: {
      owner: POLICY.owner, packageName: POLICY.name, checkedAt: now, unresolvedSubmission: false,
      unresolvedSigning: false, registry: POLICY.registry, packageStatus: 'absent',
      nameApproved: true, publicProvenanceApproved: true, priorSigning: { status: 'none' },
      privateContentReview: { reviewer: POLICY.owner, scope: 'source-and-tarball', disposition: 'approved',
        historyAndAuthorsReviewed: true, historicalEvidenceAccepted: true, commit: source.commit,
        artifact, reviewedAt: now },
    },
  };
  const workflow = { ...manifest.workflow, runId: '42', repositoryId: '100', ownerId: '101' };
  f.payload.subject[0].digest.sha512 = artifact.sha512;
  Object.assign(f.payload.predicate.buildDefinition.internalParameters.github,
    { repository_id: '100', repository_owner_id: '101' });
  const bundleBytes = Buffer.from(JSON.stringify(f.bundle(f.payload)));
  const calls = [];
  const checks = { unitOnly: true, registry: {
    registry: POLICY.registry, name: POLICY.name, status: 404, checkedAt: now,
  } };
  return { approval, files, locks, manifest, gates, workflow, payload: f.payload, bundle: f.bundle, bundleBytes, calls,
    revalidate: async () => { calls.push('read'); return checks; },
    sign: async () => { calls.push('sign'); return bundleBytes; },
    verifyBundle: async (_bundle, options) => {
      calls.push('verify');
      assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
      assert.equal(options.tlogThreshold, 1);
      assert.equal(options.ctLogThreshold, 1);
    },
    record: async state => { calls.push(state.phase); },
  };
}

function contextFixture(approval) {
  const env = {
    CI: 'true', ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_ENVIRONMENT: 'github-hosted',
    RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64', GITHUB_ACTIONS: 'true', GITHUB_JOB: 'sign-bootstrap',
    GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
    GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner,
    GITHUB_REPOSITORY_ID: '100', GITHUB_REPOSITORY_OWNER_ID: '101', GITHUB_RUN_ID: '42',
    GITHUB_RUN_ATTEMPT: '1', GITHUB_REF: approval.ref, GITHUB_SHA: approval.commit,
    GITHUB_WORKFLOW_SHA: approval.commit, GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${approval.ref}`,
  };
  return { env, approval, event: { inputs: { action: 'sign-bootstrap', approval: JSON.stringify(approval) },
    repository: { id: 100, full_name: POLICY.repository, private: false, fork: false,
      owner: { id: 101, login: POLICY.owner } }, sender: { login: POLICY.owner } },
  runtime: { platform: 'linux', arch: 'x64', versions: { node: POLICY.node } } };
}

test('bootstrap unit: only approved first 2.0.1 with fresh owner disclosure/content/absence may sign', () => {
  validateApproval(bootstrapFixture().approval, 'sign-bootstrap');
  for (const mutate of [
    a => { a.version = '1.3.1'; a.ref = 'refs/tags/npm/v1.3.1'; },
    a => { a.ownerPreflight.nameApproved = false; },
    a => { a.ownerPreflight.publicProvenanceApproved = false; },
    a => { a.ownerPreflight.unresolvedSigning = true; },
    a => { a.ownerPreflight.unresolvedSubmission = true; },
    a => { a.ownerPreflight.packageStatus = 'unknown'; },
    a => { a.ownerPreflight.privateContentReview.historyAndAuthorsReviewed = false; },
    a => { a.ownerPreflight.checkedAt = '2020-01-01T00:00:00Z'; },
    a => { a.ownerPreflight.privateContentReview.artifact.sha256 = '0'.repeat(64); },
    a => { a.ownerPreflight.trust = {}; },
  ]) {
    const { approval } = bootstrapFixture();
    mutate(approval);
    assert.throws(() => validateApproval(approval, 'sign-bootstrap'));
  }
});

test('bootstrap unit: actual supported context is checked before signer; reruns and identity substitutions fail', () => {
  const original = contextFixture(bootstrapFixture().approval);
  validateBootstrapContext(original);
  for (const [key, value] of Object.entries({
    CI: 'false', GITHUB_ACTIONS: 'false', GITHUB_JOB: 'stage', GITHUB_RUN_ATTEMPT: '2',
    RUNNER_ENVIRONMENT: 'self-hosted', ACTUAL_RUNNER_ENVIRONMENT: 'self-hosted',
    GITHUB_REPOSITORY_ID: '999', GITHUB_REPOSITORY_OWNER_ID: '999', GITHUB_RUN_ID: '44',
    GITHUB_SHA: '0'.repeat(40), GITHUB_REF: 'refs/tags/v2.0.1',
  })) assert.throws(() => validateBootstrapContext({ ...original, env: { ...original.env, [key]: value } }));
  for (const runtime of [{ ...original.runtime, platform: 'darwin' }, { ...original.runtime, arch: 'arm64' },
    { ...original.runtime, versions: { node: '24.11.0' } }]) {
    assert.throws(() => validateBootstrapContext({ ...original, runtime }));
  }
  const env = { ...original.env, PATH: '/unit-only/bin', GITHUB_EVENT_PATH: '/unit-only/event',
    NPM_PUBLICATION_CLI: '/unit-only/npm/bin/npm-cli.js',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.invalid/unit-only',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'unit-only-not-a-credential',
    GITHUB_TOKEN: 'unit-only-never-forwarded', OTHER_SECRET: 'unit-only',
  };
  const child = bootstrapEnvironment(env, '/unit-only/private-home');
  assert.equal(child.GITHUB_TOKEN, undefined);
  assert.equal(child.OTHER_SECRET, undefined);
  assert.equal(child.GITHUB_SHA, env.GITHUB_SHA);
  assert.equal(child.HOME, '/unit-only/private-home');
  for (const key of ['NPM_TOKEN', 'NODE_AUTH_TOKEN', 'SIGSTORE_ID_TOKEN', 'NODE_OPTIONS', 'npm_config_registry']) {
    assert.throws(() => bootstrapEnvironment({ ...env, [key]: 'unit-only-injection' }, '/unit-only/home'));
  }
});

test('bootstrap unit: every required gate and exact manifest/tarball/lock binding precedes signing', async () => {
  for (const name of REQUIRED_GATES) {
    const f = bootstrapFixture();
    delete f.gates.gates[name];
    f.files.set('gates.json', Buffer.from(JSON.stringify(f.gates)));
    f.manifest.gateReportSha256 = digest(f.files.get('gates.json')).sha256;
    f.files.set('manifest.json', Buffer.from(JSON.stringify(f.manifest)));
    f.approval.artifact.manifestSha256 = digest(f.files.get('manifest.json')).sha256;
    await assert.rejects(() => signBootstrapOnce(f));
    assert.deepEqual(f.calls, []);
  }
  for (const mutate of [
    f => f.files.set('candidate.tgz', Buffer.from('substitution')),
    f => f.files.set('extra.json', Buffer.from('{}')),
    f => { f.locks = { ...f.locks, root: '0'.repeat(64) }; },
    f => { f.approval.artifact.manifestSha256 = '0'.repeat(64); },
  ]) {
    const f = bootstrapFixture();
    mutate(f);
    assert.throws(() => validateCandidate(f.files, f.approval, f.locks));
  }
});

test('bootstrap unit: one signing boundary follows durable unknown intent and real verifier boundary', async () => {
  const f = bootstrapFixture();
  const result = await signBootstrapOnce(f);
  assert.deepEqual(f.calls, ['read', 'signing-outcome-unknown', 'sign', 'verify', 'read', 'bootstrap-signed-not-published']);
  assert.equal(result.receipt.registrySignatures, 'pending-publication');
  assert.equal(result.receipt.ownerPublicationApproval, 'not-performed');
  for (const delta of [
    { record: async () => { throw new Error('unit-only ledger failure'); } },
    { sign: async () => { throw new Error('unit-only lost signing response'); } },
    { sign: async () => Buffer.from('{}') },
    { verifyBundle: async () => { throw new Error('unit-only invalid signature'); } },
  ]) {
    const failed = bootstrapFixture();
    await assert.rejects(() => signBootstrapOnce({ ...failed, ...delta }));
    assert.equal(failed.calls.includes('bootstrap-signed-not-published'), false);
    assert.ok(failed.calls.filter(item => item === 'sign').length <= 1);
  }
  const failed = bootstrapFixture();
  let reads = 0;
  await assert.rejects(() => signBootstrapOnce({ ...failed, revalidate: async () => {
    if (++reads === 2) throw new Error('unit-only changed registry/source after signing');
    return failed.revalidate();
  } }));
  assert.equal(failed.calls.filter(item => item === 'sign').length, 1);
  assert.equal(failed.calls.includes('bootstrap-signed-not-published'), false);
});

test('bootstrap unit: owner re-verification checks signed source/run/repository and fresh approval, never publishes', async () => {
  const f = bootstrapFixture();
  const result = await signBootstrapOnce(f);
  const receiptBytes = Buffer.from(JSON.stringify(result.receipt));
  const files = new Map([...f.files, ['provenance.sigstore', result.bundleBytes], ['bootstrap.json', receiptBytes]]);
  const approval = { ...f.approval, scope: 'verify-bootstrap',
    ownerPreflight: { ...f.approval.ownerPreflight, priorSigning: { status: 'reconciled', runIds: ['42'] } },
    signedArtifact: {
    artifactId: '60', artifactDigest: `sha256:${'b'.repeat(64)}`, runId: '42', runAttempt: 1,
    receiptSha256: digest(receiptBytes).sha256, bundleSha256: digest(result.bundleBytes).sha256,
  } };
  const options = { ...f, approval, files };
  const verified = await verifyBootstrap(options);
  assert.equal(verified.npmWrite, 'not-performed');
  assert.equal(verified.registrySignatures, 'pending-publication');
  for (const mutate of [
    p => { p.subject[0].digest.sha512 = '0'.repeat(128); },
    p => { p.predicate.buildDefinition.internalParameters.github.repository_id = '999'; },
    p => { p.predicate.buildDefinition.internalParameters.github.repository_owner_id = '999'; },
    p => { p.predicate.runDetails.metadata.invocationId += '0'; },
  ]) {
    const payload = structuredClone(f.payload);
    mutate(payload);
    const bundle = Buffer.from(JSON.stringify(f.bundle(payload)));
    const changedReceipt = { ...result.receipt,
      provenance: { ...result.receipt.provenance, sha256: digest(bundle).sha256 } };
    const changedBytes = Buffer.from(JSON.stringify(changedReceipt));
    await assert.rejects(() => verifyBootstrap({ ...options,
      approval: { ...approval, signedArtifact: { ...approval.signedArtifact,
        bundleSha256: digest(bundle).sha256, receiptSha256: digest(changedBytes).sha256 } },
      files: new Map([...files, ['provenance.sigstore', bundle], ['bootstrap.json', changedBytes]]),
    }));
  }
  await assert.rejects(() => verifyBootstrap({ ...options,
    verifyBundle: async () => { throw new Error('unit-only signature failure'); } }));
  await assert.rejects(() => verifyBootstrap({ ...options, approval: { ...approval, approvedAt: '2020-01-01' } }));
  await assert.rejects(() => verifyBootstrap({ ...options,
    files: new Map([...files, ['bootstrap.json', Buffer.from('{}')]]) }));
});

test('bootstrap unit: fixed anonymous registry GET requires definitive absence, errors never retry', async () => {
  for (const status of [200, 301, 401, 403, 409, 429, 500]) {
    let calls = 0;
    await assert.rejects(() => readAbsentRegistry({ fetcher: async (url, options) => {
      calls++;
      assert.equal(url, `${POLICY.registry}${POLICY.name}`);
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers.authorization, undefined);
      return { status };
    } }));
    assert.equal(calls, 1);
  }
  assert.equal((await readAbsentRegistry({ fetcher: async () => ({ status: 404 }) })).status, 404);
  await assert.rejects(() => readAbsentRegistry({ fetcher: async () => { throw new Error('unit-only network failure'); } }));
});

test('bootstrap unit: registry TLS failure stops before signing without retry or fallback', async () => {
  const f = bootstrapFixture();
  const cause = Object.assign(new Error('unit-only TLS handshake failure'), {
    code: 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  });
  const failure = new TypeError('unit-only fetch failure', { cause });
  let requests = 0;
  await assert.rejects(() => signBootstrapOnce({ ...f, revalidate: async () => ({
    registry: await readAbsentRegistry({ fetcher: async (url, options) => {
      requests++;
      assert.equal(url, `${POLICY.registry}${POLICY.name}`);
      assert.equal(options.headers.authorization, undefined);
      throw failure;
    } }),
  }) }), error => error === failure);
  assert.equal(requests, 1);
  assert.deepEqual(f.calls, [], 'No signing, verification success or ledger acceptance after failed registry access');
});

test('bootstrap unit: exact downloaded files, links and exclusive receipt output remain guarded', t => {
  const owned = ownedDirectory();
  t.after(() => removeOwnedDirectory(owned));
  const root = realpathSync.native(owned.dir);
  const directory = join(root, 'signed');
  mkdirSync(directory);
  for (const name of BOOTSTRAP_FILES) writeFileSync(join(directory, name), '{}');
  assert.equal(readBootstrapDirectory(directory).size, 5);
  writeFileSync(join(directory, 'extra.json'), '{}');
  assert.throws(() => readBootstrapDirectory(directory));
  unlinkSync(join(directory, 'extra.json'));
  linkSync(join(directory, 'candidate.tgz'), join(root, 'linked.tgz'));
  assert.throws(() => readBootstrapDirectory(directory), /linked/);
  unlinkSync(join(root, 'linked.tgz'));
  const output = join(root, 'verified.json');
  writeVerificationReceipt(output, { unitOnly: true }, directory);
  assert.throws(() => writeVerificationReceipt(output, {}, directory), /EEXIST/);
  assert.throws(() => writeVerificationReceipt(join(directory, 'receipt.json'), {}, directory), /outside/);
});

let ownerPublicKey;
function publicationFixture() {
  if (!ownerPublicKey) {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096 });
    const der = publicKey.export({ type: 'spki', format: 'der' });
    ownerPublicKey = { spki: der.toString('base64'), sha256: digest(der).sha256 };
  }
  const f = bootstrapFixture();
  const approval = { ...f.approval, scope: 'publish-bootstrap',
    ownerPreflight: { ...f.approval.ownerPreflight, priorSigning: { status: 'reconciled', runIds: ['42'] } },
    signedArtifact: { artifactId: '60', artifactDigest: `sha256:${'b'.repeat(64)}`, runId: '42',
      runAttempt: 1, receiptSha256: 'c'.repeat(64), bundleSha256: digest(f.bundleBytes).sha256 },
    ownerAuth: { ...ownerPublicKey, transaction: 'ab'.repeat(16) },
  };
  const calls = [];
  const records = [];
  const challenge = Object.assign(new Error('unit-only sensitive body must never escape'), {
    code: 'EOTP', statusCode: 401, method: 'PUT', uri: `${POLICY.registry}${POLICY.name}`,
    body: { authUrl: 'https://www.npmjs.com/unit-only/authorize',
      doneUrl: 'https://registry.npmjs.org/-/unit-only/done' },
  });
  const sdk = {
    login: async opener => { calls.push('login'); await opener('https://www.npmjs.com/unit-only/login'); return 'unit-only-session'; },
    whoami: async () => { calls.push('whoami'); return POLICY.owner; },
    profile: async () => ({ name: POLICY.owner, tfa: { mode: 'auth-and-writes' } }),
    checkBytes: async () => { calls.push('bytes'); },
    publish: async (_token, otp) => {
      calls.push(otp ? 'publish-with-otp' : 'publish');
      if (!otp) throw challenge;
      return { status: 201 };
    },
    webAuth: async (pair, opener) => {
      calls.push('web-auth');
      assert.deepEqual(pair, challenge.body);
      await opener(pair.authUrl);
      return 'unit-only-otp';
    },
    readback: async () => { calls.push('readback'); },
    logout: async () => { calls.push('logout'); },
  };
  return { ...f, approval, sdk, calls, records, challengeError: challenge,
    signal: new AbortController().signal,
    revalidate: async () => { calls.push('verify-all'); },
    record: async value => { records.push(value); calls.push(value.phase); },
    challenge: async (sequence, kind, _url) => { calls.push(`encrypted-${sequence}-${kind}`); },
  };
}

test('owner unit: exact publish scope/key/source/context before login; no OIDC or credential inheritance', () => {
  const f = publicationFixture();
  const context = contextFixture(f.approval);
  Object.assign(context.env, { GITHUB_JOB: 'publish-bootstrap', GITHUB_RUN_ID: '70' });
  context.event.inputs.action = 'publish-bootstrap';
  validateOwnerContext(context);
  const sealer = validateOwnerKey(f.approval.ownerAuth);
  const binding = ownerBinding(f.approval, context.env);
  const encrypted = sealer.seal({ ...binding, sequence: 1, kind: 'login' }, 'https://www.npmjs.com/unit-only/login');
  assert.equal(encrypted.algorithm, 'RSA-OAEP-256+A256GCM');
  assert.ok(!JSON.stringify(encrypted).includes('unit-only/login'));
  for (const [key, value] of Object.entries({
    GITHUB_TOKEN: 'unit-only-reader', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'unit-only-forbidden',
    OTHER_SECRET: 'unit-only-forbidden', npm_config_registry: 'https://example.invalid/',
    NODE_OPTIONS: '--inspect', HTTP_PROXY: 'https://example.invalid/',
  })) {
    const env = { ...context.env, [key]: value };
    const child = ownerEnvironment(env, '/unit-only/home');
    assert.equal(child[key], undefined);
    if (!['GITHUB_TOKEN', 'OTHER_SECRET', 'HTTP_PROXY'].includes(key)) {
      assert.throws(() => validateOwnerContext({ ...context, env }));
    }
  }
  for (const [key, value] of Object.entries({
    GITHUB_JOB: 'stage', GITHUB_RUN_ID: '42', GITHUB_RUN_ATTEMPT: '2',
    ACTUAL_RUNNER_ENVIRONMENT: 'self-hosted', GITHUB_SHA: 'd'.repeat(40),
    GITHUB_ACTOR: 'other-owner', GITHUB_REPOSITORY_ID: '999',
  })) assert.throws(() => validateOwnerContext({ ...context, env: { ...context.env, [key]: value } }));
  for (const platform of ['win32', 'darwin']) {
    assert.throws(() => validateOwnerContext({ ...context, runtime: { ...context.runtime, platform } }));
  }
  for (const mutate of [
    a => { a.scope = 'sign-bootstrap'; },
    a => { a.version = '1.3.1'; a.ref = 'refs/tags/npm/v1.3.1'; },
    a => { a.ownerPreflight.privateContentReview.disposition = 'pending'; },
    a => { a.ownerAuth.sha256 = '0'.repeat(64); },
    a => { a.ownerAuth.transaction = 'short'; },
    a => { a.ownerPreflight.unresolvedSubmission = true; },
  ]) {
    const approval = structuredClone(f.approval);
    mutate(approval);
    assert.throws(() => validateOwnerContext({ ...context, approval }));
  }
});

test('owner unit: noncanonical transaction or key hash fails before an owner login can start', async () => {
  for (const key of ['transaction', 'sha256']) {
    const f = publicationFixture();
    f.approval.ownerAuth[key] += '\n';
    await assert.rejects(() => publishOwnerOnce(f));
    assert.deepEqual(f.calls, []);
  }
});

test('owner unit: confirmed package PUT challenge allows one checked browser-2FA continuation', async () => {
  const f = publicationFixture();
  assert.deepEqual(await publishOwnerOnce(f), {
    outcome: 'published-readback-matched', attempts: 2, cleanup: 'revoked', success: true,
  });

  assert.equal(f.calls.filter(v => v === 'verify-all').length, 3);
  assert.equal(f.calls.filter(v => v === 'publish').length, 1);
  assert.equal(f.calls.filter(v => v === 'publish-with-otp').length, 1);
  assert.deepEqual(f.records.filter(v => v.phase === 'submission-outcome-unknown').map(v => v.attempt), [1, 2]);
  for (const operation of ['publish', 'publish-with-otp']) {
    assert.equal(f.calls[f.calls.indexOf(operation) - 1], 'submission-outcome-unknown');
  }
  const serialized = JSON.stringify(f.records);
  for (const secret of ['unit-only-session', 'unit-only-otp', 'unit-only/authorize', 'unit-only/done', 'sensitive body']) {
    assert.ok(!serialized.includes(secret), 'Safe ledger must never contain SDK secret/error material');
  }
});

test('owner unit: ambiguous writes, wrong EOTP origin/method/status, or second EOTP never retry', async () => {
  for (const delta of [
    { code: 'ECONNRESET' }, { code: 'E409' }, { method: 'POST' }, { statusCode: 403 },
    { uri: `${POLICY.registry}another-package` }, { body: {} },
  ]) {
    const f = publicationFixture();
    f.sdk.publish = async () => { f.calls.push('publish'); throw Object.assign(f.challengeError, delta); };
    const result = await publishOwnerOnce(f);
    assert.equal(result.outcome, 'submission-outcome-unknown');
    assert.equal(result.attempts, 1);
    assert.equal(result.cleanup, 'revoked');
    assert.equal(f.calls.includes('web-auth'), false);
    assert.equal(f.calls.filter(v => v === 'publish').length, 1);
  }
  const f = publicationFixture();
  f.sdk.publish = async () => { throw f.challengeError; };
  assert.equal((await publishOwnerOnce(f)).attempts, 2);
  assert.equal(f.calls.filter(v => v === 'web-auth').length, 1);
});

test('owner unit: freshness/source/gate failures block each boundary and ledger failure blocks PUT', async () => {
  for (const failureAt of [1, 2, 3]) {
    const f = publicationFixture();
    let checks = 0;
    f.revalidate = async () => { if (++checks === failureAt) throw new Error('unit-only changed source/gates/registry'); };
    const result = await publishOwnerOnce(f);
    assert.equal(result.attempts, failureAt === 3 ? 1 : 0);
    assert.equal(f.calls.includes('login'), failureAt !== 1);
    assert.equal(result.success, false);
  }
  const f = publicationFixture();
  f.record = async value => {
    if (value.phase === 'submission-outcome-unknown') throw new Error('unit-only durable write failed');
  };
  assert.equal((await publishOwnerOnce(f)).success, false);
  assert.equal(f.calls.includes('publish'), false);
});

test('owner unit: wrong npm owner, missing write-2FA and changed bytes stop with session cleanup', async () => {
  for (const change of [
    f => { f.sdk.whoami = async () => 'not-the-owner'; },
    f => { f.sdk.profile = async () => ({ name: POLICY.owner, tfa: { mode: 'auth-only' } }); },
    f => { f.sdk.checkBytes = async () => { throw new Error('unit-only replaced tarball'); }; },
  ]) {
    const f = publicationFixture();
    change(f);
    const result = await publishOwnerOnce(f);
    assert.equal(result.cleanup, 'revoked');
    assert.equal(f.calls.includes('publish'), false);
  }
  const f = publicationFixture();
  f.sdk.logout = async () => { throw new Error('unit-only cleanup transport failure'); };
  const result = await publishOwnerOnce(f);
  assert.equal(result.outcome, 'published-readback-matched');
  assert.equal(result.cleanup, 'revocation-failed-owner-action-required');
  assert.equal(result.success, false);
});

test('owner unit: SDK first success and readback failure retain honest publication status, never republish', async () => {
  const f = publicationFixture();
  let writes = 0;
  f.sdk.publish = async () => { writes++; return { status: 201 }; };
  f.sdk.readback = async () => { throw new Error('unit-only unknown registry readback'); };
  const result = await publishOwnerOnce(f);
  assert.equal(result.outcome, 'published-awaiting-registry-readback');
  assert.equal(result.attempts, 1);
  assert.equal(writes, 1);
  assert.equal(result.cleanup, 'revoked');
  assert.equal(result.success, false);
});

test('owner regression: cancellation during SDK provenance wait cannot initiate PUT; logout remains independent', async () => {
  const f = publicationFixture();
  const controller = new AbortController();
  f.signal = controller.signal;
  let puts = 0;
  const transport = registryTransport(async () => { puts++; return { status: 201 }; });
  f.sdk.publish = async (_token, _otp, signal) => {
    // Controlled stand-in for libnpmpublish's asynchronous pre-PUT provenance verification.
    await Promise.resolve();
    controller.abort();
    return transport(`${POLICY.registry}${POLICY.name}`, { method: 'PUT', signal });
  };
  const result = await publishOwnerOnce(f);
  assert.equal(puts, 0);
  assert.equal(result.outcome, 'submission-outcome-unknown');
  assert.equal(result.cleanup, 'revoked');
  assert.equal(f.calls.filter(value => value === 'logout').length, 1);
});

test('owner unit: registry transport refuses foreign destinations and overrides retries/redirect/cache policy', async () => {
  const calls = [];
  const transport = registryTransport(async (url, options) => { calls.push({ url, options }); return {}; });
  await transport('/-/whoami', { redirect: 'follow', retry: { retries: 7 }, strictSSL: false, cachePath: '/unit-only' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.strictSSL, true);
  assert.equal(calls[0].options.retry.retries, 0);
  assert.equal(calls[0].options.cachePath, undefined);
  for (const url of ['http://registry.npmjs.org/', 'https://example.invalid/',
    `https://${['fixture-user', 'fixture-password'].join(':')}@registry.npmjs.org/`,
    'https://registry.npmjs.org/#fragment', 'https://registry.npmjs.org:444/']) {
    assert.throws(() => transport(url));
    assert.throws(() => officialRegistryUrl(url));
  }
  for (const url of ['http://www.npmjs.com/', 'https://registry.npmjs.org/', 'https://www.npmjs.com.evil.invalid/']) {
    assert.throws(() => officialWebsiteUrl(url));
  }
  assert.equal(calls.length, 1);
  assert.throws(() => confirmedPublicationChallenge({
    ...publicationFixture().challengeError,
    body: { authUrl: 'https://www.npmjs.com/', doneUrl: 'https://example.invalid/' },
  }));
});

test('owner unit: parent/child correlation rejects replay, wrong transaction/source and unsuccessful verification', async () => {
  const f = publicationFixture();
  const binding = ownerBinding(f.approval, { GITHUB_RUN_ID: '70' });
  const request = { type: 'revalidate', requestId: 1, binding };
  validateVerificationRequest(request, binding, 1);
  const reply = { type: 'verified', requestId: 1, binding, ok: true };
  validateOwnerReply(reply, request);
  assert.throws(() => validateVerificationRequest(request, binding, 2));
  assert.throws(() => validateVerificationRequest({ ...request, binding: { ...binding, transaction: '0'.repeat(32) } }, binding, 1));
  assert.throws(() => validateOwnerReply({ ...reply, ok: false }, request));
  assert.throws(() => validateOwnerReply({ ...reply, requestId: 2 }, request));
  const emitter = new EventEmitter();
  const abort = new AbortController();
  const pending = verificationRequest(sent => assert.deepEqual(sent, request), binding, 1, emitter, abort.signal);
  emitter.emit('message', reply);
  await pending;
  assert.equal(emitter.listenerCount('message'), 0);
  const rejected = verificationRequest(() => {}, binding, 2, emitter, abort.signal);
  emitter.emit('message', reply);
  await assert.rejects(rejected, /correlation/);
});

test('owner unit: private owned state publishes complete JSON atomically and refuses overwrite or binding replacement', t => {
  const f = publicationFixture();
  const owned = ownedDirectory();
  t.after(() => removeOwnedDirectory(owned));
  const root = realpathSync.native(owned.dir);
  const env = { RUNNER_TEMP: root, GITHUB_RUN_ID: '70' };
  const state = ownerState(env, f.approval, true);
  state.write('ledger', 'unit-only.json', { status: 'unit-only' });
  assert.deepEqual(readJsonFile(join(state.directory, 'ledger', 'unit-only.json')), { status: 'unit-only' });
  assert.throws(() => state.write('ledger', 'unit-only.json', {}), /EEXIST/);
  assert.throws(() => atomicJson(root, '../escape.json', {}));
  assert.throws(() => ownerState(env, f.approval, true), /EEXIST/);
  const changed = structuredClone(f.approval);
  changed.ownerAuth.transaction = '0'.repeat(32);
  assert.throws(() => ownerState(env, changed));
});

test('owner unit: real SDK caller retains exact bytes, rejects manifest option overrides and never selects staging', async t => {
  const f = publicationFixture();
  const owned = ownedDirectory();
  t.after(() => removeOwnedDirectory(owned));
  const directory = realpathSync.native(owned.dir);
  const files = new Map([...f.files, ['bootstrap.json', Buffer.from('{}')], ['provenance.sigstore', f.bundleBytes]]);
  for (const [name, bytes] of files) writeFileSync(join(directory, name), bytes);
  const manifest = { name: POLICY.name, version: '2.0.1', dependencies: { 'smol-toml': '^1.8.0' },
    repository: { type: 'git', url: `git+https://github.com/${POLICY.repository}.git` } };
  let writes = 0;
  const controller = new AbortController();
  const sdk = createOwnerSdk({ directory, approval: f.approval, home: directory,
    libraries: { pacote: { manifest: async (path, options) => {
      assert.equal(path, join(directory, 'candidate.tgz'));
      assert.equal(options.fullMetadata, true);
      assert.equal(options.fullReadJson, true);
      assert.equal(options.ignoreScripts, true);
      assert.equal(options.offline, true);
      return manifest;
    } }, publish: async (pkg, tar, options) => {
      writes++;
      assert.equal(pkg, manifest);
      assert.deepEqual(tar, f.files.get('candidate.tgz'));
      assert.equal(options.provenanceFile, join(directory, 'provenance.sigstore'));
      assert.equal(options.defaultTag, 'latest');
      assert.equal(options.access, 'public');
      assert.equal(options.npmVersion, '12.0.2');
      assert.equal(options.fetchRetries, 0);
      assert.equal(options.signal, controller.signal);
      assert.equal(options.provenance, undefined);
      assert.equal(options.stage, undefined);
      assert.equal(options.token, undefined);
      assert.equal(options['//registry.npmjs.org/:_authToken'], 'unit-only-session');
      return { status: 201 };
    } } });
  await sdk.publish('unit-only-session', 'unit-only-otp', controller.signal);
  assert.equal(writes, 1);
  manifest.tag = 'legacy';
  await assert.rejects(() => sdk.publish('unit-only-session'), /tag/);
  delete manifest.tag;
  manifest.publishConfig = { registry: 'https://example.invalid/' };
  await assert.rejects(() => sdk.publish('unit-only-session'), /publishConfig/);
  delete manifest.publishConfig;
  controller.abort();
  await assert.rejects(() => sdk.publish('unit-only-session', undefined, controller.signal));
  assert.equal(writes, 1);
});

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

function publishedFixture() {
  // Synthetic registry documents, local EC key, injected Sigstore verifier: no real npm proof.
  const f = bootstrapFixture();
  const tarball = f.files.get('candidate.tgz');
  const record = { name: POLICY.name, version: '2.0.1', source: f.manifest.source,
    workflow: f.workflow, artifact: digest(tarball) };
  const expectedBundle = JSON.parse(f.bundleBytes);
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const keyid = 'unit-only-registry-key';
  const message = `${record.name}@${record.version}:${record.artifact.integrity}`;
  const version = { name: record.name, version: record.version, dist: {
    integrity: record.artifact.integrity, shasum: createHash('sha1').update(tarball).digest('hex'),
    tarball: `${POLICY.registry}${record.name}/-/${record.name}-${record.version}.tgz`,
    signatures: [{ keyid, sig: signBytes('sha256', Buffer.from(message), pair.privateKey).toString('base64') }],
    attestations: { url: `${POLICY.registry}-/unit-only-attached-provenance`,
      provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
  } };
  const expectedTags = { latest: '2.0.1' };
  const packument = { name: record.name, versions: { '2.0.1': version }, 'dist-tags': expectedTags,
    time: { '2.0.1': new Date(Date.now() - 1000).toISOString() } };
  const attestations = { attestations: [{ predicateType: 'https://slsa.dev/provenance/v1', bundle: expectedBundle }] };
  const audit = { invalid: [], missing: [], verified: [{
    name: record.name, version: record.version, location: `node_modules/${record.name}`,
    registry: POLICY.registry, attestations: version.dist.attestations, attestationBundles: attestations.attestations,
  }] };
  const keys = { keys: [{ keyid, key: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    expires: null }] };
  return { record, packument, version, tarball, attestations, audit, expectedTags, expectedBundle, keys,
    verifyBundle: f.verifyBundle };
}

test('post-publication unit: exact target signature, audit coverage and original signing identity are required', async () => {
  const f = publishedFixture();
  const result = await verifyPublishedEvidence(f);
  assert.equal(result.registrySignatures, 'verified');
  assert.equal(result.publishedProvenance, 'cryptographically-verified');
  assert.equal(result.signingWorkflow.runId, '42');
  assert.equal(result.auditCoverage.location, `node_modules/${POLICY.name}`);
  assert.deepEqual(result.artifact, f.record.artifact);
  assert.equal(result.registryKeyIds.length, 1);
});

for (const [name, mutate] of [
  ['missing coverage', f => { f.audit.verified = []; }],
  ['missing verified array', f => { delete f.audit.verified; }],
  ['aggregate count is not coverage', f => { f.audit = { invalid: [], missing: [], verifiedCount: 5 }; }],
  ['invalid signature result', f => { f.audit.invalid = [{ name: POLICY.name }]; }],
  ['missing signature result', f => { f.audit.missing = [{ name: POLICY.name }]; }],
  ['wrong audited version', f => { f.audit.verified[0].version = '2.0.0'; }],
  ['wrong audited package', f => { f.audit.verified[0].name = 'another-package'; }],
  ['wrong audit location', f => { f.audit.verified[0].location = 'node_modules/other'; }],
  ['wrong audit registry', f => { f.audit.verified[0].registry = 'https://example.invalid/'; }],
  ['duplicate target', f => { f.audit.verified.push(structuredClone(f.audit.verified[0])); }],
  ['audit did not include actual bundles', f => { f.audit.verified[0].attestationBundles = []; }],
  ['changed channel', f => { f.packument['dist-tags'] = { latest: '2.0.0' }; }],
  ['conflicting channel', f => { f.packument['dist-tags'] = { latest: '2.0.1', legacy: '2.0.1' }; }],
  ['wrong target name', f => { f.version.name = 'another-package'; }],
  ['deprecated release', f => { f.version.deprecated = 'unit-only deprecation'; }],
  ['different tarball integrity', f => { f.version.dist.integrity = digest(Buffer.from('changed')).integrity; }],
  ['substituted tarball', f => { f.tarball = Buffer.from('changed'); }],
  ['wrong sha1 readback', f => { f.version.dist.shasum = 'f'.repeat(40); }],
  ['no target signature', f => { f.version.dist.signatures = []; }],
  ['invalid target signature', f => { f.version.dist.signatures[0].sig = Buffer.from('invalid').toString('base64'); }],
  ['no matching registry key', f => { f.keys.keys[0].keyid = 'wrong-key'; }],
  ['expired registry key', f => { f.keys.keys[0].expires = new Date(Date.now() - 60000).toISOString(); }],
  ['invalid publication time', f => { f.packument.time['2.0.1'] = 'invalid'; }],
  ['missing attached provenance', f => { f.attestations.attestations = []; }],
  ['duplicate attached provenance', f => { f.attestations.attestations.push(f.attestations.attestations[0]); }],
  ['off-registry provenance URL', f => { f.version.dist.attestations.url = 'https://example.invalid/provenance'; }],
  ['off-registry tarball URL', f => { f.version.dist.tarball = 'https://example.invalid/package.tgz'; }],
  ['different approved bundle', f => { f.expectedBundle = { different: true }; }],
  ['Sigstore chain failure', f => { f.verifyBundle = async () => { throw new Error('unit-only chain failure'); }; }],
  ['verifier run substituted for signer', f => { f.record.workflow.runId = '70'; }],
  ['wrong original workflow', f => { f.record.workflow.attempt = 2; }],
  ['wrong original source', f => { f.record.source.commit = 'd'.repeat(40); }],
]) {
  test(`post-publication unit: ${name} rejects acceptance`, async () => {
    const f = publishedFixture();
    mutate(f);
    await assert.rejects(() => verifyPublishedEvidence(f));
  });
}

test('post-publication unit: arbitrary registry destinations are rejected before the injected GET', async () => {
  let calls = 0;
  for (const url of ['http://registry.npmjs.org/x', 'https://npmjs.com/x', '/relative',
    'https://registry.npmjs.org.example.invalid/x', 'https://registry.npmjs.org:444/x',
    'https://registry.npmjs.org/x#fragment', 'https://registry.npmjs.org/x\n']) {
    assert.throws(() => registryResource(url));
    await assert.rejects(() => anonymousBytes(url, 32, async () => { calls++; }));
  }
  assert.equal(calls, 0);
});

test('post-publication unit: anonymous GETs reject HTTP failures, lost network and oversized bodies without retries', async () => {
  for (const reply of [
    () => new Response('unit-only denied', { status: 403 }),
    () => new Response('x'.repeat(33)),
    () => new Response('x', { headers: { 'content-length': '33' } }),
    () => { throw new Error('unit-only TLS handshake failure'); },
  ]) {
    let calls = 0;
    await assert.rejects(() => anonymousBytes(`${POLICY.registry}unit-only`, 32, async (_url, options) => {
      calls++;
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers.authorization, undefined);
      return reply();
    }));
    assert.equal(calls, 1);
  }
});

test('post-publication unit: hosted anonymous context rejects local runners and inherited credentials', () => {
  const f = contextFixture(bootstrapFixture().approval);
  requireAnonymousHosted(f.env, f.runtime);
  for (const key of ['GITHUB_TOKEN', 'GH_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'NODE_OPTIONS', 'npm_config_registry']) {
    assert.throws(() => requireAnonymousHosted({ ...f.env, [key]: 'unit-only-forbidden' }, f.runtime));
  }
  assert.throws(() => requireAnonymousHosted({ ...f.env, GITHUB_ACTIONS: 'false' }, f.runtime));
  assert.throws(() => requireAnonymousHosted(f.env, { ...f.runtime, platform: 'darwin' }));
  assert.throws(() => requireAnonymousHosted(f.env, { ...f.runtime, versions: { node: '24.20.0' } }));
});

function publishedLock(f) {
  return { lockfileVersion: 3, packages: {
    '': { dependencies: { [POLICY.name]: '2.0.1' } },
    [`node_modules/${POLICY.name}`]: { version: '2.0.1', integrity: f.record.artifact.integrity,
      resolved: f.version.dist.tarball },
  } };
}

test('post-publication unit: exact registry install cannot become a tarball, range, producer lock or source link', () => {
  const f = publishedFixture();
  const args = registryInstallArguments(f.record);
  assert.deepEqual(args.slice(0, 2), ['install', 'mcp-pacemaker@2.0.1']);
  assert.ok(args.includes('--ignore-scripts'));
  assert.ok(args.includes('--fetch-retries=0'));
  assert.equal(publishedConsumerGraph(publishedLock(f), f.record).length, 1);
  for (const mutate of [
    lock => { lock.packages[''].dependencies[POLICY.name] = '^2.0.1'; },
    lock => { lock.packages[`node_modules/${POLICY.name}`].link = true; },
    lock => { lock.packages[`node_modules/${POLICY.name}`].resolved = 'file:../candidate.tgz'; },
    lock => { lock.packages[`node_modules/${POLICY.name}`].integrity = 'wrong'; },
    lock => { lock.packages['node_modules/other'] = { resolved: 'https://example.invalid/other.tgz' }; },
  ]) {
    const lock = publishedLock(f);
    mutate(lock);
    assert.throws(() => publishedConsumerGraph(lock, f.record));
  }
});

test('post-publication unit: fresh consumer runs audit before package code, never forwards auth and cleans owned data', async () => {
  const f = publishedFixture();
  const calls = [];
  let project;
  const outer = ownedDirectory();
  try {
    const longTemp = join(outer.dir, 'long-published-consumer-'.repeat(6));
    mkdirSync(longTemp);
    const result = await withPublishedConsumer({
      record: f.record, tarball: f.tarball, cli: 'unit-only-pinned-cli',
      env: { PATH: process.env.PATH, RUNNER_TEMP: longTemp, GITHUB_TOKEN: 'unit-only-reader',
        NODE_AUTH_TOKEN: 'unit-only-forbidden', NPM_TOKEN: 'unit-only-forbidden', NODE_OPTIONS: 'unit-only-forbidden' },
      executor: (_file, args, options) => {
        project = options.cwd;
        for (const key of ['GITHUB_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_TOKEN', 'NODE_OPTIONS']) {
          assert.equal(options.env[key], undefined);
        }
        assert.equal(options.env.TMPDIR, join(options.env.HOME, 'tmp'));
        assert.equal(options.env.TMP, options.env.TMPDIR);
        assert.equal(options.env.TEMP, options.env.TMPDIR);
        assert.equal(readFileSync(options.env.npm_config_userconfig, 'utf8'), '');
        assert.equal(readFileSync(options.env.npm_config_globalconfig, 'utf8'), '');
        if (args[1] === '--version') return { stdout: POLICY.npm };
        if (args[1] === 'install') {
          calls.push('install');
          assert.deepEqual(readdirSync(project), ['package.json']);
          assert.equal(args[2], 'mcp-pacemaker@2.0.1');
          const installed = join(project, 'node_modules', POLICY.name);
          mkdirSync(installed, { recursive: true });
          extractTarball(f.tarball, f.record, installed);
          writeFileSync(join(project, 'package-lock.json'), JSON.stringify(publishedLock(f)));
          return { stdout: '{}' };
        }
        assert.deepEqual(args.slice(1, 5), ['audit', 'signatures', '--json', '--include-attestations']);
        calls.push('audit');
        return { stdout: JSON.stringify(f.audit) };
      },
      inspectNotices: () => ({ runtimeNotices: [] }), // Unit-only notice seam; operational default verifies real files.
      verifyAudit: async audit => {
        calls.push('verify');
        return verifyPublishedEvidence({ ...f, audit });
      },
      smoke: async () => { calls.push('smoke'); return { installedBin: true, bridgeAndUi: true, assetsChecked: 1 }; },
    });
    assert.deepEqual(calls, ['install', 'audit', 'verify', 'smoke']);
    assert.equal(result.consumer.producerLockCopied, false);
    assert.equal(result.consumer.spec, 'mcp-pacemaker@2.0.1');
    assert.throws(() => readFileSync(join(project, 'package.json')), /ENOENT/);
  } finally {
    removeOwnedDirectory(outer);
  }
});

test('post-publication unit: installed archive changes and hardlinks fail the exact-byte guard', () => {
  const f = publishedFixture();
  const owned = ownedDirectory();
  try {
    const installed = join(realpathSync.native(owned.dir), 'installed');
    mkdirSync(installed);
    extractTarball(f.tarball, f.record, installed);
    assert.equal(exactInstalledFiles(installed, f.tarball, f.record), 8);
    const cli = join(installed, 'bin', 'cli.mjs');
    writeFileSync(cli, 'changed');
    assert.throws(() => exactInstalledFiles(installed, f.tarball, f.record));
    writeFileSync(cli, 'cli');
    linkSync(cli, join(owned.dir, 'linked-cli'));
    assert.throws(() => exactInstalledFiles(installed, f.tarball, f.record));
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('post-publication unit: actual metadata attachment URL is used, with a final immutable readback', async () => {
  const f = publishedFixture();
  const calls = [];
  const fetcher = async url => {
    calls.push(url);
    if (url === `${POLICY.registry}${POLICY.name}`) return new Response(JSON.stringify(f.packument));
    if (url === f.version.dist.tarball) return new Response(f.tarball);
    if (url === f.version.dist.attestations.url) return new Response(JSON.stringify(f.attestations));
    if (url === `${POLICY.registry}-/npm/v1/keys`) return new Response(JSON.stringify(f.keys));
    throw new Error('Unexpected unit-only GET');
  };
  const result = await acceptPublished({ ...f, fetcher,
    consumer: async options => ({ evidence: await options.verifyAudit(f.audit), consumer: { unitOnly: true } }),
  });
  assert.equal(result.evidence.signingWorkflow.runId, '42');
  assert.equal(calls.filter(url => url === `${POLICY.registry}${POLICY.name}`).length, 2);
  assert.ok(calls.includes(f.version.dist.attestations.url));
  let reads = 0;
  await assert.rejects(() => acceptPublished({ ...f,
    fetcher: async url => {
      if (url === `${POLICY.registry}${POLICY.name}` &&
          ++reads === 2) {
        return new Response(JSON.stringify({ ...f.packument, 'dist-tags': { latest: '2.0.2' } }));
      }
      return fetcher(url);
    },
    consumer: async options => ({ evidence: await options.verifyAudit(f.audit) }),
  }));
});

test('post-publication unit: missing or malformed published metadata never starts a consumer', async () => {
  for (const reply of [
    () => new Response('{}'),
    () => new Response('not json'),
    () => new Response('not found', { status: 404 }),
    () => { throw new Error('unit-only network failure'); },
  ]) {
    let consumers = 0;
    await assert.rejects(() => acceptPublished({ ...publishedFixture(), fetcher: reply,
      consumer: async () => { consumers++; } }));
    assert.equal(consumers, 0);
  }
});

test('post-publication unit: owner readback alone, failed revocation and live owner processes cannot start acceptance', () => {
  const owned = ownedDirectory();
  try {
    mkdirSync(join(owned.dir, 'ledger'));
    const binding = { unitOnly: true };
    const done = { binding, success: true, outcome: 'published-readback-matched', cleanup: 'revoked', attempts: 1 };
    const supervisor = { binding, status: 'completed', childExitCode: 0 };
    writeFileSync(join(owned.dir, 'ledger', 'done.json'), JSON.stringify(done));
    writeFileSync(join(owned.dir, 'ledger', 'supervisor.json'), JSON.stringify(supervisor));
    for (const name of ['process.json', 'owner-process.json']) {
      writeFileSync(join(owned.dir, name), JSON.stringify({ pid: 12345, binding }));
    }
    const state = { directory: owned.dir, binding, check: () => {} };
    assert.equal(completedOwner(state, () => false).cleanup, 'revoked');
    assert.throws(() => completedOwner(state, () => true));
    for (const change of [{ cleanup: 'revocation-failed-owner-action-required' },
      { outcome: 'submission-outcome-unknown' }, { success: false }, { binding: { wrong: true } }]) {
      writeFileSync(join(owned.dir, 'ledger', 'done.json'), JSON.stringify({ ...done, ...change }));
      assert.throws(() => completedOwner(state, () => false));
    }
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('post-publication unit: installed bin, injected bridge status and packaged UI assets are all checked', async () => {
  const owned = ownedDirectory();
  try {
    const installed = join(realpathSync.native(owned.dir), 'installed');
    const dist = join(installed, 'ui', 'dist', 'assets');
    mkdirSync(dist, { recursive: true });
    writeFileSync(join(dist, 'unit.js'), 'unit-only asset');
    const manifest = { name: POLICY.name, version: '2.0.1',
      bin: { 'mcp-pacemaker': 'bin/cli.mjs', 'mcp-bridge': 'bin/mcp-bridge.mjs' } };
    writeFileSync(join(installed, 'package.json'), JSON.stringify(manifest));
    let variant = 'valid';
    const bridge = {
      start: async (path, version) => {
        assert.equal(path, installed);
        assert.equal(version, '2.0.1');
        if (variant === 'bridge-start') throw new Error('unit-only failed bridge');
      },
      seedAdvice: async () => {},
      request: async (_method, path) => path === '/ui' ? {
        status: variant === 'ui-status' ? 404 : 200,
        text: variant === 'no-assets' ? '<html/>' : '<script src="/ui/assets/unit.js"></script>',
      } : { status: variant === 'asset-status' ? 404 : 200,
        text: variant === 'asset-bytes' ? 'changed' : 'unit-only asset' },
      cli: async () => ({ stdout: JSON.stringify({ service: POLICY.name,
        version: variant === 'bridge-version' ? '2.0.0' : '2.0.1' }) }),
      assertUnchanged: async () => {
        if (variant === 'changed-config') throw new Error('unit-only changed config');
      },
      run: async (_t, action) => action(bridge),
    };
    const options = {
      project: owned.dir, installed, record: { name: POLICY.name, version: '2.0.1' }, env: {},
      executor: () => ({ stdout: variant === 'bin-version' ? '2.0.0' : '2.0.1' }),
      bridgeFactory: () => bridge,
      realpath: () => join(installed, 'bin', variant === 'wrong-shim' ? 'other.mjs' : 'cli.mjs'),
    };
    assert.deepEqual(await smokePublishedConsumer(options), {
      installedBin: true, bridgeAndUi: true, assetsChecked: 1,
    });
    for (variant of ['wrong-shim', 'bin-version', 'bridge-start', 'ui-status', 'no-assets',
      'asset-status', 'asset-bytes', 'bridge-version', 'changed-config']) {
      await assert.rejects(() => smokePublishedConsumer(options));
    }
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('post-publication unit: numeric approved signing-run IDs retain the original string identity', () => {
  const f = publishedFixture();
  const binding = { unitOnly: true };
  const publication = { outcome: 'published-readback-matched', cleanup: 'revoked', attempts: 1 };
  const input = { schemaVersion: 1, binding, checkedAt: new Date().toISOString(), publication, record: f.record, checks: {} };
  const source = { binding, inputSha256: digest(Buffer.from(JSON.stringify(input))).sha256 };
  for (const runId of ['42', 42]) {
    const approval = { artifact: f.record.artifact, signedArtifact: { runId } };
    validateAcceptanceInput({ input, source, approval, binding, publication, runId: '70' });
    assert.throws(() => validateAcceptanceInput({ input, source, approval, binding, publication, runId: '42' }));
    assert.throws(() => validateAcceptanceInput({ input, source, approval, binding: {}, publication, runId: '70' }));
  }
});
