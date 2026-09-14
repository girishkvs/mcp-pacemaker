import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isolatedEnvironment, runBounded, sha256, workspace } from '../tools/publication-scanners/core.mjs';
import {
  publicationSecretGates, scanPublicationRequest, validatePublicationRequest,
} from '../tools/publication-scanners/publication.mjs';
import { main } from '../tools/publication-scanners/cli.mjs';

async function sourceRequest(root) {
  const sourceRoot = join(root, 'candidate');
  await mkdir(sourceRoot);
  await mkdir(join(sourceRoot, 'ui'));
  await writeFile(join(sourceRoot, 'package.json'), JSON.stringify({ name: 'fixture-candidate', version: '2.0.1' }));
  const lock = { lockfileVersion: 3, packages: { '': {}, 'node_modules/fixture-dependency': {
    version: '1.2.3', resolved: 'https://registry.npmjs.org/fixture-dependency/-/fixture-dependency-1.2.3.tgz',
  } } };
  await writeFile(join(sourceRoot, 'package-lock.json'), JSON.stringify(lock));
  await writeFile(join(sourceRoot, 'ui', 'package-lock.json'), JSON.stringify(lock));
  const git = async args => {
    const result = await runBounded('git', ['-C', sourceRoot, ...args],
      { cwd: root, env: isolatedEnvironment(root), timeoutMs: 30_000 });
    assert.equal(result.code, 0, 'Owned fixture Git command failed');
    return result.stdout.trim();
  };
  await git(['init', '--quiet']);
  await git(['add', '.']);
  // Fixture commit only, inside the owned disposable directory.
  await git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '--quiet', '-m', 'Publication request fixture']);
  return { schemaVersion: 1, phase: 'source', sourceRoot, root: sourceRoot,
    commit: await git(['rev-parse', 'HEAD']), name: 'fixture-candidate', version: '2.0.1',
    requiredGates: ['source-private-identifiers', 'native-rebuild'] };
}

async function artifactRequest(root) {
  const request = await sourceRequest(root);
  const extractedRoot = join(root, 'extracted');
  await mkdir(extractedRoot);
  await writeFile(join(extractedRoot, 'package.json'), JSON.stringify({ name: request.name, version: request.version }));
  const tarball = join(root, 'artifact.tgz');
  // Only the binding adapter is tested here, not tar parsing or extraction.
  const bytes = Buffer.from('Owned artifact digest fixture');
  await writeFile(tarball, bytes);
  const hash512 = createHash('sha512').update(bytes).digest('hex');
  const artifact = { sha256: sha256(bytes), sha512: hash512,
    integrity: `sha512-${Buffer.from(hash512, 'hex').toString('base64')}` };
  const consumers = ['npm-default', 'disabled'].map((installScripts, index) => ({
    name: request.name, version: request.version, sha256: artifact.sha256,
    node: 'v24.21.0', npm: '12.0.2', platform: 'win32', installScripts,
    producerLockCopied: false, installedBin: true, bridgeAndUi: true,
    dependencies: [
      { name: request.name, version: request.version, integrity: artifact.integrity },
      { name: 'fixture-dependency', version: `1.2.${index + 3}`, integrity: null },
    ],
  }));
  return { ...request, phase: 'artifact', root: extractedRoot, extractedRoot, tarball, artifact, consumers,
    requiredGates: ['consumer-advisories', 'payload-private-identifiers', 'licenses-notices'] };
}

function cleanResponse(_url, options) {
  const { queries } = JSON.parse(options.body);
  return Promise.resolve(new Response(JSON.stringify({ results: queries.map(() => ({})) }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }));
}

test('T22/T42: request CLI writes safe evidence, blocks absent policy and separates a clean scan from owner review',
  async () => workspace(async root => {
    const request = await sourceRequest(root);
    const path = join(root, 'request.json');
    const output = join(root, 'report.json');
    await writeFile(path, JSON.stringify(request));
    const result = await main(['--request', path, '--output', output]);
    assert.equal(result.status, 'not-run', JSON.stringify(result));
    assert.equal(result.phase, 'source');
    assert.equal(result.commit, request.commit);
    assert.deepEqual(Object.keys(result.gates), ['source-private-identifiers']);
    assert.equal(result.gates['source-private-identifiers'].status, 'not-run');
    const stored = await readFile(output, 'utf8');
    assert.equal(JSON.parse(stored).requestFileSha256, sha256(await readFile(path)));
    assert.ok(!stored.includes(request.sourceRoot));
    assert.equal((await main(['--request', path, '--output', output])).status, 'error');
    assert.equal(await readFile(output, 'utf8'), stored, 'Existing reports are never overwritten');
    const inside = await main(['--request', path, '--output', join(request.root, 'new-report.json')]);
    assert.equal(inside.error, 'report-must-be-outside-scan-roots');
    const policyPath = join(root, 'private-policy.json');
    await writeFile(policyPath, JSON.stringify({ schemaVersion: 1,
      literals: [{ value: 'synthetic-local-private-identifier', ignoreCase: false }] }));
    const clean = await scanPublicationRequest({ request, policyPath });
    assert.equal(clean.scannerDetails.privatePolicy.status, 'passed');
    assert.equal(clean.gates['source-private-identifiers'].status, 'passed');
    assert.equal(clean.gates['source-private-identifiers'].ownerReview, 'pending');
    assert.equal(clean.privateContentReview.status, 'pending');
    assert.ok(!JSON.stringify(clean).includes('synthetic-local-private-identifier'));
    const attemptedOverride = await scanPublicationRequest({
      request: { ...request, approved: true, privateContentReview: { disposition: 'approved' } },
    });
    assert.equal(attemptedOverride.gates['source-private-identifiers'].status, 'not-run');
  }));

test('T25/T42: source request OSV hashes both producer locks and preserves actual evidence without unrelated gates',
  async () => workspace(async root => {
    const request = await sourceRequest(root);
    request.requiredGates = ['producer-advisories', 'native-rebuild'];
    const result = await scanPublicationRequest({
      request, publicPackages: ['fixture-dependency'], fetchImpl: cleanResponse,
    });
    assert.equal(result.status, 'passed', JSON.stringify(result));
    assert.deepEqual(Object.keys(result.gates), ['producer-advisories']);
    assert.deepEqual(result.scannerDetails.advisories.scope.map(item => item.scope), ['producer-root', 'producer-ui']);
    assert.equal(result.gates['producer-advisories'].evidence[0].sha256,
      sha256(JSON.stringify(result.scannerDetails.advisories)));
    const invalid = await scanPublicationRequest({ request: { ...request, commit: '0'.repeat(40) } });
    assert.equal(invalid.error, 'publication-head-binding-mismatch');
    assert.equal(invalid.gates['producer-advisories'].status, 'failed');
  }));

test('T25/T26/T42: artifact request queries both actual consumer summaries, verifies tarball hashes and leaves private gate pending',
  async () => workspace(async root => {
    const request = await artifactRequest(root);
    const versions = new Set();
    const fetchImpl = async (url, options) => {
      for (const item of JSON.parse(options.body).queries) versions.add(item.version);
      return cleanResponse(url, options);
    };
    const result = await scanPublicationRequest({
      request, publicPackages: ['fixture-dependency'], fetchImpl,
    });
    assert.equal(result.status, 'not-run', JSON.stringify(result));
    assert.deepEqual(result.artifact, request.artifact);
    assert.equal(result.gates['consumer-advisories'].status, 'passed');
    assert.equal(result.gates['payload-private-identifiers'].status, 'not-run');
    assert.equal(result.gates['licenses-notices'], undefined);
    assert.deepEqual([...versions].sort(), ['1.2.3', '1.2.4']);
    assert.equal(result.scannerDetails.advisories.scope[0].localArtifact.integrity, request.artifact.integrity);
    assert.ok(result.scannerDetails.advisories.scope.every(scope => scope.source === 'resolved-consumer-summary'));
    await writeFile(request.tarball, 'changed');
    let calls = 0;
    const failed = await scanPublicationRequest({
      request, publicPackages: ['fixture-dependency'],
      fetchImpl: async () => { calls++; throw new Error('must not query changed artifact'); },
    });
    assert.equal(failed.error, 'publication-tarball-digest-mismatch');
    assert.equal(calls, 0);
    assert.equal(failed.gates['consumer-advisories'].status, 'failed');
    assert.equal(failed.gates['payload-private-identifiers'].status, 'not-run');
  }));

test('T42: wrapper failures retain failed versus not-run semantics and reject malformed request shapes',
  async () => workspace(async root => {
    const request = await sourceRequest(root);
    request.requiredGates.push('source-gitleaks', 'source-trufflehog');
    const missing = await scanPublicationRequest({ request, tools: { gitleaks: {} } });
    assert.equal(missing.status, 'error');
    assert.equal(missing.gates['source-gitleaks'].status, 'failed');
    assert.equal(missing.gates['source-trufflehog'].status, 'failed');
    assert.equal(missing.gates['source-private-identifiers'].status, 'not-run');
    assert.equal(missing.scannerDetails.secrets.error, 'tool-path-and-approved-digest-required');
    for (const changed of [undefined, {}, { phase: '__proto__' },
      { ...request, requiredGates: {} }, { ...request, root: 'relative-private-path' }]) {
      assert.equal((await scanPublicationRequest({ request: changed })).status, 'error');
    }
    await workspace(async other => {
      const artifact = await artifactRequest(other);
      assert.throws(() => validatePublicationRequest({ ...artifact, consumers: [artifact.consumers[0]] }));
      assert.throws(() => validatePublicationRequest({ ...artifact, consumers: [
        artifact.consumers[0], artifact.consumers[0],
      ] }));
    });
  }));

test('T42: per-tool gate evidence requires every source scope and cannot hide findings or global scan errors', () => {
  const names = ['source-gitleaks', 'source-trufflehog'];
  const result = { status: 'findings', executions: ['gitleaks', 'trufflehog'].flatMap(name =>
    ['working-tree', 'history'].map(scope => ({
      scope, status: name === 'gitleaks' ? 'passed' : 'findings', commandSha256: 'c'.repeat(64),
      tool: { name, version: name === 'gitleaks' ? '8.30.1' : '3.97.1', sha256: 'd'.repeat(64) },
    }))) };
  const gates = publicationSecretGates(result, 'source', names);
  assert.equal(gates['source-gitleaks'].status, 'passed');
  assert.equal(gates['source-trufflehog'].status, 'failed');
  assert.equal(gates['source-gitleaks'].evidence[1].sha256, sha256(JSON.stringify(result.executions[0])));
  assert.match(gates['source-gitleaks'].evidence[1].description, /argument-vector SHA256/);
  const failed = publicationSecretGates({ ...result, status: 'error' }, 'source', names);
  assert.ok(Object.values(failed).every(gate => gate.status === 'failed'));
  const incomplete = publicationSecretGates({
    ...result, status: 'passed', executions: result.executions.slice(1),
  }, 'source', names);
  assert.equal(incomplete['source-gitleaks'].status, 'failed');
});
