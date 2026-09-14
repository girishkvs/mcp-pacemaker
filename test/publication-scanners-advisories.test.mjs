import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { workspace } from '../tools/publication-scanners/core.mjs';
import {
  consumerCoordinates, lockedCoordinates, scanAdvisories, validateBatch,
} from '../tools/publication-scanners/advisories.mjs';

function lock(packages = ['fixture-package']) {
  return { lockfileVersion: 3, packages: { '': { name: 'producer', version: '1.0.0' },
    ...Object.fromEntries(packages.map(name => [`node_modules/${name}`, {
      version: '1.2.3', resolved: `https://registry.npmjs.org/${name}/-/${name}-1.2.3.tgz`,
    }])) } };
}

function response(results) {
  return new Response(JSON.stringify({ results }), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

async function inputs(root, packages) {
  const path = join(root, 'package-lock.json');
  await writeFile(path, JSON.stringify(lock(packages)));
  return {
    locks: [{ path, scope: 'producer-root' }, { path, scope: 'producer-ui' }],
    publicPackages: packages ?? ['fixture-package'],
  };
}

test('T25/T26: exact root+UI producer locks differ from fresh consumer scope; only approved public coordinates leave process',
  async () => workspace(async root => {
    const input = await inputs(root);
    let calls = 0;
    const fetchImpl = async (url, options) => {
      calls++;
      assert.equal(url, 'https://api.osv.dev/v1/querybatch');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.redirect, 'error');
      assert.deepEqual(Object.keys(options.headers).sort(), ['Accept', 'Content-Type']);
      assert.deepEqual(JSON.parse(options.body), { queries: [{
        package: { ecosystem: 'npm', name: 'fixture-package' }, version: '1.2.3',
      }] });
      assert.ok(!options.body.includes(root));
      return response([{}]);
    };
    const first = await scanAdvisories({ ...input, fetchImpl });
    const second = await scanAdvisories({ ...input, fetchImpl });
    assert.equal(first.status, 'passed');
    assert.equal(second.status, 'passed');
    assert.equal(first.distinctCoordinates, 1);
    assert.deepEqual(first.scope.map(item => item.scope), ['producer-root', 'producer-ui']);
    assert.equal(calls, 2, 'Each run queries again, never a lifetime success cache');
    const consumer = await scanAdvisories({
      ...input, locks: [{ ...input.locks[0], scope: 'fresh-consumer' }], fetchImpl,
    });
    assert.equal(consumer.status, 'passed');
    assert.equal(consumer.scope[0].scope, 'fresh-consumer');
  }));

test('T25/T42: OSV batches bounded to 100 public coordinates and schema validates every response slot',
  async () => workspace(async root => {
    const names = Array.from({ length: 205 }, (_, index) => `fixture-${index}`);
    const input = await inputs(root, names);
    const batches = [];
    const result = await scanAdvisories({ ...input, fetchImpl: async (_url, options) => {
      const { queries } = JSON.parse(options.body);
      batches.push(queries.length);
      return response(queries.map(() => ({})));
    } });
    assert.equal(result.status, 'passed');
    assert.deepEqual(batches, [100, 100, 5]);
    assert.equal(result.distinctCoordinates, 205);
    for (const bad of [{}, { results: [] }, { results: [null] }, { results: [{ error: 'fixture' }] },
      { results: [{ next_page_token: 'more-results' }] }, { results: [{ vulns: null }] },
      { results: [{ vulns: [{ id: 'GHSA-fixture' }] }] }]) {
      assert.throws(() => validateBatch(bad, 1));
    }
  }));

test('T25: findings block; only reviewed exact advisory/package/version exemptions apply',
  async () => workspace(async root => {
    const input = await inputs(root);
    const fetchImpl = async () => response([{ vulns: [{ id: 'GHSA-fixture', modified: '2026-01-01T00:00:00Z' }] }]);
    assert.equal((await scanAdvisories({ ...input, fetchImpl })).status, 'findings');
    const exemptionsPath = join(root, 'exemptions.json');
    const exemption = { id: 'GHSA-fixture', package: 'fixture-package', version: '1.2.3',
      reviewedBy: 'synthetic fixture reviewer', reason: 'fixture only; not a real waiver',
      expiresAt: '2099-01-01T00:00:00Z' };
    for (const wrong of [{ ...exemption, version: '1.2.4' }, { ...exemption, id: 'GHSA-other' },
      { ...exemption, package: 'other-package' }]) {
      await writeFile(exemptionsPath, JSON.stringify({ schemaVersion: 1, exemptions: [wrong] }));
      assert.equal((await scanAdvisories({ ...input, fetchImpl, exemptionsPath })).status, 'findings');
    }
    await writeFile(exemptionsPath, JSON.stringify({ schemaVersion: 1, exemptions: [exemption] }));
    const reviewed = await scanAdvisories({ ...input, fetchImpl, exemptionsPath });
    assert.equal(reviewed.status, 'passed');
    assert.equal(reviewed.findings[0].status, 'reviewed-exemption');
    assert.ok(!JSON.stringify(reviewed).includes(exemption.reviewedBy));
    await writeFile(exemptionsPath, JSON.stringify({ schemaVersion: 1,
      exemptions: [{ ...exemption, expiresAt: '2000-01-01T00:00:00Z' }] }));
    assert.equal((await scanAdvisories({ ...input, fetchImpl, exemptionsPath })).status, 'error');
  }));

test('T22/T25/T42: private coordinates, unresolved locks, partial graphs and network/schema failures cannot pass',
  async () => workspace(async root => {
    const input = await inputs(root);
    let calls = 0;
    const fetchImpl = async () => { calls++; throw new Error('private-fixture-path-and-token'); };
    const denied = await scanAdvisories({ ...input, publicPackages: [], fetchImpl });
    assert.equal(denied.status, 'error');
    assert.equal(calls, 0);
    assert.throws(() => lockedCoordinates(lock(), { publicPackages: ['other-package'] }));
    const privateLock = lock();
    privateLock.packages['node_modules/fixture-package'].resolved = 'https://private.example.invalid/package';
    assert.throws(() => lockedCoordinates(privateLock, { publicPackages: input.publicPackages }));
    const incomplete = await scanAdvisories({ ...input, locks: [input.locks[0]], fetchImpl });
    assert.equal(incomplete.status, 'error');
    assert.equal(calls, 0);
    const failed = await scanAdvisories({ ...input, fetchImpl });
    assert.equal(failed.status, 'error');
    assert.ok(!JSON.stringify(failed).includes('private-fixture'));
    for (const fetchBad of [
      async () => new Response('forbidden', { status: 403 }),
      async () => response([]),
      async () => new Response('not-json', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      async () => response([{ next_page_token: 'incomplete' }]),
    ]) {
      assert.equal((await scanAdvisories({ ...input, fetchImpl: fetchBad })).status, 'error');
    }
  }));

test('T26: fresh consumer local artifact entry requires exact separate artifact binding, never copied producer coverage', () => {
  const value = lock();
  const entry = value.packages['node_modules/fixture-package'];
  entry.resolved = 'file:../owned-package.tgz';
  entry.integrity = `sha512-${Buffer.alloc(64).toString('base64')}`;
  const options = { publicPackages: [], localArtifact: {
    name: 'fixture-package', version: '1.2.3', sha256: 'a'.repeat(64), integrity: entry.integrity,
  } };
  assert.equal(lockedCoordinates(value, options).length, 0);
  assert.throws(() => lockedCoordinates(value, { publicPackages: options.publicPackages }));
  assert.throws(() => lockedCoordinates(value, { ...options,
    localArtifact: { ...options.localArtifact, version: '1.2.4' } }));
});

function consumerInputs(version = '2.0.1') {
  const localArtifact = { name: 'fixture-candidate', version, sha256: 'a'.repeat(64),
    integrity: `sha512-${Buffer.alloc(64).toString('base64')}` };
  return {
    localArtifact, publicPackages: ['fixture-package'],
    consumers: ['npm-default', 'disabled'].map((installScripts, index) => ({
      name: localArtifact.name, version: localArtifact.version, sha256: localArtifact.sha256,
      node: 'v24.21.0', npm: '12.0.2', platform: 'win32', installScripts,
      producerLockCopied: false, installedBin: true, bridgeAndUi: true,
      dependencies: [
        { name: localArtifact.name, version: localArtifact.version, integrity: localArtifact.integrity },
        { name: 'fixture-package', version: `1.2.${index + 3}`, integrity: null },
      ],
    })),
  };
}

test('T25/T26: actual consumer summaries query their distinct resolved versions without reconstructing locks', async () => {
  const input = consumerInputs();
  const bodies = [];
  const fetchImpl = async (_url, options) => {
    const body = JSON.parse(options.body);
    bodies.push(body);
    return response(body.queries.map(() => ({})));
  };
  const result = await scanAdvisories({ ...input, fetchImpl });
  assert.equal(result.status, 'passed', JSON.stringify(result));
  assert.equal(result.distinctCoordinates, 2);
  assert.deepEqual(bodies[0].queries.map(item => `${item.package.name}@${item.version}`).sort(),
    ['fixture-package@1.2.3', 'fixture-package@1.2.4']);
  assert.equal(result.scope.length, 2);
  for (const scope of result.scope) {
    assert.equal(scope.scope, 'fresh-consumer');
    assert.equal(scope.source, 'resolved-consumer-summary');
    assert.match(scope.consumerSummarySha256, /^[a-f0-9]{64}$/);
    assert.equal(scope.lockSha256, undefined);
    assert.deepEqual(scope.localArtifact, { ...input.localArtifact,
      status: 'validated-local-artifact', advisoryQuery: 'excluded' });
  }
  assert.ok(!JSON.stringify(bodies).includes(input.localArtifact.name));
  assert.ok(!JSON.stringify(bodies).includes(input.localArtifact.version));
  assert.ok(!JSON.stringify(bodies).includes(input.localArtifact.sha256));
  assert.ok(!JSON.stringify(bodies).includes('integrity'));
  await scanAdvisories({ ...input, fetchImpl });
  assert.equal(bodies.length, 2, 'Consumer summary queries are fresh each invocation');
});

test('T25/T42: invalid, copied, unbound or unapproved consumer summaries fail before any public query', async () => {
  const input = consumerInputs();
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error('must not query'); };
  const first = input.consumers[0];
  const mutations = [
    { ...first, producerLockCopied: true },
    { ...first, sha256: 'b'.repeat(64) },
    { ...first, installedBin: false },
    { ...first, node: 'private-path' },
    { ...first, dependencies: [] },
    { ...first, dependencies: first.dependencies.slice(1) },
    { ...first, dependencies: [...first.dependencies, { name: 'unapproved-private-name', version: '1.0.0', integrity: null }] },
    { ...first, dependencies: first.dependencies.map(item => ({ ...item, integrity: undefined })) },
    { ...first, dependencies: first.dependencies.map(item => ({ ...item, integrity: 'private-token' })) },
    { ...first, dependencies: first.dependencies.map(item => ({ ...item, integrity: 'sha512-A' })) },
  ];
  for (const changed of mutations) {
    const result = await scanAdvisories({ ...input, consumers: [changed], fetchImpl });
    assert.equal(result.status, 'error');
    assert.ok(!JSON.stringify(result).includes('private-'));
  }
  assert.equal((await scanAdvisories({
    ...input, consumers: [first, first], fetchImpl,
  })).status, 'error');
  assert.equal((await scanAdvisories({
    ...input, locks: [], fetchImpl,
  })).status, 'error');
  assert.equal(calls, 0);
  assert.equal(consumerCoordinates(first, input).length, 1);
});

test('T25/T42: both candidate versions are locally bound, never queried, and mismatches block all fetches', async () => {
  for (const version of ['1.3.1', '2.0.1']) {
    const input = consumerInputs(version);
    let calls = 0;
    const fetchImpl = async (_url, options) => {
      calls++;
      assert.ok(!options.body.includes(input.localArtifact.name));
      assert.ok(!options.body.includes(input.localArtifact.version));
      return response(JSON.parse(options.body).queries.map(() => ({})));
    };
    const good = await scanAdvisories({ ...input, fetchImpl });
    assert.equal(good.status, 'passed');
    assert.equal(calls, 1);
    assert.equal(good.scope[0].localArtifact.integrity, input.localArtifact.integrity);
    calls = 0;
    for (const changed of [
      { version: '9.9.9' }, { integrity: null }, { integrity: undefined },
      { integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}` },
    ]) {
      const consumers = structuredClone(input.consumers);
      consumers[1].dependencies[0] = { ...consumers[1].dependencies[0], ...changed };
      const denied = await scanAdvisories({
        ...input, consumers, publicPackages: [...input.publicPackages, input.localArtifact.name], fetchImpl,
      });
      assert.equal(denied.status, 'error');
    }
    const wrongSummary = structuredClone(input.consumers);
    wrongSummary[1].sha256 = 'b'.repeat(64);
    assert.equal((await scanAdvisories({ ...input, consumers: wrongSummary, fetchImpl })).status, 'error');
    const unknownDependency = structuredClone(input.consumers);
    unknownDependency[1].dependencies.push({ name: 'unapproved-dependency', version: '1.0.0', integrity: null });
    assert.equal((await scanAdvisories({ ...input, consumers: unknownDependency, fetchImpl })).error,
      'dependency-not-approved-for-public-query');
    assert.equal((await scanAdvisories({ ...input, publicPackages: undefined, fetchImpl })).status, 'error');
    assert.equal(calls, 0, 'All graphs must validate before the first fetch');
  }
});

test('T25/T42: local consumer lock binding is retained while only approved external dependencies leave the process',
  async () => workspace(async root => {
    const input = consumerInputs();
    const path = join(root, 'consumer-lock.json');
    const value = lock();
    const candidatePath = `node_modules/${input.localArtifact.name}`;
    const entry = { version: input.localArtifact.version, integrity: input.localArtifact.integrity,
      resolved: 'file:../owned-candidate.tgz' };
    value.packages[candidatePath] = entry;
    await writeFile(path, JSON.stringify(value));
    let calls = 0;
    const fetchImpl = async (_url, options) => {
      calls++;
      assert.deepEqual(JSON.parse(options.body).queries, [{
        package: { ecosystem: 'npm', name: 'fixture-package' }, version: '1.2.3',
      }]);
      return response([{}]);
    };
    const options = { locks: [{ path, scope: 'fresh-consumer' }],
      publicPackages: input.publicPackages, localArtifact: input.localArtifact, fetchImpl };
    const good = await scanAdvisories(options);
    assert.equal(good.status, 'passed');
    assert.equal(good.distinctCoordinates, 1);
    assert.equal(good.scope[0].localArtifact.sha256, input.localArtifact.sha256);
    assert.equal(good.scope[0].localArtifact.advisoryQuery, 'excluded');
    calls = 0;
    for (const changed of [
      { version: '9.9.9' }, { integrity: null }, { integrity: undefined },
      { integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}` },
      { resolved: 'https://registry.npmjs.org/fixture-candidate/-/fixture-candidate.tgz' },
    ]) {
      await writeFile(path, JSON.stringify({ ...value, packages: {
        ...value.packages, [candidatePath]: { ...entry, ...changed },
      } }));
      assert.equal((await scanAdvisories(options)).status, 'error');
    }
    value.packages['node_modules/unapproved-dependency'] = {
      version: '1.0.0', resolved: 'https://registry.npmjs.org/unapproved-dependency/-/unapproved-dependency.tgz',
    };
    await writeFile(path, JSON.stringify(value));
    assert.equal((await scanAdvisories(options)).error, 'dependency-not-approved-for-public-query');
    assert.equal(calls, 0);
  }));

test('T25: a validated local-only graph has no OSV request but still requires explicit approval input', async () => {
  const input = consumerInputs();
  input.consumers = input.consumers.map(consumer => ({ ...consumer, dependencies: [consumer.dependencies[0]] }));
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error('local artifact must not be disclosed'); };
  const result = await scanAdvisories({ ...input, publicPackages: [], fetchImpl });
  assert.equal(result.status, 'passed');
  assert.equal(result.distinctCoordinates, 0);
  assert.equal(result.queriedAt, undefined);
  assert.equal(result.noQueryReason, 'only-validated-local-artifact');
  assert.deepEqual(result.evidence, []);
  assert.ok(result.scope.every(scope => scope.localArtifact.advisoryQuery === 'excluded'));
  assert.equal((await scanAdvisories({ ...input, publicPackages: undefined, fetchImpl })).status, 'error');
  assert.equal(calls, 0);
});
