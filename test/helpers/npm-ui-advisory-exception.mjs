import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { PRODUCER_RISK_REVIEW, producerRiskAcceptance, classifyNativeAudit, scanAdvisories, requireBuildOnlyRiskScope } from '../../tools/publication-scanners/advisories.mjs';
import { digest, validateGateStatus, validateGates, REQUIRED_GATES } from '../../tools/npm-publication/policy.mjs';
import { LOCAL_CONTROLLER, validateLocalManifest, validatePreparedLocal, localHash } from '../../tools/npm-publication/local-regression.mjs';
import { syntheticLocalApproval, syntheticLocalReview } from './local-regression-fixture.mjs';

const raw = readFileSync(new URL('../fixtures/npm-ui-202-risk-audit.json', import.meta.url), 'utf8');
const rootRaw = readFileSync(new URL('../fixtures/npm-root-202-risk-audit.json', import.meta.url), 'utf8');
const lockBytes = readFileSync(new URL('../fixtures/producer-ui-risk-2.0.2-lock.json', import.meta.url));
const rootLockBytes = readFileSync(new URL('../../package-lock.json', import.meta.url));
const review = PRODUCER_RISK_REVIEW;
const time = Date.parse(review.notBefore) + 60_000;
const context = { phase: 'source', version: '2.0.2', scope: 'producer-ui',
  lockSha256: review.locks['producer-ui'], lockBytes };
const rootContext = { ...context, scope: 'producer-root',
  lockSha256: review.locks['producer-root'], lockBytes: rootLockBytes };
const execution = { exitCode: 1, signal: null, error: null };

test('Exact native UI report preserves exit1/eight affected nodes and is never called clean', () => {
  assert.throws(() => classifyNativeAudit(raw, execution, undefined, time));
  const result = classifyNativeAudit(raw, execution, context, time);
  assert.equal(result.disposition, 'RISK-ACCEPTED');
  assert.equal(result.advisoryFree, false);
  assert.equal(result.rawExitCode, 1);
  assert.equal(result.rawFindingCount, 8);
  assert.equal(result.rawAdvisoryCount, 3);
  assert.equal(result.rawCounts.high, 6);
  assert.equal(result.rawCounts.moderate, 2);
  assert.equal(result.acceptance.reviewRecordSha256, digest(Buffer.from(JSON.stringify(review))).sha256);
});

test('Exact root audit records CLI-runtime exposure separately from build-only findings', () => {
  const result = classifyNativeAudit(rootRaw, execution, rootContext, time);
  assert.equal(result.rawFindingCount, 1);
  assert.equal(result.rawAdvisoryCount, 1);
  assert.equal(result.rawCounts.moderate, 1);
  assert.equal(result.acceptance.advisories.find(item => item.package === 'smol-toml').exposure, 'cli-runtime');
  assert.equal(result.canonicalReportSha256, review.nativeReports['producer-root'].sha256);
  assert.equal(result.advisoryFree, false);
  assert.throws(() => classifyNativeAudit(rootRaw, execution, context, time));
  assert.throws(() => classifyNativeAudit(raw, execution, rootContext, time));
  assert.throws(() => classifyNativeAudit(rootRaw, execution, { ...rootContext, scope: 'fresh-consumer' }, time));
  for (const change of [
    value => { value.vulnerabilities['smol-toml'].via[0].source++; },
    value => { value.vulnerabilities['smol-toml'].via[0].range = '<2'; },
    value => { value.vulnerabilities['smol-toml'].nodes.push('node_modules/other/smol-toml'); },
    value => { value.metadata.dependencies.total++; },
  ]) {
    const changed = JSON.parse(rootRaw);
    change(changed);
    assert.throws(() => classifyNativeAudit(JSON.stringify(changed), execution, rootContext, time));
  }
  const oldUi = readFileSync(new URL('../fixtures/npm-ui-braces-audit.json', import.meta.url), 'utf8');
  assert.throws(() => classifyNativeAudit(oldUi, execution, context, time));
});

for (const [name, value] of [['version', '2.0.1'], ['version', '2.0.3'], ['version', '1.3.1'],
  ['phase', 'artifact'], ['scope', 'producer-root'], ['scope', 'fresh-consumer'],
  ['lockSha256', '0'.repeat(64)], ['lockBytes', Buffer.concat([lockBytes, Buffer.from('\n')])]]) {
  test(`UI risk rejects wrong ${name} ${String(value).slice(0, 30)}`, () => {
    assert.throws(() => classifyNativeAudit(raw, execution, { ...context, [name]: value }, time));
  });
}

test('Exact review not-before/expiry, missing/malformed record and clean unrelated releases', () => {
  assert.equal(review.approvedOn, '2026-10-06');
  assert.equal(review.expiresAt, '2026-10-12T00:00:00Z');
  assert.equal(Object.hasOwn(review, 'approvedAt'), false);
  for (const now of [Date.parse(review.notBefore) - 1, Date.parse(review.expiresAt), Date.parse(review.expiresAt) + 1]) {
    assert.throws(() => classifyNativeAudit(raw, execution, context, now));
  }
  assert.ok(producerRiskAcceptance(context, Date.parse(review.notBefore)));
  assert.ok(producerRiskAcceptance(rootContext, Date.parse(review.notBefore)));
  assert.equal(producerRiskAcceptance(context, time, null), null);
  assert.equal(producerRiskAcceptance(context, time, { ...review, scope: 'other' }), null);
  const clean = { auditReportVersion: 2, vulnerabilities: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } };
  assert.equal(classifyNativeAudit(JSON.stringify(clean), { exitCode: 0 },
    { ...context, version: '2.0.3' }, Date.parse(review.expiresAt) + 1).disposition, 'advisory-free');
});

test('Later gate/manifest admission still rejects expired or repurposed source risk evidence', async t => {
  const f = await new ContinuationFixture().setup(t);
  const gate = f.report.gates['producer-advisories'];
  validateGateStatus('producer-advisories', gate);
  assert.throws(() => validateGateStatus('consumer-advisories', gate));
  assert.throws(() => validateGateStatus('producer-advisories', { status: 'passed', riskAcceptance: gate.riskAcceptance }));
  assert.throws(() => validateGateStatus('producer-advisories', { ...gate,
    riskAcceptance: { ...gate.riskAcceptance, expiresAt: '2099-01-01T00:00:00Z' } }));
  f.clock = Date.parse(review.expiresAt);
  assert.throws(() => validateGateStatus('producer-advisories', gate));
  validateGateStatus('producer-advisories', { status: 'passed' });
});

test('Build-only findings cannot be relabelled as CLI runtime or bundled UI packages', () => {
  const root = { packages: { '': {}, 'node_modules/smol-toml': { version: '1.8.0' } } };
  const bundle = { schemaVersion: 1, packages: [], runtimeNotices: [], sources: [] };
  const bytes = value => Buffer.from(JSON.stringify(value));
  requireBuildOnlyRiskScope(bytes(root), bytes(bundle));
  for (const item of review.advisories.filter(item => item.exposure === 'ui-build')) {
    for (const field of ['packages', 'runtimeNotices']) {
      assert.throws(() => requireBuildOnlyRiskScope(bytes(root),
        bytes({ ...bundle, [field]: [{ name: item.package, version: item.version }] })));
    }
    assert.throws(() => requireBuildOnlyRiskScope(bytes({
      packages: { ...root.packages, [`node_modules/${item.package}`]: { version: item.version } },
    }), bytes(bundle)));
    assert.throws(() => requireBuildOnlyRiskScope(bytes(root),
      bytes({ ...bundle, sources: [{ path: `node_modules/${item.package}/index.js` }] })));
  }
});

test('Existing manifest reader rechecks risk release/lock/expiry without creating owner approval', async t => {
  const f = await new ContinuationFixture().setup(t);
  f.manifestCheck();
  for (const mutate of [
    m => { m.version = '2.0.3'; },
    m => { m.producerLocks.ui = '0'.repeat(64); },
    m => { delete m.producerAdvisories; },
  ]) {
    const manifest = JSON.parse(f.bytes);
    mutate(manifest);
    const bytes = Buffer.from(JSON.stringify(manifest));
    f.approval.artifact.manifestSha256 = localHash(bytes);
    assert.throws(() => validateLocalManifest(bytes, f.approval, f.report));
  }
  f.approval.artifact.manifestSha256 = localHash(f.bytes);
  f.clock = Date.parse(review.expiresAt);
  assert.throws(() => f.manifestCheck());
});

for (const change of [
  v => { v.vulnerabilities.braces.via[0].source++; },
  v => { v.vulnerabilities.braces.via[0].url += '-other'; },
  v => { v.vulnerabilities.braces.via.push({ ...v.vulnerabilities.braces.via[0], source: 9 }); },
  v => { v.vulnerabilities.chokidar.via.push('other'); },
  v => { v.vulnerabilities.braces.nodes[0] = 'node_modules/other/braces'; },
  v => { v.vulnerabilities.braces.via[0].range = '<4'; },
  v => { v.vulnerabilities.braces.name = 'other'; },
  v => { v.vulnerabilities.braces.isDirect = true; },
  v => { v.vulnerabilities.other = v.vulnerabilities.braces; },
  v => { v.metadata.vulnerabilities.high = 0; },
  v => { delete v.metadata.vulnerabilities.total; },
  v => { v.metadata.dependencies.total++; },
  v => { v.auditReportVersion = 1; },
  v => { v.error = { code: 'ENETUNREACH' }; },
]) {
  test(`Native report fingerprint rejects ${change.toString()}`, () => {
    const value = JSON.parse(raw);
    change(value);
    assert.throws(() => classifyNativeAudit(JSON.stringify(value), execution, context, time));
  });
}

for (const change of [{ exitCode: 0 }, { exitCode: 2 }, { exitCode: null }, { signal: 'SIGTERM' },
  { error: { code: 'ENOBUFS' } }, { timedOut: true }, { truncated: true }, { incomplete: true },
  { stderr: 'npm error execution did not complete' }]) {
  test(`Native audit execution cannot be waived: ${JSON.stringify(change)}`, () => {
    assert.throws(() => classifyNativeAudit(raw, { ...execution, ...change }, context, time));
  });
}

class OsvFixture {
  setup(t) {
    const directory = mkdtempSync(join(tmpdir(), 'ui-risk-unit-'));
    t.after(() => rmSync(directory, { recursive: true }));
    const rootPath = join(directory, 'root.json');
    const uiPath = join(directory, 'ui.json');
    const root = JSON.parse(rootLockBytes);
    writeFileSync(rootPath, rootLockBytes);
    writeFileSync(uiPath, lockBytes);
    const publicPackages = [...new Set([root, JSON.parse(lockBytes)].flatMap(lock =>
      Object.entries(lock.packages).filter(([path]) => path).map(([path, entry]) =>
        entry.name ?? path.split('node_modules/').at(-1))))];
    t.mock.method(Date, 'now', () => time);
    return { directory, rootPath, uiPath, root, options: {
      locks: [{ path: rootPath, scope: 'producer-root' }, { path: uiPath, scope: 'producer-ui' }],
      publicPackages, producerContext: { phase: 'source', version: '2.0.2', scope: 'producer-root-and-ui' },
    } };
  }
  fetch(extra = false, callback = () => {}) {
    return async (_url, options) => {
      callback();
      const queries = JSON.parse(options.body).queries;
      return new Response(JSON.stringify({ results: queries.map(query => ({ vulns:
        review.advisories.filter(item => item.package === query.package.name && item.version === query.version)
          .flatMap(item => [{ id: item.id, modified: '2026-10-06T00:00:08.430664Z' },
            ...(extra ? [{ id: 'GHSA-new-new-new', modified: '2026-10-06T00:00:00Z' }] : [])]),
      })) }),
      { headers: { 'Content-Type': 'application/json' } });
    };
  }
}

  class ContinuationFixture {
    async setup(t, clean = false, clock = Date.parse(review.expiresAt) - 60_000) {
      const f = new OsvFixture().setup(t);
      const fetchImpl = clean ? async (_url, options) => new Response(JSON.stringify({
        results: JSON.parse(options.body).queries.map(() => ({})),
      }), { headers: { 'Content-Type': 'application/json' } }) : new OsvFixture().fetch();
      const osv = await scanAdvisories({ ...f.options, fetchImpl });
      const zero = classifyNativeAudit(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {},
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } }));
      const nativeAudits = [{ scope: 'producer-root',
        ...(clean ? zero : classifyNativeAudit(rootRaw, execution, rootContext, time)) }, { scope: 'producer-ui',
        ...(clean ? zero : classifyNativeAudit(raw, execution, context, time)) }];
      this.clock = clock;
      Date.now.mock.mockImplementation(() => this.clock);
      this.approval = syntheticLocalApproval({ scope: 'stage', version: '2.0.2', commit: 'a'.repeat(40),
        tree: 'b'.repeat(40), ref: 'refs/tags/v2.0.2', tagObject: 'c'.repeat(40),
        approvedAt: new Date(this.clock).toISOString(), ownerPreflight: { privateContentReview: {} }, artifact: {} });
      const source = { version: '2.0.2', commit: this.approval.commit,
        rootLockSha256: osv.scope[0].lockSha256, uiLockSha256: review.locks['producer-ui'] };
      const evidence = [{ description: 'Controlled OSV report', sha256: localHash(JSON.stringify(osv)) },
        { description: 'Controlled root audit', sha256: '1'.repeat(64), exitCode: clean ? 0 : 1,
          ...(clean ? {} : { stdoutSha256: localHash(rootRaw) }) },
        { description: 'Controlled UI audit', sha256: '2'.repeat(64), exitCode: clean ? 0 : 1,
          ...(clean ? {} : { stdoutSha256: localHash(raw) }) }];
      const gate = { status: 'passed', evidence, nativeAudits, osv,
        rawFindingCount: osv.rawFindingCount, remainingFindings: osv.remainingFindings,
        disposition: clean ? 'advisory-free' : 'RISK-ACCEPTED', advisoryFree: clean,
        ...(clean ? {} : { riskAcceptance: producerRiskAcceptance(context, time) }) };
      const checks = { audits: structuredClone(nativeAudits) };
      this.report = { schemaVersion: 1, commit: source.commit, artifact: digest(Buffer.from('controlled artifact')),
        localRegression: this.approval.localRegression, source, sourceChecks: checks,
        gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, { status: 'passed',
          evidence: [{ description: 'Controlled other gate', sha256: '3'.repeat(64) }] }])) };
      this.report.gates['producer-advisories'] = gate;
      this.manifest = { version: '2.0.2', source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree']
        .map(key => [key, this.approval[key]])), producerLocks: { root: source.rootLockSha256, ui: source.uiLockSha256 },
        localRegression: this.approval.localRegression,
        preparationApproval: { approver: 'girishkvs', scope: 'prepare', approvedAt: this.approval.approvedAt },
        localRegressionReview: syntheticLocalReview(this.approval.localRegression, this.approval.approvedAt),
        producerAdvisories: { source, checks: structuredClone(checks), gate: structuredClone(gate) } };
      this.bytes = Buffer.from(JSON.stringify(this.manifest));
      this.approval.artifact.manifestSha256 = localHash(this.bytes);
      return this;
    }

    gateCheck(report = this.report) {
      return validateGates(JSON.parse(JSON.stringify(report)), this.approval, this.report.artifact);
    }

    manifestCheck(report = this.report) {
      return validateLocalManifest(this.bytes, this.approval, JSON.parse(JSON.stringify(report)));
    }
  }

  test('Complete serialized risk and zero-finding continuation routes retain their original manifest and qualification', async t => {
    const f = await new ContinuationFixture().setup(t);
    f.gateCheck();
    f.manifestCheck();
    validatePreparedLocal(JSON.parse(f.bytes), f.approval);
    const bytes = Buffer.from(f.bytes);
    const qualification = JSON.stringify(f.approval.localRegression);
    f.clock = Date.parse(review.expiresAt);
    assert.throws(() => f.gateCheck());
    assert.throws(() => f.manifestCheck());
    assert.throws(() => validatePreparedLocal(JSON.parse(f.bytes), f.approval));
    assert.deepEqual(f.bytes, bytes);
    assert.equal(JSON.stringify(f.approval.localRegression), qualification);
  });

  test('Complete serialized zero-findings route needs no exception even after its expiry', async t => {
    const f = await new ContinuationFixture().setup(t, true);
    f.clock = Date.parse(review.expiresAt);
    f.gateCheck();
    f.manifestCheck();
    validatePreparedLocal(JSON.parse(f.bytes), f.approval);
  });

  for (const clock of [Date.parse(review.notBefore) - 1, Date.parse(review.expiresAt), Date.parse(review.expiresAt) + 1]) {
    test(`Every serialized continuation boundary rejects the risk outside its window: ${clock}`, async t => {
      const f = await new ContinuationFixture().setup(t, false, Math.min(clock - 1000, Date.parse(review.expiresAt) - 60_000));
      f.clock = clock;
      assert.throws(() => f.gateCheck());
      assert.throws(() => f.manifestCheck());
      assert.throws(() => validateLocalManifest(f.bytes, f.approval));
      assert.throws(() => validatePreparedLocal(JSON.parse(f.bytes), f.approval));
    });
  }

  test('Prepared continuation compares the retained producer evidence with its original source report', async t => {
    const f = await new ContinuationFixture().setup(t);
    const sourceReport = { phase: 'source', source: f.report.source, checks: f.report.sourceChecks,
      gates: f.report.gates };
    validatePreparedLocal(JSON.parse(f.bytes), f.approval, f.approval, JSON.parse(JSON.stringify(sourceReport)));
    const changed = JSON.parse(JSON.stringify(sourceReport));
    delete changed.gates['producer-advisories'].riskAcceptance;
    assert.throws(() => validatePreparedLocal(JSON.parse(f.bytes), f.approval, f.approval, changed));
    const stripped = JSON.parse(f.bytes);
    stripped.producerAdvisories.gate = { status: 'passed', evidence: f.report.gates['producer-advisories'].evidence };
    delete stripped.producerAdvisories.checks;
    assert.throws(() => validatePreparedLocal(stripped, f.approval));
  });

  for (const boundary of ['gate', 'local manifest', 'prepared manifest']) {
    test(`Serialized ${boundary} requires one-to-one native stdout evidence`, async t => {
      const f = await new ContinuationFixture().setup(t);
      const changed = structuredClone(f.report);
      const gate = changed.gates['producer-advisories'];
      gate.nativeAudits[0].reportSha256 = gate.nativeAudits[1].reportSha256;
      changed.sourceChecks.audits = structuredClone(gate.nativeAudits);
      const manifest = JSON.parse(f.bytes);
      manifest.producerAdvisories.checks = structuredClone(changed.sourceChecks);
      manifest.producerAdvisories.gate = structuredClone(gate);
      const bytes = Buffer.from(JSON.stringify(manifest));
      f.approval.artifact.manifestSha256 = localHash(bytes);
      if (boundary === 'gate') assert.throws(() => f.gateCheck(changed));
      if (boundary === 'local manifest') assert.throws(() => validateLocalManifest(bytes, f.approval, changed));
      if (boundary === 'prepared manifest') assert.throws(() => validatePreparedLocal(manifest, f.approval));
    });
  }

  const continuationMutations = [
    ['top acceptance removed', g => { delete g.riskAcceptance; }],
    ['native acceptance removed', g => { delete g.nativeAudits[1].acceptance; }],
    ['root acceptance removed', g => { delete g.nativeAudits[0].acceptance; }],
    ['root report replaced by UI report', g => { g.nativeAudits[0].canonicalReportSha256 = g.nativeAudits[1].canonicalReportSha256; }],
    ['root raw counts hidden', g => { g.nativeAudits[0].rawCounts.moderate = 0; }],
    ['root native digest missing', g => { delete g.evidence[1].stdoutSha256; }],
    ['root native digest duplicated', g => { g.evidence[1].stdoutSha256 = g.evidence[2].stdoutSha256; }],
    ['both acceptances removed', g => { delete g.riskAcceptance; delete g.nativeAudits[1].acceptance; }],
    ['all classification fields removed', g => {
      for (const key of Object.keys(g)) if (!['status', 'evidence'].includes(key)) delete g[key];
    }],
    ['native scope under good OSV', g => { g.nativeAudits[1].acceptance.scope = 'producer-root'; }],
    ['OSV scope under good native', g => { g.osv.riskAcceptance.scope = 'fresh-consumer'; }],
    ['OSV acceptance removed', g => { delete g.osv.riskAcceptance; }],
    ['OSV finding acceptance removed', g => { delete g.osv.findings[0].riskAcceptance; }],
    ['OSV finding wrong advisory', g => { g.osv.findings[0].id = 'GHSA-other'; }],
    ['OSV duplicate finding', g => { g.osv.findings.push(structuredClone(g.osv.findings[0])); g.osv.rawFindingCount++; }],
    ['advisory-free contradiction', g => { g.advisoryFree = true; }],
    ['native counts contradiction', g => { g.nativeAudits[1].rawCounts.high = 0; }],
    ['native disposition contradiction', g => { g.nativeAudits[1].disposition = 'advisory-free'; }],
    ['OSV counts contradiction', g => { g.osv.rawFindingCount = 0; }],
    ['selected UI audit missing', g => { g.nativeAudits.pop(); }],
    ['selected audit root scope', g => { g.nativeAudits[1].scope = 'producer-root'; }],
    ['native consumer scope', g => { g.nativeAudits[1].acceptance.scope = 'fresh-consumer'; }],
    ['duplicate selected audit', g => { g.nativeAudits.push(structuredClone(g.nativeAudits[1])); }],
    ['source checks drift', (_g, r) => { r.sourceChecks.audits[1].rawExitCode = 0; }],
    ['source checks removed', (_g, r) => { delete r.sourceChecks; }],
    ['wrong UI lock', (_g, r) => { r.source.uiLockSha256 = '0'.repeat(64); }],
    ['wrong root lock', (_g, r) => { r.source.rootLockSha256 = '0'.repeat(64); }],
    ['wrong release', (_g, r) => { r.source.version = '2.0.3'; }],
    ['wrong advisory', g => { g.nativeAudits[1].acceptance.id = 'GHSA-other'; }],
    ['wrong record hash', g => { g.riskAcceptance.reviewRecordSha256 = '0'.repeat(64); }],
    ['extended expiry', g => { g.nativeAudits[1].acceptance.expiresAt = '2099-01-01T00:00:00Z'; }],
  ];
  for (const [name, mutate] of continuationMutations) {
    test(`Serialized continuation rejects ${name} without changing prepared bytes or qualification`, async t => {
      const f = await new ContinuationFixture().setup(t);
      const originalBytes = Buffer.from(f.bytes);
      const originalQualification = JSON.stringify(f.approval.localRegression);
      const changed = JSON.parse(JSON.stringify(f.report));
      mutate(changed.gates['producer-advisories'], changed);
      const gate = changed.gates['producer-advisories'];
      if (gate.osv) gate.evidence[0].sha256 = localHash(JSON.stringify(gate.osv));
      assert.throws(() => f.gateCheck(changed), 'Actual validateGates must reject');
      assert.throws(() => f.manifestCheck(changed), 'Actual validateLocalManifest must reject');
      assert.deepEqual(f.bytes, originalBytes);
      assert.equal(JSON.stringify(f.approval.localRegression), originalQualification);
    });
  }

  test('Expired source findings cannot lose all exception fields or all classification fields', async t => {
    const f = await new ContinuationFixture().setup(t);
    f.clock = Date.parse(review.expiresAt) + 1;
    for (const all of [false, true]) {
      const changed = JSON.parse(JSON.stringify(f.report));
      const gate = changed.gates['producer-advisories'];
      delete gate.riskAcceptance;
      delete gate.nativeAudits[1].acceptance;
      if (all) {
        for (const key of Object.keys(gate)) if (!['status', 'evidence'].includes(key)) delete gate[key];
        delete changed.sourceChecks;
      }
      assert.throws(() => f.gateCheck(changed));
      assert.throws(() => f.manifestCheck(changed));
    }
  });
test('OSV exact root and UI scopes retain all four findings and raw response evidence', async t => {
  const f = new OsvFixture().setup(t);
  const result = await scanAdvisories({ ...f.options, fetchImpl: new OsvFixture().fetch() });
  assert.equal(result.status, 'passed');
  assert.equal(result.rawFindingCount, 4);
  assert.equal(result.remainingFindings, 0);
  assert.equal(result.findings[0].status, 'reviewed-exemption');
  assert.equal(result.findings[0].modified, '2026-10-06T00:00:08.430664Z');
  assert.equal(result.riskAcceptance.scope, 'producer-root-and-ui');
  assert.deepEqual(result.findings.map(item => item.id).sort(), review.advisories.map(item => item.id).sort());
  assert.equal(result.advisoryFree, false);
  assert.ok(result.evidence.every(item => item.rawResponseSha256.length === 64 && item.responseBytes > 0));
});

test('Fresh consumers do not inherit the producer smol-toml runtime exception', async t => {
  const f = new OsvFixture().setup(t);
  const localArtifact = { name: 'mcp-pacemaker', version: '2.0.2', sha256: 'a'.repeat(64),
    integrity: `sha512-${Buffer.alloc(64).toString('base64')}` };
  const consumer = { ...localArtifact, node: 'v24.21.0', npm: '12.0.2', platform: 'linux',
    installScripts: 'disabled', producerLockCopied: false, installedBin: true, bridgeAndUi: true,
    dependencies: [
      { name: localArtifact.name, version: localArtifact.version, integrity: localArtifact.integrity },
      { name: 'smol-toml', version: '1.8.0', integrity: null },
    ] };
  const result = await scanAdvisories({ consumers: [consumer], localArtifact,
    publicPackages: f.options.publicPackages, producerContext: f.options.producerContext,
    fetchImpl: new OsvFixture().fetch() });
  assert.equal(result.status, 'findings');
  assert.equal(result.rawFindingCount, 1);
  assert.equal(result.remainingFindings, 1);
  assert.equal(result.findings[0].name, 'smol-toml');
  assert.equal(result.findings[0].status, 'blocked');
  assert.equal(result.findings[0].riskAcceptance, undefined);
  assert.equal(result.riskAcceptance, undefined);
});

for (const mode of ['root-too', 'consumer', 'additional', 'wrong-release', 'wrong-phase', 'wrong-scope', 'no-context',
  'changed-lock', 'changed-root-lock', 'drift-during-query', 'release-during-query', 'expired-during-query', 'network-error']) {
  test(`Producer exception does not waive ${mode}`, async t => {
    const f = new OsvFixture().setup(t);
    if (mode === 'root-too') {
      f.root.packages['node_modules/braces'] = JSON.parse(lockBytes).packages['node_modules/braces'];
      writeFileSync(f.rootPath, JSON.stringify(f.root));
    }
    if (mode === 'consumer') f.options.locks = [{ path: f.uiPath, scope: 'fresh-consumer' }];
    if (mode === 'wrong-release') f.options.producerContext.version = '2.0.3';
    if (mode === 'wrong-phase') f.options.producerContext.phase = 'artifact';
    if (mode === 'wrong-scope') f.options.producerContext.scope = 'producer-ui';
    if (mode === 'no-context') delete f.options.producerContext;
    if (mode === 'changed-lock') writeFileSync(f.uiPath, Buffer.concat([lockBytes, Buffer.from('\n')]));
    if (mode === 'changed-root-lock') writeFileSync(f.rootPath, Buffer.concat([rootLockBytes, Buffer.from('\n')]));
    const fetchImpl = new OsvFixture().fetch(mode === 'additional', () => {
      if (mode === 'drift-during-query') writeFileSync(f.uiPath, '{}');
      if (mode === 'release-during-query') f.options.producerContext.version = '2.0.3';
      if (mode === 'expired-during-query') Date.now.mock.mockImplementation(() => Date.parse(review.expiresAt));
      if (mode === 'network-error') throw new Error('controlled network failure');
    });
    const result = await scanAdvisories({ ...f.options, fetchImpl });
    assert.notEqual(result.status, 'passed');
  });
}

test('Modified exception modules are in the private controller binding and import without I/O', () => {
  for (const path of ['tools/publication-scanners/advisories.mjs', 'tools/publication-scanners/publication.mjs',
    'tools/npm-publication/gates.mjs', 'tools/npm-publication/source-gates.mjs']) assert.ok(LOCAL_CONTROLLER.includes(path));
  const module = new URL('../../tools/publication-scanners/advisories.mjs', import.meta.url).href;
  const source = `import fs from 'node:fs';import {SourceTextModule,SyntheticModule} from 'node:vm';
    const entry=${JSON.stringify(module)};
    const texts=new Map([entry,new URL('./core.mjs',entry).href].map(url=>[url,fs.readFileSync(new URL(url),'utf8')]));
    const modules=new Map();const fail=()=>{throw new Error('module I/O denied')};
    async function load(url){
      if(modules.has(url))return modules.get(url);
      let m;
      if(url.startsWith('node:')){
        const native=await import(url);
        const blocked=['readFile','readFileSync','createReadStream','lstat','realpath','spawn','mkdtemp','writeFile'];
        m=new SyntheticModule(Object.keys(native),function(){for(const key of Object.keys(native))this.setExport(key,blocked.includes(key)?fail:native[key])});
      }else{m=new SourceTextModule(texts.get(url),{identifier:url});}
      modules.set(url,m);return m;
    }
    const main=await load(entry);await main.link((name,parent)=>load(name.startsWith('node:')?name:new URL(name,parent.identifier).href));
    globalThis.fetch=fail;await main.evaluate();console.log('import-no-io');`;
  const child = spawnSync(process.execPath, ['--experimental-vm-modules', '--input-type=module', '-e', source],
    { encoding: 'utf8', timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), 'import-no-io');
});
