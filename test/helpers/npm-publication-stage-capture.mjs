import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const require = createRequire(import.meta.url);
const { fixture, zip } = require('../../tools/npm-publication/offline-stage/fixture.cjs');
const root = fileURLToPath(new URL('../../', import.meta.url));
const moduleUrl = name => pathToFileURL(join(root, `tools/npm-publication/${name}.mjs`));
const { captureTransport, inspectStageBody, validateCapture, STAGE_URL, CAPTURE_LIMITS } =
  await import(moduleUrl('stage-capture'));
const { verifyStaged } = await import(moduleUrl('verify-staged'));
const { readAuthenticatedStageCapture, reconcileStageCapture } = await import(moduleUrl('stage-capture-hosted'));
const { githubReaders } = await import(moduleUrl('matrix'));
const { validateStageProof, STAGE_SCENARIOS } = await import(moduleUrl('stage-proof-contract'));
const { runStageProof, stageProofEnvironment } = await import(moduleUrl('local-stage-check'));
const { stageProofFixture } = await import('./stage-proof-fixture.mjs');
const { stageCaptureFixture } = await import('./stage-capture-fixture.mjs');
const f = fixture(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
// Register synchronously like the existing helper suites. Awaiting registration
// while sibling modules are still loading can block older Node test runners.
const check = (name, callback) => { test(`stage capture: ${name}`, callback); };
const makeCapture = async (overrides = {}) => {
  const files = new Map();
  let calls = 0;
  const transport = captureTransport({
    expected: f.record, save: (name, bytes) => files.set(`capture/${name}`, bytes),
    fetcher: async (_, options) => {
      calls++;
      assert.equal(options.redirect, 'error');
      assert.deepEqual(options.retry, { retries: 0 });
      return new Response(JSON.stringify({ stageId: f.stageId }), { status: 201 });
    }, ...overrides,
  });
  await transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) });
  return { files, transport, calls };
};
await check('complete positive captured same body and response', async () => {
  const c = await makeCapture();
  const capture = validateCapture({ record: f.record,
    receiptBytes: c.files.get('capture/receipt.json'), bundleBytes: c.files.get('capture/provenance.sigstore') });
  assert.equal(capture.stageId, f.stageId);
  assert.equal(c.calls, 1);
  await assert.rejects(c.transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }),
    /already spent/);
});
for (const [name, change] of Object.entries({
  absent: body => { delete body._attachments; },
  extraAttachment: body => { body._attachments.other = {}; },
  alteredTarball: body => { body._attachments[`mcp-pacemaker-${f.record.version}.tgz`].data = 'YQ=='; },
  wrongChannel: body => { body['dist-tags'] = { other: f.record.version }; },
  bundleAsBase64: body => {
    body._attachments[`mcp-pacemaker-${f.record.version}.sigstore`].data =
      Buffer.from(JSON.stringify(f.bundle)).toString('base64');
  },
  wrongLength: body => { body._attachments[`mcp-pacemaker-${f.record.version}.sigstore`].length++; },
  missingManifestIntegrity: body => { delete body.versions[f.record.version].dist.integrity; },
})) {
  await check(`request rejects ${name}`, async () => {
    const body = structuredClone(f.body);
    change(body);
    assert.throws(() => inspectStageBody(JSON.stringify(body), f.record));
  });
}

await check('real GitHub reader validates API and ZIP linkage without forwarding its token to storage', async () => {
  const fixture = stageCaptureFixture(f.record, f.bundle);
  const value = fixture.fixtureOnly;
  const api = `https://api.github.com/repos/girishkvs/mcp-pacemaker`;
  const storage = 'https://artifact.fixture.invalid/original.zip';
  const seen = [];
  const readers = githubReaders({ GITHUB_TOKEN: 'synthetic-github-reader-fixture' }, {
    fetcher: async (input, options) => {
      const url = String(input);
      seen.push(url);
      if (url === storage) {
        assert.equal(options.headers, undefined, 'GitHub auth must not reach signed storage');
        assert.equal(options.redirect, 'error');
        return new Response(value.archive);
      }
      assert.equal(options.headers.authorization, 'Bearer synthetic-github-reader-fixture');
      assert.equal(options.redirect, 'manual');
      const routes = new Map([
        [`${api}/actions/runs/123/attempts/1`, value.run],
        [`${api}/actions/runs/123/attempts/1/jobs?per_page=100&page=1`,
          { total_count: 1, jobs: value.jobs }],
        [`${api}/actions/artifacts/456`, value.metadata],
      ]);
      if (url === `${api}/actions/artifacts/456/zip`) {
        return new Response(null, { status: 302, headers: { location: storage } });
      }
      assert.ok(routes.has(url), 'Unexpected API resource in capture reader');
      return new Response(JSON.stringify(routes.get(url)));
    },
  });
  const result = await readAuthenticatedStageCapture({ ...fixture, readers });
  assert.equal(result.artifactDigest, value.metadata.digest);
  assert.equal(seen.length, 5);
});

for (const [name, response] of [
  ['API auth failure', () => new Response('{}', { status: 401 })],
  ['API redirect', () => new Response(null, { status: 302, headers: { location: 'https://untrusted.invalid/' } })],
]) {
  await check(`real GitHub reader refuses ${name}`, async () => {
    const fixture = stageCaptureFixture(f.record, f.bundle);
    let calls = 0;
    const readers = githubReaders({ GITHUB_TOKEN: 'synthetic-only' },
      { fetcher: async () => { calls++; return response(); } });
    await assert.rejects(readAuthenticatedStageCapture({ ...fixture, readers }));
    assert.equal(calls, 1);
  });
}

await check('existing stage reuse requires the original authenticated capture and exact source/workflow', async () => {
  const fixture = stageCaptureFixture(f.record, f.bundle);
  const approval = { name: f.record.name, version: f.record.version, ...f.record.source,
    artifact: f.record.artifact, ownerPreflight: {
      pending: { status: 'matching', stageId: f.stageId, captureArtifactId: fixture.artifactId,
        workflow: f.record.workflow },
    } };
  const original = await reconcileStageCapture(approval, fixture.readers);
  assert.equal(original.stageId, f.stageId);
  assert.deepEqual(original.workflow, f.record.workflow);
  assert.equal(original.capture.authentication, 'original-github-api-artifact');
  for (const mutate of [
    value => { delete value.ownerPreflight.pending.captureArtifactId; },
    value => { value.ownerPreflight.pending.stageId = '22222222-2222-2222-2222-222222222222'; },
    value => { value.tree = '0'.repeat(40); },
    value => { value.artifact.sha256 = '0'.repeat(64); },
    value => { value.ownerPreflight.pending.workflow.runId = '124'; },
  ]) {
    const changed = structuredClone(approval);
    mutate(changed);
    await assert.rejects(reconcileStageCapture(changed, fixture.readers));
  }
});

const invocation = { root: 'C:\\work\\checkout-false', cli: 'C:\\input\\npm\\bin\\npm-cli.js',
  node: 'C:\\publisher-node.exe', home: 'C:\\work\\stage-proof-fixtures' };
await check('durable gate accepts a complete explicitly synthetic proof component', () => {
  const report = stageProofFixture(root, f.record.version, invocation);
  validateStageProof(report, { root, version: f.record.version, invocation });
});
for (const mode of STAGE_SCENARIOS) {
  await check(`durable gate requires every original child record field and outcome: ${mode}`, () => {
    const report = stageProofFixture(root, f.record.version, invocation);
    const selected = report.cases.find(item => item.mode === mode);
    for (const field of Object.keys(selected.command)) {
      const changed = structuredClone(report);
      const item = changed.cases.find(item => item.mode === mode);
      delete item.command[field];
      item.sha256 = f.sha(JSON.stringify(item.command));
      assert.throws(() => validateStageProof(changed, { root, version: f.record.version, invocation }));
    }
    for (const mutate of [
      value => { value.exitCode = value.exitCode === 0 ? 1 : 0; }, value => { value.signal = 'SIGTERM'; },
      value => { value.error = 'ETIMEDOUT'; }, value => { value.timeoutMs++; },
      value => { value.cwd = 'C:\\wrong'; }, value => { value.executable = 'C:\\other-node.exe'; },
      value => { value.args[0] += '.other'; },
      value => { value.stdout = '{"syntheticOnly":true,"passed":true}'; },
    ]) {
      const changed = structuredClone(report);
      const item = changed.cases.find(item => item.mode === mode);
      mutate(item.command);
      item.sha256 = f.sha(JSON.stringify(item.command));
      assert.throws(() => validateStageProof(changed, { root, version: f.record.version, invocation }));
    }
  });
}
await check('durable gate rejects old/partial reports, changed source, reordered cases and false execution claims', () => {
  for (const mutate of [
    value => { value.schemaVersion = 0; }, value => { value.cases.pop(); },
    value => { value.cases.reverse(); }, value => { value.files[0].sha256 = '0'.repeat(64); },
    value => { value.status = 'failed'; }, value => { value.syntheticOnly = false; },
    value => { value.realSigning = true; }, value => { value.realRegistry = true; },
    value => { value.authenticated = true; }, value => { value.releaseReady = true; },
    value => { value.node = 'v20.20.2'; },
  ]) {
    const report = stageProofFixture(root, f.record.version, invocation);
    mutate(report);
    assert.throws(() => validateStageProof(report, { root, version: f.record.version, invocation }));
  }
});
await check('durable gate recomputes fixture body/bundle/intent/response rather than trusting rehashed claims', () => {
  for (const mutate of [
    value => { delete value.fixtureEvidence; },
    value => { value.requestSha256 = '0'.repeat(64); },
    value => { value.bundleSha256 = '0'.repeat(64); },
    value => { value.fixtureEvidence.body = '{}'; },
    value => { value.fixtureEvidence.bundle = '{}'; },
    value => { value.fixtureEvidence.intent = '{}'; },
    value => { value.fixtureEvidence.receipt = '{}'; },
    value => {
      const receipt = JSON.parse(value.fixtureEvidence.receipt);
      receipt.response.sha256 = '0'.repeat(64);
      value.fixtureEvidence.receipt = JSON.stringify(receipt);
    },
  ]) {
    const report = stageProofFixture(root, f.record.version, invocation);
    const item = report.cases.find(item => item.mode === 'success');
    const value = JSON.parse(item.command.stdout);
    mutate(value);
    item.command.stdout = JSON.stringify(value);
    item.sha256 = f.sha(JSON.stringify(item.command));
    assert.throws(() => validateStageProof(report, { root, version: f.record.version, invocation }));
  }
});
await check('publisher proof refuses Node20 before input reads/children and strips owner environment', () => {
  let calls = 0;
  assert.throws(() => runStageProof({ nodeVersion: 'v20.20.2', execute: () => { calls++; } }),
    /publisher Node24/);
  assert.equal(calls, 0);
  const env = stageProofEnvironment({
    SystemRoot: 'C:\\Windows', GITHUB_TOKEN: 'fixture', NPM_TOKEN: 'fixture', HTTP_PROXY: 'fixture',
    NODE_OPTIONS: 'fixture', npm_config_registry: 'fixture', HOME: 'C:\\owner',
  }, 'C:\\owned', 'C:\\node\\node.exe');
  for (const key of ['GITHUB_TOKEN', 'NPM_TOKEN', 'HTTP_PROXY', 'NODE_OPTIONS', 'npm_config_registry']) {
    assert.equal(env[key], undefined);
  }
  assert.equal(env.HOME, 'C:\\owned');
});
await check('service proof binds actual CLI timeout separately from enforced timeout', () => {
  for (const mode of ['fulcio-cli-307', 'fulcio-cli-308', 'fulcio-cli-503', 'fulcio-default-307']) {
    for (const mutate of [
      value => { delete value.configuredTimeoutMs; },
      value => { value.configuredTimeoutMs = mode.includes('default') ? 300_000 : 5000; },
      value => { value.configuredTimeoutMs = String(value.configuredTimeoutMs); },
      value => { value.outerOptions[0].timeoutMs = 300_000; },
      value => { value.requests[0].timeoutMs = 300_000; },
    ]) {
      const report = stageProofFixture(root, f.record.version, invocation);
      const item = report.cases.find(value => value.mode === mode);
      const value = JSON.parse(item.command.stdout);
      mutate(value);
      item.command.stdout = JSON.stringify(value);
      item.sha256 = f.sha(JSON.stringify(item.command));
      assert.throws(() => validateStageProof(report, { root, version: f.record.version, invocation }));
    }
  }
});
for (const [name, fetcher] of Object.entries({
  malformed: async () => new Response('{', { status: 200 }),
  lost: async () => { throw new Error('synthetic lost response'); },
  noStageId: async () => new Response('{}', { status: 200 }),
  wrongStageId: async () => new Response('{"stageId":"not-a-stage"}', { status: 200 }),
  failureStatus: async () => new Response('{}', { status: 500 }),
  oversized: async () => new Response('x'.repeat(CAPTURE_LIMITS.response + 1), { status: 200 }),
  truncated: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([123])); controller.error(new Error('truncated')); },
  }), { status: 200 }),
})) {
  await check(`response ${name} stays unknown and spent`, async () => {
    const files = new Map();
    let calls = 0;
    const transport = captureTransport({ expected: f.record,
      save: (name, bytes) => files.set(name, bytes),
      fetcher: async (...args) => { calls++; return fetcher(...args); } });
    const args = [STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }];
    await assert.rejects(transport(...args), /outcome unknown/);
    assert.equal(files.has('receipt.json'), false);
    assert.equal(JSON.parse(files.get('intent.json')).status, 'submission-outcome-unknown');
    await assert.rejects(transport(...args), /already spent/);
    assert.equal(calls, 1);
  });
}
await check('deadline aborts a late response without later success receipt', async () => {
  const files = new Map();
  let release;
  const transport = captureTransport({ expected: f.record, timeoutMs: 10,
    save: (name, bytes) => files.set(name, bytes),
    fetcher: () => new Promise(resolve => { release = resolve; }) });
  await assert.rejects(transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }), /unknown/);
  release(new Response(JSON.stringify({ stageId: f.stageId })));
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(files.has('receipt.json'), false);
});
await check('credential canary is not retained', async () => {
  let saves = 0;
  const transport = captureTransport({ expected: f.record, secrets: ['SYNTHETIC-NOT-A-SIGNATURE'],
    save: () => { saves++; }, fetcher: () => assert.fail('must not dispatch') });
  await assert.rejects(transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }), /Credential/);
  assert.equal(saves, 0);
});
await check('already aborted request never dispatches', async () => {
  let calls = 0;
  const controller = new AbortController();
  controller.abort();
  const transport = captureTransport({ expected: f.record, save: () => {},
    fetcher: () => { calls++; } });
  await assert.rejects(transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body),
    signal: controller.signal }), /unknown/);
  assert.equal(calls, 0);
});
await check('oversized request rejected before parsing or dispatch', () => {
  assert.throws(() => inspectStageBody('x'.repeat(CAPTURE_LIMITS.body + 1), f.record), /Oversized/);
});
await check('oversized bundle rejected', () => {
  const body = structuredClone(f.body);
  const attachment = body._attachments[`mcp-pacemaker-${f.record.version}.sigstore`];
  attachment.data = 'x'.repeat(CAPTURE_LIMITS.bundle + 1);
  attachment.length = attachment.data.length;
  assert.throws(() => inspectStageBody(JSON.stringify(body), f.record), /Oversized/);
});
await check('npm JSON character length differs from UTF8 bytes and remains exact', async () => {
  const body = structuredClone(f.body);
  const bundle = structuredClone(f.bundle);
  bundle.dsseEnvelope.signatures[0].keyid = 'synthetic-π';
  const attachment = body._attachments[`mcp-pacemaker-${f.record.version}.sigstore`];
  attachment.data = JSON.stringify(bundle);
  attachment.length = attachment.data.length;
  const result = inspectStageBody(JSON.stringify(body), f.record);
  assert.ok(result.bundle.bytes > attachment.length);
  assert.deepEqual(result.bundleBytes, Buffer.from(attachment.data));
});
await check('failed durable intent never dispatches', async () => {
  const transport = captureTransport({ expected: f.record, save: () => { throw new Error('disk'); },
    fetcher: () => assert.fail('must not dispatch') });
  await assert.rejects(transport(STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }), /disk/);
});
await check('failed final capture leaves unknown and never retries', async () => {
  let calls = 0;
  const saved = new Map();
  const transport = captureTransport({ expected: f.record,
    save: (name, bytes) => {
      if (name === 'receipt.json') throw new Error('disk');
      saved.set(name, bytes);
    },
    fetcher: async () => { calls++; return new Response(JSON.stringify({ stageId: f.stageId })); } });
  const args = [STAGE_URL, { method: 'POST', body: JSON.stringify(f.body) }];
  await assert.rejects(transport(...args), /unknown/);
  await assert.rejects(transport(...args), /already spent/);
  assert.equal(calls, 1);
  assert.equal(saved.has('receipt.json'), false);
});
const positive = await makeCapture();
const receiptBytes = positive.files.get('capture/receipt.json');
const bundleBytes = positive.files.get('capture/provenance.sigstore');
const receipt = JSON.parse(receiptBytes);
const mutations = {
  oldSchema: r => { r.schemaVersion = 0; },
  fakeAuthentication: r => { r.authentication = true; },
  wrongRun: r => { r.subject.workflow.runId = '456'; },
  wrongCommit: r => { r.subject.source.commit = 'd'.repeat(40); },
  wrongStage: r => { r.response.stageId = '22222222-2222-2222-2222-222222222222'; },
  wrongBundleDigest: r => { r.bundle.sha256 = '0'.repeat(64); },
  wrongBundleLength: r => { r.bundle.bytes++; },
  badRequestDigest: r => { r.request.sha256 = 'bad'; },
  wrongUrl: r => { r.request.url += '/redirect'; },
  wrongMethod: r => { r.request.method = 'PUT'; },
  unknown: r => { r.status = 'submission-outcome-unknown'; },
  oversizedBody: r => { r.request.bytes = CAPTURE_LIMITS.body + 1; },
  noTimeout: r => { delete r.timeoutMs; },
  longElapsed: r => { r.elapsedMs = CAPTURE_LIMITS.timeoutMs + 1; },
};
for (const key of Object.keys(receipt)) {
  mutations[`missing-${key}`] = r => { delete r[key]; };
}
for (const key of Object.keys(receipt.request)) {
  mutations[`missing-request-${key}`] = r => { delete r.request[key]; };
}
for (const key of Object.keys(receipt.response)) {
  mutations[`missing-response-${key}`] = r => { delete r.response[key]; };
}
for (const [name, mutation] of Object.entries(mutations)) {
  await check(`capture rejects ${name}`, () => {
    const value = structuredClone(receipt);
    mutation(value);
    assert.throws(() => validateCapture({ record: f.record,
      receiptBytes: Buffer.from(JSON.stringify(value)), bundleBytes }));
  });
}
const hostedFixture = () => {
  const record = structuredClone(f.record);
  record.capture = validateCapture({ record, receiptBytes, bundleBytes });
  const files = new Map(positive.files);
  files.set('stage-1.json', Buffer.from(JSON.stringify(record)));
  files.set('stage-0.json', Buffer.from(JSON.stringify({ ...record, capture: undefined,
    status: 'submission-outcome-unknown', stageId: null })));
  const run = { id: 123, run_attempt: 1, path: '.github/workflows/npm-publish.yml',
    event: 'workflow_dispatch', status: 'completed', conclusion: 'success', head_sha: record.source.commit,
    head_branch: record.source.ref.slice('refs/tags/'.length),
    repository: { id: 789, full_name: 'girishkvs/mcp-pacemaker' },
    head_repository: { id: 789, full_name: 'girishkvs/mcp-pacemaker' },
    actor: { login: 'girishkvs' }, triggering_actor: { login: 'girishkvs' } };
  const jobs = [{ name: 'stage', status: 'completed', conclusion: 'success',
    head_sha: record.source.commit, run_id: 123, labels: ['ubuntu-24.04'] }];
  const metadata = { id: 456, name: 'npm-stage-ledger-123-1', expired: false,
    workflow_run: { id: 123, head_sha: record.source.commit, repository_id: 789, head_repository_id: 789 } };
  const archive = zip(files);
  metadata.digest = `sha256:${f.sha(archive)}`;
  const readers = {
    readJson: async () => run, readJobs: async () => jobs,
    readArtifactMetadata: async () => metadata, readArtifactArchive: async () => archive,
  };
  let signatures = 0;
  return { record, run, jobs, metadata, files,
    input: { record, view: { id: record.stageId, packageName: record.name, version: record.version,
      tag: record.channel, shasum: f.sha(f.bytes, 'sha1') }, bytes: f.bytes, receiptBytes, bundleBytes,
    artifactId: '456', currentTags: record.ownerPreflight.expectedDistTags, readers,
    verifyBundle: async (_, options) => {
      signatures++;
      assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
    } }, signatures: () => signatures };
};
await check('synthetic hosted archive reaches separate signature verifier', async () => {
  const h = hostedFixture();
  const result = await verifyStaged(h.input);
  assert.equal(h.signatures(), 1);
  assert.equal(result.ownerPublicationApproval, 'not-performed');
  assert.equal(result.capture.authentication, 'original-github-api-artifact');
});
await check('actual signature failure propagates after authenticated fixture capture', async () => {
  const h = hostedFixture();
  const failure = new Error('synthetic cryptographic rejection');
  h.input.verifyBundle = async () => { throw failure; };
  await assert.rejects(verifyStaged(h.input), error => error === failure);
});
for (const [name, change] of Object.entries({
  missingCapture: h => { h.input.receiptBytes = undefined; },
  differentBundle: h => { h.input.bundleBytes = Buffer.from(JSON.stringify({ ...f.bundle, other: 1 })); },
  fakeAuthenticatedFlag: h => { h.input = { ...h.input, artifactId: undefined, authenticated: true }; },
  wrongRunCommit: h => { h.run.head_sha = 'd'.repeat(40); },
  runFailed: h => { h.run.conclusion = 'failure'; },
  rerun: h => { h.run.run_attempt = 2; },
  fork: h => { h.run.head_repository.full_name = 'other/repo'; },
  nonOwner: h => { h.run.actor.login = 'other'; },
  expiredArtifact: h => { h.metadata.expired = true; },
  archiveMismatch: h => { h.metadata.digest = `sha256:${'0'.repeat(64)}`; },
  selfHosted: h => { h.jobs[0].labels.push('self-hosted'); },
  stageSkipped: h => { h.jobs[0].conclusion = 'skipped'; },
  stageIdMismatch: h => { h.input.view.id = '22222222-2222-2222-2222-222222222222'; },
  relabelledExistingStage: h => { h.record.status = 'owner-reconciled-existing-stage'; },
  wrongArtifactId: h => { h.input.artifactId = '457'; },
  wrongCaptureDescriptor: h => { h.record.capture.bundleSha256 = '0'.repeat(64); },
})) {
  await check(`hosted admission rejects ${name}`, async () => {
    const h = hostedFixture();
    change(h);
    await assert.rejects(verifyStaged(h.input));
    assert.equal(h.signatures(), 0);
  });
}
