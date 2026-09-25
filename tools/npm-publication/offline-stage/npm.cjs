'use strict';
// Fresh-process substitutions only. All IDs, credentials, signatures and HTTP
// responses are synthetic fixtures. The real npm CLI/SDK transport stays offline.
const denied = require('./deny.cjs');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const Module = require('node:module');
const { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } = require('node:fs');
const { dirname, join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { fixture } = require('./fixture.cjs');
const [lane, cliArgument, mode, homeArgument] = process.argv.slice(2);
const issuerControl = mode.startsWith('issuer-');
const providerControl = mode.startsWith('provider-');
const cliMode = mode === 'cli' ||
  issuerControl;
const root = resolve(lane);
const f = fixture(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
const home = resolve(homeArgument);
const captureDirectory = join(home, 'capture');
mkdirSync(captureDirectory);
const cli = resolve(cliArgument);
const req = createRequire(cli);
const config = { user: join(home, 'user.npmrc'), global: join(home, 'global.npmrc') };
for (const path of Object.values(config)) writeFileSync(path, '', { flag: 'wx' });
const tarball = join(home, 'candidate.tgz');
writeFileSync(tarball, f.bytes, { flag: 'wx' });
Object.assign(process.env, {
  HOME: home, USERPROFILE: home, TMP: home, TEMP: home, TMPDIR: home,
  GITHUB_ACTIONS: 'true', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://offline.invalid/oidc?api-version=2.0&request=fixture-original',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fixture-oidc-request-secret',
  GITHUB_REPOSITORY: 'girishkvs/mcp-pacemaker', GITHUB_SERVER_URL: 'https://github.com',
  GITHUB_WORKFLOW_REF: f.record.workflow.ref, GITHUB_SHA: f.record.source.commit,
  GITHUB_WORKFLOW_SHA: f.record.source.commit, GITHUB_REF: f.record.source.ref,
  GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REPOSITORY_ID: '789', GITHUB_REPOSITORY_OWNER_ID: '10',
  RUNNER_ENVIRONMENT: 'github-hosted', ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted',
  RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64', GITHUB_JOB: 'stage',
  GITHUB_API_URL: 'https://api.github.com', GITHUB_REPOSITORY_OWNER: 'girishkvs',
  GITHUB_ACTOR: 'girishkvs', GITHUB_TRIGGERING_ACTOR: 'girishkvs',
});
process.chdir(home);
if (mode === 'issuer-http') process.env.ACTIONS_ID_TOKEN_REQUEST_URL = 'http://offline.invalid/oidc';
if (mode === 'issuer-userinfo') process.env.ACTIONS_ID_TOKEN_REQUEST_URL = 'https://fixture:password@offline.invalid/oidc';
if (mode === 'issuer-fragment') process.env.ACTIONS_ID_TOKEN_REQUEST_URL += '#fragment';
const requests = [];
let attestCalls = 0;
let stageCalls = 0;
let expectedBody;
let expectedBundle;
let parentResult;
const sigstorePath = req.resolve('sigstore');
const signingFixture = {
  attest: async payload => {
    attestCalls++;
    return f.bundleFor(payload);
  },
  verify: async () => assert.fail('This automatic staging path must not verify a supplied bundle'),
  sign: async () => assert.fail('No actual SDK signing operation is allowed'),
  createVerifier: async () => assert.fail('No actual SDK trust/network operation is allowed'),
};
// Inject BELOW real make-fetch-happen remote/retry/redirect handling.
const fetchPath = req.resolve('minipass-fetch');
let fetchLibrary;
const jwt = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"repository_visibility":"public"}').toString('base64url')}.UNSIGNED`;
const lowerTransport = async (request, options) => {
  const url = new URL(request.url);
  requests.push({ path: url.pathname, method: request.method, ...(issuerControl || providerControl ? {
    protocol: url.protocol, audience: url.searchParams.get('audience'),
    credentialHeaderPresent: request.headers.has('authorization'),
    retry: options.retry, timeout: options.timeout, size: options.size,
    signalPresent: Boolean(options.signal), apiVersion: url.searchParams.get('api-version'),
    originalRequest: url.searchParams.get('request'),
  } : {}) });
  let result;
  let status = 200;
  const headers = {};
  if (url.hostname === 'offline.invalid') {
    if (issuerControl ||
        providerControl) {
      assert.equal(url.protocol, 'https:');
      assert.equal(url.searchParams.get('audience'), providerControl ? 'sigstore' : 'npm:registry.npmjs.org');
      assert.equal(url.searchParams.get('api-version'), '2.0');
      assert.equal(url.searchParams.get('request'), 'fixture-original');
      assert.deepEqual(options.retry, { retries: 0 });
      assert.equal(options.timeout, 30_000);
      assert.equal(options.size, 64 * 1024);
      assert.ok(options.signal);
    }
    if (mode.endsWith('-302') ||
        mode.endsWith('-307') ||
        mode.endsWith('-308')) {
      status = Number(mode.slice(-3));
      headers.location = 'http://offline.invalid/redirected';
      result = {};
    } else if (mode.endsWith('-503')) {
      status = 503;
      result = {};
    } else if (mode.endsWith('-oversize')) result = 'x'.repeat(64 * 1024 + 1);
    else if (mode.endsWith('-malformed')) result = '{';
    else result = { value: jwt };
  }
  else if (url.pathname.includes('/oidc/token/exchange/')) result = { token: 'fixture-registry-secret' };
  else if (url.pathname.endsWith('/visibility')) result = { public: true };
  else if (url.pathname === '/mcp-pacemaker') result = { name: 'mcp-pacemaker', versions: {} };
  else if (url.pathname === '/-/stage/package/mcp-pacemaker') {
    stageCalls++;
    assert.equal(request.method, 'POST');
    assert.deepEqual(options.retry, { retries: 0 });
    assert.equal(options.redirect, 'manual', 'Real remote transport must defer redirect decisions to real fetch.js');
    expectedBody = Buffer.from(options.body);
    expectedBundle = Buffer.from(JSON.parse(options.body)._attachments[
      `mcp-pacemaker-${f.record.version}.sigstore`].data);
    if (mode.startsWith('redirect-')) {
      status = Number(mode.slice('redirect-'.length));
      headers.location = 'https://registry.npmjs.org/-/stage/package/mcp-pacemaker';
    } else if (mode === 'lost') {
      throw Object.assign(new Error('synthetic lost response'), { code: 'ECONNRESET', type: 'request-timeout' });
    } else if (mode === 'malformed') result = '{';
    else result = { stageId: f.stageId };
  } else throw new Error('Unexpected synthetic request route');
  const stream = new (req('minipass').Minipass)();
  if (!mode.endsWith('-deadline')) stream.end(typeof result === 'string' ? result : JSON.stringify(result ?? {}));
  return new fetchLibrary.Response(stream, { url: request.url, status, headers });
};
// Substitutions happen only AFTER the original pinned module loads. The
// production adapter still rejects pre-existing cache entries and checks every
// loader input first. This hook exists only in this disposable test process.
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const path = Module._resolveFilename(request, parent, isMain);
  const value = originalLoad.call(this, request, parent, isMain);
  if (path === fetchPath) {
    fetchLibrary ??= value;
    const substitute = Object.assign(lowerTransport, fetchLibrary);
    req.cache[path].exports = substitute;
    return substitute;
  }
  if (path === sigstorePath) {
    const substitute = { ...value, ...signingFixture };
    req.cache[path].exports = substitute;
    return substitute;
  }
  return value;
};

(async () => {
  const sdk = await import(pathToFileURL(join(root, 'tools/npm-publication/stage-sdk.mjs')));
  if (!cliMode &&
      mode !== 'admission') {
    sdk.installStageCapture({ cli, expected: f.record, directory: captureDirectory,
      secrets: ['fixture-oidc-request-secret'] });
  }
  const { validateCapture } = await import(pathToFileURL(join(root, 'tools/npm-publication/stage-capture.mjs')));
  if (providerControl) {
    const { CIContextProvider } = req('@sigstore/sign');
    const started = Date.now();
    const operation = new CIContextProvider('sigstore').getToken();
    if (mode === 'provider-success') assert.equal(await operation, jwt);
    else await assert.rejects(operation);
    assert.equal(requests.length, 1, 'Issuer redirect/retry must not make a second hop');
    assert.equal(stageCalls, 0);
    assert.equal(attestCalls, 0);
    assert.deepEqual(denied, []);
    assert.deepEqual(readdirSync(captureDirectory), []);
    console.log(JSON.stringify({ syntheticOnly: true, mode, passed: true, actualNode: process.versions.node,
      provider: 'actual-CIContextProvider', elapsedMs: Date.now() - started, requests,
      stageCalls, attestStubCalls: attestCalls, deniedHostAttempts: denied, realSigning: false }));
    return;
  }
  const validate = () => {
    assert.equal(stageCalls, 1, 'One actual lower-transport stage attempt only');
    assert.equal(attestCalls, mode === 'cli' ? 1 : 2);
    assert.deepEqual(denied, [], 'No real host boundary may even be attempted');
    for (const path of Object.values(config)) assert.equal(readFileSync(path, 'utf8'), '');
    const checkOwnedFiles = path => {
      for (const entry of readdirSync(path, { withFileTypes: true })) {
        const file = join(path, entry.name);
        if (entry.isDirectory()) checkOwnedFiles(file);
        else {
          assert.equal(entry.name.endsWith('.log'), false, 'npm log file must not be created');
          const bytes = readFileSync(file);
          for (const secret of ['fixture-registry-secret', 'fixture-oidc-request-secret', jwt]) {
            assert.equal(bytes.includes(Buffer.from(secret)), false, 'No fixture auth may persist');
          }
        }
      }
    };
    checkOwnedFiles(home);
    const intentBytes = readFileSync(join(captureDirectory, 'intent.json'));
    const intent = JSON.parse(intentBytes);
    assert.equal(intent.request.sha256, f.sha(expectedBody));
    assert.equal(intent.request.bytes, expectedBody.length);
    assert.deepEqual(readFileSync(join(captureDirectory, 'provenance.sigstore')), expectedBundle);
    for (const secret of ['fixture-registry-secret', 'fixture-oidc-request-secret', jwt]) {
      assert.equal(intentBytes.includes(Buffer.from(secret)), false);
      assert.equal(expectedBundle.includes(Buffer.from(secret)), false);
    }
    if (['success', 'cli'].includes(mode)) {
      const receiptBytes = readFileSync(join(captureDirectory, 'receipt.json'));
      validateCapture({ record: f.record, receiptBytes, bundleBytes: expectedBundle });
      assert.equal(JSON.parse(receiptBytes).response.sha256, f.sha(JSON.stringify({ stageId: f.stageId })));
    } else {
      assert.throws(() => readFileSync(join(captureDirectory, 'receipt.json')), { code: 'ENOENT' });
    }
    console.log(JSON.stringify({ syntheticOnly: true, mode, lane: root, npm: '12.0.2',
      actualNode: process.versions.node, stageCalls, attestStubCalls: attestCalls, requests,
      deniedHostAttempts: denied, captureDirectory, passed: true,
      requestSha256: f.sha(expectedBody), bundleSha256: f.sha(expectedBundle),
      unknownRetained: true, successRetained: ['success', 'cli'].includes(mode),
      fixtureEvidence: { body: expectedBody.toString('utf8'), bundle: expectedBundle.toString('utf8'),
        intent: intentBytes.toString('utf8'), receipt: ['success', 'cli'].includes(mode)
          ? readFileSync(join(captureDirectory, 'receipt.json'), 'utf8') : null },
      ...(mode === 'cli' ? { parentResult } : {}) }));
  };
  if (cliMode ||
      mode === 'admission') {
    const { capturedStageOutput } = await import(pathToFileURL(join(root, 'tools/npm-publication/run.mjs')));
    const { syntheticLocalApproval } = await import(pathToFileURL(join(root, 'test/helpers/local-regression-fixture.mjs')));
    const now = new Date().toISOString();
    const approval = syntheticLocalApproval({
      schemaVersion: 1, name: f.record.name, version: f.record.version, ...f.record.source,
      scope: 'stage', approver: 'girishkvs', approvedAt: now, ciRunId: '41', ciAttempt: 1,
      artifact: { ...f.record.artifact, manifestSha256: 'd'.repeat(64),
        artifactDigest: `sha256:${'e'.repeat(64)}`, artifactId: '43', runId: '44', runAttempt: 1 },
      ownerPreflight: { owner: 'girishkvs', checkedAt: now, packageName: 'mcp-pacemaker',
        privateContentReview: { reviewer: 'girishkvs', scope: 'source-and-tarball', disposition: 'approved',
          historyAndAuthorsReviewed: true, historicalEvidenceAccepted: true, commit: f.record.source.commit,
          artifact: f.record.artifact, reviewedAt: now },
        unresolvedSubmission: false, expectedDistTags: { latest: '2.0.0' }, pending: { status: 'none' },
        trust: { repository: 'girishkvs/mcp-pacemaker', workflow: 'npm-publish.yml',
          environment: 'npm-publish', allowPublish: false, allowStagePublish: true } },
    });
    const context = join(home, 'synthetic-context.json');
    const event = join(home, 'synthetic-event.json');
    process.env.GITHUB_EVENT_PATH = event;
    const writeContext = value => {
      writeFileSync(context, JSON.stringify({ approval: value, subject: f.record, config }));
      writeFileSync(event, JSON.stringify({ inputs: { action: 'stage', approval: JSON.stringify(value) },
        repository: { full_name: 'girishkvs/mcp-pacemaker', private: false, fork: false },
        sender: { login: 'girishkvs' } }));
    };
    writeContext(approval);
    const child = join(root, 'tools/npm-publication/stage-child.mjs');
    const { startStageChild } = await import(pathToFileURL(child));
    process.argv = [process.execPath, child, context, tarball, captureDirectory, cli];
    if (mode === 'admission') {
      const changed = structuredClone(approval);
      delete changed.ownerPreflight.privateContentReview.localRegression;
      writeContext(changed);
      assert.throws(startStageChild);
      writeContext(approval);
      process.env.GITHUB_ACTOR = 'not-the-owner';
      assert.throws(startStageChild);
      process.env.GITHUB_ACTOR = 'girishkvs';
      writeFileSync(tarball, 'changed fixture bytes');
      assert.throws(startStageChild);
      writeFileSync(tarball, f.bytes);
      writeFileSync(config.user, 'registry=https://untrusted.invalid/');
      assert.throws(startStageChild);
      writeFileSync(config.user, '');
      assert.equal(attestCalls, 0);
      assert.equal(stageCalls, 0);
      assert.deepEqual(requests, []);
      assert.deepEqual(denied, []);
      assert.deepEqual(readdirSync(captureDirectory), []);
      console.log(JSON.stringify({ syntheticOnly: true, mode, actualNode: process.versions.node,
        npm: '12.0.2', passed: true, controls: 4, stageCalls: 0, attestStubCalls: 0,
        deniedHostAttempts: [], requests: [], entrypoint: 'stage-child.mjs' }));
      return;
    }
    // Observe, without replacing, the actual CLI exit and completed capture.
    const originalWrite = process.stdout.write;
    let cliStdout = '';
    process.stdout.write = function (chunk, ...args) {
      cliStdout += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk;
      return originalWrite.call(this, chunk, ...args);
    };
    process.on('exit', code => {
      process.stdout.write = originalWrite;
      if (issuerControl) {
        assert.equal(code, 1, 'Issuer failure must remain a real unsuccessful CLI exit');
        const invalidUrl = ['issuer-http', 'issuer-userinfo', 'issuer-fragment'].includes(mode);
        assert.equal(requests.length, invalidUrl ? 0 : 1, 'No second issuer hop, exchange or stage');
        assert.equal(stageCalls, 0);
        assert.equal(attestCalls, 0);
        assert.deepEqual(denied, []);
        assert.deepEqual(readdirSync(captureDirectory), []);
        console.log(JSON.stringify({ syntheticOnly: true, mode, passed: true, actualNode: process.versions.node,
          observedCliExit: code, requests, stageCalls, attestStubCalls: attestCalls, deniedHostAttempts: denied }));
        return;
      }
      assert.equal(code, 0, 'Actual npm CLI did not succeed');
      const parentInput = { stdout: cliStdout.trim(), approval, bytes: f.bytes,
        subject: f.record, directory: captureDirectory };
      const parent = capturedStageOutput(parentInput);
      assert.deepEqual(Object.keys(parent).sort(), ['capture', 'stdout']);
      assert.equal(parent.capture.stageId, f.stageId);
      assert.equal(parent.capture.receiptSha256, f.sha(readFileSync(join(captureDirectory, 'receipt.json'))));
      assert.equal(parent.capture.bundleSha256, f.sha(expectedBundle));
      parentResult = { stdoutSha256: f.sha(parent.stdout), capture: parent.capture };
      assert.throws(() => capturedStageOutput({ ...parentInput, stdout: '{}' }));
      const changedId = JSON.parse(parentInput.stdout);
      changedId['mcp-pacemaker'].stageId = ['22222222', '2222', '2222', '2222', '222222222222'].join('-');
      assert.throws(() => capturedStageOutput({ ...parentInput, stdout: JSON.stringify(changedId) }));
      validate();
    });
    startStageChild();
    return;
  }
  const publish = req('libnpmpublish').publish;
  const opts = { stage: true, access: 'public', registry: 'https://registry.npmjs.org/',
    provenance: true, npmVersion: '12.0.2', defaultTag: f.record.channel,
    fetchRetries: 0, '//registry.npmjs.org/:_authToken': 'fixture-registry-secret' };
  const operation = () => publish(structuredClone(f.manifest), f.bytes, opts);
  if (mode === 'success') {
    const result = await operation();
    assert.equal(result.stageId, f.stageId);
  } else await assert.rejects(operation(), /outcome unknown/);
  await assert.rejects(operation(), /already spent/);
  // A second automatic attest may run before the adapter rejects a second POST;
  // it is a synthetic test callback, not real signing or staging.
  assert.equal(attestCalls, 2);
  validate();
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
