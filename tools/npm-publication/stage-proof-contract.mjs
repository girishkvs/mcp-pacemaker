import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, win32 } from 'node:path';
import { createRequire } from 'node:module';
import { gunzipSync } from 'node:zlib';
import { digest, npm12Contents } from './policy.mjs';
import { CAPTURE_LIMITS, inspectStageBody, validateCapture } from './stage-capture.mjs';
import { exactLocalKeys, localHash, localSha } from './local-regression.mjs';
import { treeEntries } from './local-source.mjs';
import { physical } from './local-inputs.mjs';
const { fixture } = createRequire(import.meta.url)('./offline-stage/fixture.cjs');

export const STAGE_SCENARIOS = Object.freeze(['deny-control', 'oidc', 'admission', 'cli', 'success', 'redirect-301',
  'redirect-302', 'redirect-303', 'redirect-307', 'redirect-308', 'lost', 'malformed',
  'issuer-http', 'issuer-userinfo', 'issuer-fragment', 'issuer-302', 'issuer-307', 'issuer-308',
  'issuer-503', 'issuer-oversize', 'issuer-malformed',
  'provider-success', 'provider-302', 'provider-503', 'provider-oversize', 'provider-malformed', 'provider-deadline',
  'loader-main', 'loader-exports', 'loader-delegate', 'loader-shadow',
  'loader-cache-transport', 'loader-cache-registry', 'loader-cache-low', 'loader-cache-signing',
  'loader-cache-provider', 'loader-cache-hidden',
  'dual-audience', 'fulcio-success', 'fulcio-cli-307', 'fulcio-cli-308', 'fulcio-cli-503',
  'fulcio-default-307', 'fulcio-default-308', 'fulcio-default-503',
  'fulcio-malformed', 'fulcio-oversize', 'fulcio-deadline']);
export const STAGE_PROOF_FILES = Object.freeze([
  'stage-capture.mjs', 'stage-sdk.mjs', 'stage-sdk-pins.json', 'stage-child.mjs', 'policy.mjs',
  'local-stage-check.mjs', 'stage-proof-contract.mjs', 'offline-stage/deny.cjs',
  'offline-stage/fixture.cjs', 'offline-stage/npm.cjs', 'offline-stage/oidc.cjs', 'offline-stage/control.cjs',
  'offline-stage/loader.cjs', 'stage-issuer.mjs', 'stage-loader.mjs', 'stage-sdk-loader.json', 'run.mjs',
  'offline-stage/services.cjs', 'stage-fulcio.mjs',
].map(name => `tools/npm-publication/${name}`).concat(['test/helpers/local-regression-fixture.mjs']));
export const STAGE_CHILD_TIMEOUT = 60_000;
export const stageProofExit = mode => mode.startsWith('issuer-') ? 1 : 0;
export const DENIAL_COVERAGE = Object.freeze([
  'node:http.request', 'node:http.get', 'node:http.createServer',
  'node:https.request', 'node:https.get', 'node:https.createServer',
  'node:http2.connect', 'node:http2.createServer', 'node:http2.createSecureServer',
  'node:net.connect', 'node:net.createConnection', 'node:net.createServer',
  'node:tls.connect', 'node:tls.createServer', 'node:dgram.createSocket',
  'node:child_process.spawn', 'node:child_process.spawnSync', 'node:child_process.exec',
  'node:child_process.execSync', 'node:child_process.execFile', 'node:child_process.execFileSync',
  'node:child_process.fork', 'node:worker_threads.Worker',
  'Socket.connect', 'Server.listen', 'ChildProcess.spawn', 'dgram.Socket.bind',
  'dgram.Socket.connect', 'dgram.Socket.send',
  'dns.lookup', 'dns.lookupService', 'dns.resolve', 'dns.reverse',
  'dns.promises.lookup', 'dns.promises.lookupService', 'dns.promises.resolve', 'dns.promises.reverse',
  'Resolver.resolve', 'Resolver.reverse', 'PromiseResolver.resolve', 'PromiseResolver.reverse',
  'global.fetch', 'global.WebSocket',
]);
export const proofFiles = root => STAGE_PROOF_FILES.map(path => ({
  path, sha256: localHash(readFileSync(join(root, path))),
}));

const checkoutBindings = new WeakMap();
const checkoutAttributes = ['text', 'eol', 'filter', 'working-tree-encoding', 'ident'];

// Only the replay reader uses this handle. Expected hashes come from actual
// bounded Git reads, never report.files or a caller-supplied list of hashes.
export function bindStageProofCheckout({ root, identity, readGit }) {
  root = physical(root);
  identity = structuredClone(identity);
  exactLocalKeys(identity, ['schemaVersion', 'version', 'head', 'tree', 'clean', 'entries', 'files']);
  assert.equal(identity.schemaVersion, 1);
  assert.equal(identity.clean, true, 'Stage checkout binding requires a clean committed source');
  for (const value of [identity.head, identity.tree]) assert.match(value, /^[a-f0-9]{40}$/);
  assert.equal(typeof readGit, 'function');
  const bytes = args => {
    const value = readGit(args);
    assert.ok(Buffer.isBuffer(value) &&
      value.length <= 4 * 1024 ** 2, 'Bounded binary Git output required');
    return value;
  };
  const text = args => new TextDecoder('utf-8', { fatal: true }).decode(bytes(args)).trimEnd();
  const entries = treeEntries(text(['ls-tree', '-rz', '--full-tree', identity.head]));
  assert.deepEqual(entries, identity.entries);
  assert.deepEqual(identity.files.map(file => file.path), entries.map(file => file.path));
  let total = 0;
  for (const file of identity.files) {
    exactLocalKeys(file, ['path', 'size', 'sha256']);
    localSha(file.sha256);
    assert.ok(Number.isSafeInteger(file.size) &&
      file.size >= 0 &&
      file.size <= 64 * 1024 ** 2);
    total += file.size;
    assert.ok(total <= 512 * 1024 ** 2);
  }
  const recheck = () => {
    assert.equal(text(['rev-parse', 'HEAD']), identity.head, 'Stage source HEAD changed');
    assert.equal(text(['rev-parse', 'HEAD^{tree}']), identity.tree, 'Stage source tree changed');
    const attributesPath = text(['rev-parse', '--path-format=absolute', '--git-path', 'info/attributes']);
    assert.equal(existsSync(attributesPath), false, 'Uncommitted attribute overrides are forbidden');
    for (const file of identity.files) {
      const source = readFileSync(physical(join(root, file.path)));
      assert.equal(source.length, file.size, 'Frozen source/attributes changed after identity verification');
      assert.equal(localHash(source), file.sha256, 'Frozen source/attributes changed after identity verification');
    }
  };
  recheck();
  const fields = new TextDecoder('utf-8', { fatal: true }).decode(bytes([
    'check-attr', `--source=${identity.head}`, '-z', ...checkoutAttributes, '--', ...STAGE_PROOF_FILES,
  ])).split('\0');
  assert.equal(fields.pop(), '', 'Incomplete checkout attribute evidence');
  assert.equal(fields.length, STAGE_PROOF_FILES.length * checkoutAttributes.length * 3);
  let offset = 0;
  const files = STAGE_PROOF_FILES.map(path => {
    const entry = identity.entries.find(value => value.path === path);
    assert.ok(entry, 'Stage proof input is not a committed source member');
    const attributes = {};
    for (const name of checkoutAttributes) {
      assert.equal(fields[offset++], path);
      assert.equal(fields[offset++], name);
      attributes[name] = fields[offset++];
    }
    for (const name of ['filter', 'working-tree-encoding', 'ident']) {
      assert.equal(attributes[name], 'unspecified', `Unsupported stage checkout conversion: ${name}`);
    }
    assert.ok(['set', 'auto', 'unset'].includes(attributes.text), 'Missing declared text/binary attributes');
    assert.ok(['lf', 'crlf', 'unspecified'].includes(attributes.eol), 'Unsupported declared EOL');
    if (attributes.text === 'unset') assert.equal(attributes.eol, 'unspecified');
    const sourceBlob = text(['-c', 'core.autocrlf=false', `--attr-source=${identity.head}`,
      'hash-object', `--path=${path}`, '--', join(root, path)]);
    assert.equal(sourceBlob, entry.blob, 'Frozen stage source does not clean to its committed Git blob');
    const blob = bytes(['cat-file', 'blob', entry.blob]);
    assert.equal(createHash('sha1').update(`blob ${blob.length}\0`).update(blob).digest('hex'),
      entry.blob, 'Stage source Git blob identity mismatch');
    // Force the recorded Windows checkout policy and committed attributes.
    // Conversion runs only after rejecting every executable/encoding filter.
    const checkedOut = bytes(['-c', 'core.autocrlf=false', '-c', 'core.eol=crlf',
      `--attr-source=${identity.head}`, 'cat-file', '--filters', `--path=${path}`, entry.blob]);
    if (attributes.text === 'unset') assert.deepEqual(checkedOut, blob, 'Binary source must remain byte-exact');
    return { path, sha256: localHash(checkedOut) };
  });
  recheck();
  const handle = Object.freeze({ kind: 'verified-stage-checkout-binding' });
  checkoutBindings.set(handle, { root, head: identity.head, version: identity.version, files, recheck });
  return handle;
}

export function requireStageProofCheckout(checkout, root, sourceHead, version) {
  const binding = checkoutBindings.get(checkout);
  assert.ok(binding, 'A verified Git checkout binding is required; report hashes are not a binding');
  assert.equal(binding.root, physical(root));
  assert.equal(binding.head, sourceHead);
  assert.equal(binding.version, version);
  binding.recheck();
  return binding.files.map(file => ({ ...file }));
}

export function stageChildArgs(paths, mode, root, cli, home) {
  if (mode === 'deny-control') return [paths.join(root, 'tools/npm-publication/offline-stage/control.cjs')];
  if (mode === 'dual-audience' ||
      mode.startsWith('fulcio-')) {
    return [paths.join(root, 'tools/npm-publication/offline-stage/services.cjs'), root, cli, mode, home];
  }
  if (mode.startsWith('loader-')) {
    return [paths.join(root, 'tools/npm-publication/offline-stage/loader.cjs'), root, cli, mode, home];
  }
  const script = paths.join(root, 'tools/npm-publication/offline-stage',
    mode === 'oidc' ? 'oidc.cjs' : 'npm.cjs');
  return mode === 'oidc' ? [script, cli, home] : [script, root, cli, mode, home];
}

export function validateStageProof(report, { root, version, invocation, checkout, sourceHead }) {
  exactLocalKeys(report, ['schemaVersion', 'kind', 'status', 'syntheticOnly', 'node', 'npm',
    'version', 'releaseReady', 'authenticated', 'realSigning', 'realRegistry', 'files', 'invocation', 'cases']);
  assert.equal(report.schemaVersion, 4);
  assert.equal(report.kind, 'pinned-npm12-offline-stage-proof');
  assert.equal(report.status, 'passed');
  assert.equal(report.syntheticOnly, true);
  assert.equal(report.node, 'v24.21.0');
  assert.equal(report.npm, '12.0.2');
  assert.equal(report.version, version);
  for (const key of ['releaseReady', 'authenticated', 'realSigning', 'realRegistry']) assert.equal(report[key], false);
  const expectedFiles = checkout === undefined ? proofFiles(root) :
    requireStageProofCheckout(checkout, root, sourceHead, version);
  assert.deepEqual(report.files, expectedFiles);
  exactLocalKeys(report.invocation, ['root', 'cli', 'node', 'home']);
  if (invocation) assert.deepEqual(report.invocation, invocation, 'Stage proof command/cwd differs');
  const paths = report.invocation.root.includes('\\') ? win32 : { join };
  assert.deepEqual(report.cases.map(item => item.mode), STAGE_SCENARIOS);
  for (const item of report.cases) {
    exactLocalKeys(item, ['mode', 'command', 'sha256']);
    const command = item.command;
    assert.equal(localHash(JSON.stringify(command)), item.sha256);
    exactLocalKeys(command, ['executable', 'args', 'cwd', 'timeoutMs', 'elapsedMs',
      'exitCode', 'signal', 'error', 'stdout', 'stderr']);
    assert.equal(command.executable, report.invocation.node);
    assert.equal(command.cwd, report.invocation.root);
    assert.deepEqual(command.args, stageChildArgs(paths, item.mode, report.invocation.root,
      report.invocation.cli, paths.join(report.invocation.home, item.mode)));
    assert.equal(command.timeoutMs, STAGE_CHILD_TIMEOUT);
    assert.ok(Number.isSafeInteger(command.elapsedMs) &&
      command.elapsedMs >= 0 &&
      command.elapsedMs <= STAGE_CHILD_TIMEOUT);
    assert.equal(command.exitCode, stageProofExit(item.mode));
    assert.equal(command.signal, null);
    assert.equal(command.error, null);
    for (const key of ['stdout', 'stderr']) {
      assert.ok(typeof command[key] === 'string' &&
        Buffer.byteLength(command[key]) <= 1024 * 1024);
    }
    const lines = command.stdout.trimEnd().split('\n');
    const value = JSON.parse(lines.at(-1));
    assert.equal(value.syntheticOnly, true);
    if (item.mode === 'deny-control') {
      assert.equal(value.mode, item.mode);
      assert.equal(value.passed, true);
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.blocked, DENIAL_COVERAGE.length);
      assert.deepEqual(value.coverage, DENIAL_COVERAGE);
      assert.equal(value.underlayCalls, 0);
      assert.equal(value.realIo, false);
      continue;
    }
    assert.deepEqual(value.deniedHostAttempts, []);
    if (item.mode === 'dual-audience' ||
        item.mode.startsWith('fulcio-')) {
      assert.equal(value.mode, item.mode);
      assert.equal(value.passed, true);
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.realSigning, false);
      assert.equal(value.realCertificateIssued, false);
      assert.equal(value.realTokenObtained, false);
      assert.equal(value.stageRequests, 0);
      assert.ok(Number.isSafeInteger(value.elapsedMs) &&
        value.elapsedMs >= 0 &&
        value.elapsedMs <= STAGE_CHILD_TIMEOUT);
      if (item.mode === 'dual-audience') {
        assert.deepEqual(value.requests, [
          { kind: 'issuer', audience: 'npm:registry.npmjs.org', protocol: 'https:', method: 'GET' },
          { kind: 'exchange', protocol: 'https:', method: 'POST' },
          { kind: 'issuer', audience: 'sigstore', protocol: 'https:', method: 'GET' },
        ]);
        assert.deepEqual(value.outerOptions, []);
        assert.equal(value.configuredRetries, undefined);
        assert.equal(value.configuredTimeoutMs, undefined);
      } else {
        assert.deepEqual(value.outerOptions, [{ retries: 0, timeoutMs: 30_000 }]);
        assert.equal(value.configuredRetries, item.mode.includes('default') ? 2 : 0);
        assert.equal(value.configuredTimeoutMs, item.mode.includes('default') ? 5000 : 300_000);
        assert.deepEqual(value.requests, [{ kind: 'certificate', protocol: 'https:', method: 'POST',
          identityInBody: true, authorizationHeader: false, timeoutMs: 30_000,
          responseLimit: 256 * 1024, lowerRetries: 0 }]);
        if (item.mode === 'fulcio-deadline') assert.ok(value.elapsedMs >= 29_000);
      }
      continue;
    }
    if (item.mode.startsWith('loader-')) {
      assert.equal(value.mode, item.mode);
      assert.equal(value.passed, true);
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.unpinnedEntryExecuted, false);
      assert.equal(value.originalVendorModified, false);
      assert.equal(value.ownedVendor, paths.join(report.invocation.home, item.mode, 'npm-owned'));
      continue;
    }
    if (item.mode.startsWith('issuer-') ||
        item.mode.startsWith('provider-')) {
      assert.equal(value.mode, item.mode);
      assert.equal(value.passed, true);
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.stageCalls, 0);
      assert.equal(value.attestStubCalls, 0);
      const provider = item.mode.startsWith('provider-');
      const invalidUrl = ['issuer-http', 'issuer-userinfo', 'issuer-fragment'].includes(item.mode);
      assert.equal(value.requests.length, invalidUrl ? 0 : 1);
      if (provider) {
        assert.equal(value.provider, 'actual-CIContextProvider');
        assert.equal(value.realSigning, false);
        assert.ok(Number.isSafeInteger(value.elapsedMs) &&
          value.elapsedMs >= 0 &&
          value.elapsedMs <= STAGE_CHILD_TIMEOUT);
        if (item.mode === 'provider-deadline') assert.ok(value.elapsedMs >= 29_000);
      } else assert.equal(value.observedCliExit, 1);
      for (const request of value.requests) {
        assert.deepEqual(request, { path: '/oidc', method: 'GET', protocol: 'https:',
          audience: provider ? 'sigstore' : 'npm:registry.npmjs.org',
          credentialHeaderPresent: true, retry: { retries: 0 }, timeout: 30_000,
          size: 64 * 1024, signalPresent: true, apiVersion: '2.0', originalRequest: 'fixture-original' });
      }
      continue;
    }
    if (item.mode === 'oidc') {
      assert.equal(value.actualNpm, '12.0.2');
      assert.equal(value.savedBundleReplaced, true);
      assert.equal(value.automaticAttestStubCalls, 1);
      assert.equal(value.savedVerifyStubCalls, 0);
      assert.equal(value.bothExplicitFlagsRejected, true);
    } else if (item.mode === 'admission') {
      assert.equal(value.mode, 'admission');
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.npm, '12.0.2');
      assert.equal(value.passed, true);
      assert.equal(value.controls, 4);
      assert.equal(value.stageCalls, 0);
      assert.equal(value.attestStubCalls, 0);
      assert.equal(value.entrypoint, 'stage-child.mjs');
      assert.deepEqual(value.requests, []);
    } else {
      assert.equal(value.passed, true);
      assert.equal(value.mode, item.mode);
      assert.equal(value.lane, report.invocation.root);
      assert.equal(value.actualNode, '24.21.0');
      assert.equal(value.npm, '12.0.2');
      assert.equal(value.stageCalls, 1);
      assert.equal(value.attestStubCalls, item.mode === 'cli' ? 1 : 2);
      assert.equal(value.unknownRetained, true);
      assert.equal(value.successRetained, ['cli', 'success'].includes(item.mode));
      localSha(value.requestSha256);
      localSha(value.bundleSha256);
      exactLocalKeys(value.fixtureEvidence, ['body', 'bundle', 'intent', 'receipt']);
      const evidence = value.fixtureEvidence;
      for (const key of ['body', 'bundle', 'intent']) assert.equal(typeof evidence[key], 'string');
      const expected = fixture(version);
      const metadata = JSON.parse(evidence.body);
      const tarball = Buffer.from(metadata._attachments[`mcp-pacemaker-${version}.tgz`].data, 'base64');
      assert.deepEqual(gunzipSync(tarball, { maxOutputLength: 1024 * 1024 }),
        gunzipSync(expected.bytes), 'Offline CLI/SDK did not submit the exact synthetic package');
      const record = { ...expected.record, artifact: digest(tarball) };
      const body = inspectStageBody(evidence.body, record);
      assert.equal(value.requestSha256, body.request.sha256);
      assert.equal(value.bundleSha256, body.bundle.sha256);
      assert.deepEqual(Buffer.from(evidence.bundle), body.bundleBytes);
      const bundle = JSON.parse(evidence.bundle);
      const payload = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
      const expectedPayload = structuredClone(expected.payload);
      expectedPayload.subject[0].digest.sha512 = record.artifact.sha512;
      Object.assign(expectedPayload.predicate.buildDefinition.internalParameters.github,
        { repository_id: '789', repository_owner_id: '10' });
      assert.deepEqual(payload, expectedPayload, 'Actual npm provenance must preserve the original fixture GitHub claims');
      const base = { schemaVersion: 1, kind: 'npm12-actual-stage-post-observation',
        authentication: 'requires-original-github-artifact', subject: body.subject,
        request: body.request, bundle: body.bundle, timeoutMs: CAPTURE_LIMITS.timeoutMs };
      assert.deepEqual(JSON.parse(evidence.intent), { ...base, status: 'submission-outcome-unknown' });
      if (['cli', 'success'].includes(item.mode)) {
        assert.equal(typeof evidence.receipt, 'string');
        const receipt = JSON.parse(evidence.receipt);
        assert.equal(receipt.response.sha256, localHash(JSON.stringify({ stageId: expected.stageId })));
        assert.equal(receipt.response.bytes, Buffer.byteLength(JSON.stringify({ stageId: expected.stageId })));
        validateCapture({ record, receiptBytes: Buffer.from(evidence.receipt), bundleBytes: body.bundleBytes });
      } else assert.equal(evidence.receipt, null, 'Unknown/redirected outcomes must not have a success receipt');
      assert.equal(value.captureDirectory, paths.join(report.invocation.home, item.mode, 'capture'));
      const post = { path: '/-/stage/package/mcp-pacemaker', method: 'POST' };
      assert.deepEqual(value.requests, item.mode === 'cli'
        ? [{ path: '/oidc', method: 'GET' },
          { path: '/-/npm/v1/oidc/token/exchange/package/mcp-pacemaker', method: 'POST' },
          { path: '/mcp-pacemaker', method: 'GET' }, post] : [post]);
      if (item.mode === 'cli') {
        const cliStdout = lines.slice(0, -1).join('\n').trim();
        npm12Contents(cliStdout, { version }, tarball, true);
        const output = JSON.parse(cliStdout);
        const contents = output['mcp-pacemaker'];
        assert.deepEqual(Object.keys(output), ['mcp-pacemaker']);
        assert.equal(contents.version, version);
        assert.equal(contents.name, 'mcp-pacemaker');
        assert.equal(contents.stageId, ['11111111', '1111', '1111', '1111', '111111111111'].join('-'));
        assert.equal(value.parentResult.stdoutSha256, localHash(lines.slice(0, -1).join('\n').trim()));
        assert.deepEqual(value.parentResult.capture, validateCapture({
          record, receiptBytes: Buffer.from(evidence.receipt), bundleBytes: body.bundleBytes,
        }));
      }
    }
  }
  return report;
}
