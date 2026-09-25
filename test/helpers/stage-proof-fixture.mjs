import { join, win32 } from 'node:path';
import { createRequire } from 'node:module';
import { CAPTURE_LIMITS, inspectStageBody, validateCapture } from '../../tools/npm-publication/stage-capture.mjs';
import { localHash } from '../../tools/npm-publication/local-regression.mjs';
import { DENIAL_COVERAGE, STAGE_SCENARIOS, STAGE_CHILD_TIMEOUT, proofFiles, stageChildArgs, stageProofExit } from '../../tools/npm-publication/stage-proof-contract.mjs';
const { fixture } = createRequire(import.meta.url)('../../tools/npm-publication/offline-stage/fixture.cjs');

// Producer-shaped unit-only receipts. No npm, signer, transport or process is run.
export function stageProofFixture(root, version, invocation) {
  const paths = invocation.root.includes('\\') ? win32 : { join };
  const f = fixture(version);
  Object.assign(f.payload.predicate.buildDefinition.internalParameters.github,
    { repository_id: '789', repository_owner_id: '10' });
  const bundle = f.bundleFor(Buffer.from(JSON.stringify(f.payload)));
  const attachment = f.body._attachments[`mcp-pacemaker-${version}.sigstore`];
  attachment.data = JSON.stringify(bundle);
  attachment.length = attachment.data.length;
  const bodyText = JSON.stringify(f.body);
  const body = inspectStageBody(bodyText, f.record);
  const base = { schemaVersion: 1, kind: 'npm12-actual-stage-post-observation',
    authentication: 'requires-original-github-artifact', subject: body.subject,
    request: body.request, bundle: body.bundle, timeoutMs: CAPTURE_LIMITS.timeoutMs };
  const response = JSON.stringify({ stageId: f.stageId });
  const receipt = { ...base, status: 'observed-successful-stage-response', elapsedMs: 1,
    response: { status: 200, stageId: f.stageId, bytes: Buffer.byteLength(response), sha256: localHash(response) } };
  const report = { schemaVersion: 4, kind: 'pinned-npm12-offline-stage-proof', status: 'passed',
    syntheticOnly: true, node: 'v24.21.0', npm: '12.0.2', version, releaseReady: false,
    authenticated: false, realSigning: false, realRegistry: false,
    files: proofFiles(root), invocation, cases: [] };
  for (const mode of STAGE_SCENARIOS) {
    const home = paths.join(invocation.home, mode);
    const post = { path: '/-/stage/package/mcp-pacemaker', method: 'POST' };
    let value = mode === 'deny-control' ? { syntheticOnly: true, mode, passed: true,
      blocked: DENIAL_COVERAGE.length, coverage: DENIAL_COVERAGE,
      underlayCalls: 0, actualNode: '24.21.0', realIo: false } : mode === 'oidc' ? { syntheticOnly: true, actualNpm: '12.0.2',
      savedBundleReplaced: true, automaticAttestStubCalls: 1, savedVerifyStubCalls: 0,
      bothExplicitFlagsRejected: true, deniedHostAttempts: [] } : mode === 'admission' ? {
      syntheticOnly: true, mode, actualNode: '24.21.0', npm: '12.0.2', passed: true,
      controls: 4, stageCalls: 0, attestStubCalls: 0, deniedHostAttempts: [], requests: [],
      entrypoint: 'stage-child.mjs',
    } : {
      syntheticOnly: true, mode, lane: invocation.root, npm: '12.0.2', actualNode: '24.21.0',
      stageCalls: 1, attestStubCalls: mode === 'cli' ? 1 : 2,
      requests: mode === 'cli' ? [{ path: '/oidc', method: 'GET' },
        { path: '/-/npm/v1/oidc/token/exchange/package/mcp-pacemaker', method: 'POST' },
        { path: '/mcp-pacemaker', method: 'GET' }, post] : [post],
      deniedHostAttempts: [], captureDirectory: paths.join(home, 'capture'), passed: true,
      requestSha256: body.request.sha256, bundleSha256: body.bundle.sha256,
      unknownRetained: true, successRetained: ['cli', 'success'].includes(mode),
      fixtureEvidence: { body: bodyText, bundle: body.bundleBytes.toString('utf8'),
        intent: JSON.stringify({ ...base, status: 'submission-outcome-unknown' }),
        receipt: ['cli', 'success'].includes(mode) ? JSON.stringify(receipt) : null },
    };
    if (mode.startsWith('loader-')) {
      value = { syntheticOnly: true, mode, passed: true, actualNode: '24.21.0',
        unpinnedEntryExecuted: false, deniedHostAttempts: [], originalVendorModified: false,
        ownedVendor: paths.join(home, 'npm-owned') };
    }
    if (mode.startsWith('issuer-') ||
        mode.startsWith('provider-')) {
      const provider = mode.startsWith('provider-');
      const invalidUrl = ['issuer-http', 'issuer-userinfo', 'issuer-fragment'].includes(mode);
      value = { syntheticOnly: true, mode, passed: true, actualNode: '24.21.0',
        stageCalls: 0, attestStubCalls: 0, deniedHostAttempts: [], requests: invalidUrl ? [] : [{
          path: '/oidc', method: 'GET', protocol: 'https:', audience: provider ? 'sigstore' : 'npm:registry.npmjs.org',
          credentialHeaderPresent: true, retry: { retries: 0 }, timeout: 30_000, size: 64 * 1024,
          signalPresent: true, apiVersion: '2.0', originalRequest: 'fixture-original',
        }], ...(provider ? { provider: 'actual-CIContextProvider', elapsedMs: mode === 'provider-deadline' ? 30_000 : 1,
          realSigning: false } : { observedCliExit: 1 }) };
    }
    if (mode === 'dual-audience' ||
        mode.startsWith('fulcio-')) {
      const pair = mode === 'dual-audience';
      value = { syntheticOnly: true, mode, passed: true, actualNode: '24.21.0',
        realSigning: false, realCertificateIssued: false, realTokenObtained: false,
        stageRequests: 0, deniedHostAttempts: [], elapsedMs: mode === 'fulcio-deadline' ? 30_000 : 1,
        ...(pair ? {
          requests: [
            { kind: 'issuer', audience: 'npm:registry.npmjs.org', protocol: 'https:', method: 'GET' },
            { kind: 'exchange', protocol: 'https:', method: 'POST' },
            { kind: 'issuer', audience: 'sigstore', protocol: 'https:', method: 'GET' },
          ], outerOptions: [],
        } : {
          requests: [{ kind: 'certificate', protocol: 'https:', method: 'POST', identityInBody: true,
            authorizationHeader: false, timeoutMs: 30_000, responseLimit: 256 * 1024, lowerRetries: 0 }],
          outerOptions: [{ retries: 0, timeoutMs: 30_000 }],
          configuredRetries: mode.includes('default') ? 2 : 0,
          configuredTimeoutMs: mode.includes('default') ? 5000 : 300_000,
        }) };
    }
    const cli = mode === 'cli' ? `${JSON.stringify({ 'mcp-pacemaker': {
      name: 'mcp-pacemaker', version, id: `mcp-pacemaker@${version}`,
      filename: `mcp-pacemaker-${version}.tgz`, size: f.bytes.length,
      integrity: f.record.artifact.integrity, shasum: f.sha(f.bytes, 'sha1'),
      files: [{ path: 'package.json', size: Buffer.byteLength(JSON.stringify(f.manifest)), mode: 0o644 }],
      entryCount: 1, bundled: [],
      stageId: ['11111111', '1111', '1111', '1111', '111111111111'].join('-'),
    } })}\n` : '';
    if (mode === 'cli') value.parentResult = { stdoutSha256: localHash(cli.trim()),
      capture: validateCapture({ record: f.record,
        receiptBytes: Buffer.from(JSON.stringify(receipt)), bundleBytes: body.bundleBytes }) };
    const command = { executable: invocation.node,
      args: stageChildArgs(paths, mode, invocation.root, invocation.cli, home), cwd: invocation.root,
      timeoutMs: STAGE_CHILD_TIMEOUT, elapsedMs: 1, exitCode: stageProofExit(mode), signal: null, error: null,
      stdout: `${cli}${JSON.stringify(value)}\n`, stderr: '' };
    report.cases.push({ mode, command, sha256: localHash(JSON.stringify(command)) });
  }
  return report;
}
