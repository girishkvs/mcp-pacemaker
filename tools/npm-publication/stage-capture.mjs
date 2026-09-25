import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, openSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const STAGE_URL = 'https://registry.npmjs.org/-/stage/package/mcp-pacemaker';
export const CAPTURE_LIMITS = Object.freeze({
  body: 64 * 1024 * 1024, bundle: 2 * 1024 * 1024, response: 64 * 1024, timeoutMs: 30_000,
});
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const artifact = bytes => ({
  sha256: sha256(bytes), sha512: createHash('sha512').update(bytes).digest('hex'),
  integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
});
const keys = (value, expected) => {
  assert.ok(value &&
    typeof value === 'object' &&
    !Array.isArray(value), 'Missing capture object');
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), 'Unexpected capture fields');
};
const bounded = (bytes, limit) => {
  assert.ok(Buffer.isBuffer(bytes) &&
    bytes.length > 0 &&
    bytes.length <= limit, 'Missing or oversized capture bytes');
};
const stageId = value => assert.match(value ?? '',
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i, 'Unknown stage response; do not retry');
const json = bytes => {
  const text = bytes.toString('utf8');
  assert.deepEqual(Buffer.from(text), bytes, 'Non-UTF8 capture');
  return JSON.parse(text);
};

export function captureSubject(record) {
  const subject = {
    name: record.name, version: record.version, channel: record.channel,
    source: record.source, workflow: record.workflow, artifact: record.artifact,
  };
  assert.equal(subject.name, 'mcp-pacemaker');
  assert.ok(['1.3.1', '2.0.1'].includes(subject.version));
  assert.equal(subject.channel, subject.version === '1.3.1' ? 'legacy' : 'latest');
  keys(subject.source, ['ref', 'tagObject', 'commit', 'tree']);
  for (const key of ['tagObject', 'commit', 'tree']) assert.match(subject.source[key], /^[a-f0-9]{40}$/);
  assert.ok(subject.source.ref.startsWith('refs/tags/'));
  keys(subject.workflow, ['ref', 'commit', 'runId', 'attempt']);
  assert.equal(subject.workflow.ref,
    `girishkvs/mcp-pacemaker/.github/workflows/npm-publish.yml@${subject.source.ref}`);
  assert.equal(subject.workflow.commit, subject.source.commit);
  assert.match(subject.workflow.runId, /^[1-9][0-9]*$/);
  assert.equal(subject.workflow.attempt, 1);
  keys(subject.artifact, ['sha256', 'sha512', 'integrity']);
  assert.match(subject.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.match(subject.artifact.sha512, /^[a-f0-9]{128}$/);
  assert.equal(subject.artifact.integrity,
    `sha512-${Buffer.from(subject.artifact.sha512, 'hex').toString('base64')}`);
  return structuredClone(subject);
}

export function inspectStageBody(body, expected) {
  const subject = captureSubject(expected);
  assert.equal(typeof body, 'string', 'Stage transport must receive the actual serialized JSON');
  assert.ok(Buffer.byteLength(body) <= CAPTURE_LIMITS.body, 'Oversized stage request');
  const bytes = Buffer.from(body);
  bounded(bytes, CAPTURE_LIMITS.body);
  const metadata = json(bytes);
  assert.equal(JSON.stringify(metadata), body, 'Unexpected npm JSON serialization');
  assert.equal(metadata._id, subject.name);
  assert.equal(metadata.name, subject.name);
  assert.equal(metadata.access, 'public');
  assert.deepEqual(metadata['dist-tags'], { [subject.channel]: subject.version });
  keys(metadata.versions, [subject.version]);
  const manifest = metadata.versions[subject.version];
  assert.equal(manifest.name, subject.name);
  assert.equal(manifest.version, subject.version);
  assert.equal(manifest.dist.integrity, subject.artifact.integrity);
  const stem = `${subject.name}-${subject.version}`;
  keys(metadata._attachments, [`${stem}.tgz`, `${stem}.sigstore`]);
  const tarball = metadata._attachments[`${stem}.tgz`];
  keys(tarball, ['content_type', 'data', 'length']);
  assert.equal(tarball.content_type, 'application/octet-stream');
  assert.equal(typeof tarball.data, 'string');
  const tarBytes = Buffer.from(tarball.data, 'base64');
  assert.equal(tarBytes.toString('base64'), tarball.data);
  assert.equal(tarball.length, tarBytes.length);
  assert.deepEqual(artifact(tarBytes), subject.artifact, 'POST differs from approved tarball');
  assert.equal(manifest.dist.shasum, createHash('sha1').update(tarBytes).digest('hex'));
  const attachment = metadata._attachments[`${stem}.sigstore`];
  keys(attachment, ['content_type', 'data', 'length']);
  assert.equal(typeof attachment.data, 'string', 'npm12 Sigstore data is JSON text, not base64');
  assert.equal(attachment.length, attachment.data.length);
  assert.ok(Buffer.byteLength(attachment.data) <= CAPTURE_LIMITS.bundle, 'Oversized stage bundle');
  const bundleBytes = Buffer.from(attachment.data);
  bounded(bundleBytes, CAPTURE_LIMITS.bundle);
  const bundle = json(bundleBytes);
  assert.equal(JSON.stringify(bundle), attachment.data);
  assert.equal(attachment.content_type, bundle.mediaType);
  assert.ok(['application/vnd.dev.sigstore.bundle.v0.3+json',
    'application/vnd.dev.sigstore.bundle+json;version=0.2'].includes(bundle.mediaType));
  assert.equal(bundle.dsseEnvelope?.payloadType, 'application/vnd.in-toto+json');
  const payload = json(Buffer.from(bundle.dsseEnvelope.payload, 'base64'));
  assert.deepEqual(payload.subject, [{
    name: `pkg:npm/${subject.name}@${subject.version}`, digest: { sha512: subject.artifact.sha512 },
  }]);
  return { subject, bundleBytes, request: {
    method: 'POST', url: STAGE_URL, sha256: sha256(bytes), bytes: bytes.length,
  }, bundle: { sha256: sha256(bundleBytes), bytes: bundleBytes.length } };
}

export function durableCaptureSink(directory) {
  return (name, bytes) => {
    assert.ok(['intent.json', 'provenance.sigstore', 'receipt.json'].includes(name));
    const fd = openSync(join(directory, name), 'wx', 0o600);
    try {
      writeFileSync(fd, bytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };
}

// This receipt is an observation, not a signature or authorization. Only the
// authenticated original hosted artifact can establish where it came from.
export function captureTransport({ fetcher, expected, save, secrets = [],
  timeoutMs = CAPTURE_LIMITS.timeoutMs }) {
  assert.ok(Number.isSafeInteger(timeoutMs) &&
    timeoutMs > 0 &&
    timeoutMs <= CAPTURE_LIMITS.timeoutMs);
  let spent = false;
  return async (uri, options) => {
    assert.equal(String(uri), STAGE_URL, 'Only the exact stage endpoint is supported');
    assert.equal(options.method, 'POST', 'Direct publish/approval is not supported');
    assert.equal(spent, false, 'Stage attempt already spent; never retry');
    spent = true;
    const capture = inspectStageBody(options.body, expected);
    const authorization = new Headers(options.headers).get('authorization') ?? '';
    const credentials = [...secrets, authorization, authorization.slice(authorization.indexOf(' ') + 1)]
      .filter(Boolean);
    for (const secret of credentials) {
      assert.equal(capture.bundleBytes.includes(Buffer.from(secret)), false,
        'Credential-like bytes in capture; refusing retention');
    }
    const base = { schemaVersion: 1, kind: 'npm12-actual-stage-post-observation',
      authentication: 'requires-original-github-artifact', subject: capture.subject,
      request: capture.request, bundle: capture.bundle, timeoutMs };
    save('provenance.sigstore', capture.bundleBytes);
    save('intent.json', Buffer.from(JSON.stringify({ ...base, status: 'submission-outcome-unknown' })));
    const controller = new AbortController();
    const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
    let response;
    let timer;
    const start = performance.now();
    const operation = async () => {
      signal.throwIfAborted();
      response = await fetcher(uri, {
        ...options, redirect: 'error', retry: { retries: 0 }, strictSSL: true,
        timeout: timeoutMs, signal, cache: 'no-store', cachePath: undefined,
        proxy: undefined, noProxy: '*', size: CAPTURE_LIMITS.response,
      });
      signal.throwIfAborted();
      assert.ok([200, 201].includes(response.status), 'Unknown stage response; do not retry');
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        signal.throwIfAborted();
        size += chunk.length;
        assert.ok(size <= CAPTURE_LIMITS.response, 'Oversized stage response; do not retry');
        chunks.push(Buffer.from(chunk));
      }
      const bytes = Buffer.concat(chunks);
      bounded(bytes, CAPTURE_LIMITS.response);
      const parsed = json(bytes);
      stageId(parsed.stageId);
      signal.throwIfAborted();
      const receipt = { ...base, status: 'observed-successful-stage-response',
        response: { status: response.status, sha256: sha256(bytes), bytes: bytes.length,
          stageId: parsed.stageId }, elapsedMs: Math.ceil(performance.now() - start) };
      save('receipt.json', Buffer.from(JSON.stringify(receipt)));
      // npm-registry-fetch expects a live response body. Return the original
      // consumed response with only its JSON reader replaced, using the same bytes.
      response.json = async () => json(bytes);
      return response;
    };
    try {
      return await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          response?.body?.destroy?.();
          reject(new Error('Stage deadline exceeded; outcome unknown, never retry'));
        }, timeoutMs);
      })]);
    } catch {
      controller.abort();
      response?.body?.destroy?.();
      throw new Error('Stage submission/capture failed; outcome unknown, never retry');
    } finally {
      clearTimeout(timer);
    }
  };
}

export function validateCapture({ record, receiptBytes, bundleBytes }) {
  bounded(receiptBytes, 32 * 1024);
  bounded(bundleBytes, CAPTURE_LIMITS.bundle);
  const receipt = json(receiptBytes);
  keys(receipt, ['schemaVersion', 'kind', 'authentication', 'subject', 'request', 'bundle',
    'timeoutMs', 'status', 'response', 'elapsedMs']);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.kind, 'npm12-actual-stage-post-observation');
  assert.equal(receipt.authentication, 'requires-original-github-artifact');
  assert.equal(receipt.status, 'observed-successful-stage-response');
  assert.deepEqual(receipt.subject, captureSubject(record));
  keys(receipt.request, ['method', 'url', 'sha256', 'bytes']);
  assert.equal(receipt.request.method, 'POST');
  assert.equal(receipt.request.url, STAGE_URL);
  assert.match(receipt.request.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(receipt.request.bytes) &&
    receipt.request.bytes > bundleBytes.length &&
    receipt.request.bytes <= CAPTURE_LIMITS.body);
  assert.deepEqual(receipt.bundle, { sha256: sha256(bundleBytes), bytes: bundleBytes.length });
  assert.equal(receipt.timeoutMs, CAPTURE_LIMITS.timeoutMs);
  keys(receipt.response, ['status', 'sha256', 'bytes', 'stageId']);
  assert.ok([200, 201].includes(receipt.response.status));
  assert.match(receipt.response.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(receipt.response.bytes) &&
    receipt.response.bytes > 0 &&
    receipt.response.bytes <= CAPTURE_LIMITS.response);
  stageId(receipt.response.stageId);
  assert.equal(receipt.response.stageId, record.stageId);
  assert.ok(Number.isSafeInteger(receipt.elapsedMs) &&
    receipt.elapsedMs >= 0 &&
    receipt.elapsedMs <= CAPTURE_LIMITS.timeoutMs);
  return { stageId: receipt.response.stageId, receiptSha256: sha256(receiptBytes),
    bundleSha256: sha256(bundleBytes) };
}
