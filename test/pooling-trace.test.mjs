// Nested discrimination cases own port 8882; the ordinary API fixture keeps its port.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { PoolingTrace, TRACE_MAX_BYTES, TRACE_MAX_EVENTS, TRACE_MAX_LINE_BYTES,
  traceErrorCode, validateTraceRecord } from '../bin/pooling-trace.mjs';
import { PoolingTraceArtifact, TRACE_ARTIFACT_BYTES, validateTraceArtifact } from './helpers/pooling-trace-artifact.mjs';
import { killBridge } from './helpers/kill-bridge.mjs';

class TraceFixture {
  constructor(t) {
    this.directory = fs.mkdtempSync(join(tmpdir(), 'pooling-trace-test-'));
    this.source = join(this.directory, 'source');
    fs.mkdirSync(this.source);
    this.sink = new PoolingTrace(this.source);
    this.operation = this.sink.operation(process.hrtime.bigint() + 9000000000n);
    this.artifacts = new PoolingTraceArtifact();
    t.after(() => fs.rmSync(this.directory, { recursive: true, force: true }));
  }

  records() {
    return fs.readdirSync(this.source).flatMap((name) =>
      fs.readFileSync(join(this.source, name), 'utf8').trim().split('\n').map(JSON.parse));
  }

  collect() {
    return this.artifacts.collect(this.source, this.directory);
  }
}

test('disabled pooling tracing writes nothing and cannot initialize a writer', (t) => {
  const fixture = new TraceFixture(t);
  const disabled = new PoolingTrace();
  assert.equal(disabled.operation(process.hrtime.bigint() + 9000000000n), undefined);
  assert.deepEqual(fs.readdirSync(fixture.source), []);
});

test('trace and upload allowlists exclude input secrets, paths, names and raw files', (t) => {
  const fixture = new TraceFixture(t);
  const secret = 'private-fixture-secret-do-not-publish';
  for (const name of ['servers.json', 'servers.pending.json', 'admin.nonce', 'stderr.log']) {
    fs.writeFileSync(join(fixture.directory, name), JSON.stringify({
      command: secret, argv: [secret], name: secret, nonce: secret, credential: secret, path: secret,
    }));
  }
  fs.mkdirSync(join(fixture.directory, 'servers.json.pooling-transaction'));
  fs.writeFileSync(join(fixture.directory, 'servers.json.pooling-transaction', 'state-1.json'), secret);
  fixture.operation.record('request-start');
  fixture.operation.record('worker-error', { code: traceErrorCode({ code: secret, message: secret }), state: 2 });
  fixture.operation.record('body-end', { bytes: 12, command: secret, operation: secret });
  const artifact = fixture.collect();
  assert.equal(artifact.issues.includes('invalid-record'), true);
  const captured = join(fixture.directory, 'captured.json');
  const published = join(fixture.directory, 'upload', 'trace.json');
  fixture.artifacts.write(captured, artifact);
  fixture.artifacts.publish(captured, published);
  const emitted = [...fs.readdirSync(fixture.source).map((name) => join(fixture.source, name)), captured, published];
  for (const path of emitted) {
    const text = fs.readFileSync(path, 'utf8');
    assert.equal(text.includes(secret), false, 'A secret reached trace output.');
    assert.equal(text.includes(fixture.directory), false, 'A private path reached trace output.');
    assert.equal(/nonce|credential|argv|stderr|servers\.json/.test(text), false, 'A forbidden field reached trace output.');
  }
  assert.equal(artifact.files.pending.exists, true);
  assert.equal(artifact.capture, 'unsealed');
  const safe = fixture.records()[0];
  for (const field of ['command', 'path', 'name', 'env', 'nonce', 'revision', 'stderr']) {
    assert.throws(() => validateTraceRecord({ ...safe, [field]: secret }), /Invalid pooling trace/);
    assert.throws(() => validateTraceArtifact({ ...artifact, [field]: secret }), /Invalid pooling trace/);
  }
  assert.throws(() => validateTraceArtifact({ ...artifact, environment: { ...artifact.environment, env: secret } }));
  assert.throws(() => validateTraceArtifact({ ...artifact, files: { ...artifact.files, nonce: secret } }));
  assert.throws(() => validateTraceRecord({ ...safe, event: secret }));
  assert.throws(() => validateTraceRecord({ ...safe, elapsedMs: Infinity }));
  assert.throws(() => validateTraceRecord({ ...safe, operation: secret }));
  const original = fs.readFileSync(captured);
  assert.throws(() => fixture.artifacts.write(captured, artifact), { code: 'EEXIST' });
  assert.deepEqual(fs.readFileSync(captured), original);
  const secondSink = new PoolingTrace(fixture.source);
  secondSink.operation(process.hrtime.bigint() + 9000000000n).record('request-start');
  assert.equal(secondSink.failed, true);
  assert.deepEqual(fixture.records(), artifact.records);
});

test('trace bounds are hard and explicitly report truncation', (t) => {
  const fixture = new TraceFixture(t);
  for (let index = 0; index < TRACE_MAX_EVENTS * 2; index++) fixture.operation.record('request-start');
  const records = fixture.records();
  assert.equal(records.length, TRACE_MAX_EVENTS);
  assert.equal(records.at(-1).event, 'capture-truncated');
  for (const name of fs.readdirSync(fixture.source)) {
    assert.ok(fs.statSync(join(fixture.source, name)).size <= TRACE_MAX_BYTES);
  }
  assert.equal(fixture.collect().issues.includes('truncated'), true);
  assert.ok(Buffer.byteLength(JSON.stringify(fixture.collect())) <= TRACE_ARTIFACT_BYTES);
  const nearByteLimit = join(fixture.directory, 'byte-limit');
  fs.mkdirSync(nearByteLimit);
  const sink = new PoolingTrace(nearByteLimit);
  sink.bytes = TRACE_MAX_BYTES - TRACE_MAX_LINE_BYTES;
  sink.operation(process.hrtime.bigint() + 9000000000n).record('request-start');
  const limited = fixture.artifacts.collect(nearByteLimit, fixture.directory);
  assert.equal(limited.records.length, 1);
  assert.equal(limited.records[0].event, 'capture-truncated');
});

test('trace write failures do not replace operation failures and remain visible', (t) => {
  const fixture = new TraceFixture(t);
  const missing = join(fixture.directory, 'missing');
  const sink = new PoolingTrace(missing);
  const operation = sink.operation(process.hrtime.bigint() + 9000000000n);
  const original = new Error('original operation failure');
  assert.throws(() => {
    operation.record('request-start');
    throw original;
  }, (error) => error === original);
  assert.equal(sink.failed, true);
  fs.mkdirSync(missing);
  operation.record('request-start');
  const artifact = fixture.artifacts.collect(missing, fixture.directory);
  assert.equal(artifact.issues.includes('write-failed'), true);
  assert.equal(artifact.records[0].event, 'capture-failed');
  assert.equal(fixture.artifacts.collect(join(missing, 'absent'), fixture.directory)
    .issues.includes('missing-source'), true);
});

test('artifact collection refuses oversized, extra-field and partial input without leaking it', (t) => {
  const fixture = new TraceFixture(t);
  const secret = 'rejected-source-secret';
  fs.writeFileSync(join(fixture.source, '1-0.jsonl'), secret.repeat(TRACE_MAX_BYTES));
  fs.writeFileSync(join(fixture.source, '2-0.jsonl'), JSON.stringify({ command: secret }) + '\n');
  fs.writeFileSync(join(fixture.source, '3-0.jsonl'), secret);
  fs.writeFileSync(join(fixture.source, '4-0.jsonl'), 'x'.repeat(TRACE_MAX_LINE_BYTES + 1) + '\n');
  fs.writeFileSync(join(fixture.source, '5-0.jsonl'), secret);
  const artifact = fixture.collect();
  assert.equal(artifact.issues.includes('invalid-source'), true);
  assert.equal(artifact.issues.includes('source-limit'), true);
  assert.equal(JSON.stringify(artifact).includes(secret), false);
  assert.equal(artifact.records.length, 0);
  const input = join(fixture.directory, 'oversized.json');
  const output = join(fixture.directory, 'upload.json');
  fs.writeFileSync(input, ' '.repeat(TRACE_ARTIFACT_BYTES + 1));
  assert.throws(() => fixture.artifacts.publish(input, output), /Invalid pooling trace input/);
  assert.equal(fs.existsSync(output), false);
  fs.writeFileSync(input, JSON.stringify({ ...artifact, secret }));
  assert.throws(() => fixture.artifacts.publish(input, output), /Invalid pooling trace artifact/);
  assert.equal(fs.existsSync(output), false);
  const mismatched = join(fixture.directory, 'mismatched');
  fs.mkdirSync(mismatched);
  new PoolingTrace(mismatched).operation(process.hrtime.bigint() + 9000000000n).record('request-start');
  fs.renameSync(join(mismatched, fs.readdirSync(mismatched)[0]), join(mismatched, '1-0.jsonl'));
  const mismatch = fixture.artifacts.collect(mismatched, fixture.directory);
  assert.equal(mismatch.issues.includes('invalid-source'), true);
  assert.deepEqual(mismatch.records, []);
});

// Faults are local opt-in proof only; normal npm test never injects these delays.
const runFaults = process.platform === 'win32' &&
  process.env.MCP_POOLING_TRACE_RUN_FAULTS === '1';
for (const fault of ['worker-start', 'first-helper', 'post-stage']) {
  test(`real deadline diagnostics distinguish ${fault} without changing the original failure`,
    { skip: !runFaults, timeout: 40000 }, async (t) => {
      const fixture = new TraceFixture(t);
      const output = join(fixture.directory, 'captured');
      const env = { ...process.env, MCP_POOLING_API_TEST_PORT: '8882',
        MCP_POOLING_TRACE_ARTIFACT_DIR: output, MCP_POOLING_TRACE_TEST_FAULT: fault,
        NODE_OPTIONS: `--import=${new URL('./helpers/pooling-trace-faults.mjs', import.meta.url).href}` };
      // An inherited child-v8 context makes Node skip this nested runner entirely.
      delete env.NODE_TEST_CONTEXT;
      const child = spawn(process.execPath, [
        '--test', '--test-concurrency=1', '--test-name-pattern=one-click apply and undo',
        fileURLToPath(new URL('./pooling-api.test.mjs', import.meta.url)),
      ], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env,
      });
      let text = '';
      let truncated = false;
      child.stdout.on('data', (chunk) => {
        if (text.length + chunk.length <= 131072) text += chunk;
        else truncated = true;
      });
      child.stderr.resume();
      const exited = once(child, 'exit');
      const guard = setTimeout(() => killBridge(child), 30000);
      t.after(() => { clearTimeout(guard); killBridge(child); });
      const [exitCode] = await exited;
      clearTimeout(guard);
      const originalFailure = text.includes('504 !== 202') &&
        text.includes('Pooling change expired before config commit. Reread the config.');
      let artifact;
      let captureFailed = false;
      try {
        const path = join(output, 'captured.json');
        artifact = validateTraceArtifact(JSON.parse(fs.readFileSync(path, 'utf8')));
        if (process.env.MCP_POOLING_TRACE_PROOF_DIR) {
          fixture.artifacts.publish(path, join(process.env.MCP_POOLING_TRACE_PROOF_DIR, `${fault}.json`));
        }
      } catch {
        captureFailed = true;
      }
      t.diagnostic(`POOLING_TRACE_CHILD ${JSON.stringify({ fault, exitCode, truncated,
        originalFailure, captureFailed })}`);
      assert.equal(truncated, false);
      assert.equal(exitCode, 1, 'The unchanged 202 assertion must still fail.');
      assert.equal(originalFailure, true, 'The controlled operation must retain the original failure.');
      assert.equal(captureFailed, false, 'Safe proof capture must succeed.');
      assert.deepEqual(artifact.issues, []);
      const records = artifact.records;
      const response = records.find((record) => record.event === 'response');
      assert.equal(response.status, 504);
      assert.ok(response.elapsedMs >= 8900 && response.elapsedMs < 10000);
      assert.equal(records.some((record) => record.event === 'writer-expire'), true);
      const helpers = records.filter((record) => record.event === 'helper-start');
      if (fault === 'worker-start') {
        assert.equal(helpers.length, 0);
        assert.equal(artifact.files.pending.exists, false);
      } else {
        const selected = fault === 'first-helper' ? 1 : 4;
        assert.equal(helpers.length, selected);
        const result = records.find((record) => record.event === 'helper-end' && record.call === selected);
        assert.equal(result.code, 'ETIMEDOUT');
        assert.ok(result.helperPid > 0);
        assert.equal(artifact.files.pending.exists, fault === 'post-stage');
        if (fault === 'post-stage') {
          assert.equal(records.some((record) => record.event === 'helper-end' &&
            record.action === 'stage' && record.exit === 0), true);
        }
      }
      t.diagnostic(`POOLING_TRACE_PROOF ${JSON.stringify({ fault, status: response.status,
        elapsedMs: response.elapsedMs, pid: response.pid, helpers: helpers.length,
        pending: artifact.files.pending.exists, capture: artifact.capture })}`);
    });
}
