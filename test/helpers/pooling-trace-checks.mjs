// Imported by pooling-api.test.mjs, which is already in the explicit npm test list.
// Nested discrimination cases own ports 8882 and 8883.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { threadId } from 'node:worker_threads';
import { PoolingTrace, TRACE_MAX_BYTES, TRACE_MAX_EVENTS, TRACE_MAX_LINE_BYTES,
  traceErrorCode, validateTraceRecord } from '../../bin/pooling-trace.mjs';
import { PoolingTraceArtifact, TRACE_ARTIFACT_BYTES, validateTraceArtifact } from './pooling-trace-artifact.mjs';
import { PoolingTraceFixture } from './pooling-trace-fixture.mjs';
import { killBridge } from './kill-bridge.mjs';

const targets = {
  api: 'one-click apply and undo preserve active sessions even when file watching is off',
  batch: 'batch API stages a complete copy and activates only after the five-second reload',
};

class TraceFixture {
  constructor(t) {
    this.directory = fs.mkdtempSync(join(tmpdir(), 'pooling-trace-test-'));
    this.source = join(this.directory, 'source');
    fs.mkdirSync(this.source);
    this.sinks = [];
    this.sink = this.createSink(this.source);
    this.operation = this.sink.operation(process.hrtime.bigint() + 9000000000n);
    this.artifacts = new PoolingTraceArtifact();
    this.diagnostics = [];
    t.after(() => {
      for (const sink of this.sinks) sink.close();
      fs.rmSync(this.directory, { recursive: true, force: true });
    });
  }

  createSink(directory) {
    const sink = new PoolingTrace(directory);
    this.sinks.push(sink);
    return sink;
  }

  records() {
    return fs.readdirSync(this.source).flatMap((name) =>
      fs.readFileSync(join(this.source, name), 'utf8').trim().split('\n').map(JSON.parse));
  }

  collect() {
    return this.artifacts.collect(this.source, this.directory);
  }

  deadlineRecords(event) {
    this.operation.record(event, event === 'writer-expire'
      ? { expired: true, state: 4 } : { code: 'WRITER_DEADLINE', state: 4 });
    this.operation.record('response', { status: 504 });
    return this.records().map((record, index) =>
      ({ ...record, elapsedMs: 9001 + index, remainingMs: -1 - index }));
  }

  deadlineResponse(records) {
    const response = records.find((record) => record.event === 'response');
    assert.ok(response, 'The controlled operation must record its response.');
    assert.equal(response.status, 504);
    assert.ok(response.elapsedMs >= 8900 && response.elapsedMs < 10000);
    const outcome = records.find((record) => {
      const isDeadline = (record.event === 'writer-expire' && record.expired === true) ||
        (record.event === 'writer-result' && record.code === 'WRITER_DEADLINE');
      return isDeadline &&
        record.operation === response.operation &&
        record.pid === response.pid &&
        record.thread === response.thread &&
        record.sequence < response.sequence;
    });
    assert.ok(outcome, 'The response must follow a deadline outcome from the same writer.');
    assert.ok(outcome.remainingMs <= 0 && outcome.elapsedMs <= response.elapsedMs,
      'The writer deadline must have elapsed before its response.');
    return response;
  }

  capture(target = 'api') {
    const capture = new PoolingTraceFixture({
      name: targets[target], diagnostic: (line) => this.diagnostics.push(line),
    }, this.directory, target);
    capture.directory = this.source;
    capture.destination = join(this.directory, 'captured');
    return capture;
  }
}

for (const event of ['writer-expire', 'writer-result']) {
  test(`deadline trace accepts the ${event} deadline path`, (t) => {
    const fixture = new TraceFixture(t);
    const records = fixture.deadlineRecords(event);
    records.forEach(validateTraceRecord);
    assert.equal(fixture.deadlineResponse(records), records[1]);
  });
}

for (const [name, change] of [
  ['unrelated failure', (record) => { record.code = 'IO_ERROR'; }],
  ['different operation', (record) => { record.operation = '00000000-0000-4000-8000-000000000000'; }],
  ['different process', (record) => { record.pid += 1; }],
  ['different thread', (record) => { record.thread += 1; }],
  ['outcome after response', (record) => { record.sequence += 2; }],
  ['unexpired budget', (record) => { record.remainingMs = 1; }],
]) {
  test(`deadline trace rejects ${name}`, (t) => {
    const fixture = new TraceFixture(t);
    const records = fixture.deadlineRecords('writer-result');
    change(records[0]);
    assert.throws(() => fixture.deadlineResponse(records));
  });
}

test('deadline trace rejects cancellation and missing deadline evidence', (t) => {
  const fixture = new TraceFixture(t);
  const records = fixture.deadlineRecords('writer-expire');
  records[0].expired = false;
  assert.throws(() => fixture.deadlineResponse(records));
  assert.throws(() => fixture.deadlineResponse(records.slice(1)));
});

test('disabled pooling tracing writes nothing and cannot initialize a writer', (t) => {
  const fixture = new TraceFixture(t);
  const disabled = new PoolingTrace();
  assert.equal(disabled.operation(process.hrtime.bigint() + 9000000000n), undefined);
  const capture = new PoolingTraceFixture({
    name: 'unselected test', diagnostic: (line) => fixture.diagnostics.push(line),
  }, fixture.directory, 'api');
  capture.finish();
  assert.equal(capture.directory, undefined);
  assert.deepEqual(fixture.diagnostics, []);
  assert.deepEqual(fs.readdirSync(fixture.source), []);
});

test('trace metadata handles absent, default-zero and explicit runner concurrency', () => {
  const artifacts = new PoolingTraceArtifact();
  for (const args of [[], ['--test-concurrency=0']]) {
    assert.deepEqual(artifacts.concurrency(args, 4),
      { effectiveConcurrency: 3, concurrencySource: 'node-default' });
    assert.deepEqual(artifacts.concurrency(args, 1),
      { effectiveConcurrency: 1, concurrencySource: 'node-default' });
  }
  assert.deepEqual(artifacts.concurrency(['--test-concurrency=1'], 4),
    { effectiveConcurrency: 1, concurrencySource: 'explicit' });
  assert.deepEqual(artifacts.concurrency(['--test-concurrency=2'], 4),
    { effectiveConcurrency: 2, concurrencySource: 'explicit' });
  assert.throws(() => artifacts.concurrency(['--test-concurrency=private-invalid-value'], 4),
    /Unsupported pooling trace concurrency/);
});

test('trace collection retains safe phases when environment metadata fails validation or collection', (t) => {
  const fixture = new TraceFixture(t);
  fixture.operation.record('request-start');
  fixture.operation.record('helper-start', { action: 'inspect-access', call: 1, timeoutMs: 9000 });
  const capture = fixture.capture();
  const secret = 'private-environment-metadata';
  for (const failure of ['invalid', 'throws']) {
    capture.artifacts.environment = () => {
      if (failure === 'throws') throw new Error(secret);
      return { ...fixture.artifacts.environment(), cpuModel: secret, effectiveConcurrency: 0 };
    };
    const artifact = capture.artifacts.collect(fixture.source, fixture.directory);
    assert.equal(artifact.environment, null);
    assert.deepEqual(artifact.issues, ['metadata-unavailable']);
    assert.equal(artifact.records.length, 2);
    assert.equal(artifact.records[1].event, 'helper-start');
    assert.throws(() => validateTraceArtifact({ ...artifact, issues: [] }), /Invalid pooling trace artifact/);
    capture.destination = undefined;
    capture.finish();
    const rendered = fixture.diagnostics.at(-1);
    assert.ok(rendered.startsWith('POOLING_TRACE '));
    assert.equal(rendered.includes(secret), false);
    assert.deepEqual(JSON.parse(rendered.slice('POOLING_TRACE '.length)).records, artifact.records);
  }
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
  const capture = fixture.capture();
  capture.finish();
  const emitted = [...fs.readdirSync(fixture.source).map((name) => join(fixture.source, name)),
    captured, published, join(capture.destination, `api-${process.pid}.json`)];
  const texts = [...emitted.map((path) => fs.readFileSync(path, 'utf8')), ...fixture.diagnostics];
  for (const text of texts) {
    assert.equal(text.includes(secret), false, 'A secret reached trace output.');
    assert.equal(text.includes(fixture.directory), false, 'A private path reached trace output.');
    assert.equal(/nonce|credential|argv|stderr|servers\.json/.test(text), false, 'A forbidden field reached trace output.');
  }
  assert.equal(fixture.diagnostics.length, 1);
  assert.deepEqual(validateTraceArtifact(JSON.parse(fixture.diagnostics[0].slice('POOLING_TRACE '.length))), artifact);
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
  const secondSink = fixture.createSink(fixture.source);
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
  fixture.capture().finish();
  assert.ok(Buffer.byteLength(fixture.diagnostics[0]) <= TRACE_ARTIFACT_BYTES + 'POOLING_TRACE '.length);
  assert.equal(JSON.parse(fixture.diagnostics[0].slice('POOLING_TRACE '.length)).issues.includes('truncated'), true);
  const nearByteLimit = join(fixture.directory, 'byte-limit');
  fs.mkdirSync(nearByteLimit);
  const sink = fixture.createSink(nearByteLimit);
  sink.bytes = TRACE_MAX_BYTES - TRACE_MAX_LINE_BYTES;
  sink.operation(process.hrtime.bigint() + 9000000000n).record('request-start');
  const limited = fixture.artifacts.collect(nearByteLimit, fixture.directory);
  assert.equal(limited.records.length, 1);
  assert.equal(limited.records[0].event, 'capture-truncated');
});

test('trace exclusive creation refuses an existing hardlink without modifying its victim', (t) => {
  const fixture = new TraceFixture(t);
  const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
  const victim = join(fixture.directory, 'owned-victim');
  fs.writeFileSync(victim, 'private-victim-bytes');
  const before = fs.readFileSync(victim);
  fs.linkSync(victim, path);
  assert.equal(fs.statSync(victim).nlink, 2);
  fixture.operation.record('request-start');
  assert.equal(fixture.sink.failed, true);
  assert.equal(fixture.sink.events, 0);
  assert.deepEqual(fs.readFileSync(victim), before);
});

for (const replacement of ['hardlink', 'regular-file', 'missing']) {
  test(`trace stops after ${replacement} path replacement and preserves the operation error`, (t) => {
    const fixture = new TraceFixture(t);
    fixture.operation.record('request-start');
    const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
    const retained = join(fixture.directory, 'original-trace');
    const originalTrace = fs.readFileSync(path);
    const victim = join(fixture.directory, 'owned-victim');
    fs.writeFileSync(victim, 'private-victim-bytes');
    const before = fs.readFileSync(victim);
    fs.renameSync(path, retained);
    if (replacement === 'hardlink') fs.linkSync(victim, path);
    if (replacement === 'regular-file') fs.writeFileSync(path, before);
    const original = new Error('original operation failure');
    assert.throws(() => {
      try {
        throw original;
      } finally {
        fixture.operation.record('body-end', { bytes: 1 });
      }
    }, (error) => error === original);
    assert.equal(fixture.sink.failed, true);
    assert.equal(fixture.sink.stopped, true);
    fixture.operation.record('body-end', { bytes: 2 });
    assert.equal(fixture.sink.events, 1);
    assert.deepEqual(fs.readFileSync(victim), before);
    assert.deepEqual(fs.readFileSync(retained), originalTrace);
    if (replacement === 'missing') assert.equal(fs.existsSync(path), false);
    else assert.deepEqual(fs.readFileSync(path), before);
  });
}

test('trace stops if its owned file gains another hardlink', (t) => {
  const fixture = new TraceFixture(t);
  fixture.operation.record('request-start');
  const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
  const before = fs.readFileSync(path);
  const alias = join(fixture.directory, 'another-link');
  fs.linkSync(path, alias);
  assert.equal(fs.statSync(path).nlink, 2);
  fixture.operation.record('body-end', { bytes: 1 });
  assert.equal(fixture.sink.failed, true);
  assert.equal(fixture.sink.stopped, true);
  assert.deepEqual(fs.readFileSync(path), before);
  assert.deepEqual(fs.readFileSync(alias), before);
});

test('trace stops after an external size change without adding more bytes', (t) => {
  const fixture = new TraceFixture(t);
  fixture.operation.record('request-start');
  const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
  fs.appendFileSync(path, 'private-external-bytes');
  const before = fs.readFileSync(path);
  fixture.operation.record('body-end', { bytes: 1 });
  assert.equal(fixture.sink.failed, true);
  assert.equal(fixture.sink.stopped, true);
  assert.deepEqual(fs.readFileSync(path), before);
});

test('trace writes stay on the owned descriptor when replacement happens after the ownership check', (t) => {
  const fixture = new TraceFixture(t);
  fixture.operation.record('request-start');
  const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
  const retained = join(fixture.directory, 'original-trace');
  const originalTrace = fs.readFileSync(path);
  const victim = join(fixture.directory, 'owned-victim');
  fs.writeFileSync(victim, 'private-victim-bytes');
  const before = fs.readFileSync(victim);
  const append = fs.appendFileSync;
  let descriptorUsed = false;
  t.mock.method(fs, 'appendFileSync', (file, data, options) => {
    descriptorUsed = typeof file === 'number';
    fs.renameSync(path, retained);
    fs.linkSync(victim, path);
    return append(file, data, options);
  });
  fixture.operation.record('body-end', { bytes: 1 });
  assert.equal(descriptorUsed, true);
  assert.equal(fixture.sink.failed, true);
  assert.equal(fixture.sink.stopped, true);
  assert.deepEqual(fs.readFileSync(victim), before);
  const ownedBytes = fs.readFileSync(retained);
  assert.deepEqual(ownedBytes.subarray(0, originalTrace.length), originalTrace);
  assert.equal(ownedBytes.toString('utf8').trim().split('\n').length, 2);
  assert.ok(ownedBytes.length <= TRACE_MAX_BYTES);
});

for (const stop of ['close', 'event-limit', 'byte-limit', 'invalid-record', 'write-failure']) {
  test(`trace ${stop} closes its descriptor once and ignores late events`, (t) => {
    const fixture = new TraceFixture(t);
    const append = fs.appendFileSync;
    const close = fs.closeSync;
    let descriptor;
    let closes = 0;
    let failWrite = false;
    t.mock.method(fs, 'appendFileSync', (file, data, options) => {
      descriptor = file;
      if (failWrite) throw new Error('private-write-error');
      return append(file, data, options);
    });
    fixture.operation.record('request-start');
    assert.equal(typeof descriptor, 'number');
    t.mock.method(fs, 'closeSync', (file) => {
      if (file === descriptor) closes++;
      return close(file);
    });
    if (stop === 'close') fixture.sink.close();
    if (stop === 'event-limit') {
      for (let index = 0; index < TRACE_MAX_EVENTS; index++) fixture.operation.record('request-start');
      assert.equal(fixture.sink.events, TRACE_MAX_EVENTS);
    }
    if (stop === 'byte-limit') {
      fixture.sink.bytes = TRACE_MAX_BYTES - TRACE_MAX_LINE_BYTES;
      fixture.operation.record('request-start');
    }
    if (stop === 'invalid-record') fixture.operation.record('request-start', { secret: 'private-input' });
    if (stop === 'write-failure') {
      failWrite = true;
      const original = new Error('original operation failure');
      assert.throws(() => {
        try {
          throw original;
        } finally {
          fixture.operation.record('request-start');
        }
      }, (error) => error === original);
      assert.equal(fixture.sink.failed, true);
    }
    assert.equal(closes, 1);
    assert.equal(fixture.sink.stopped, true);
    fixture.sink.close();
    fixture.operation.record('request-start');
    assert.equal(closes, 1);
    assert.equal(fixture.sink.operation(process.hrtime.bigint() + 9000000000n), undefined);
    const path = join(fixture.source, `${process.pid}-${threadId}.jsonl`);
    const before = fs.readFileSync(path);
    fixture.operation.record('request-start');
    assert.deepEqual(fs.readFileSync(path), before);
    assert.ok(before.length <= TRACE_MAX_BYTES);
    assert.equal(before.includes(Buffer.from('private-')), false);
    fs.unlinkSync(path);
    fixture.operation.record('request-start');
    assert.equal(fs.existsSync(path), false);
  });
}

test('trace close errors are safe and do not retry a possibly closed descriptor', (t) => {
  const fixture = new TraceFixture(t);
  fixture.operation.record('request-start');
  const close = fs.closeSync;
  let closes = 0;
  t.mock.method(fs, 'closeSync', (file) => {
    closes++;
    close(file);
    throw new Error('private-close-error');
  });
  const original = new Error('original operation failure');
  assert.throws(() => {
    try {
      throw original;
    } finally {
      fixture.sink.close();
    }
  }, (error) => error === original);
  assert.equal(fixture.sink.failed, true);
  fixture.sink.close();
  fixture.operation.record('request-start');
  assert.equal(closes, 1);
  t.mock.restoreAll();
  const artifact = fixture.collect();
  assert.equal(artifact.capture, 'unsealed');
  fixture.capture().finish();
  assert.equal(fixture.diagnostics[0].includes('private-close-error'), false);
});

test('trace write failures do not replace operation failures and remain visible', (t) => {
  const fixture = new TraceFixture(t);
  const missing = join(fixture.directory, 'missing');
  const sink = fixture.createSink(missing);
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
  fixture.createSink(mismatched).operation(process.hrtime.bigint() + 9000000000n).record('request-start');
  fs.renameSync(join(mismatched, fs.readdirSync(mismatched)[0]), join(mismatched, '1-0.jsonl'));
  const mismatch = fixture.artifacts.collect(mismatched, fixture.directory);
  assert.equal(mismatch.issues.includes('invalid-source'), true);
  assert.deepEqual(mismatch.records, []);
});

for (const target of ['api', 'batch']) {
  test(`${target} fixture renders safe helper fields after an injected operation failure`, (t) => {
    const fixture = new TraceFixture(t);
    const capture = fixture.capture(target);
    fixture.operation.record('request-start');
    fixture.operation.record('helper-start', { action: 'inspect-access', call: 1, timeoutMs: 9000 });
    fixture.operation.record('helper-end', { action: 'inspect-access', call: 1,
      helperPid: process.pid, exit: null, code: 'ETIMEDOUT' });
    const secret = 'config-command-nonce-private-child-output';
    fs.writeFileSync(join(fixture.directory, 'servers.json'), JSON.stringify({ command: secret, env: { secret } }));
    fs.writeFileSync(join(fixture.directory, 'stderr.log'), secret);
    const original = new Error(secret);
    assert.throws(() => {
      try {
        throw original;
      } finally {
        capture.finish();
      }
    }, (error) => error === original);
    assert.equal(fixture.diagnostics.length, 1);
    const artifact = validateTraceArtifact(JSON.parse(fixture.diagnostics[0].slice('POOLING_TRACE '.length)));
    assert.equal(artifact.records[1].timeoutMs, 9000);
    assert.equal(artifact.records[2].helperPid, process.pid);
    assert.equal(artifact.records[2].code, 'ETIMEDOUT');
    assert.equal(typeof artifact.records[2].elapsedMs, 'number');
    const saved = fs.readFileSync(join(capture.destination, `${target}-${process.pid}.json`), 'utf8');
    for (const text of [saved, ...fixture.diagnostics]) {
      assert.equal(text.includes(secret), false);
      assert.equal(text.includes(fixture.directory), false);
      assert.equal(/command|nonce|stderr/.test(text), false);
    }
  });
}

test('fixture setup, capture and artifact write failures remain safe and preserve the original error', (t) => {
  const fixture = new TraceFixture(t);
  const secret = 'private-capture-error';
  fs.writeFileSync(join(fixture.directory, 'trace'), secret);
  const capture = fixture.capture();
  assert.equal(fixture.diagnostics[0], 'POOLING_TRACE_CAPTURE {"issue":"setup-failed"}');
  fixture.operation.record('request-start');
  fs.writeFileSync(capture.destination, secret);
  capture.finish();
  assert.equal(fixture.diagnostics.at(-1), 'POOLING_TRACE_CAPTURE {"issue":"write-failed"}');
  capture.artifacts.collect = () => { throw new Error(secret); };
  const original = new Error('original assertion failure');
  assert.throws(() => {
    try {
      throw original;
    } finally {
      capture.finish();
    }
  }, (error) => error === original);
  assert.equal(fixture.diagnostics.at(-1), 'POOLING_TRACE_CAPTURE {"issue":"capture-failed"}');
  assert.equal(fixture.diagnostics.some((line) => line.includes(secret)), false);
});

// Local opt-in proof only: the normal CI target must not inject delays.
const runFaults = process.platform === 'win32' &&
  process.env.MCP_POOLING_TRACE_RUN_FAULTS === '1';
const cases = [
  { target: 'api', fault: 'worker-start' },
  { target: 'api', fault: 'first-helper' },
  { target: 'api', fault: 'post-stage' },
  { target: 'batch', fault: 'first-helper' },
];
for (const { target, fault } of cases) {
  test(`real deadline diagnostics distinguish ${target} ${fault} without changing the original failure`,
    { skip: !runFaults, timeout: 40000 }, async (t) => {
      const fixture = new TraceFixture(t);
      const output = join(fixture.directory, 'captured');
      const env = { ...process.env, MCP_POOLING_API_TEST_PORT: '8882', MCP_POOLING_BATCH_API_TEST_PORT: '8883',
        MCP_POOLING_TRACE_ARTIFACT_DIR: output, MCP_POOLING_TRACE_TEST_FAULT: fault,
        NODE_OPTIONS: `--import=${new URL('./pooling-trace-faults.mjs', import.meta.url).href}` };
      // An inherited child-v8 context makes Node skip this nested runner entirely.
      delete env.NODE_TEST_CONTEXT;
      const file = target === 'api' ? '../pooling-api.test.mjs' : '../pooling-batch-api.test.mjs';
      const child = spawn(process.execPath, [
        '--test', '--test-concurrency=1', '--test-reporter=tap', `--test-name-pattern=${targets[target]}`,
        fileURLToPath(new URL(file, import.meta.url)),
      ], { stdio: ['ignore', 'pipe', 'pipe'], env });
      let text = '';
      let stderr = '';
      let bytes = 0;
      let truncated = false;
      child.stdout.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes <= TRACE_ARTIFACT_BYTES + 65536) text += chunk;
        else truncated = true;
      });
      child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4096); });
      const exited = once(child, 'exit');
      const guard = setTimeout(() => killBridge(child), 30000);
      t.after(() => { clearTimeout(guard); killBridge(child); });
      const [exitCode] = await exited;
      clearTimeout(guard);
      const originalFailure = text.includes('504 !== 202') &&
        text.includes('Pooling change expired before config commit. Reread the config.');
      const rendered = text.split('\n').find((line) => line.startsWith('# POOLING_TRACE '));
      t.diagnostic(`POOLING_TRACE_CHILD ${JSON.stringify({ target, fault, exitCode, truncated,
        originalFailure, rendered: Boolean(rendered) })}`);
      let artifact;
      try {
        artifact = validateTraceArtifact(JSON.parse(rendered?.slice('# POOLING_TRACE '.length)));
      } catch {
        // Never print an invalid record or a parser error containing its input.
      }
      if (artifact) {
        t.diagnostic(`POOLING_TRACE_FAULT ${JSON.stringify(artifact)}`);
        if (process.env.MCP_POOLING_TRACE_PROOF_DIR) {
          fixture.artifacts.write(join(process.env.MCP_POOLING_TRACE_PROOF_DIR, `${target}-${fault}.json`), artifact);
        }
      }
      assert.equal(truncated, false);
      assert.equal(exitCode, 1, 'The unchanged 202 assertion must still fail.');
      assert.equal(originalFailure, true, 'The controlled operation must retain the original failure.');
      assert.ok(rendered, 'The failed test must render its safe trace before deleting its fixture.');
      const rawNoiseObserved = stderr.includes('pooling-private-child-output') ||
        text.includes('# pooling-private-child-output');
      assert.equal(rawNoiseObserved, true, 'The privacy probe must produce raw child noise.');
      assert.ok(artifact, 'The failed test must render a valid bounded artifact.');
      const paths = fs.readdirSync(output);
      assert.equal(paths.length, 1);
      assert.match(paths[0], new RegExp(`^${target}-[0-9]+\\.json$`));
      const path = join(output, paths[0]);
      const saved = fixture.artifacts.boundedRead(path, TRACE_ARTIFACT_BYTES);
      assert.deepEqual(JSON.parse(saved), artifact);
      for (const value of ['must-not-leak', 'batch-private-value', 'PRIVATE_SENTINEL',
        'pooling-private-child-output', 'echo-mcp-server', process.execPath, fixture.directory]) {
        assert.equal(saved.includes(value), false, 'A private input reached the saved artifact.');
        assert.equal(rendered.includes(value), false, 'A private input reached the diagnostic.');
      }
      assert.deepEqual(artifact.issues, []);
      const records = artifact.records;
      const response = fixture.deadlineResponse(records);
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
      t.diagnostic(`POOLING_TRACE_PROOF ${JSON.stringify({ target, fault, status: response.status,
        elapsedMs: response.elapsedMs, pid: response.pid, helpers: helpers.length,
        pending: artifact.files.pending.exists, capture: artifact.capture })}`);
    });
}
