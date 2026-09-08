// This file owns port 8873. Config, journals and control files belong only to each test's temp directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import http from 'node:http';
import net from 'node:net';
import { killBridge } from './helpers/kill-bridge.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8873;
const PARAMS = {
  protocolVersion: '2025-11-25', capabilities: {},
  clientInfo: { name: 'shared-http-client', version: '1', title: 'Exact shared HTTP identity' },
};

class Exchange {
  constructor(method, path, { headers = {}, body, expectedSse = false, timeoutMs = 15_000 } = {}) {
    this.expectedSse = expectedSse;
    this.messages = [];
    this.body = '';
    this.partial = '';
    this.ended = false;
    this.completion = new Promise((resolveComplete) => { this.resolveComplete = resolveComplete; });
    this.headerArrival = new Promise((resolveHeaders) => { this.resolveHeaders = resolveHeaders; });
    this.request = http.request({ host: '127.0.0.1', port: PORT, method, path, headers, agent: false },
      (response) => {
        this.status = response.statusCode;
        this.headers = response.headers;
        this.resolveHeaders();
        response.setEncoding('utf8');
        response.on('data', (chunk) => this.data(chunk));
        response.on('end', () => this.finish());
        response.on('error', (error) => this.finish(error));
        response.on('aborted', () => this.finish(new Error('HTTP response aborted')));
      });
    this.request.on('error', (error) => this.finish(error));
    this.timer = setTimeout(() => this.request.destroy(new Error(`HTTP deadline exceeded: ${method} ${path}`)), timeoutMs);
    this.timer.unref();
    this.request.end(body);
  }

  data(chunk) {
    this.body += chunk;
    if (this.body.length > 1_048_576) {
      this.request.destroy(new Error('Test response exceeded its byte budget'));
      return;
    }
    if (!this.headers['content-type']?.startsWith('text/event-stream')) return;
    this.partial += chunk;
    this.partial = this.partial.replaceAll('\r\n', '\n');
    let boundary;
    while ((boundary = this.partial.indexOf('\n\n')) >= 0) {
      const frame = this.partial.slice(0, boundary);
      this.partial = this.partial.slice(boundary + 2);
      const data = frame.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trimStart()).join('\n');
      if (!data) continue;
      try {
        this.messages.push(JSON.parse(data));
      } catch {
        this.request.destroy(new Error('Invalid JSON in MCP SSE frame'));
        return;
      }
    }
  }

  finish(error) {
    if (this.ended) return;
    this.ended = true;
    this.error = error;
    clearTimeout(this.timer);
    this.resolveHeaders();
    this.resolveComplete();
  }

  async receivedHeaders() {
    await this.headerArrival;
    if (this.error) throw this.error;
    return this;
  }

  async complete() {
    await this.completion;
    if (this.error) throw this.error;
    return this;
  }

  async message() {
    await this.complete();
    if (this.expectedSse) assert.match(this.headers['content-type'] ?? '', /^text\/event-stream/, this.body);
    if (this.headers['content-type']?.startsWith('text/event-stream')) {
      const replies = this.messages.filter((message) => Object.hasOwn(message, 'id'));
      assert.equal(replies.length, 1, `Expected exactly one POST reply: ${this.body}`);
      return replies[0];
    }
    assert.match(this.headers['content-type'] ?? '', /^application\/json/, this.body);
    return JSON.parse(this.body);
  }

  close() {
    if (!this.ended) this.request.destroy(new Error('Test teardown closed HTTP exchange'));
  }
}

class BridgeRig {
  constructor(t, { definition = {}, manualInitialize = false, env = {} } = {}) {
    this.directory = mkdtempSync(join(tmpdir(), 'pacemaker-shared-http-'));
    this.config = join(this.directory, 'servers.json');
    this.exchanges = [];
    this.logs = '';
    this.servers = {};
    for (const name of ['alpha', 'beta']) {
      const controls = join(this.directory, `${name}-controls`);
      mkdirSync(controls);
      this.servers[name] = {
        type: 'stdio', sharing: 'shared', command: process.execPath,
        args: [join(ROOT, 'test', 'fixtures', 'shared-http-b6-peer.mjs'),
          join(this.directory, `${name}.jsonl`), controls, manualInitialize ? 'manual' : 'automatic'],
        maxSessions: 128, sharedMaxSessions: 128, sharedMaxInFlight: 8,
        sharedDrainTimeoutMs: 500, sharedRetryDelayMs: 1,
        ...definition,
      };
    }
    writeFileSync(this.config, JSON.stringify(this.servers));
    this.env = env;
    t.after(() => this.stop());
  }

  async start() {
    const probe = net.createServer();
    await new Promise((resolveListen, rejectListen) => {
      probe.once('error', rejectListen);
      probe.listen(PORT, '127.0.0.1', resolveListen);
    });
    await new Promise((resolveClose, rejectClose) => probe.close((error) => error ? rejectClose(error) : resolveClose()));
    this.child = spawn(process.execPath, [join(ROOT, 'bin', 'mcp-bridge.mjs'),
      '--port', String(PORT), '--host', '127.0.0.1', '--config', this.config], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env, MCP_CONFIG_WATCH: '0', MCP_LOG_MAX_BYTES: '0', MCP_RESUME: '1',
        MCP_RESUME_TTL_MS: '600000', MCP_RECYCLE_MINUTES: '0', MCP_IDLE_TIMEOUT_MS: '0',
        MCP_HEALTH_INTERVAL_MS: '0', MCP_TOKEN_REFRESH_LEAD_MS: '0', MCP_MAX_CONCURRENT_SPAWNS: '0',
        MCP_QUEUE_TIMEOUT_MS: '0', MCP_INIT_TIMEOUT_MS: '8000', MCP_REQUEST_TIMEOUT_MS: '4000',
        ...this.env,
      },
    });
    this.exited = new Promise((resolveExit) => {
      this.child.once('exit', resolveExit);
      this.child.once('error', (error) => { this.processError = error; resolveExit(); });
    });
    for (const stream of [this.child.stdout, this.child.stderr]) {
      stream.on('data', (chunk) => { this.logs = (this.logs + chunk.toString()).slice(-32_768); });
    }
    await this.until(async () => {
      if (this.processError) throw this.processError;
      assert.equal(this.child.exitCode, null, this.logs);
      try {
        const response = await this.exchange('GET', '/api/status').complete();
        assert.equal(response.status, 200, response.body);
        const snapshot = JSON.parse(response.body);
        assert.equal(snapshot.port, PORT);
        assert.equal(snapshot.service, 'mcp-pacemaker');
        return true;
      } catch (error) {
        if (error.code !== 'ECONNREFUSED') throw error;
        return false;
      }
    }, 'bridge startup');
    this.nonce = readFileSync(join(this.directory, 'admin.nonce'), 'utf8').trim();
    return this;
  }

  async stop() {
    for (const exchange of this.exchanges) exchange.close();
    if (this.child) {
      if (this.child.exitCode === null &&
          this.child.signalCode === null) {
        killBridge(this.child);
      }
      await this.until(() => this.child.exitCode !== null || this.child.signalCode !== null || this.processError,
        'recorded bridge PID to exit');
      await this.exited;
    }
    rmSync(this.directory, { recursive: true, force: true });
  }

  exchange(method, path, options) {
    const exchange = new Exchange(method, path, options);
    this.exchanges.push(exchange);
    return exchange;
  }

  async until(predicate, description, timeoutMs = 10_000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const value = await predicate();
      if (value) return value;
      assert.ok(Date.now() < deadline, `Timed out waiting for ${description}\n${this.logs}`);
      await delay(20);
    }
  }

  rpc(name, sid, method, id, params, protocolVersion = PARAMS.protocolVersion) {
    const message = { jsonrpc: '2.0', method };
    if (id !== undefined) message.id = id;
    if (params !== undefined) message.params = params;
    const headers = {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      'mcp-protocol-version': protocolVersion,
    };
    if (sid) headers['mcp-session-id'] = sid;
    const expectedSse = Object.hasOwn(params?._meta ?? {}, 'progressToken');
    return this.exchange('POST', `/${name}/mcp`, { headers, body: JSON.stringify(message), expectedSse });
  }

  batch(sid, messages, protocolVersion) {
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
      'mcp-protocol-version': protocolVersion };
    if (sid) headers['mcp-session-id'] = sid;
    const expectedSse = messages.some((message) => Object.hasOwn(message.params?._meta ?? {}, 'progressToken'));
    return this.exchange('POST', '/alpha/mcp', { headers, body: JSON.stringify(messages), expectedSse });
  }

  async attach(name = 'alpha', id = 'initialize', params = PARAMS) {
    const response = this.rpc(name, null, 'initialize', id, params);
    const message = await response.message();
    assert.equal(response.status, 200, response.body);
    assert.equal(message.jsonrpc, '2.0');
    assert.equal(message.id, id);
    assert.equal(message.error, undefined, response.body);
    assert.deepEqual(message.result, {
      protocolVersion: params.protocolVersion, capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'shared-http-b6-peer', version: '1' },
      instructions: 'Actual shared HTTP fixture initialization result',
    });
    const sid = response.headers['mcp-session-id'];
    assert.ok(sid);
    const initialized = await this.rpc(name, sid, 'notifications/initialized', undefined, undefined, params.protocolVersion).complete();
    assert.equal(initialized.status, 202, initialized.body);
    return sid;
  }

  call(sid, id, args, { name = 'alpha', progressToken, protocolVersion = PARAMS.protocolVersion } = {}) {
    const params = { name: 'echo', arguments: args };
    if (progressToken !== undefined) params._meta = { progressToken };
    return this.rpc(name, sid, 'tools/call', id, params, protocolVersion);
  }

  async result(exchange, id) {
    const message = await exchange.message();
    assert.equal(exchange.status, 200, exchange.body);
    assert.equal(message.jsonrpc, '2.0');
    assert.equal(message.id, id);
    assert.equal(message.error, undefined, exchange.body);
    return JSON.parse(message.result.content[0].text);
  }

  async failure(exchange, id, kinds, execution, phase) {
    const message = await exchange.message();
    assert.equal(message.jsonrpc, '2.0');
    assert.equal(message.id, id);
    assert.equal(message.result, undefined, exchange.body);
    assert.equal(typeof message.error?.code, 'number', exchange.body);
    const allowed = Array.isArray(kinds) ? kinds : [kinds];
    assert.ok(allowed.includes(message.error.data?.kind), exchange.body);
    assert.equal(message.error.data.execution, execution);
    assert.equal(message.error.data.phase, phase);
    return message.error;
  }

  async snapshot(name = 'alpha') {
    const exchange = await this.exchange('GET', '/api/status').complete();
    assert.equal(exchange.status, 200, exchange.body);
    const server = JSON.parse(exchange.body).servers.find((entry) => entry.name === name);
    assert.ok(server);
    return server;
  }

  records(name = 'alpha') {
    const file = join(this.directory, `${name}.jsonl`);
    if (!existsSync(file)) return [];
    const text = readFileSync(file, 'utf8');
    const complete = text.slice(0, text.lastIndexOf('\n'));
    return complete ? complete.split('\n').map((line) => JSON.parse(line)) : [];
  }

  requests(method, name = 'alpha') {
    return this.records(name).filter((entry) => entry.event === 'request' && entry.message.method === method);
  }

  async dispatched(tag, name = 'alpha') {
    return this.until(() => this.requests('tools/call', name).find((entry) => entry.message.params.arguments.tag === tag),
      `fixture request ${name}/${tag}`);
  }

  signal(pid, command, name = 'alpha') {
    writeFileSync(join(this.directory, `${name}-controls`, String(pid), command), 'release');
  }

  async delete(sid, name = 'alpha') {
    return this.exchange('DELETE', `/${name}/mcp`, { headers: { 'mcp-session-id': sid } }).complete();
  }

  async recycle(name = 'alpha') {
    const exchange = await this.exchange('POST', `/admin/recycle/${name}`,
      { headers: { 'x-mcp-nonce': this.nonce } }).complete();
    assert.equal(exchange.status, 200, exchange.body);
    assert.equal(JSON.parse(exchange.body).ok, true);
  }

  async reload(definition, name = 'alpha') {
    this.servers[name] = { ...this.servers[name], ...definition };
    writeFileSync(this.config, JSON.stringify(this.servers));
    const response = await this.exchange('POST', '/admin/reload',
      { headers: { 'x-mcp-nonce': this.nonce } }).complete();
    assert.equal(response.status, 200, response.body);
    const result = JSON.parse(response.body);
    assert.equal(result.ok, true);
    assert.deepEqual(result.changed, [name]);
    return result;
  }

  async retired(name = 'alpha', timeoutMs = 10_000) {
    return this.until(async () => {
      const server = await this.snapshot(name);
      assert.ok(Object.hasOwn(server, 'shared'), 'status must expose shared manager inspection');
      return server.shared === null ? server : false;
    }, `${name} shared generation retirement`, timeoutMs);
  }
}

test('shared HTTP reuses one initialized OS child across 60 initialize/DELETE cycles and concurrent sessions', { timeout: 30_000 }, async (t) => {
  const h = await new BridgeRig(t).start();
  const before = await h.snapshot();
  let pid;
  let generation;
  for (let cycle = 0; cycle < 60; cycle++) {
    const sid = await h.attach('alpha', `init-${cycle}`);
    const result = await h.result(h.call(sid, 1, { cycle }), 1);
    assert.equal(result.initializes, 1);
    assert.equal(result.initialized, 1);
    assert.deepEqual(result.arguments, { cycle });
    pid ??= result.pid;
    assert.equal(result.pid, pid);
    const status = await h.snapshot();
    assert.ok(status.shared, 'shared mode must expose the reused actual group');
    generation ??= status.shared.generation;
    assert.equal(status.shared.generation, generation);
    assert.equal((await h.delete(sid)).status, 204);
  }
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  assert.notEqual(a, b);
  await Promise.all([h.result(h.call(a, 1, { owner: 'a' }), 1), h.result(h.call(b, 1, { owner: 'b' }), 1)]);
  const after = await h.snapshot();
  assert.equal(after.sharing, 'shared');
  assert.equal(after.shared.state, 'ready');
  assert.equal(after.shared.members, 2);
  assert.equal(after.shared.unresolved, 0);
  assert.equal(after.shared.queued, 0);
  assert.equal(after.shared.generation, generation);
  assert.deepEqual(after.pids, [pid]);
  assert.equal(after.sessions, 2);
  assert.equal(after.spawn.total - before.spawn.total, 1);
  assert.equal(after.spawn.attempts - before.spawn.attempts, 1);
  assert.equal(after.spawn.sessionStarts - before.spawn.sessionStarts, 62);
  assert.equal(after.spawn.samples, 1);
  assert.equal(h.records().filter((entry) => entry.event === 'spawn').length, 1);
  assert.equal(h.requests('initialize').length, 1);
  assert.equal(h.requests('notifications/initialized').length, 1);
});

test('shared HTTP requires each virtual initialized notification before dispatching business calls', async (t) => {
  const h = await new BridgeRig(t).start();
  const first = h.rpc('alpha', null, 'initialize', 'first', PARAMS);
  await first.message();
  const sid = first.headers['mcp-session-id'];
  assert.ok(sid);
  await h.failure(h.call(sid, 1, { tag: 'too-early' }), 1, 'SHARED_NOT_INITIALIZED', 'unsent', 'admission');
  assert.equal(h.requests('tools/call').length, 0);
  assert.equal((await h.rpc('alpha', sid, 'notifications/initialized').complete()).status, 202);
  await h.result(h.call(sid, 2, { tag: 'ready' }), 2);
  assert.equal(h.requests('tools/call').length, 1);
});

test('shared HTTP rejects incompatible initialization explicitly without another actual spawn', async (t) => {
  const h = await new BridgeRig(t).start();
  const sid = await h.attach();
  const before = await h.snapshot();
  const cases = [
    [{ ...PARAMS, capabilities: { roots: { listChanged: true } } }, 'initialize'],
    [{ ...PARAMS, capabilities: { sampling: {} } }, 'initialize'],
    [{ ...PARAMS, clientInfo: { ...PARAMS.clientInfo, title: 'Different identity' } }, 'admission'],
    [{ ...PARAMS, protocolVersion: '2025-06-18' }, 'admission'],
    [{ ...PARAMS, _meta: { distinct: ['a', 'b'] } }, 'admission'],
  ];
  for (const [index, [params, phase]] of cases.entries()) {
    await h.failure(h.rpc('alpha', null, 'initialize', index, params), index, 'SHARED_INCOMPATIBLE', 'unsent', phase);
  }
  const after = await h.snapshot();
  assert.equal(after.shared.generation, before.shared.generation);
  assert.equal(after.shared.members, 1);
  assert.equal(after.spawn.total, 1);
  assert.equal(after.spawn.samples, 1);
  assert.equal(h.requests('initialize').length, 1);
  await h.result(h.call(sid, 1, { stillCompatible: true }), 1);
});

test('shared HTTP routes typed IDs, out-of-order replies and progress only on each originating POST SSE', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const cases = [
    { sid: a, id: 1, token: 7, tag: 'a-number' },
    { sid: a, id: '1', token: '7', tag: 'a-string' },
    { sid: b, id: 1, token: 7, tag: 'b-number' },
    { sid: b, id: '1', token: '7', tag: 'b-string' },
  ];
  for (const entry of cases) {
    entry.args = { op: 'hold', tag: entry.tag, id: 'argument-id', requestId: 42, nested: { progressToken: 'ordinary' } };
    entry.post = h.call(entry.sid, entry.id, entry.args, { progressToken: entry.token });
  }
  for (const entry of cases) {
    entry.dispatched = await h.dispatched(entry.tag);
    h.signal(entry.dispatched.pid, `progress-${entry.tag}`);
    await h.until(() => entry.post.messages.length, `progress for ${entry.tag}`);
    assert.equal(entry.post.status, 200);
    assert.match(entry.post.headers['content-type'], /^text\/event-stream/);
    assert.deepEqual(entry.post.messages, [{
      jsonrpc: '2.0', method: 'notifications/progress',
      params: { progressToken: entry.token, progress: 1, total: 2, message: entry.tag },
    }]);
    assert.equal(entry.post.ended, false);
  }
  assert.equal(new Set(cases.map((entry) => entry.dispatched.message.id)).size, 4);
  assert.equal(new Set(cases.map((entry) => entry.dispatched.pid)).size, 1);
  for (const index of [3, 1, 2, 0]) {
    const entry = cases[index];
    h.signal(entry.dispatched.pid, `release-${entry.tag}`);
    const result = await h.result(entry.post, entry.id);
    assert.deepEqual(result.arguments, entry.args);
    assert.equal(entry.post.messages.length, 2);
  }
  assert.equal((await h.snapshot()).shared.unresolved, 0);
});

test('shared HTTP cancellation keeps execution ownership and cannot cancel another client with the same ID', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const pa = h.call(a, 9, { op: 'hold', tag: 'cancel-a' }, { progressToken: 1 });
  const pb = h.call(b, 9, { op: 'hold', tag: 'cancel-b' }, { progressToken: 1 });
  const da = await h.dispatched('cancel-a');
  const db = await h.dispatched('cancel-b');
  assert.equal((await h.rpc('alpha', a, 'notifications/cancelled', undefined, { requestId: 9 }).complete()).status, 202);
  await h.failure(pa, 9, 'SHARED_CANCELLED', 'potentially-executed', 'execution');
  await h.until(() => h.requests('notifications/cancelled').length === 1, 'owner cancellation');
  assert.equal(h.requests('notifications/cancelled')[0].message.params.requestId, da.message.id);
  assert.notEqual(da.message.id, db.message.id);
  assert.equal(pb.ended, false);
  assert.equal((await h.snapshot()).shared.unresolved, 2);
  h.signal(db.pid, 'release-cancel-b');
  assert.equal((await h.result(pb, 9)).arguments.tag, 'cancel-b');
  h.signal(da.pid, 'release-cancel-a');
  await h.until(async () => (await h.snapshot()).shared.unresolved === 0, 'cancelled execution to finish');
  assert.equal(pa.messages.filter((message) => Object.hasOwn(message, 'id')).length, 1);
});

test('shared HTTP DELETE drops only its owner queued work and preserves another client and its PID', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharedMaxInFlight: 2 } }).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const pa = h.call(a, 1, { op: 'hold', tag: 'delete-a' }, { progressToken: 'a' });
  const pb = h.call(b, 1, { op: 'hold', tag: 'keep-b' }, { progressToken: 'b' });
  const da = await h.dispatched('delete-a');
  const db = await h.dispatched('keep-b');
  const queuedA = h.call(a, 2, { op: 'hold', tag: 'unsent-a' });
  const queuedB = h.call(b, 2, { op: 'hold', tag: 'queued-b' });
  await h.until(async () => (await h.snapshot()).shared.queued === 2, 'two queued calls');
  assert.equal((await h.delete(a)).status, 204);
  await h.failure(pa, 1, 'SHARED_DETACHED', 'potentially-executed', 'execution');
  await h.failure(queuedA, 2, 'SHARED_DETACHED', 'unsent', 'queue');
  const during = await h.snapshot();
  assert.equal(during.shared.members, 1);
  assert.equal(during.shared.unresolved, 2);
  assert.deepEqual(during.pids, [db.pid]);
  assert.equal(during.spawn.total, 1);
  h.signal(db.pid, 'release-keep-b');
  await h.result(pb, 1);
  const next = await h.dispatched('queued-b');
  h.signal(next.pid, 'release-queued-b');
  await h.result(queuedB, 2);
  h.signal(da.pid, 'release-delete-a');
  await h.until(async () => (await h.snapshot()).shared.unresolved === 0, 'detached execution completion');
  assert.equal(h.requests('tools/call').filter((entry) => entry.message.params.arguments.tag === 'unsent-a').length, 0);
  assert.equal((await h.rpc('alpha', a, 'ping', 3).complete()).status, 404);
  assert.equal((await h.exchange('GET', '/alpha/mcp', { headers: { 'mcp-session-id': a } }).complete()).status, 404);
});

test('shared HTTP binds GET, POST and DELETE session IDs to their configured server, including resumable IDs', async (t) => {
  const h = await new BridgeRig(t).start();
  const a = await h.attach('alpha', 'init-a');
  const b = await h.attach('beta', 'init-b');
  for (const retired of [false, true]) {
    if (retired) {
      await h.recycle('alpha');
      await h.retired('alpha');
    }
    const wrongGet = await h.exchange('GET', '/beta/mcp', { headers: { 'mcp-session-id': a } }).complete();
    assert.equal(wrongGet.status, 404);
    assert.equal((await h.rpc('beta', a, 'ping', 80).complete()).status, 404);
    assert.equal((await h.delete(a, 'beta')).status, 404);
    await h.result(h.call(a, retired ? 3 : 2, { owner: 'alpha' }), retired ? 3 : 2);
    await h.result(h.call(b, retired ? 3 : 2, { owner: 'beta' }, { name: 'beta' }), retired ? 3 : 2);
  }
  assert.equal((await h.snapshot('alpha')).spawn.total, 2);
  assert.equal((await h.snapshot('beta')).spawn.total, 1);
  assert.equal(h.requests('ping', 'beta').length, 0);
});

test('shared HTTP rejects classic SSE and stateful methods without a fallback process', async (t) => {
  const h = await new BridgeRig(t).start();
  const classic = await h.exchange('GET', '/alpha/sse').receivedHeaders();
  assert.ok(classic.status >= 400 && classic.status < 500, `Classic SSE must be rejected, got ${classic.status}`);
  await classic.complete();
  assert.equal((await h.snapshot()).spawn.total, 0);
  const sid = await h.attach();
  await h.failure(h.rpc('alpha', sid, 'logging/setLevel', 1, { level: 'debug' }),
    1, 'SHARED_UNSUPPORTED_METHOD', 'unsent', 'admission');
  await h.failure(h.rpc('alpha', sid, 'tools/call', 2, { name: 'echo', arguments: {}, task: { ttl: 1000 } }),
    2, 'SHARED_UNSUPPORTED_METHOD', 'unsent', 'admission');
  assert.equal(h.requests('tools/call').length, 0);
  assert.equal(h.requests('logging/setLevel').length, 0);
  assert.equal((await h.snapshot()).spawn.total, 1);
});

test('shared HTTP child exit fails all pending POSTs promptly with execution metadata and no replay', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const pending = h.call(a, 1, { op: 'hold', tag: 'exit-pending' }, { progressToken: 'exit' });
  await h.dispatched('exit-pending');
  const started = performance.now();
  const crash = h.call(b, 1, { op: 'exit', tag: 'exit-trigger' });
  const kinds = ['SHARED_CHILD_EXIT', 'SHARED_STDOUT_CLOSED'];
  await Promise.all([
    h.failure(pending, 1, kinds, 'potentially-executed', 'execution'),
    h.failure(crash, 1, kinds, 'potentially-executed', 'execution'),
  ]);
  assert.ok(performance.now() - started < 2_000, 'child exit must not wait out the 4-second request timeout');
  const retired = await h.retired();
  assert.equal(retired.spawn.total, 1);
  assert.equal(h.requests('tools/call').length, 2);
  assert.equal(h.requests('initialize').length, 1);
});

test('shared HTTP recycle drains busy work then retires promptly; the existing SID resumes without replay', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharedDrainTimeoutMs: 5000 },
    env: { MCP_REQUEST_TIMEOUT_MS: '10000' } }).start();
  const sid = await h.attach();
  const pending = h.call(sid, 1, { op: 'hold', tag: 'drain-once' }, { progressToken: 1 });
  const dispatched = await h.dispatched('drain-once');
  const generation = (await h.snapshot()).shared.generation;
  await h.recycle();
  const draining = await h.snapshot();
  assert.equal(draining.shared.state, 'draining');
  assert.equal(draining.shared.unresolved, 1);
  assert.equal(draining.spawn.total, 1);
  await h.failure(h.call(sid, 2, { tag: 'must-not-dispatch' }), 2, 'SHARED_DRAINING', 'unsent', 'admission');
  const started = performance.now();
  h.signal(dispatched.pid, 'release-drain-once');
  await h.result(pending, 1);
  await h.retired('alpha', 2500);
  assert.ok(performance.now() - started < 2500, 'drained child must retire before the 5-second drain deadline');
  const resumed = await h.result(h.call(sid, 3, { tag: 'after-recycle' }), 3);
  const after = await h.snapshot();
  assert.notEqual(resumed.pid, dispatched.pid);
  assert.notEqual(after.shared.generation, generation);
  assert.equal(after.shared.members, 1);
  assert.equal(after.spawn.total, 2);
  assert.equal(after.spawn.sessionResumes, 1);
  assert.equal(after.spawn.samples, 2);
  assert.equal(h.requests('initialize').length, 2);
  assert.equal(h.requests('tools/call').filter((entry) => entry.message.params.arguments.tag === 'drain-once').length, 1);
  assert.equal(h.requests('tools/call').filter((entry) => entry.message.params.arguments.tag === 'must-not-dispatch').length, 0);
});

test('shared HTTP drain deadline fails unresolved execution explicitly rather than replaying it', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharedDrainTimeoutMs: 400 } }).start();
  const sid = await h.attach();
  const pending = h.call(sid, 1, { op: 'hold', tag: 'hung-once' }, { progressToken: 1 });
  await h.dispatched('hung-once');
  const started = performance.now();
  await h.recycle();
  await h.failure(pending, 1, 'SHARED_DRAIN_TIMEOUT', 'potentially-executed', 'execution');
  assert.ok(performance.now() - started < 2000, 'drain failure must precede the 4-second request budget');
  assert.equal((await h.retired()).spawn.total, 1);
  assert.equal(h.requests('tools/call').length, 1);
});

test('shared HTTP simultaneous resumes of the same SID use one creation promise and one virtual attachment', async (t) => {
  const h = await new BridgeRig(t, { manualInitialize: true }).start();
  const initial = h.rpc('alpha', null, 'initialize', 'initial', PARAMS);
  const firstInit = await h.until(() => h.requests('initialize')[0], 'initial manual handshake');
  h.signal(firstInit.pid, 'initialize');
  assert.ok((await initial.message()).result);
  const sid = initial.headers['mcp-session-id'];
  assert.ok(sid);
  assert.equal((await h.rpc('alpha', sid, 'notifications/initialized').complete()).status, 202);
  await h.until(() => h.requests('notifications/initialized').length === 1, 'first upstream initialized notification');
  await h.recycle();
  await h.retired();
  const before = await h.snapshot();
  const a = h.call(sid, 1, { tag: 'resume-number' });
  const b = h.call(sid, '1', { tag: 'resume-string' });
  const init = await h.until(() => h.requests('initialize')[1], 'replacement manual handshake');
  const starting = await h.until(async () => {
    const snapshot = await h.snapshot();
    return snapshot.requests >= before.requests + 2 ? snapshot : false;
  }, 'both same-SID requests to arrive during initialization');
  assert.equal(starting.shared.state, 'starting');
  assert.equal(starting.shared.waiters, 1, 'same-SID resume must be single-flight before virtual attachment');
  h.signal(init.pid, 'initialize');
  const results = await Promise.all([h.result(a, 1), h.result(b, '1')]);
  assert.equal(results[0].pid, results[1].pid);
  assert.notEqual(results[0].pid, firstInit.pid);
  assert.equal(results[0].arguments.tag, 'resume-number');
  assert.equal(results[1].arguments.tag, 'resume-string');
  const after = await h.snapshot();
  assert.equal(after.shared.members, 1);
  assert.equal(after.sessions, 1);
  assert.deepEqual(after.pids, [init.pid]);
  assert.equal(after.spawn.total, 2);
  assert.equal(after.spawn.sessionResumes, 1);
  assert.equal(h.requests('initialize').length, 2);
  assert.equal(h.requests('notifications/initialized').length, 2);
  assert.equal(h.requests('tools/call').length, 2);
});

test('shared HTTP cursors remain bound to the originating SID and generation', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const list = await h.rpc('alpha', a, 'tools/list', 1, {}).message();
  assert.ok(list.result.nextCursor);
  assert.notEqual(list.result.nextCursor, 'fixture-server-cursor');
  await h.failure(h.rpc('alpha', b, 'tools/list', 1, { cursor: list.result.nextCursor }),
    1, 'SHARED_CURSOR_INVALID', 'unsent', 'admission');
  await h.recycle();
  await h.retired();
  await h.failure(h.rpc('alpha', a, 'tools/list', 2, { cursor: list.result.nextCursor }),
    2, 'SHARED_CURSOR_INVALID', 'unsent', 'admission');
  assert.equal(h.requests('tools/list').length, 1);
});

test('shared HTTP unsupported callbacks fail all affected POSTs explicitly without routing to an arbitrary client', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const held = h.call(a, 1, { op: 'hold', tag: 'callback-pending' }, { progressToken: 1 });
  await h.dispatched('callback-pending');
  const callback = h.call(b, 1, { op: 'callback', tag: 'unsupported-callback' }, { progressToken: 1 });
  await Promise.all([
    h.failure(held, 1, 'SHARED_UNSUPPORTED_CALLBACK', 'potentially-executed', 'execution'),
    h.failure(callback, 1, 'SHARED_UNSUPPORTED_CALLBACK', 'potentially-executed', 'execution'),
  ]);
  assert.equal(held.messages.length, 1);
  assert.equal(callback.messages.length, 1);
  assert.equal((await h.retired()).spawn.total, 1);
  assert.equal(h.requests('tools/call').length, 2);
});

test('shared HTTP DELETE during a shared resume fences both same-SID callers without disturbing another resume', async (t) => {
  const h = await new BridgeRig(t, { manualInitialize: true }).start();
  const initial = h.rpc('alpha', null, 'initialize', 'initial', PARAMS);
  const firstInit = await h.until(() => h.requests('initialize')[0], 'initial manual handshake');
  h.signal(firstInit.pid, 'initialize');
  assert.ok((await initial.message()).result);
  const a = initial.headers['mcp-session-id'];
  assert.ok(a);
  assert.equal((await h.rpc('alpha', a, 'notifications/initialized').complete()).status, 202);
  const b = await h.attach('alpha', 'init-b');
  await h.recycle();
  await h.retired();
  const before = await h.snapshot();
  const deletedCalls = [
    h.call(a, 1, { tag: 'deleted-resume-number' }),
    h.call(a, '1', { tag: 'deleted-resume-string' }),
  ];
  const survivor = h.call(b, 1, { tag: 'surviving-resume' });
  const init = await h.until(() => h.requests('initialize')[1], 'replacement manual handshake');
  const starting = await h.until(async () => {
    const snapshot = await h.snapshot();
    return snapshot.requests >= before.requests + 3 ? snapshot : false;
  }, 'all resume requests to arrive while initialization is blocked');
  assert.equal(starting.shared.state, 'starting');
  assert.equal(starting.shared.waiters, 2);
  assert.equal((await h.delete(a)).status, 204);
  const saved = JSON.parse(readFileSync(join(h.directory, 'sessions.json'), 'utf8'));
  assert.equal(Object.hasOwn(saved, a), false);
  assert.equal(Object.hasOwn(saved, b), true);
  assert.equal((await h.rpc('alpha', a, 'ping', 3).complete()).status, 404);
  h.signal(init.pid, 'initialize');
  for (const call of deletedCalls) assert.equal((await call.complete()).status, 404, call.body);
  const result = await h.result(survivor, 1);
  assert.equal(result.pid, init.pid);
  assert.notEqual(result.pid, firstInit.pid);
  const after = await h.snapshot();
  assert.equal(after.shared.members, 1);
  assert.equal(after.shared.waiters, 0);
  assert.equal(after.sessions, 1);
  assert.equal(after.spawn.total, 2);
  assert.equal(after.spawn.sessionResumes, 1);
  assert.deepEqual(after.pids, [init.pid]);
  assert.equal(h.requests('initialize').length, 2);
  assert.equal(h.requests('tools/call').length, 1);
  assert.equal(h.requests('tools/call')[0].message.params.arguments.tag, 'surviving-resume');
  assert.equal((await h.rpc('alpha', a, 'ping', 4).complete()).status, 404);
  assert.equal((await h.exchange('GET', '/alpha/mcp', { headers: { 'mcp-session-id': a } }).complete()).status, 404);
  await h.result(h.call(b, 2, { tag: 'still-surviving' }), 2);
  assert.equal((await h.snapshot()).spawn.total, 2);
});

test('shared HTTP virtual-exit fallback preserves failure metadata when the actual reply exceeds the owner output budget', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharedMaxBufferBytes: 1024 } }).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const held = h.call(b, 1, { op: 'hold', tag: 'output-survivor' }, { progressToken: 1 });
  const dispatched = await h.dispatched('output-survivor');
  const before = await h.snapshot();
  const started = performance.now();
  const error = await h.failure(h.call(a, 1, { op: 'large-result', tag: 'output-once' }, { progressToken: 1 }),
    1, 'SHARED_OUTPUT_LIMIT', 'potentially-executed', 'execution');
  assert.equal(error.data.generation, before.shared.generation);
  assert.ok(performance.now() - started < 2000, 'virtual exit must settle before the request timeout');
  assert.equal(held.ended, false);
  const during = await h.snapshot();
  assert.equal(during.shared.generation, before.shared.generation);
  assert.equal(during.shared.state, 'ready');
  assert.equal(during.shared.members, 1);
  assert.equal(during.shared.unresolved, 1);
  assert.equal(during.spawn.total, 1);
  assert.deepEqual(during.pids, [dispatched.pid]);
  h.signal(dispatched.pid, 'release-output-survivor');
  await h.result(held, 1);
  const resumed = await h.result(h.call(a, 2, { tag: 'after-local-output-failure' }), 2);
  assert.equal(resumed.pid, dispatched.pid);
  assert.equal(h.requests('tools/call').filter((entry) => entry.message.params.arguments.tag === 'output-once').length, 1);
  assert.equal(h.requests('initialize').length, 1);
  assert.equal((await h.snapshot()).spawn.total, 1);
});

test('shared HTTP deep valid input returns an unsent SSE error and the same session can immediately call again', async (t) => {
  const h = await new BridgeRig(t).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const held = h.call(b, 1, { op: 'hold', tag: 'depth-survivor' }, { progressToken: 1 });
  const dispatched = await h.dispatched('depth-survivor');
  const before = await h.snapshot();
  // Build the wire body directly so Node's serializer cannot fail before the bridge sees it.
  const deep = `${'{"nested":'.repeat(2500)}0${'}'.repeat(2500)}`;
  const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","_meta":{"progressToken":1},"arguments":${deep}}}`;
  assert.doesNotThrow(() => JSON.parse(body));
  const started = performance.now();
  const request = h.exchange('POST', '/alpha/mcp', {
    headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      'mcp-session-id': a, 'mcp-protocol-version': PARAMS.protocolVersion,
    },
    body,
    expectedSse: true,
  });
  const error = await h.failure(request,
    1, 'SHARED_DEPTH_LIMIT', 'unsent', 'admission');
  assert.equal(error.data.generation, before.shared.generation);
  assert.ok(performance.now() - started < 2000, 'depth rejection must not wait for a request timeout');
  assert.equal(h.requests('tools/call').length, 1);
  assert.equal(held.ended, false);
  const normal = await h.result(h.call(a, 2, { tag: 'after-deep-input' }), 2);
  assert.equal(normal.pid, dispatched.pid);
  h.signal(dispatched.pid, 'release-depth-survivor');
  await h.result(held, 1);
  const after = await h.snapshot();
  assert.equal(after.shared.generation, before.shared.generation);
  assert.equal(after.shared.members, 2);
  assert.equal(after.shared.unresolved, 0);
  assert.equal(after.spawn.total, 1);
  assert.equal(after.spawn.sessionResumes, 0);
  assert.equal(h.requests('tools/call').length, 2);
});

test('shared HTTP rejects translated wire overflow as unsent SSE without queuing it or disrupting another owner', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharedMaxInFlight: 1 } }).start();
  const [a, b] = await Promise.all([h.attach('alpha', 'init-a'), h.attach('alpha', 'init-b')]);
  const held = h.call(b, 1, { op: 'hold', tag: 'wire-survivor' }, { progressToken: 1 });
  const dispatched = await h.dispatched('wire-survivor');
  const before = await h.snapshot();
  const params = { name: 'echo', arguments: { padding: '' }, _meta: { progressToken: 1 } };
  const message = { jsonrpc: '2.0', method: 'tools/call', id: 1, params };
  params.arguments.padding = 'x'.repeat(1_048_557 - Buffer.byteLength(JSON.stringify(message)));
  assert.equal(Buffer.byteLength(JSON.stringify(message)), 1_048_557);
  const error = await h.failure(h.rpc('alpha', a, 'tools/call', 1, params),
    1, 'SHARED_REQUEST_LIMIT', 'unsent', 'admission');
  assert.equal(error.data.generation, before.shared.generation);
  assert.equal(h.requests('tools/call').length, 1);
  assert.equal(held.ended, false);
  const during = await h.snapshot();
  assert.equal(during.shared.queued, 0);
  assert.equal(during.shared.unresolved, 1);
  assert.equal(during.shared.members, 2);
  const normal = h.call(a, 2, { tag: 'after-wire-overflow' });
  h.signal(dispatched.pid, 'release-wire-survivor');
  await h.result(held, 1);
  assert.equal((await h.result(normal, 2)).pid, dispatched.pid);
  const after = await h.snapshot();
  assert.equal(after.shared.generation, before.shared.generation);
  assert.equal(after.shared.unresolved, 0);
  assert.equal(after.spawn.total, 1);
  assert.equal(after.spawn.sessionResumes, 0);
  assert.equal(h.requests('tools/call').length, 2);
});

test('shared HTTP projects actual tools capabilities and uses the upstream negotiated version for cached virtual sessions', async (t) => {
  const h = await new BridgeRig(t, { manualInitialize: true }).start();
  const first = h.rpc('alpha', null, 'initialize', 'init-a', PARAMS);
  const initialize = await h.until(() => h.requests('initialize')[0], 'negotiating fixture initialize');
  const protocolVersion = '2025-03-26';
  const actual = {
    protocolVersion,
    capabilities: { experimental: {}, prompts: { listChanged: false },
      resources: { subscribe: false, listChanged: false }, tools: { listChanged: false },
      logging: {}, completions: {}, tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } },
    serverInfo: { name: 'shared-http-b6-peer', version: '2', title: 'Actual fixture identity' },
    instructions: 'Preserve actual upstream instructions.', _meta: { nested: ['retain', { exact: true }] },
  };
  writeFileSync(join(h.directory, 'alpha-controls', String(initialize.pid), 'initialize-result.json'), JSON.stringify(actual));
  h.signal(initialize.pid, 'initialize');
  const projected = { ...actual, capabilities: { tools: { listChanged: false } } };
  assert.deepEqual((await first.message()).result, projected);
  const a = first.headers['mcp-session-id'];
  assert.ok(a);
  assert.equal((await h.rpc('alpha', a, 'notifications/initialized', undefined, undefined, protocolVersion).complete()).status, 202);
  const second = h.rpc('alpha', null, 'initialize', 'init-b', PARAMS);
  assert.deepEqual((await second.message()).result, projected);
  const b = second.headers['mcp-session-id'];
  assert.ok(b);
  assert.notEqual(a, b);
  assert.equal((await h.rpc('alpha', b, 'notifications/initialized', undefined, undefined, protocolVersion).complete()).status, 202);
  assert.equal((await h.call(a, 1, { tag: 'wrong-header' }).complete()).status, 400);
  assert.equal(h.requests('tools/call').length, 0);
  const calls = [h.call(a, 2, { owner: 'a' }, { progressToken: 1, protocolVersion }),
    h.call(b, 2, { owner: 'b' }, { progressToken: 1, protocolVersion })];
  const results = await Promise.all(calls.map((call) => h.result(call, 2)));
  assert.deepEqual(results.map((result) => result.arguments.owner), ['a', 'b']);
  assert.ok(results.every((result) => result.pid === initialize.pid));
  await h.failure(h.rpc('alpha', a, 'prompts/list', 3, {}, protocolVersion),
    3, 'SHARED_UNSUPPORTED_METHOD', 'unsent', 'admission');
  await h.failure(h.rpc('alpha', b, 'tools/call', 3,
    { name: 'echo', arguments: {}, task: { ttl: 1000 } }, protocolVersion),
    3, 'SHARED_UNSUPPORTED_METHOD', 'unsent', 'admission');
  assert.equal(h.requests('initialize').length, 1);
  assert.equal(h.requests('initialize')[0].message.params.protocolVersion, PARAMS.protocolVersion);
  assert.equal(h.requests('notifications/initialized').length, 1);
  const after = await h.snapshot();
  assert.equal(after.shared.members, 2);
  assert.equal(after.shared.unresolved, 0);
  assert.equal(after.spawn.total, 1);
  assert.equal(after.spawn.samples, 1);
  assert.deepEqual(after.pids, [initialize.pid]);
});

test('shared HTTP stale configuration queued behind a busy legacy child fails before creating a shared generation', async (t) => {
  const h = await new BridgeRig(t, { definition: { sharing: 'isolated', maxSessions: 1 },
    env: { MCP_QUEUE_TIMEOUT_MS: '10000', MCP_REQUEST_TIMEOUT_MS: '15000' } }).start();
  const old = await h.attach();
  const busy = h.call(old, 1, { op: 'hold', tag: 'legacy-busy' });
  const dispatched = await h.dispatched('legacy-busy');
  assert.equal((await h.reload({ sharing: 'shared' })).restarted, 0);
  const before = await h.snapshot();
  assert.equal(before.shared, null);
  assert.equal(before.sessions, 1);
  const queued = h.rpc('alpha', null, 'initialize', 'queued-old-definition', PARAMS);
  await h.until(async () => (await h.snapshot()).requests >= before.requests + 1, 'queued initialize to arrive');
  assert.equal(queued.ended, false);
  assert.equal(h.requests('initialize').length, 1);
  assert.equal((await h.reload({ env: { B6_TEST_GENERATION: 'latest' } })).restarted, 0);
  assert.equal(busy.ended, false);
  assert.equal((await h.snapshot()).shared, null);
  h.signal(dispatched.pid, 'release-legacy-busy');
  assert.equal((await h.result(busy, 1)).pid, dispatched.pid);
  assert.equal((await h.delete(old)).status, 204);
  await queued.complete();
  assert.equal(queued.status, 409, queued.body);
  const rejected = await h.snapshot();
  assert.equal(rejected.shared, null, 'stale admission must not leave an initialized shared child');
  assert.equal(rejected.spawn.total, 1, 'stale admission must fail before manager.acquire');
  assert.equal(rejected.spawn.attempts, 1);
  assert.equal(h.requests('initialize').length, 1);
  assert.equal(h.records().filter((entry) => entry.event === 'spawn').length, 1);
  assert.match(queued.body, /configuration changed while waiting for capacity/);
  const current = await h.attach('alpha', 'latest-definition');
  const result = await h.result(h.call(current, 1, { tag: 'latest-only' }), 1);
  assert.notEqual(result.pid, dispatched.pid);
  const after = await h.snapshot();
  assert.equal(after.shared.state, 'ready');
  assert.equal(after.shared.members, 1);
  assert.equal(after.spawn.total, 2);
  assert.equal(h.requests('initialize').length, 2);
  assert.equal(h.requests('tools/call').length, 2);
});

test('shared HTTP March two-reply JSON overflow is bounded during collection and cancels only the failed POST', async (t) => {
  for (const hasPendingBatchCall of [false, true]) {
    const h = await new BridgeRig(t, { definition: { sharedMaxBufferBytes: 512, sharedMaxInFlight: 4 },
      env: { MCP_REQUEST_TIMEOUT_MS: '8000' } }).start();
    const protocolVersion = '2025-03-26';
    const params = { ...PARAMS, protocolVersion };
    const [a, b] = await Promise.all([h.attach('alpha', 'init-a', params), h.attach('alpha', 'init-b', params)]);
    const otherClient = h.call(b, 3, { op: 'hold', tag: 'batch-other-client' }, { protocolVersion });
    const otherPost = h.call(a, 99, { op: 'hold', tag: 'batch-other-post' }, { protocolVersion });
    const db = await h.dispatched('batch-other-client');
    const da = await h.dispatched('batch-other-post');
    const before = await h.snapshot();
    const messages = [
      { jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'echo', arguments: { op: 'sized-hold', tag: 'batch-first' } } },
      { jsonrpc: '2.0', id: '1', method: 'tools/call',
        params: { name: 'echo', arguments: { op: 'sized-hold', tag: 'batch-second' } } },
    ];
    if (hasPendingBatchCall) messages.push({ jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'echo', arguments: { op: 'hold', tag: 'batch-cancel-only' } } });
    const post = h.batch(a, messages, protocolVersion);
    const first = await h.dispatched('batch-first');
    const second = await h.dispatched('batch-second');
    assert.equal((await h.snapshot()).shared.queued, hasPendingBatchCall ? 1 : 0);
    h.signal(first.pid, 'release-batch-first');
    await h.until(() => h.records().some((entry) => entry.event === 'response' && entry.message.id === first.message.id),
      'first bounded batch reply');
    const pending = hasPendingBatchCall ? await h.dispatched('batch-cancel-only') : null;
    assert.equal(post.ended, false);
    const started = performance.now();
    h.signal(second.pid, 'release-batch-second');
    await post.complete();
    assert.ok(performance.now() - started < 2000, 'overflow must not wait for the unfinished batch call');
    assert.equal(post.status, 502, post.body);
    assert.match(post.headers['content-type'], /^application\/json/);
    const overflow = JSON.parse(post.body);
    assert.match(overflow.error.message, /response exceeds the output limit; calls were not replayed/);
    assert.equal(overflow.error.data.execution, 'potentially-executed');
    assert.ok(Buffer.byteLength(post.body) <= 512);
    const replies = [first, second].map((request, index) => {
      const response = h.records().find((entry) => entry.event === 'response' && entry.message.id === request.message.id);
      assert.ok(response);
      const wire = { jsonrpc: '2.0', ...response.message };
      assert.ok(Buffer.byteLength(JSON.stringify(wire)) + 1 <= 512, 'each upstream reply fits independently');
      return { ...wire, id: messages[index].id };
    });
    assert.ok(Buffer.byteLength(JSON.stringify(replies)) > 512, 'only their combined JSON body exceeds the budget');
    if (pending) {
      await h.until(() => h.requests('notifications/cancelled').length === 1,
        'only unfinished batch work to be cancelled', 2000);
      assert.equal(h.requests('notifications/cancelled')[0].message.params.requestId, pending.message.id);
      assert.notEqual(pending.message.id, db.message.id);
      assert.notEqual(pending.message.id, da.message.id);
    } else {
      assert.equal(h.requests('notifications/cancelled').length, 0);
    }
    assert.equal(otherClient.ended, false);
    assert.equal(otherPost.ended, false);
    const during = await h.snapshot();
    assert.equal(during.shared.generation, before.shared.generation);
    assert.equal(during.shared.state, 'ready');
    assert.equal(during.shared.members, 2);
    assert.equal(during.shared.unresolved, pending ? 3 : 2);
    assert.equal(during.spawn.total, 1);
    h.signal(db.pid, 'release-batch-other-client');
    h.signal(da.pid, 'release-batch-other-post');
    assert.equal((await h.result(otherClient, 3)).pid, db.pid);
    assert.equal((await h.result(otherPost, 99)).pid, db.pid);
    if (pending) h.signal(pending.pid, 'release-batch-cancel-only');
    await h.until(async () => (await h.snapshot()).shared.unresolved === 0, 'cancelled execution to finish without replay');
    assert.equal((await h.result(h.call(a, 100, { tag: 'after-batch-overflow' }, { protocolVersion }), 100)).pid, db.pid);
    for (const message of messages) {
      assert.equal(h.requests('tools/call').filter((entry) =>
        entry.message.params.arguments.tag === message.params.arguments.tag).length, 1);
    }
    assert.equal(h.requests('initialize').length, 1);
    assert.equal((await h.snapshot()).spawn.total, 1);
    await h.stop();
  }
});

test('shared HTTP permits March batches only, preserves singleton arrays and rejects all initialize batches before spawning', async (t) => {
  for (const protocolVersion of ['2025-03-26', '2025-06-18', '2025-11-25']) {
    const h = await new BridgeRig(t).start();
    const params = { ...PARAMS, protocolVersion };
    const initialize = { jsonrpc: '2.0', id: 'init', method: 'initialize', params };
    const ping = { jsonrpc: '2.0', id: 1, method: 'ping' };
    for (const messages of [[initialize], [initialize, ping], []]) {
      const rejected = await h.batch(null, messages, protocolVersion).complete();
      assert.equal(rejected.status, 400, rejected.body);
      assert.equal((await h.snapshot()).spawn.total, 0);
    }
    const sid = await h.attach('alpha', 'regular-init', params);
    const singleton = h.batch(sid, [ping], protocolVersion);
    if (protocolVersion === '2025-03-26') {
      assert.deepEqual(await singleton.message(), [{ jsonrpc: '2.0', id: 1, result: {} }]);
      const collision = await h.batch(sid, [
        { jsonrpc: '2.0', id: 2, method: 'ping' }, { jsonrpc: '2.0', id: '2', method: 'ping' },
      ], protocolVersion).message();
      assert.deepEqual(collision, [{ jsonrpc: '2.0', id: 2, result: {} }, { jsonrpc: '2.0', id: '2', result: {} }]);
      const progressBatch = await h.batch(sid, [
        { jsonrpc: '2.0', id: 3, method: 'ping', params: { _meta: { progressToken: 1 } } },
        { jsonrpc: '2.0', id: '3', method: 'ping', params: { _meta: { progressToken: '1' } } },
      ], protocolVersion).complete();
      assert.equal(progressBatch.status, 200);
      assert.match(progressBatch.headers['content-type'], /^text\/event-stream/);
      assert.deepEqual(progressBatch.messages, [
        { jsonrpc: '2.0', id: 3, result: {} }, { jsonrpc: '2.0', id: '3', result: {} },
      ]);
      const notifications = await h.batch(sid, [
        { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 'never-sent' } },
      ], protocolVersion).complete();
      assert.equal(notifications.status, 202);
    } else {
      assert.equal((await singleton.complete()).status, 400);
      assert.equal((await h.batch(sid, [ping, { ...ping, id: '1' }], protocolVersion).complete()).status, 400);
      assert.equal((await h.batch(sid, [ping], '2025-03-26').complete()).status, 400);
      assert.equal(h.requests('ping').length, 0);
    }
    const before = h.requests('ping').length;
    const reinitialize = await h.batch(sid, [initialize], protocolVersion).complete();
    assert.equal(reinitialize.status, 400);
    assert.equal((await h.batch(sid, [{ ...ping, id: 8 }, { ...ping, id: 8 }], protocolVersion).complete()).status, 400);
    assert.equal(h.requests('ping').length, before);
    assert.deepEqual(await h.rpc('alpha', sid, 'ping', 9, undefined, protocolVersion).message(),
      { jsonrpc: '2.0', id: 9, result: {} });
    assert.equal(h.requests('initialize').length, 1);
    const after = await h.snapshot();
    assert.equal(after.shared.members, 1);
    assert.equal(after.spawn.total, 1);
    await h.stop();
  }
});
