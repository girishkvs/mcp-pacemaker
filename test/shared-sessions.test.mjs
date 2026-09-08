import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SharedSessionManager, SHARED_DEFAULTS } from '../bin/shared-sessions.mjs';

const PARAMS = {
  protocolVersion: '2025-11-25', capabilities: {},
  clientInfo: { name: 'shared-test-client', version: '1', title: 'Complete identity' },
};
const DEFINITION = { type: 'stdio', sharing: 'shared', command: 'synthetic-peer' };

class Peer extends EventEmitter {
  constructor(number, automaticInit = true) {
    super();
    this.pid = number;
    this.__spawnedAt = Date.now();
    this.exitCode = null;
    this.signalCode = null;
    this.messages = [];
    this.automaticInit = automaticInit;
    this.initialized = false;
    this.credentialExpiresAt = Date.now() + 50;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.stdin = new Writable({
      write: (chunk, encoding, callback) => {
        for (const line of chunk.toString().trimEnd().split('\n')) this.receive(JSON.parse(line));
        callback();
      },
    });
  }

  receive(message) {
    this.messages.push(message);
    this.emit('message', message);
    if (message.method === 'initialize' &&
        this.automaticInit) {
      queueMicrotask(() => this.initialize(message));
    }
    if (message.method === 'notifications/initialized') {
      assert.equal(this.initialized, false);
      this.initialized = true;
    }
    if (message.method === 'tools/call') assert.equal(this.initialized, true);
  }

  initialize(request = this.requests('initialize')[0], override = {}) {
    this.reply(request, {
      protocolVersion: request.params.protocolVersion, capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'strict-peer', version: '1' }, instructions: 'Real peer result',
      ...override,
    });
  }

  requests(method) {
    return this.messages.filter((message) => message.method === method);
  }

  send(message) {
    this.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  }

  reply(request, result) {
    this.send({ id: request.id, result });
  }

  credentialCall(request) {
    if (Date.now() >= this.credentialExpiresAt) {
      this.send({ id: request.id, error: { code: -32077, message: 'Server credential expired',
        data: { owner: 'server' } } });
    } else {
      this.reply(request, { content: [{ type: 'text', text: 'Server credential valid' }] });
    }
  }

  exit(code = 0) {
    this.exitCode = code;
    this.emit('exit', code, null);
    this.emit('close', code, null);
  }
}

class Client extends EventEmitter {
  constructor(child) {
    super();
    this.child = child;
    this.messages = [];
    this.progress = [];
    this.failures = [];
    this.exits = [];
    this.buffer = '';
    child.stdout.on('data', (chunk) => {
      this.buffer += chunk.toString();
      let end;
      while ((end = this.buffer.indexOf('\n')) >= 0) {
        const message = JSON.parse(this.buffer.slice(0, end));
        this.buffer = this.buffer.slice(end + 1);
        this.messages.push(message);
        this.emit('message', message);
      }
    });
    child.on('sharedProgress', (detail) => this.progress.push(detail));
    child.on('sharedFailure', (detail) => this.failures.push(detail));
    child.on('exit', (code, signal) => this.exits.push({ code, signal }));
  }

  send(method, id, params) {
    const message = { jsonrpc: '2.0', method };
    if (id !== undefined) message.id = id;
    if (params !== undefined) message.params = params;
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  async response(id) {
    for (;;) {
      const found = this.messages.find((message) => message.id === id);
      if (found) return found;
      await once(this, 'message');
    }
  }

  async initialize(params = PARAMS) {
    this.send('initialize', 'init', params);
    const response = await this.response('init');
    assert.ok(response.result, JSON.stringify(response));
    this.send('notifications/initialized');
    return this;
  }

  call(id, args = {}, extra = {}) {
    this.send('tools/call', id, { name: 'stateless', arguments: args, ...extra });
  }
}

class Rig {
  constructor(t, { definition = {}, manager = {}, automaticInit = true, delayedKill = false } = {}) {
    this.definition = { ...DEFINITION, ...definition };
    this.children = [];
    this.kills = [];
    this.failures = [];
    this.retirements = [];
    this.logs = [];
    this.initializations = [];
    this.responses = [];
    this.manager = new SharedSessionManager({
      spawn: async () => {
        const child = new Peer(this.children.length + 1, automaticInit);
        this.children.push(child);
        return child;
      },
      kill: (child) => {
        this.kills.push(child);
        if (!delayedKill) child.exit();
      },
      onFailure: (name, detail) => this.failures.push({ name, ...detail }),
      onInitialized: (name, elapsedMs) => this.initializations.push({ name, elapsedMs }),
      onResponse: (name) => this.responses.push(name),
      log: (name, text) => this.logs.push({ name, text }),
      ...manager,
    });
    this.manager.on('retired', (detail) => this.retirements.push(detail));
    t.after(() => this.manager.shutdown());
  }

  acquire(params = PARAMS, definition = this.definition) {
    return this.manager.acquire('server', definition, params);
  }

  async attach(params = PARAMS) {
    return new Client(await this.acquire(params)).initialize(params);
  }

  async turn() {
    await new Promise((resolve) => setImmediate(resolve));
  }

  clock(t) {
    t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000 });
  }

  async initializeClients(result, params = PARAMS) {
    const pending = Promise.all([this.acquire(params), this.acquire(params)]);
    await this.turn();
    this.children[0].initialize(undefined, result);
    return Promise.all((await pending).map((child) => new Client(child).initialize(params)));
  }

  failure(response, kind, execution) {
    assert.ok(response?.error, 'expected an explicit shared failure response');
    assert.equal(response.error.data.kind, kind);
    if (execution) assert.equal(response.error.data.execution, execution);
  }

  async rejectedWrite(client, line, kind, id = 1) {
    const callbacks = [];
    assert.doesNotThrow(() => client.child.stdin.write(line, (error) => callbacks.push(error)));
    await this.turn();
    assert.equal(callbacks.length, 1, 'every Writable callback must complete');
    assert.ifError(callbacks[0]);
    const response = client.messages.find((message) => message.id === id);
    assert.ok(response, 'the unsent request must fail immediately');
    this.failure(response, kind, 'unsent');
    assert.equal(response.error.data.phase, 'admission');
    assert.equal(client.child.active, true);
    assert.equal(this.manager.inspect('server').state, 'ready');
    assert.equal(this.manager.inspect('server').queued, 0);
    assert.equal(this.failures.length, 0);
    assert.equal(this.kills.length, 0);
    assert.equal(this.responses.length, 0);
  }

  depthLine(message, depth = 9_000) {
    const nested = `${'{"nested":'.repeat(depth)}0${'}'.repeat(depth)}`;
    const line = `${JSON.stringify({ jsonrpc: '2.0', ...message }).replace('"__shared_depth_value__"', nested)}\n`;
    assert.doesNotThrow(() => JSON.parse(line));
    assert.ok(Buffer.byteLength(line) < SHARED_DEFAULTS.sharedMaxLineBytes);
    return line;
  }
}

class PeerProcesses {
  constructor(t) {
    this.children = [];
    this.launches = 0;
    t.after(() => Promise.all(this.children.map((child) => this.stop(child))));
  }

  spawn() {
    const child = spawn(process.execPath, [
      fileURLToPath(new URL('./fixtures/shared-session-b6-peer.mjs', import.meta.url)),
    ], { stdio: ['pipe', 'pipe', 'pipe'] });
    child.once('spawn', () => { this.launches++; });
    this.children.push(child);
    return child;
  }

  async stop(child) {
    if (child.exitCode !== null ||
        child.signalCode !== null) return;
    const exit = once(child, 'exit');
    child.kill();
    await exit;
  }
}

class DepthPeers extends PeerProcesses {
  spawn(name) {
    const child = spawn(process.execPath, [
      fileURLToPath(new URL('./fixtures/shared-depth-b6-peer.mjs', import.meta.url)),
    ], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] });
    child.__spawnedAt = Date.now();
    child.serverName = name;
    child.requests = [];
    child.wires = [];
    child.once('spawn', () => { this.launches++; });
    child.on('message', (event) => {
      if (event.kind === 'request') child.requests.push(event.message);
      else child.wires.push(event);
    });
    this.children.push(child);
    return child;
  }

  async request(child, tag) {
    for (;;) {
      const request = child.requests.find((message) => message.params?.arguments?.tag === tag);
      if (request) return request;
      await once(child, 'message');
    }
  }

  send(child, message, depth = 0) {
    child.send({ message, depth });
  }
}

test('defaults and every bound reject unsafe integers, coercions, zero where unsafe and excessive values', () => {
  assert.equal(SHARED_DEFAULTS.sharedLingerMs, 1_800_000);
  const manager = new SharedSessionManager({ spawn() {}, kill() {} });
  for (const name of Object.keys(SHARED_DEFAULTS)) {
    for (const value of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', null]) {
      assert.throws(() => manager.options({ [name]: value }), /safe integer/);
    }
  }
  for (const name of ['initTimeoutMs', 'requestTimeoutMs']) {
    for (const value of [0, -1, 0.5, '2', Infinity, 2_147_483_648]) {
      assert.throws(() => new SharedSessionManager({ spawn() {}, kill() {}, [name]: value }), /safe integer/);
    }
  }
  assert.equal(manager.options({ sharedLingerMs: 0, sharedMaxQueued: 0 }).sharedMaxQueued, 0);
});

test('more than fifty real initialize/DELETE cycles and concurrent sessions reuse one OS child', { timeout: 15_000 }, async (t) => {
  const children = [];
  const failures = [];
  const manager = new SharedSessionManager({
    spawn: async () => {
      const child = spawn(process.execPath, [
        fileURLToPath(new URL('./fixtures/shared-session-b6-peer.mjs', import.meta.url)),
      ], { stdio: ['pipe', 'pipe', 'pipe'] });
      child.__spawnedAt = Date.now();
      children.push(child);
      return child;
    },
    kill: (child) => child.kill(),
    onFailure: (name, detail) => failures.push(detail),
  });
  t.after(async () => {
    const exit = children.filter((child) => child.exitCode === null).map((child) => once(child, 'exit'));
    manager.shutdown();
    await Promise.all(exit);
  });
  const pids = new Set();
  for (let i = 0; i < 60; i++) {
    const client = await new Client(await manager.acquire('real', DEFINITION, PARAMS)).initialize();
    client.call(1, { cycle: i });
    const stats = JSON.parse((await client.response(1)).result.content[0].text);
    pids.add(stats.pid);
    assert.equal(stats.initializes, 1);
    assert.equal(stats.initialized, 1);
    assert.equal(stats.calls, i + 1);
    assert.deepEqual(stats.arguments, { cycle: i });
    assert.equal(client.child.detach(), true);
    assert.equal(client.child.detach(), false);
  }
  const [a, b] = await Promise.all([1, 2].map(async () =>
    new Client(await manager.acquire('real', DEFINITION, PARAMS)).initialize()));
  a.call(1);
  b.call(1);
  await Promise.all([a.response(1), b.response(1)]);
  assert.equal(a.child.pid, b.child.pid);
  assert.equal(a.child.__sharedSession, true);
  assert.ok(a.child.__spawnedAt);
  assert.equal(a.child.exitCode, null);
  assert.equal(a.child.signalCode, null);
  assert.equal(manager.inspect('real').members, 2);
  assert.equal(children.length, 1);
  assert.equal(pids.size, 1);
  assert.equal(failures.length, 0);
});

test('concurrent arrivals reserve one spawn and initialization before awaiting the gate', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let spawns = 0;
  const peer = new Peer(1, false);
  const r = new Rig(t, { manager: { spawn: async () => { spawns++; await gate; return peer; } } });
  const arrivals = Array.from({ length: 16 }, () => r.acquire());
  await r.turn();
  assert.equal(spawns, 1);
  assert.equal(r.manager.inspect('server').waiters, 16);
  release();
  await r.turn();
  assert.equal(peer.requests('initialize').length, 1);
  peer.initialize();
  const children = await Promise.all(arrivals);
  assert.equal(new Set(children.map((child) => child.pid)).size, 1);
  assert.equal(peer.requests('notifications/initialized').length, 1);
  assert.equal(peer.stdout.listenerCount('data'), 1);
  assert.equal(r.manager.inspect('server').members, 16);
});

test('canonical initialization includes all identity, metadata, arrays and config without changing the group', async (t) => {
  const r = new Rig(t);
  const params = { ...PARAMS, _meta: { nested: { z: 1, a: ['a', 'b'] } } };
  await r.acquire(params);
  await r.acquire({
    _meta: { nested: { a: ['a', 'b'], z: 1 } }, clientInfo: { ...PARAMS.clientInfo },
    capabilities: {}, protocolVersion: PARAMS.protocolVersion,
  });
  const incompatible = [
    { ...params, clientInfo: { ...params.clientInfo, title: 'Different' } },
    { ...params, _meta: { nested: { z: 1, a: ['b', 'a'] } } },
    { ...params, _meta: undefined },
    { ...params, capabilities: { sampling: {} } },
    { ...params, capabilities: { roots: { listChanged: false } } },
    { ...params, capabilities: { experimental: {} } },
    { ...params, protocolVersion: '2025-06-18' },
    { ...params, additional: null },
  ];
  for (const changed of incompatible) {
    await assert.rejects(() => r.acquire(changed), /SHARED_(INCOMPATIBLE|INVALID_CONFIG)/);
  }
  for (const changed of [
    { ...r.definition, env: { PRINCIPAL: 'different' } },
    { ...r.definition, command: 'new-peer' },
    { ...r.definition, sharedLingerMs: 5 },
  ]) {
    await assert.rejects(() => r.acquire(params, changed), /SHARED_INCOMPATIBLE/);
  }
  assert.equal(r.children.length, 1);
  assert.equal(r.manager.inspect('server').members, 2);
  assert.equal(r.failures.length, 0);
});

test('released versions are accepted and unsupported profiles fail before spawning', async (t) => {
  for (const protocolVersion of ['2025-03-26', '2025-06-18', '2025-11-25']) {
    const r = new Rig(t);
    await r.attach({ ...PARAMS, protocolVersion });
    assert.equal(r.children.length, 1);
  }
  const r = new Rig(t);
  for (const params of [
    { ...PARAMS, protocolVersion: '2026-07-28' },
    { ...PARAMS, capabilities: { tasks: {} } },
    { ...PARAMS, capabilities: { elicitation: {} } },
    { ...PARAMS, capabilities: [] },
    { ...PARAMS, clientInfo: { name: 'missing-version' } },
  ]) await assert.rejects(() => r.acquire(params), /SHARED_INCOMPATIBLE/);
  for (const definition of [{ ...DEFINITION, sharing: 'isolated' }, { ...DEFINITION, type: 'http' }]) {
    await assert.rejects(() => r.acquire(PARAMS, definition), /SHARED_INCOMPATIBLE/);
  }
  assert.equal(r.children.length, 0);
});

test('actual initialization result is retained and each virtual client must finish its handshake', async (t) => {
  const r = new Rig(t);
  const a = new Client(await r.acquire());
  const b = await r.attach();
  a.call(1);
  r.failure(await a.response(1), 'SHARED_NOT_INITIALIZED', 'unsent');
  a.send('initialize', 'own-id', PARAMS);
  assert.deepEqual((await a.response('own-id')).result, (await b.response('init')).result);
  a.call(2);
  r.failure(await a.response(2), 'SHARED_NOT_INITIALIZED');
  a.send('notifications/initialized');
  a.call(3);
  assert.equal(r.children[0].requests('tools/call').length, 1);
  assert.equal((await a.response('own-id')).result.instructions, 'Real peer result');
});

test('failed initialization rejects all waiters, kills once and allows a later bounded retry', async (t) => {
  const r = new Rig(t, { automaticInit: false, definition: { sharedRetryDelayMs: 10 } });
  r.clock(t);
  const a = assert.rejects(() => r.acquire(), (error) => {
    assert.equal(error.code, 'SHARED_INIT_REJECTED');
    assert.deepEqual(error.upstreamError, { code: -32099, message: 'original init error' });
    return true;
  });
  const b = assert.rejects(() => r.acquire(), /SHARED_INIT_REJECTED/);
  await r.turn();
  r.children[0].send({ id: r.children[0].requests('initialize')[0].id,
    error: { code: -32099, message: 'original init error' } });
  await Promise.all([a, b]);
  assert.equal(r.kills.length, 1);
  assert.equal(r.failures.length, 1);
  assert.equal(r.initializations.length, 0);
  await assert.rejects(() => r.acquire(), /SHARED_RETRY_LATER/);
  t.mock.timers.tick(10);
  const next = r.acquire();
  await r.turn();
  r.children[1].initialize();
  await next;
  assert.equal(r.children.length, 2);
});

test('invalid init result and init timeout are explicit lifecycle failures, not successful defaults', async (t) => {
  for (const result of [
    {}, { capabilities: { tools: {}, unknown: {} } }, { protocolVersion: '2026-07-28' },
    { serverInfo: null }, { capabilities: { tools: null } },
  ]) {
    const r = new Rig(t, { automaticInit: false });
    const pending = assert.rejects(() => r.acquire(), /SHARED_INIT_INCOMPATIBLE/);
    await r.turn();
    if (Object.keys(result).length) {
      r.children[0].initialize(undefined, result);
    } else {
      r.children[0].reply(r.children[0].requests('initialize')[0], {});
    }
    await pending;
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
    assert.equal(r.initializations.length, 0);
  }
  const r = new Rig(t, { automaticInit: false, manager: { initTimeoutMs: 20 } });
  r.clock(t);
  const pending = assert.rejects(() => r.acquire(), /SHARED_INIT_TIMEOUT/);
  await r.turn();
  t.mock.timers.tick(20);
  await pending;
  assert.equal(r.manager.inspect('server'), null);
  assert.equal(r.initializations.length, 0);
});

test('typed same IDs, out-of-order results and late responses never cross virtual sessions', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1, { id: 1, requestId: 'unchanged', nested: { progressToken: 'raw' } });
  a.call('1');
  b.call(1);
  b.call('1');
  const calls = r.children[0].requests('tools/call');
  assert.equal(new Set(calls.map((call) => call.id)).size, 4);
  assert.deepEqual(calls[0].params.arguments, { id: 1, requestId: 'unchanged', nested: { progressToken: 'raw' } });
  for (const [index, label] of [[3, 'b-string'], [1, 'a-string'], [2, 'b-number'], [0, 'a-number']]) {
    r.children[0].reply(calls[index], { label });
  }
  assert.deepEqual(a.messages.slice(1).map((message) => [message.id, message.result.label]),
    [['1', 'a-string'], [1, 'a-number']]);
  assert.deepEqual((await a.response(1)).result, { label: 'a-number' });
  assert.deepEqual((await a.response('1')).result, { label: 'a-string' });
  assert.deepEqual((await b.response(1)).result, { label: 'b-number' });
  assert.deepEqual((await b.response('1')).result, { label: 'b-string' });
  r.children[0].reply(calls[0], { secret: 'late' });
  r.children[0].send({ id: 'unknown', result: { secret: 'unowned' } });
  await r.turn();
  assert.equal(a.messages.length, 3);
  assert.equal(b.messages.length, 3);
});

test('progress and cancellation use owner-scoped typed tokens and originating POST request IDs', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1, {}, { _meta: { progressToken: 7, untouched: { id: '1' } } });
  b.call(1, {}, { _meta: { progressToken: 7 } });
  a.call('1', {}, { _meta: { progressToken: '7' } });
  const peer = r.children[0];
  const calls = peer.requests('tools/call');
  for (const call of calls) {
    peer.send({ method: 'notifications/progress',
      params: { progressToken: call.params._meta.progressToken, progress: 0.5 } });
  }
  peer.send({ method: 'notifications/progress', params: { progressToken: 'forged', progress: 100 } });
  assert.deepEqual(a.progress.map((item) => [item.requestId, item.message.params.progressToken]), [[1, 7], ['1', '7']]);
  assert.deepEqual(b.progress.map((item) => [item.requestId, item.message.params.progressToken]), [[1, 7]]);
  assert.deepEqual(calls[0].params._meta.untouched, { id: '1' });
  assert.equal(a.messages.filter((message) => message.method === 'notifications/progress').length, 0);
  a.send('notifications/cancelled', undefined, { requestId: 1 });
  assert.equal(peer.requests('notifications/cancelled')[0].params.requestId, calls[0].id);
  assert.equal(r.manager.inspect('server').unresolved, 3);
  peer.send({ method: 'notifications/progress',
    params: { progressToken: calls[0].params._meta.progressToken, progress: 1 } });
  assert.equal(a.progress.length, 2);
  peer.reply(calls[0], { ignored: true });
  peer.reply(calls[1], { delivered: true });
  peer.reply(calls[2], { typed: true });
  r.failure(await a.response(1), 'SHARED_CANCELLED', 'potentially-executed');
  assert.deepEqual((await b.response(1)).result, { delivered: true });
  assert.deepEqual((await a.response('1')).result, { typed: true });
  assert.equal(r.manager.inspect('server').unresolved, 0);
});

test('foreign cancellations and forged client responses cannot answer or cancel another owner', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  b.call(9);
  const call = r.children[0].requests('tools/call')[0];
  a.send('notifications/cancelled', undefined, { requestId: 9 });
  a.send('notifications/cancelled', undefined, { requestId: call.id });
  assert.equal(r.children[0].requests('notifications/cancelled').length, 0);
  a.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: call.id, result: { forged: true } })}\n`);
  r.children[0].reply(call, { real: true });
  assert.deepEqual((await b.response(9)).result, { real: true });
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_INVALID_MESSAGE');
  assert.equal(r.failures.length, 0);
});

test('server ping with a colliding operation ID is a callback, not that operation response', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  a.call(1);
  const peer = r.children[0];
  const call = peer.requests('tools/call')[0];
  peer.send({ method: 'ping', id: call.id });
  assert.deepEqual(peer.messages.at(-1), { jsonrpc: '2.0', id: call.id, result: {} });
  assert.equal(r.manager.inspect('server').unresolved, 1);
  peer.reply(call, { tool: true });
  assert.deepEqual((await a.response(1)).result, { tool: true });
});

test('unsupported callbacks fail explicitly and retire the group without guessed recipients', async (t) => {
  for (const method of ['sampling/createMessage', 'roots/list', 'elicitation/create', 'extension/private']) {
    const r = new Rig(t);
    const [a, b] = await Promise.all([r.attach(), r.attach()]);
    a.call(1);
    const peer = r.children[0];
    const call = peer.requests('tools/call')[0];
    peer.send({ id: call.id, method, params: { private: 'never route' } });
    const answer = peer.messages.at(-1);
    assert.equal(answer.id, call.id);
    assert.equal(answer.error.code, -32601);
    r.failure(await a.response(1), 'SHARED_UNSUPPORTED_CALLBACK', 'potentially-executed');
    await r.turn();
    assert.equal(b.messages.length, 1);
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
    assert.equal(a.exits.length, 1);
    assert.equal(b.exits.length, 1);
  }
});

test('stateful methods and task-augmented calls are rejected without upstream dispatch', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  const methods = ['logging/setLevel', 'resources/subscribe', 'resources/unsubscribe', 'resources/read',
    'prompts/get', 'tasks/get', 'tasks/list', 'tasks/cancel'];
  for (const [index, method] of methods.entries()) {
    a.send(method, index, {});
    r.failure(await a.response(index), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  }
  a.call('task', {}, { task: { ttl: 100 } });
  r.failure(await a.response('task'), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  assert.equal(r.children[0].messages.length, 2);
  assert.equal(r.failures.length, 0);
});

test('catalog changes are common only when advertised; unowned logs and unknown extensions never leak', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  peer.send({ method: 'notifications/tools/list_changed', params: { private: 'discarded' } });
  peer.send({ method: 'notifications/message', params: { data: 'private log body' } });
  await r.turn();
  assert.deepEqual(a.messages.at(-1), { jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  assert.deepEqual(b.messages.at(-1), a.messages.at(-1));
  assert.equal(JSON.stringify(r.logs).includes('private log body'), false);
  peer.send({ method: 'notifications/unknown', params: { secret: true } });
  await r.turn();
  assert.equal(r.failures[0].kind, 'SHARED_UNSUPPORTED_NOTIFICATION');
  assert.equal(a.messages.length, 2);
  assert.equal(b.messages.length, 2);
});

test('cursors are opaque and bound to their virtual session and child generation', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.send('tools/list', 1, {});
  const peer = r.children[0];
  peer.reply(peer.requests('tools/list')[0], { tools: [], nextCursor: 'server-cursor' });
  const cursor = (await a.response(1)).result.nextCursor;
  assert.notEqual(cursor, 'server-cursor');
  b.send('tools/list', 1, { cursor });
  assert.equal(peer.requests('tools/list').length, 1);
  r.failure(await b.response(1), 'SHARED_CURSOR_INVALID', 'unsent');
  a.send('tools/list', 2, { cursor });
  assert.equal(peer.requests('tools/list')[1].params.cursor, 'server-cursor');
  peer.reply(peer.requests('tools/list')[1], { tools: [] });
  await a.response(2);
  r.manager.recycle('server');
  const c = await r.attach();
  c.send('tools/list', 1, { cursor });
  r.failure(await c.response(1), 'SHARED_CURSOR_INVALID', 'unsent');
  assert.equal(r.children[1].requests('tools/list').length, 0);
});

test('DELETE cancels only its dispatched work, drops its queued work and preserves another client', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 2 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  b.call(1);
  a.call(2);
  b.call(2);
  const peer = r.children[0];
  const [callA, callB] = peer.requests('tools/call');
  a.child.detach();
  assert.equal(r.manager.inspect('server').members, 1);
  assert.equal(r.manager.inspect('server').unresolved, 2);
  assert.equal(r.manager.inspect('server').queued, 1);
  assert.deepEqual(peer.requests('notifications/cancelled').map((message) => message.params.requestId), [callA.id]);
  peer.reply(callB, { b: 1 });
  const remaining = peer.requests('tools/call');
  assert.equal(remaining.length, 3);
  peer.reply(remaining[2], { b: 2 });
  peer.reply(callA, { ignored: true });
  assert.deepEqual((await b.response(1)).result, { b: 1 });
  assert.deepEqual((await b.response(2)).result, { b: 2 });
  assert.equal(r.kills.length, 0);
  assert.equal(r.failures.length, 0);
});

test('child exit immediately fails pending and queued calls exactly once without replay', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 1 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  b.call(1);
  const peer = r.children[0];
  peer.exit(17);
  assert.equal(a.messages.find((message) => message.id === 1)?.error.data.kind, 'SHARED_CHILD_EXIT');
  r.failure(await a.response(1), 'SHARED_CHILD_EXIT', 'potentially-executed');
  r.failure(await b.response(1), 'SHARED_CHILD_EXIT', 'unsent');
  peer.emit('error', new Error('late error'));
  await r.turn();
  assert.equal(r.failures.length, 1);
  assert.equal(r.retirements.length, 1);
  assert.equal(r.retirements[0].reason, 'SHARED_CHILD_EXIT');
  assert.equal(a.exits.length, 1);
  assert.equal(b.exits.length, 1);
  assert.equal(peer.requests('tools/call').length, 1);
  assert.equal(r.children.length, 1);
});

test('recycle drains busy execution then kills promptly and fences old callbacks from replacement', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  a.call(1);
  const old = r.children[0];
  const generation = a.child.__sharedGeneration;
  const result = r.manager.recycle('server');
  assert.equal(result.found, true);
  assert.equal(result.state, 'draining');
  assert.equal(r.kills.length, 0);
  a.call(2);
  r.failure(await a.response(2), 'SHARED_DRAINING', 'unsent');
  await assert.rejects(() => r.acquire(), /SHARED_DRAINING/);
  old.reply(old.requests('tools/call')[0], { done: true });
  assert.deepEqual((await a.response(1)).result, { done: true });
  assert.equal(r.kills.length, 1);
  assert.equal(r.manager.inspect('server'), null);
  const b = await r.attach();
  assert.notEqual(b.child.__sharedGeneration, generation);
  old.emit('exit', 1, null);
  old.emit('error', new Error('stale'));
  old.send({ id: 'old', method: 'sampling/createMessage' });
  await r.turn();
  assert.equal(r.manager.inspect('server').generation, b.child.__sharedGeneration);
  assert.equal(r.failures.length, 0);
  assert.equal(r.retirements.length, 1);
  assert.equal(old.requests('tools/call').length, 1);
});

test('drain deadline reports potentially-executed work and never treats cancellation as completion', async (t) => {
  const r = new Rig(t, { definition: { sharedDrainTimeoutMs: 20, sharedLingerMs: 0 } });
  r.clock(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  b.call(1);
  a.child.detach();
  r.manager.recycle('server');
  t.mock.timers.tick(19);
  assert.equal(r.kills.length, 0);
  assert.equal(r.manager.inspect('server').unresolved, 2);
  t.mock.timers.tick(1);
  r.failure(await b.response(1), 'SHARED_DRAIN_TIMEOUT', 'potentially-executed');
  assert.equal(r.kills.length, 1);
  assert.equal(r.failures.length, 1);
  assert.equal(r.children[0].requests('tools/call').length, 2);
});

test('request timeout preserves ownership through bounded drain and queued timeouts remain unsent', async (t) => {
  const r = new Rig(t, { manager: { requestTimeoutMs: 20 },
    definition: { sharedDrainTimeoutMs: 30, sharedMaxInFlight: 1 } });
  r.clock(t);
  const a = await r.attach();
  a.call(1);
  a.call(2);
  t.mock.timers.tick(20);
  r.failure(await a.response(1), 'SHARED_REQUEST_TIMEOUT', 'potentially-executed');
  r.failure(await a.response(2), 'SHARED_DRAINING', 'unsent');
  assert.equal(r.manager.inspect('server').unresolved, 1);
  assert.equal(r.kills.length, 0);
  t.mock.timers.tick(30);
  assert.equal(r.kills.length, 1);
  assert.equal(r.failures.length, 1);
  assert.equal(r.children[0].requests('tools/call').length, 1);
});

test('round-robin queue avoids head-of-line starvation from one session', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 1 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  a.call(2);
  a.call(3);
  a.call(4);
  b.call(1, { owner: 'b' });
  const peer = r.children[0];
  peer.reply(peer.requests('tools/call')[0], { owner: 'a1' });
  peer.reply(peer.requests('tools/call')[1], { owner: 'a2' });
  assert.equal(peer.requests('tools/call').length, 3);
  assert.deepEqual(peer.requests('tools/call')[2].params.arguments, { owner: 'b' });
  peer.reply(peer.requests('tools/call')[2], { owner: 'b1' });
  assert.deepEqual((await b.response(1)).result, { owner: 'b1' });
  assert.equal(r.manager.inspect('server').queued, 1);
});

test('a hung request does not block another session when a dispatch slot is free', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 2 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  b.call(1);
  const peer = r.children[0];
  peer.reply(peer.requests('tools/call')[1], { notBlocked: true });
  assert.deepEqual((await b.response(1)).result, { notBlocked: true });
  assert.equal(r.manager.inspect('server').unresolved, 1);
});

test('linger retains compatible reuse but does not evict unresolved detached execution', async (t) => {
  const r = new Rig(t, { definition: { sharedLingerMs: 20 } });
  r.clock(t);
  const a = await r.attach();
  a.child.detach();
  t.mock.timers.tick(19);
  assert.equal(r.kills.length, 0);
  const b = await r.attach();
  t.mock.timers.tick(1);
  assert.equal(r.kills.length, 0);
  b.call(1);
  b.child.detach();
  t.mock.timers.tick(100);
  assert.equal(r.kills.length, 0);
  r.children[0].reply(r.children[0].requests('tools/call')[0], {});
  t.mock.timers.tick(19);
  assert.equal(r.kills.length, 0);
  t.mock.timers.tick(1);
  assert.equal(r.kills.length, 1);
});

test('server-owned credential expiry fails unchanged; fresh generation succeeds with no failed-call replay', async (t) => {
  const r = new Rig(t);
  r.clock(t);
  const a = await r.attach();
  const old = r.children[0];
  t.mock.timers.tick(51);
  a.call(1, { operation: 'expired-once' });
  old.credentialCall(old.requests('tools/call')[0]);
  assert.deepEqual((await a.response(1)).error, {
    code: -32077, message: 'Server credential expired', data: { owner: 'server' },
  });
  a.call(2, { operation: 'drain-existing' });
  r.manager.recycle('server');
  assert.equal(r.manager.inspect('server').state, 'draining');
  old.credentialCall(old.requests('tools/call')[1]);
  await a.response(2);
  const b = await r.attach();
  const fresh = r.children[1];
  b.call(1, { operation: 'new-call' });
  fresh.credentialCall(fresh.requests('tools/call')[0]);
  assert.equal((await b.response(1)).result.content[0].text, 'Server credential valid');
  assert.equal(old.requests('tools/call').filter((call) => call.params.arguments.operation === 'expired-once').length, 1);
  assert.equal(fresh.requests('tools/call').length, 1);
  assert.deepEqual(r.definition, DEFINITION);
});

test('bounds cover sessions, operations, queues, retained IDs, cursors and input lines', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxSessions: 1, sharedMaxInFlight: 1,
    sharedMaxQueued: 1, sharedMaxIds: 4, sharedMaxCursors: 1 } });
  const a = await r.attach();
  await assert.rejects(() => r.acquire(), /SHARED_SESSION_LIMIT/);
  a.call(1);
  a.call(2);
  a.call(3);
  assert.equal(a.messages.find((message) => message.id === 3)?.error.data.kind, 'SHARED_QUEUE_LIMIT');
  r.failure(await a.response(3), 'SHARED_QUEUE_LIMIT', 'unsent');
  assert.equal(r.manager.inspect('server').unresolved, 1);
  assert.equal(r.manager.inspect('server').queued, 1);
  a.call(4);
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_ID_LIMIT');
  assert.equal(r.children[0].requests('tools/call').length, 1);
  assert.equal(r.failures.length, 0);

  const cursors = new Rig(t, { definition: { sharedMaxCursors: 1 } });
  const b = await cursors.attach();
  const peer = cursors.children[0];
  for (const id of [1, 2]) {
    b.send('tools/list', id);
    peer.reply(peer.requests('tools/list').at(-1), { tools: [], nextCursor: `page-${id}` });
    const response = await b.response(id);
    if (id === 2) cursors.failure(response, 'SHARED_CURSOR_LIMIT');
  }
  const input = new Rig(t, { definition: { sharedMaxLineBytes: 512 } });
  const c = await input.attach();
  c.child.stdin.write('x'.repeat(513));
  await input.turn();
  assert.equal(c.failures[0].kind, 'SHARED_INPUT_LIMIT');
});

test('duplicate IDs are tombstoned, not overwritten, and terminal IDs cannot be reused', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  a.call(1);
  r.children[0].reply(r.children[0].requests('tools/call')[0], {});
  await a.response(1);
  a.call(1);
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_DUPLICATE_ID');
  assert.equal(r.children[0].requests('tools/call').length, 1);
  assert.equal(r.failures.length, 0);
});

test('slow virtual stdout is bounded without killing a healthy shared child', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxBufferBytes: 512 } });
  const a = await r.attach();
  const b = await r.attach();
  a.child.stdout.pause();
  a.call(1);
  r.children[0].reply(r.children[0].requests('tools/call')[0], { value: 'x'.repeat(600) });
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_OUTPUT_LIMIT');
  assert.equal(r.manager.inspect('server').members, 1);
  b.call(1);
  r.children[0].reply(r.children[0].requests('tools/call')[1], { healthy: true });
  assert.deepEqual((await b.response(1)).result, { healthy: true });
  assert.equal(r.failures.length, 0);
});

test('oversized or malformed child lines fail the generation and pending calls immediately', async (t) => {
  for (const line of ['x'.repeat(513), '{bad json}\n', `${JSON.stringify([])}\n`]) {
    const r = new Rig(t, { definition: { sharedMaxLineBytes: 512 } });
    const a = await r.attach();
    a.call(1);
    r.children[0].stdout.write(line);
    const response = await a.response(1);
    assert.match(response.error.data.kind, /^SHARED_(INPUT_LIMIT|INVALID_JSON|INVALID_MESSAGE)$/);
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
  }
});

test('removal during gated spawn rejects waiters and kills the late candidate without resurrecting sessions', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const peer = new Peer(1);
  const r = new Rig(t, { manager: { spawn: async () => { await gate; return peer; } } });
  const pending = assert.rejects(() => r.acquire(), /SHARED_REMOVED/);
  await r.turn();
  assert.equal(r.manager.remove('server').state, 'stopping');
  await pending;
  await assert.rejects(() => r.acquire(), /SHARED_STOPPING/);
  release();
  await r.turn();
  assert.equal(r.kills.length, 1);
  assert.equal(peer.requests('initialize').length, 0);
  assert.equal(r.manager.inspect('server'), null);
  assert.equal(r.failures.length, 0);
});

test('retirement waits for actual exit, kill timeout is observable, and shutdown is final', async (t) => {
  const r = new Rig(t, { delayedKill: true, definition: { sharedDrainTimeoutMs: 10 } });
  r.clock(t);
  await r.attach();
  assert.equal(r.manager.recycle('server').state, 'stopping');
  await assert.rejects(() => r.acquire(), /SHARED_STOPPING/);
  assert.equal(r.retirements.length, 0);
  t.mock.timers.tick(10);
  assert.equal(r.failures[0].kind, 'SHARED_KILL_TIMEOUT');
  r.children[0].exit();
  await r.turn();
  assert.equal(r.retirements.length, 1);
  assert.deepEqual(r.manager.remove('missing'), { found: false });
  assert.deepEqual(r.manager.recycle('missing'), { found: false });
  assert.deepEqual(r.manager.shutdown(), { groups: 0 });
  await assert.rejects(() => r.acquire(), /SHARED_SHUTDOWN/);
});

test('spawn failure and exit during initialization fail all waiters without waiting out the init budget', async (t) => {
  const failed = new Rig(t, { manager: { spawn: async () => { throw new Error('spawn rejected'); } } });
  await Promise.all([1, 2].map(() => assert.rejects(() => failed.acquire(), /SHARED_SPAWN_FAILED/)));
  assert.equal(failed.failures.length, 1);
  assert.equal(failed.manager.inspect('server'), null);
  const r = new Rig(t, { automaticInit: false });
  const attempts = [1, 2].map(() => assert.rejects(() => r.acquire(), /SHARED_CHILD_EXIT/));
  await r.turn();
  r.children[0].exit(1);
  await Promise.all(attempts);
  assert.equal(r.failures.length, 1);
});

test('a stalled virtual handshake expires locally without disrupting another ready member', async (t) => {
  const r = new Rig(t, { manager: { initTimeoutMs: 20 } });
  r.clock(t);
  const stalled = new Client(await r.acquire());
  const ready = await r.attach();
  t.mock.timers.tick(20);
  await r.turn();
  assert.equal(stalled.failures[0].kind, 'SHARED_SESSION_INIT_TIMEOUT');
  assert.equal(ready.exits.length, 0);
  assert.equal(r.manager.inspect('server').members, 1);
  assert.equal(r.failures.length, 0);
});

test('queued request timeout behind real writable backpressure does not retire a healthy generation', async (t) => {
  const peer = new Peer(1);
  let release;
  peer.stdin = new Writable({
    highWaterMark: 1,
    write: (chunk, encoding, callback) => {
      const message = JSON.parse(chunk.toString());
      peer.receive(message);
      if (message.method === 'notifications/initialized') {
        release = callback;
      } else {
        callback();
      }
    },
  });
  const r = new Rig(t, { manager: { spawn: async () => peer, requestTimeoutMs: 20 } });
  r.clock(t);
  const a = await r.attach();
  a.call(1);
  assert.equal(r.manager.inspect('server').queued, 1);
  assert.equal(r.manager.inspect('server').unresolved, 0);
  t.mock.timers.tick(20);
  r.failure(await a.response(1), 'SHARED_QUEUE_TIMEOUT', 'unsent');
  assert.equal(r.manager.inspect('server').state, 'ready');
  release();
  await r.turn();
  a.call(2);
  peer.reply(peer.requests('tools/call')[0], { afterBackpressure: true });
  assert.deepEqual((await a.response(2)).result, { afterBackpressure: true });
  assert.equal(r.failures.length, 0);
});

test('queued cancellation is unsent; duplicate progress tokens do not overwrite active ownership', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 1 } });
  const a = await r.attach();
  a.call(1, { task: 'ordinary argument', id: 1 }, { _meta: { progressToken: 'same' } });
  a.call(2, {}, { _meta: { progressToken: 'same' } });
  r.failure(await a.response(2), 'SHARED_DUPLICATE_PROGRESS', 'unsent');
  a.call(3);
  a.send('notifications/cancelled', undefined, { requestId: 3 });
  r.failure(await a.response(3), 'SHARED_CANCELLED', 'unsent');
  assert.equal(r.children[0].requests('notifications/cancelled').length, 0);
  assert.equal(r.children[0].requests('tools/call').length, 1);
  assert.deepEqual(r.children[0].requests('tools/call')[0].params.arguments,
    { task: 'ordinary argument', id: 1 });
});

test('without a POST progress subscriber the affected virtual session fails instead of broadcasting on GET', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.child.removeAllListeners('sharedProgress');
  a.call(1, {}, { _meta: { progressToken: 'token' } });
  const call = r.children[0].requests('tools/call')[0];
  r.children[0].send({ method: 'notifications/progress',
    params: { progressToken: call.params._meta.progressToken, progress: 1 } });
  r.failure(await a.response(1), 'SHARED_PROGRESS_UNROUTABLE', 'potentially-executed');
  await r.turn();
  assert.equal(b.progress.length, 0);
  assert.equal(b.messages.length, 1);
  assert.equal(r.failures.length, 0);
  assert.equal(r.manager.inspect('server').unresolved, 1);
});

test('retained bytes and total queued bytes are bounded independently of item counts', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxBufferBytes: 512, sharedMaxInFlight: 1 } });
  const a = await r.attach();
  a.call(1);
  a.call(2, { body: 'a'.repeat(200) });
  a.call(3, { body: 'a'.repeat(200) });
  r.failure(await a.response(3), 'SHARED_QUEUE_LIMIT', 'unsent');
  assert.equal(r.manager.inspect('server').queued, 1);
  const retained = new Rig(t, { definition: { sharedMaxBufferBytes: 512 } });
  const b = await retained.attach();
  for (const id of ['a'.repeat(200), 'b'.repeat(200)]) {
    b.send('unsupported/method', id);
    await b.response(id);
  }
  b.send('unsupported/method', 'c'.repeat(200));
  await retained.turn();
  assert.equal(b.failures[0].kind, 'SHARED_RETAINED_LIMIT');
  assert.equal(retained.failures.length, 0);
});

test('JSON lines handle fragmented UTF-8 and multiple messages without changing arbitrary tool content', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  const first = Buffer.from(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'stateless', arguments: { text: '☕', id: 'unaltered' } } })}\n`);
  const split = first.indexOf(Buffer.from('☕')) + 1;
  a.child.stdin.write(first.subarray(0, split));
  a.child.stdin.write(Buffer.concat([first.subarray(split), Buffer.from(
    `${JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'ping' })}\n`)]));
  const peer = r.children[0];
  assert.deepEqual(peer.requests('tools/call')[0].params.arguments, { text: '☕', id: 'unaltered' });
  peer.reply(peer.requests('tools/call')[0], { echoed: '☕' });
  peer.reply(peer.requests('ping')[0], {});
  assert.deepEqual((await a.response(1)).result, { echoed: '☕' });
  assert.deepEqual((await a.response('1')).result, {});
});

test('invalid envelopes, invalid UTF-8 and unsupported client notifications fail only their owner', async (t) => {
  const invalid = [
    Buffer.from('{"jsonrpc":"2.0","method":"ping","id":null}\n'),
    Buffer.from('{"jsonrpc":"2.0","method":"ping","id":3,"result":{}}\n'),
    Buffer.from('{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}\n'),
    Buffer.from([0xff, 10]),
  ];
  for (const input of invalid) {
    const r = new Rig(t);
    const [a, b] = await Promise.all([r.attach(), r.attach()]);
    a.child.stdin.write(input);
    await r.turn();
    assert.equal(a.exits.length, 1);
    assert.equal(b.exits.length, 0);
    assert.equal(r.failures.length, 0);
  }
});

test('malformed child error envelopes are not delivered as successful protocol data', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  a.call(1);
  r.children[0].send({ id: r.children[0].requests('tools/call')[0].id, error: null });
  r.failure(await a.response(1), 'SHARED_INVALID_MESSAGE', 'potentially-executed');
  assert.equal(r.failures.length, 1);
});

test('unadvertised catalog changes fail explicitly and no-tools servers cannot accept tools calls', async (t) => {
  const r = new Rig(t, { automaticInit: false });
  const pending = r.acquire();
  await r.turn();
  r.children[0].initialize(undefined, { capabilities: {} });
  const a = await new Client(await pending).initialize();
  a.call(1);
  r.failure(await a.response(1), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  r.children[0].send({ method: 'notifications/tools/list_changed' });
  await r.turn();
  assert.equal(r.failures[0].kind, 'SHARED_UNSUPPORTED_NOTIFICATION');
  assert.equal(a.messages.length, 2);
});

test('late spawn after initialization timeout is killed before any business dispatch', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const peer = new Peer(1);
  const r = new Rig(t, { manager: {
    initTimeoutMs: 10, spawn: async () => { await gate; return peer; },
  } });
  r.clock(t);
  const pending = assert.rejects(() => r.acquire(), /SHARED_INIT_TIMEOUT/);
  await r.turn();
  t.mock.timers.tick(10);
  await pending;
  assert.equal(r.manager.inspect('server').state, 'stopping');
  release();
  await r.turn();
  assert.equal(r.kills.length, 1);
  assert.equal(peer.messages.length, 0);
  assert.equal(r.failures.length, 1);
  assert.equal(r.manager.inspect('server'), null);
});

test('a failed kill and its later watchdog report one underlying failure, not one per virtual child', async (t) => {
  const r = new Rig(t, { manager: { kill: () => { throw new Error('kill unavailable'); } },
    definition: { sharedDrainTimeoutMs: 10 } });
  r.clock(t);
  await Promise.all([r.attach(), r.attach()]);
  r.manager.recycle('server');
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].kind, 'SHARED_KILL_FAILED');
  t.mock.timers.tick(10);
  assert.equal(r.failures.length, 1);
  assert.equal(r.manager.inspect('server').state, 'stopping');
  r.children[0].exit();
  await r.turn();
  assert.equal(r.retirements.length, 1);
});

test('identical isolated and shared workloads have actual spawn counter deltas of 52 versus 1', { timeout: 60_000 }, async (t) => {
  const isolated = new PeerProcesses(t);
  const shared = new PeerProcesses(t);
  const manager = new SharedSessionManager({
    spawn: () => shared.spawn(),
    kill: (child) => shared.stop(child),
  });
  t.after(() => manager.shutdown());
  const before = { isolated: isolated.launches, shared: shared.launches };
  for (let cycle = 0; cycle < 52; cycle++) {
    const single = await new Client(isolated.spawn()).initialize();
    single.call(1, { cycle });
    const isolatedResult = JSON.parse((await single.response(1)).result.content[0].text);
    await isolated.stop(single.child);
    const reused = await new Client(await manager.acquire('shared', DEFINITION, PARAMS)).initialize();
    reused.call(1, { cycle });
    const sharedResult = JSON.parse((await reused.response(1)).result.content[0].text);
    reused.child.detach();
    assert.deepEqual(isolatedResult.arguments, sharedResult.arguments);
  }
  assert.deepEqual({ isolated: isolated.launches - before.isolated, shared: shared.launches - before.shared },
    { isolated: 52, shared: 1 });
  const retired = once(manager, 'retired');
  manager.shutdown();
  await retired;
});

test('onInitialized samples each successful group once from actual spawn, excluding gate wait and cached linger', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const peers = [];
  const r = new Rig(t, { manager: { spawn: async () => {
    await gate;
    const peer = new Peer(peers.length + 1, false);
    peers.push(peer);
    return peer;
  } } });
  r.clock(t);
  const arrivals = [r.acquire(), r.acquire()];
  await r.turn();
  t.mock.timers.tick(5_000);
  release();
  await r.turn();
  t.mock.timers.tick(25);
  peers[0].initialize();
  const children = await Promise.all(arrivals);
  assert.deepEqual(r.initializations, [{ name: 'server', elapsedMs: 25 }]);
  for (const child of children) child.detach();
  t.mock.timers.tick(10_000);
  const cached = await r.attach();
  assert.equal(cached.child.pid, peers[0].pid);
  peers[0].initialize();
  assert.deepEqual(r.initializations, [{ name: 'server', elapsedMs: 25 }]);
  r.manager.recycle('server');
  const replacement = r.acquire();
  await r.turn();
  t.mock.timers.tick(7);
  peers[1].initialize();
  await replacement;
  assert.deepEqual(r.initializations, [
    { name: 'server', elapsedMs: 25 }, { name: 'server', elapsedMs: 7 },
  ]);
});

test('onInitialized requires a function and invalid spawn timestamps do not fabricate latency samples', async (t) => {
  assert.throws(() => new SharedSessionManager({ spawn() {}, kill() {}, onInitialized: 1 }),
    /callbacks must be functions/);
  for (const stamp of [undefined, NaN, -1, Number.MAX_SAFE_INTEGER]) {
    const peer = new Peer(1);
    peer.__spawnedAt = stamp;
    const r = new Rig(t, { manager: { spawn: async () => peer } });
    await r.attach();
    assert.equal(r.initializations.length, 0);
    assert.match(r.logs[0].text, /initialization latency unavailable/);
    assert.equal(r.failures.length, 0);
  }
});

test('onInitialized hook failures are logged without failing a healthy group or repeating samples', async (t) => {
  for (const asynchronous of [false, true]) {
    let samples = 0;
    const r = new Rig(t, { manager: { onInitialized: () => {
      samples++;
      if (asynchronous) return Promise.reject(new Error('metric hook failed'));
      throw new Error('metric hook failed');
    } } });
    await Promise.all([r.attach(), r.attach()]);
    await r.turn();
    assert.equal(samples, 1);
    assert.equal(r.manager.inspect('server').state, 'ready');
    assert.equal(r.failures.length, 0);
    assert.deepEqual(r.logs, [{ name: 'server', text: 'shared: onInitialized callback failed' }]);
  }
});

test('parsed messages share the stdin handshake, typed ID ownership, progress, cancellation and tombstones', async (t) => {
  const r = new Rig(t);
  const a = new Client(await r.acquire());
  const b = await r.attach();
  a.child.writeMessage({ jsonrpc: '2.0', id: 'init', method: 'initialize', params: PARAMS });
  assert.ok((await a.response('init')).result);
  a.child.writeMessage({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const request = { jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'stateless', arguments: { unchanged: [1, '1'] }, _meta: { progressToken: 1 } } };
  const original = structuredClone(request);
  assert.equal(a.child.writeMessage(request), undefined);
  b.call(1, {}, { _meta: { progressToken: 1 } });
  a.child.writeMessage({ ...request, id: '1', params: { ...request.params, _meta: { progressToken: '1' } } });
  b.call('1');
  assert.deepEqual(request, original);
  const peer = r.children[0];
  const calls = peer.requests('tools/call');
  assert.equal(new Set(calls.map((call) => call.id)).size, 4);
  peer.send({ method: 'notifications/progress',
    params: { progressToken: calls[0].params._meta.progressToken, progress: 1 } });
  assert.deepEqual(a.progress, [{ requestId: 1,
    message: { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 1, progress: 1 } } }]);
  assert.equal(b.progress.length, 0);
  a.child.writeMessage({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: '1' } });
  r.failure(await a.response('1'), 'SHARED_CANCELLED', 'potentially-executed');
  assert.deepEqual(peer.requests('notifications/cancelled').map((message) => message.params.requestId), [calls[2].id]);
  for (const index of [3, 1, 0, 2]) peer.reply(calls[index], { index });
  assert.deepEqual((await a.response(1)).result, { index: 0 });
  assert.deepEqual((await b.response(1)).result, { index: 1 });
  assert.deepEqual((await b.response('1')).result, { index: 3 });
  assert.equal(a.messages.filter((message) => message.id === '1').length, 1);
  a.send('ping', 1);
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_DUPLICATE_ID');
  assert.equal(b.child.active, true);
  assert.equal(peer.requests('tools/call').length, 4);
  assert.equal(peer.requests('initialize').length, 1);
  assert.equal(peer.requests('notifications/initialized').length, 1);
  assert.equal(r.children.length, 1);
  assert.equal(r.failures.length, 0);
});

test('parsed deep input rejects before serialization, consumes its ID and leaves other work and later calls usable', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  b.call(9);
  for (const depth of [2_500, 9_000]) {
    const line = r.depthLine({ id: depth, method: 'tools/call',
      params: { name: 'stateless', arguments: '__shared_depth_value__' } }, depth);
    const message = JSON.parse(line);
    const original = JSON.stringify;
    let attempts = 0;
    const serializer = t.mock.method(JSON, 'stringify', (value, ...args) => {
      if (value === message) {
        attempts++;
        throw new RangeError('deep message must not reach serialization');
      }
      return original(value, ...args);
    });
    try {
      assert.doesNotThrow(() => a.child.writeMessage(message));
      await r.turn();
    } finally {
      serializer.mock.restore();
    }
    assert.equal(attempts, 0);
    const response = a.messages.find((entry) => entry.id === depth);
    r.failure(response, 'SHARED_DEPTH_LIMIT', 'unsent');
    assert.equal(response.error.data.phase, 'admission');
    assert.equal(response.error.data.generation, a.child.__sharedGeneration);
    assert.equal(a.child.ids.has(depth), true);
    assert.equal(a.child.active, true);
    assert.equal(peer.requests('tools/call').length, 1);
    assert.equal(r.manager.inspect('server').unresolved, 1);
  }
  a.child.writeMessage({ jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'stateless', arguments: { ordinary: true } } });
  peer.reply(peer.requests('tools/call')[1], { owner: 'a' });
  peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
  assert.deepEqual((await a.response(2)).result, { owner: 'a' });
  assert.deepEqual((await b.response(9)).result, { owner: 'b' });
  assert.equal(peer.requests('tools/call').length, 2);
  assert.equal(r.children.length, 1);
  assert.equal(r.failures.length, 0);
});

test('parsed messages cannot shrink oversized original input past line limits by translating IDs or ignoring metadata', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxLineBytes: 512 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  b.call(9);
  const messages = [
    { id: 'x'.repeat(600), method: 'ping' },
    { id: 2, method: 'initialize', params: PARAMS, padding: 'x'.repeat(600) },
    { id: 3, method: 'tools/call', params: { name: 'stateless', arguments: { padding: 'x'.repeat(600) } } },
  ];
  for (const message of messages) {
    a.child.writeMessage({ jsonrpc: '2.0', ...message });
    await r.turn();
    const reply = a.messages.find((entry) => entry.id === message.id);
    r.failure(reply, 'SHARED_INPUT_LIMIT', 'unsent');
    assert.equal(reply.error.data.phase, 'admission');
    assert.equal(a.child.ids.has(message.id), true);
    assert.equal(a.child.active, true);
    assert.equal(r.manager.inspect('server').unresolved, 1);
  }
  a.child.writeMessage({ jsonrpc: '2.0', id: 4, method: 'ping' });
  peer.reply(peer.requests('ping')[0], { normal: true });
  peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
  assert.equal((await a.response(4)).result.normal, true);
  assert.equal((await b.response(9)).result.owner, 'b');
  assert.equal(peer.requests('ping').length, 1);
  assert.equal(peer.requests('tools/call').length, 1);
  assert.equal(peer.requests('initialize').length, 1);
  assert.equal(r.children.length, 1);
  assert.equal(r.failures.length, 0);
});

test('parsed messages retain final translated-wire and buffer limits for direct and queued calls', async (t) => {
  for (const sharedMaxInFlight of [1, 2]) {
    for (const limited of ['sharedMaxLineBytes', 'sharedMaxBufferBytes']) {
      const r = new Rig(t, { definition: { sharedMaxInFlight, [limited]: 512 } });
      const [a, b] = await Promise.all([r.attach(), r.attach()]);
      const peer = r.children[0];
      b.call(9);
      const message = { jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'stateless', arguments: { padding: '' }, _meta: { progressToken: 1 } } };
      message.params.arguments.padding = 'x'.repeat(511 - Buffer.byteLength(JSON.stringify(message)));
      assert.equal(Buffer.byteLength(JSON.stringify(message)), 511);
      a.child.writeMessage(message);
      await r.turn();
      r.failure(a.messages.find((entry) => entry.id === 1), 'SHARED_REQUEST_LIMIT', 'unsent');
      assert.equal(r.manager.inspect('server').queued, 0);
      assert.equal(r.manager.inspect('server').unresolved, 1);
      assert.equal(peer.requests('tools/call').length, 1);
      peer.reply(peer.requests('tools/call')[0], {});
      await b.response(9);
      a.child.writeMessage({ jsonrpc: '2.0', id: 2, method: 'ping' });
      peer.reply(peer.requests('ping')[0], { healthy: true });
      assert.equal((await a.response(2)).result.healthy, true);
      assert.equal(r.children.length, 1);
      assert.equal(r.failures.length, 0);
    }
  }
});

test('parsed messages enforce envelope, ID and notification bounds without failing another owner', async (t) => {
  for (const [message, kind] of [
    [[], 'SHARED_INVALID_MESSAGE'],
    [{ jsonrpc: '2.0', method: 'ping', id: {} }, 'SHARED_INVALID_ID'],
    [{ jsonrpc: '2.0', method: 'notifications/cancelled', params: { padding: 'x'.repeat(600) } }, 'SHARED_INPUT_LIMIT'],
  ]) {
    const r = new Rig(t, { definition: { sharedMaxLineBytes: 512 } });
    const [a, b] = await Promise.all([r.attach(), r.attach()]);
    assert.doesNotThrow(() => a.child.writeMessage(message));
    await r.turn();
    assert.equal(a.failures[0].kind, kind);
    assert.equal(a.child.active, false);
    assert.equal(b.child.active, true);
    b.call(1);
    r.children[0].reply(r.children[0].requests('tools/call')[0], { healthy: true });
    assert.equal((await b.response(1)).result.healthy, true);
    assert.equal(r.children.length, 1);
    assert.equal(r.failures.length, 0);
  }
  const r = new Rig(t);
  const a = await r.attach();
  const notification = JSON.parse(r.depthLine({ method: 'notifications/cancelled',
    params: { data: '__shared_depth_value__' } }));
  assert.doesNotThrow(() => a.child.writeMessage(notification));
  await r.turn();
  assert.equal(a.failures[0].kind, 'SHARED_DEPTH_LIMIT');
  assert.equal(r.children[0].requests('notifications/cancelled').length, 0);
});

test('parsed writes after detach, child exit or recycle throw an unsent admission error and never reach replacements', async (t) => {
  for (const close of ['detach', 'exit', 'recycle']) {
    const r = new Rig(t, { definition: { sharedRetryDelayMs: 1 } });
    const a = await r.attach();
    const peer = r.children[0];
    const generation = a.child.__sharedGeneration;
    if (close === 'detach') a.child.detach();
    else if (close === 'exit') peer.exit(1);
    else r.manager.recycle('server');
    for (const message of [
      { jsonrpc: '2.0', id: 1, method: 'ping' },
      JSON.parse(r.depthLine({ id: 2, method: 'tools/call', params: { arguments: '__shared_depth_value__' } })),
    ]) {
      assert.throws(() => a.child.writeMessage(message), (error) => {
        assert.equal(error.code, 'SHARED_DETACHED');
        assert.deepEqual(error.data, {
          kind: 'SHARED_DETACHED', phase: 'admission', execution: 'unsent', generation,
        });
        return true;
      });
    }
    assert.equal(peer.requests('ping').length, 0);
    assert.equal(peer.requests('tools/call').length, 0);
    const remaining = r.manager.cooldowns.get('server') - Date.now();
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
    const b = await r.attach();
    b.child.writeMessage({ jsonrpc: '2.0', id: 1, method: 'ping' });
    const fresh = r.children.at(-1);
    fresh.reply(fresh.requests('ping')[0], { healthy: true });
    assert.equal((await b.response(1)).result.healthy, true);
    assert.throws(() => a.child.writeMessage({ jsonrpc: '2.0', id: 3, method: 'ping' }),
      (error) => error.code === 'SHARED_DETACHED');
    assert.equal(fresh.requests('ping').length, 1);
    assert.equal(fresh.requests('tools/call').length, 0);
    assert.equal(r.children.length, close === 'detach' ? 1 : 2);
    assert.equal(r.failures.length, close === 'exit' ? 1 : 0);
  }
});

test('parsed input serialization failures are explicit unsent errors and preserve the ready session', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  const message = { jsonrpc: '2.0', id: 1, method: 'ping' };
  const original = JSON.stringify;
  const serializer = t.mock.method(JSON, 'stringify', (value, ...args) => {
    if (value === message) throw new RangeError('synthetic parsed-input serialization failure');
    return original(value, ...args);
  });
  try {
    assert.doesNotThrow(() => a.child.writeMessage(message));
    await r.turn();
  } finally {
    serializer.mock.restore();
  }
  r.failure(a.messages.find((entry) => entry.id === 1), 'SHARED_SERIALIZATION_FAILED', 'unsent');
  assert.equal(a.child.active, true);
  assert.equal(a.child.ids.has(1), true);
  assert.equal(r.children[0].requests('ping').length, 0);
  a.child.writeMessage({ jsonrpc: '2.0', id: 2, method: 'ping' });
  r.children[0].reply(r.children[0].requests('ping')[0], { recovered: true });
  assert.equal((await a.response(2)).result.recovered, true);
  assert.equal(r.children.length, 1);
  assert.equal(r.failures.length, 0);
});

test('deep valid JSON is rejected locally without throwing, wedging Writable callbacks or blocking another owner', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  b.call(9);
  const nested = `${'{"nested":'.repeat(2_500)}0${'}'.repeat(2_500)}`;
  const line = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stateless","arguments":${nested}}}\n`;
  assert.doesNotThrow(() => JSON.parse(line));
  assert.ok(Buffer.byteLength(line) < SHARED_DEFAULTS.sharedMaxLineBytes);
  await r.rejectedWrite(a, line, 'SHARED_DEPTH_LIMIT');
  assert.equal(peer.requests('tools/call').length, 1);
  assert.equal(r.manager.inspect('server').unresolved, 1);
  a.call(2, { ordinary: true });
  assert.equal(peer.requests('tools/call').length, 2);
  peer.reply(peer.requests('tools/call')[1], { owner: 'a' });
  peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
  assert.deepEqual((await a.response(2)).result, { owner: 'a' });
  assert.deepEqual((await b.response(9)).result, { owner: 'b' });
  assert.equal(r.children.length, 1);
});

for (const category of ['response', 'progress']) {
  test(`real asynchronous upstream ${category} depth fails only its generation without replay or host crash`,
    { timeout: 10_000 }, async (t) => {
      const peers = new DepthPeers(t);
      const r = new Rig(t, {
        definition: { sharedMaxInFlight: 2, sharedRetryDelayMs: 1 },
        manager: {
          spawn: async (name) => peers.spawn(name), kill: (child) => child.kill(),
          requestTimeoutMs: 5_000, initTimeoutMs: 5_000,
        },
      });
      const [a, b] = await Promise.all([r.attach(), r.attach()]);
      const other = await new Client(await r.manager.acquire('healthy', r.definition, PARAMS)).initialize();
      const peer = peers.children.find((child) => child.serverName === 'server');
      const healthy = peers.children.find((child) => child.serverName === 'healthy');
      const generation = a.child.__sharedGeneration;
      a.child.on('sharedProgress', ({ message }) => JSON.stringify(message));
      b.call(1, { tag: 'other-owner-held' });
      await peers.request(peer, 'other-owner-held');
      a.call(1, { tag: `deep-${category}` }, { _meta: { progressToken: 1 } });
      const request = await peers.request(peer, `deep-${category}`);
      a.call(2, { tag: 'queued-never-sent' });
      other.call(1, { tag: 'unrelated-group' });
      const otherRequest = await peers.request(healthy, 'unrelated-group');
      assert.equal(r.manager.inspect('server').unresolved, 2);
      assert.equal(r.manager.inspect('server').queued, 1);
      const exit = once(a.child, 'exit');
      const retirement = once(r.manager, 'retired');
      const message = category === 'response'
        ? { id: request.id, result: { structuredContent: '__shared_depth_value__' } }
        : { method: 'notifications/progress', params: {
          progressToken: request.params._meta.progressToken, progress: 1, details: '__shared_depth_value__',
        } };
      peers.send(peer, message, 9_000);
      await exit;
      await r.turn();
      for (const [client, id, phase, execution] of [
        [a, 1, 'execution', 'potentially-executed'], [b, 1, 'execution', 'potentially-executed'],
        [a, 2, 'queue', 'unsent'],
      ]) {
        const reply = client.messages.find((entry) => entry.id === id);
        assert.ok(reply, 'controlled depth failure must settle each pending request immediately');
        r.failure(reply, 'SHARED_UPSTREAM_DEPTH_LIMIT', execution);
        assert.equal(reply.error.data.phase, phase);
        assert.equal(reply.error.data.generation, generation);
      }
      assert.deepEqual(a.progress, []);
      assert.deepEqual(b.progress, []);
      assert.equal(a.failures[0].kind, 'SHARED_UPSTREAM_DEPTH_LIMIT');
      assert.equal(b.failures[0].kind, 'SHARED_UPSTREAM_DEPTH_LIMIT');
      assert.equal(r.failures.length, 1);
      assert.equal(r.failures[0].kind, 'SHARED_UPSTREAM_DEPTH_LIMIT');
      assert.equal(r.responses.length, 0);
      const [retired] = await retirement;
      assert.equal(retired.generation, generation);
      assert.equal(retired.failed, true);
      assert.equal(r.manager.inspect('server'), null);
      assert.equal(peer.wires.length, 1);
      assert.equal(peer.wires[0].depth, 9_000);
      assert.ok(peer.wires[0].bytes > 99_000);
      assert.ok(peer.wires[0].bytes < SHARED_DEFAULTS.sharedMaxLineBytes);
      assert.equal(r.manager.inspect('healthy').state, 'ready');
      assert.equal(other.child.active, true);
      peers.send(healthy, { id: otherRequest.id, result: { healthy: true } });
      assert.deepEqual((await other.response(1)).result, { healthy: true });
      const remaining = r.manager.cooldowns.get('server') - Date.now();
      if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
      const replacement = await r.attach();
      const fresh = peers.children.find((child) => child.pid === replacement.child.pid);
      assert.notEqual(replacement.child.__sharedGeneration, generation);
      replacement.call(3, { tag: 'explicit-new-call' });
      const newRequest = await peers.request(fresh, 'explicit-new-call');
      peers.send(fresh, { id: newRequest.id, result: { replacement: true } });
      assert.deepEqual((await replacement.response(3)).result, { replacement: true });
      assert.deepEqual(peer.requests.filter((entry) => entry.method === 'tools/call')
        .map((entry) => entry.params.arguments.tag), ['other-owner-held', `deep-${category}`]);
      assert.deepEqual(fresh.requests.filter((entry) => entry.method === 'tools/call')
        .map((entry) => entry.params.arguments.tag), ['explicit-new-call']);
      assert.deepEqual(r.responses, ['healthy', 'server']);
      assert.equal(peers.launches, 3);
      assert.equal(r.failures.length, 1);
      r.manager.shutdown();
    });
}

test('upstream depth rejects initialize results and errors before caching or returning their data', async (t) => {
  for (const errorResponse of [false, true]) {
    const r = new Rig(t, { automaticInit: false });
    const pending = Promise.all([r.acquire(), r.acquire()]);
    const rejected = assert.rejects(pending, (error) => {
      assert.equal(error.code, 'SHARED_UPSTREAM_DEPTH_LIMIT');
      assert.equal(error.data.phase, 'initialize');
      assert.equal(error.data.execution, 'unsent');
      assert.ok(error.data.generation);
      return true;
    });
    await r.turn();
    const peer = r.children[0];
    const id = peer.requests('initialize')[0].id;
    const message = errorResponse
      ? { id, error: { code: -32000, message: 'Rejected', data: '__shared_depth_value__' } }
      : { id, result: { protocolVersion: PARAMS.protocolVersion, capabilities: { tools: {} },
        serverInfo: { name: 'depth-peer', version: '1' }, _meta: '__shared_depth_value__' } };
    assert.doesNotThrow(() => peer.stdout.write(r.depthLine(message)));
    await rejected;
    assert.equal(peer.requests('notifications/initialized').length, 0);
    assert.equal(r.initializations.length, 0);
    assert.equal(r.responses.length, 0);
    assert.equal(r.failures.length, 1);
    assert.equal(r.failures[0].kind, 'SHARED_UPSTREAM_DEPTH_LIMIT');
    assert.equal(r.kills.length, 1);
  }
});

test('upstream depth is checked before callbacks, response errors and even dropped notifications', async (t) => {
  for (const category of ['ping', 'sampling/createMessage', 'error', 'notifications/message',
    'notifications/resources/list_changed', 'notifications/unknown']) {
    const r = new Rig(t);
    const [a, b] = await Promise.all([r.attach(), r.attach()]);
    a.call(1);
    b.call(1);
    const peer = r.children[0];
    const message = category === 'error'
      ? { id: peer.requests('tools/call')[0].id,
        error: { code: -32000, message: 'Rejected', data: '__shared_depth_value__' } }
      : { method: category, params: { data: '__shared_depth_value__' },
        ...(!category.startsWith('notifications/') ? { id: 'callback' } : {}) };
    assert.doesNotThrow(() => peer.stdout.write(r.depthLine(message)));
    await r.turn();
    for (const client of [a, b]) {
      r.failure(client.messages.find((reply) => reply.id === 1),
        'SHARED_UPSTREAM_DEPTH_LIMIT', 'potentially-executed');
      assert.equal(client.messages.length, 2);
      assert.deepEqual(client.progress, []);
    }
    assert.equal(peer.messages.some((entry) => entry.id === 'callback'), false);
    assert.equal(r.responses.length, 0);
    assert.equal(r.logs.length, 0);
    assert.equal(r.failures.length, 1);
    assert.equal(r.failures[0].kind, 'SHARED_UPSTREAM_DEPTH_LIMIT');
  }
});

test('upstream response and progress accept depth 64 intact and reject depth 65 before delivery', async (t) => {
  for (const category of ['response', 'progress']) {
    for (const depth of [62, 63]) {
      const r = new Rig(t);
      const a = await r.attach();
      a.call(1, {}, { _meta: { progressToken: 1 } });
      const peer = r.children[0];
      const request = peer.requests('tools/call')[0];
      const message = category === 'response'
        ? { id: request.id, result: { structuredContent: '__shared_depth_value__' } }
        : { method: 'notifications/progress', params: {
          progressToken: request.params._meta.progressToken, data: '__shared_depth_value__',
        } };
      const line = r.depthLine(message, depth);
      assert.doesNotThrow(() => peer.stdout.write(line));
      await r.turn();
      if (depth === 63) {
        r.failure(a.messages.find((reply) => reply.id === 1),
          'SHARED_UPSTREAM_DEPTH_LIMIT', 'potentially-executed');
        assert.equal(a.progress.length, 0);
        assert.equal(r.responses.length, 0);
        assert.equal(r.failures.length, 1);
      } else {
        const expected = JSON.parse(line);
        if (category === 'response') {
          assert.deepEqual((await a.response(1)).result, expected.result);
        } else {
          expected.params.progressToken = 1;
          assert.deepEqual(a.progress, [{ requestId: 1, message: expected }]);
          peer.reply(request, { complete: true });
          assert.deepEqual((await a.response(1)).result, { complete: true });
        }
        assert.equal(r.responses.length, 1);
        assert.equal(r.manager.inspect('server').state, 'ready');
        assert.equal(r.failures.length, 0);
      }
    }
  }
});

test('virtual serialization failure closes only that output without recursive retries or business replay', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxInFlight: 3 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  a.call(1);
  a.call(2);
  b.call(9);
  a.call(3);
  const calls = peer.requests('tools/call');
  const line = `${JSON.stringify({ jsonrpc: '2.0', id: calls[0].id, result: { value: 1 } })}\n`;
  const original = JSON.stringify;
  let attempts = 0;
  const serializer = t.mock.method(JSON, 'stringify', (message, ...args) => {
    if ([1, 2, 3].includes(message?.id) &&
        !message.method) {
      attempts++;
      throw new RangeError('synthetic serialization failure');
    }
    return original(message, ...args);
  });
  try {
    assert.doesNotThrow(() => peer.stdout.write(line));
    await r.turn();
  } finally {
    serializer.mock.restore();
  }
  assert.equal(attempts, 1, 'failed virtual output must not retry serialization during detach');
  assert.equal(a.child.active, false);
  assert.equal(a.failures[0].kind, 'SHARED_SERIALIZATION_FAILED');
  assert.equal(a.failures[0].generation, a.child.__sharedGeneration);
  assert.equal(b.child.active, true);
  assert.equal(r.manager.inspect('server').state, 'ready');
  assert.equal(r.manager.inspect('server').queued, 0);
  assert.equal(r.manager.inspect('server').unresolved, 2);
  assert.deepEqual(peer.requests('notifications/cancelled').map((entry) => entry.params.requestId), [calls[1].id]);
  peer.reply(calls[2], { healthy: true });
  assert.deepEqual((await b.response(9)).result, { healthy: true });
  peer.reply(calls[1], { completedAfterDetach: true });
  assert.equal(r.manager.inspect('server').unresolved, 0);
  assert.equal(peer.requests('tools/call').length, 3);
  assert.equal(r.failures.length, 0);
  assert.equal(r.kills.length, 0);
});

test('child-write serialization failure settles pending execution once instead of escaping stdout callbacks', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.call(1);
  b.call(1);
  const peer = r.children[0];
  const line = `${JSON.stringify({ jsonrpc: '2.0', id: 'peer-ping', method: 'ping' })}\n`;
  const original = JSON.stringify;
  const serializer = t.mock.method(JSON, 'stringify', (message, ...args) => {
    if (message?.id === 'peer-ping') throw new RangeError('synthetic child-write serialization failure');
    return original(message, ...args);
  });
  try {
    assert.doesNotThrow(() => peer.stdout.write(line));
    await r.turn();
  } finally {
    serializer.mock.restore();
  }
  for (const client of [a, b]) {
    const reply = client.messages.find((message) => message.id === 1);
    r.failure(reply, 'SHARED_SERIALIZATION_FAILED', 'potentially-executed');
    assert.equal(reply.error.data.phase, 'execution');
    assert.equal(reply.error.data.generation, client.child.__sharedGeneration);
  }
  assert.equal(peer.requests('tools/call').length, 2);
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].kind, 'SHARED_SERIALIZATION_FAILED');
  assert.equal(r.responses.length, 0);
  assert.equal(r.kills.length, 1);
});

test('progress delivery exceptions fail the owner explicitly while other clients complete on the same child', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  a.child.on('sharedProgress', () => { throw new RangeError('synthetic progress serialization failure'); });
  a.call(1, {}, { _meta: { progressToken: 1 } });
  b.call(1);
  const peer = r.children[0];
  const calls = peer.requests('tools/call');
  assert.doesNotThrow(() => peer.send({ method: 'notifications/progress',
    params: { progressToken: calls[0].params._meta.progressToken, progress: 1 } }));
  await r.turn();
  const reply = a.messages.find((message) => message.id === 1);
  r.failure(reply, 'SHARED_PROGRESS_DELIVERY_FAILED', 'potentially-executed');
  assert.equal(reply.error.data.phase, 'execution');
  assert.equal(reply.error.data.generation, a.child.__sharedGeneration);
  assert.equal(a.failures[0].kind, 'SHARED_PROGRESS_DELIVERY_FAILED');
  assert.equal(a.child.active, false);
  assert.equal(b.child.active, true);
  assert.equal(r.manager.inspect('server').unresolved, 2);
  assert.equal(r.manager.inspect('server').state, 'ready');
  assert.deepEqual(peer.requests('notifications/cancelled').map((entry) => entry.params.requestId), [calls[0].id]);
  peer.reply(calls[1], { healthy: true });
  assert.deepEqual((await b.response(1)).result, { healthy: true });
  peer.reply(calls[0], { completedAfterDetach: true });
  assert.equal(r.manager.inspect('server').unresolved, 0);
  assert.equal(peer.requests('tools/call').length, 2);
  assert.equal(r.failures.length, 0);
  assert.equal(r.kills.length, 0);
});

test('unexpected cloning errors complete Writable callbacks and leave the same session usable', async (t) => {
  const r = new Rig(t);
  const a = await r.attach();
  const clone = t.mock.method(globalThis, 'structuredClone', () => {
    throw new RangeError('synthetic clone failure');
  });
  const line = `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'stateless', arguments: {} } })}\n`;
  await r.rejectedWrite(a, line, 'SHARED_CLONE_FAILED');
  assert.equal(r.children[0].requests('tools/call').length, 0);
  clone.mock.restore();
  a.call(2);
  r.children[0].reply(r.children[0].requests('tools/call')[0], { recovered: true });
  assert.equal((await a.response(2)).result.recovered, true);
});

test('ID and progress expansion beyond the final wire limit rejects direct and queued calls before execution', async (t) => {
  for (const sharedMaxInFlight of [1, 2]) {
    const r = new Rig(t, { definition: { sharedMaxInFlight } });
    const [a, b] = await Promise.all([r.attach(), r.attach()]);
    const peer = r.children[0];
    b.call(9);
    const message = { jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'stateless', arguments: { padding: '' }, _meta: { progressToken: 1 } } };
    const acceptedInputBytes = 1_048_557;
    message.params.arguments.padding = 'x'.repeat(acceptedInputBytes - Buffer.byteLength(JSON.stringify(message)));
    const line = `${JSON.stringify(message)}\n`;
    assert.equal(Buffer.byteLength(line), acceptedInputBytes + 1);
    assert.ok(Buffer.byteLength(line) < SHARED_DEFAULTS.sharedMaxLineBytes);
    await r.rejectedWrite(a, line, 'SHARED_REQUEST_LIMIT');
    assert.equal(peer.requests('tools/call').length, 1);
    assert.equal(r.manager.inspect('server').unresolved, 1);
    a.call(2, { ordinary: true });
    peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
    peer.reply(peer.requests('tools/call')[1], { owner: 'a' });
    assert.equal((await a.response(2)).result.owner, 'a');
    assert.equal((await b.response(9)).result.owner, 'b');
    assert.equal(r.children.length, 1);
  }
});

test('the final wire byte limit includes the newline rather than just serialized JSON', async (t) => {
  const sharedMaxLineBytes = 512;
  const r = new Rig(t, { definition: { sharedMaxLineBytes } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  b.call(9);
  const templateId = peer.requests('tools/call')[0].id;
  const message = { jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'stateless', arguments: { padding: '' } } };
  const expanded = { ...message, id: templateId };
  message.params.arguments.padding = 'x'.repeat(sharedMaxLineBytes - Buffer.byteLength(JSON.stringify(expanded)));
  assert.equal(Buffer.byteLength(JSON.stringify(expanded)), sharedMaxLineBytes);
  await r.rejectedWrite(a, `${JSON.stringify(message)}\n`, 'SHARED_REQUEST_LIMIT');
  assert.equal(peer.requests('tools/call').length, 1);
  message.id = 2;
  message.params.arguments.padding = message.params.arguments.padding.slice(1);
  a.child.stdin.write(`${JSON.stringify(message)}\n`);
  assert.equal(peer.requests('tools/call').length, 2);
  assert.equal(Buffer.byteLength(JSON.stringify(peer.requests('tools/call')[1])) + 1, sharedMaxLineBytes);
  peer.reply(peer.requests('tools/call')[1], { boundary: true });
  peer.reply(peer.requests('tools/call')[0], {});
  assert.equal((await a.response(2)).result.boundary, true);
  await b.response(9);
});

test('cursor expansion is checked before dispatch and rejecting a large page does not consume its cursor', async (t) => {
  const sharedMaxLineBytes = 2_048;
  const r = new Rig(t, { definition: { sharedMaxLineBytes } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  b.call(9);
  a.send('tools/list', 1);
  peer.reply(peer.requests('tools/list')[0], { tools: [], nextCursor: 'c'.repeat(1_200) });
  const cursor = (await a.response(1)).result.nextCursor;
  assert.notEqual(cursor, 'c'.repeat(1_200));
  assert.equal(r.responses.length, 1);
  r.responses.length = 0;
  const message = { jsonrpc: '2.0', id: 2, method: 'tools/list',
    params: { cursor, _meta: { progressToken: 1, padding: 'x'.repeat(900) } } };
  const line = `${JSON.stringify(message)}\n`;
  assert.ok(Buffer.byteLength(line) < sharedMaxLineBytes);
  await r.rejectedWrite(a, line, 'SHARED_REQUEST_LIMIT', 2);
  assert.equal(peer.requests('tools/list').length, 1);
  assert.equal(r.manager.inspect('server').unresolved, 1);
  a.send('tools/list', 3, { cursor });
  assert.equal(peer.requests('tools/list')[1].params.cursor, 'c'.repeat(1_200));
  peer.reply(peer.requests('tools/list')[1], { tools: [] });
  peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
  assert.deepEqual((await a.response(3)).result, { tools: [] });
  assert.equal((await b.response(9)).result.owner, 'b');
});

test('a single expanded request exceeding the buffer budget is rejected before upstream dispatch', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxBufferBytes: 512 } });
  const a = await r.attach();
  const message = { jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'stateless', arguments: { padding: 'x'.repeat(430) } } };
  assert.ok(Buffer.byteLength(JSON.stringify(message)) < SHARED_DEFAULTS.sharedMaxLineBytes);
  await r.rejectedWrite(a, `${JSON.stringify(message)}\n`, 'SHARED_REQUEST_LIMIT');
  assert.equal(r.children[0].requests('tools/call').length, 0);
});

test('occupied upstream buffers reject only the unsent owner before marking execution', async (t) => {
  const r = new Rig(t, { definition: { sharedMaxBufferBytes: 512 } });
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  const buffered = [];
  peer.stdin = new Writable({
    write: (chunk, encoding, callback) => {
      peer.receive(JSON.parse(chunk.toString()));
      buffered.push(callback);
    },
  });
  b.call(9, { padding: 'x'.repeat(200) });
  assert.ok(peer.stdin.writableLength < 512);
  a.call(1, { padding: 'x'.repeat(200) });
  await r.turn();
  const rejected = a.messages.find((message) => message.id === 1);
  assert.ok(rejected, 'a buffer admission failure must settle without dispatch');
  r.failure(rejected, 'SHARED_UPSTREAM_BUFFER_LIMIT', 'unsent');
  assert.equal(rejected.error.data.phase, 'queue');
  assert.equal(peer.requests('tools/call').length, 1);
  assert.equal(r.manager.inspect('server').unresolved, 1);
  assert.equal(r.failures.length, 0);
  assert.equal(r.responses.length, 0);
  assert.equal(r.kills.length, 0);
  buffered.shift()();
  peer.reply(peer.requests('tools/call')[0], { owner: 'b' });
  assert.equal((await b.response(9)).result.owner, 'b');
  a.call(2);
  buffered.shift()();
  peer.reply(peer.requests('tools/call')[1], { owner: 'a' });
  assert.equal((await a.response(2)).result.owner, 'a');
});

test('onResponse counts accepted operation responses, including real errors with synthetic-looking codes and data', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  assert.equal(r.initializations.length, 1);
  assert.deepEqual(r.responses, []);
  a.call(1, {}, { _meta: { progressToken: 7 } });
  const request = peer.requests('tools/call')[0];
  peer.send({ method: 'notifications/progress', params: {
    progressToken: request.params._meta.progressToken, progress: 1,
  } });
  peer.send({ method: 'notifications/tools/list_changed' });
  peer.send({ id: request.id, method: 'ping' });
  peer.send({ id: 'unknown', result: {} });
  assert.equal(a.progress.length, 1);
  assert.deepEqual(r.responses, []);
  const error = { code: -32001, message: 'Tool-defined response',
    data: { kind: 'SHARED_REQUEST_TIMEOUT', execution: 'unsent' } };
  peer.send({ id: request.id, error });
  assert.deepEqual((await a.response(1)).error, error);
  assert.deepEqual(r.responses, ['server']);
  peer.send({ id: request.id, error });
  peer.initialize();
  a.send('resources/list', 2);
  r.failure(await a.response(2), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  assert.deepEqual(r.responses, ['server']);
  b.call(1);
  peer.reply(peer.requests('tools/call')[1], { isError: true, content: [] });
  assert.equal((await b.response(1)).result.isError, true);
  assert.deepEqual(r.responses, ['server', 'server']);
  a.call(3);
  peer.reply(peer.requests('tools/call')[2], { ok: true });
  assert.equal((await a.response(3)).result.ok, true);
  assert.deepEqual(r.responses, ['server', 'server', 'server']);
});

test('onResponse excludes local cancellation and detach but counts their later matched execution completions once', async (t) => {
  const r = new Rig(t);
  const [a, b] = await Promise.all([r.attach(), r.attach()]);
  const peer = r.children[0];
  a.call(1);
  b.call(1);
  a.send('notifications/cancelled', undefined, { requestId: 1 });
  r.failure(await a.response(1), 'SHARED_CANCELLED', 'potentially-executed');
  b.child.detach();
  assert.deepEqual(r.responses, []);
  assert.equal(r.manager.inspect('server').unresolved, 2);
  const settledMessages = [a.messages.length, b.messages.length];
  for (const request of peer.requests('tools/call')) peer.reply(request, { completed: true });
  await r.turn();
  assert.deepEqual(r.responses, ['server', 'server']);
  assert.deepEqual([a.messages.length, b.messages.length], settledMessages);
  for (const request of peer.requests('tools/call')) peer.reply(request, { duplicated: true });
  assert.deepEqual(r.responses, ['server', 'server']);
  assert.equal(r.manager.inspect('server').unresolved, 0);
});

test('onResponse excludes timeouts, queued rejection, malformed responses and incompatible callbacks', async (t) => {
  for (const failure of ['timeout', 'malformed', 'cursor', 'callback']) {
    const r = new Rig(t, { manager: { requestTimeoutMs: 10 },
      definition: { sharedMaxInFlight: 1, sharedMaxQueued: 0 } });
    r.clock(t);
    const a = await r.attach();
    const peer = r.children[0];
    a.send(failure === 'cursor' ? 'tools/list' : 'tools/call', 1, { name: 'stateless' });
    a.call(2);
    r.failure(await a.response(2), 'SHARED_QUEUE_LIMIT', 'unsent');
    const request = peer.requests(failure === 'cursor' ? 'tools/list' : 'tools/call')[0];
    if (failure === 'timeout') t.mock.timers.tick(10);
    if (failure === 'malformed') peer.send({ id: request.id, error: null });
    if (failure === 'cursor') peer.reply(request, { tools: [], nextCursor: 7 });
    if (failure === 'callback') peer.send({ id: request.id, method: 'sampling/createMessage', params: {} });
    await r.turn();
    assert.deepEqual(r.responses, [], failure);
    assert.ok(a.messages.find((message) => message.id === 1).error);
    r.manager.shutdown();
    t.mock.timers.reset();
  }
});

test('onResponse validates its callback and logs thrown or rejected hooks without failing healthy operations', async (t) => {
  assert.throws(() => new SharedSessionManager({ spawn() {}, kill() {}, onResponse: 1 }),
    /callbacks must be functions/);
  for (const asynchronous of [false, true]) {
    const calls = [];
    const r = new Rig(t, { manager: { onResponse: (name) => {
      calls.push(name);
      if (asynchronous) return Promise.reject(new Error('health hook failed'));
      throw new Error('health hook failed');
    } } });
    const a = await r.attach();
    const peer = r.children[0];
    for (const id of [1, 2]) {
      a.call(id);
      peer.reply(peer.requests('tools/call').at(-1), { id });
      assert.equal((await a.response(id)).result.id, id);
    }
    await r.turn();
    assert.deepEqual(calls, ['server', 'server']);
    assert.equal(r.manager.inspect('server').state, 'ready');
    assert.equal(r.failures.length, 0);
    assert.deepEqual(r.logs, [
      { name: 'server', text: 'shared: onResponse callback failed' },
      { name: 'server', text: 'shared: onResponse callback failed' },
    ]);
  }
});

test('server capability projection retains actual tools flags and all initialization metadata for every virtual client', async (t) => {
  for (const capabilities of [
    { tools: {} },
    { experimental: {}, prompts: { listChanged: false }, resources: { subscribe: false, listChanged: false },
      tools: { listChanged: false } },
    { tools: { listChanged: true }, prompts: { listChanged: true }, resources: { subscribe: true, listChanged: true },
      logging: {}, completions: {}, tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } },
      experimental: {} },
  ]) {
    const r = new Rig(t, { automaticInit: false });
    const upstream = {
      protocolVersion: PARAMS.protocolVersion, capabilities,
      serverInfo: { name: 'projection-peer', version: '2', title: 'Actual implementation',
        websiteUrl: 'https://example.test', icons: [{ src: 'https://example.test/icon.png' }] },
      instructions: 'Retain these actual upstream instructions.',
      _meta: { nested: ['first', { second: true }] }, extraMetadata: { unchanged: 7 },
    };
    const original = structuredClone(upstream);
    const [a, b] = await r.initializeClients(upstream);
    const cached = await r.attach();
    const expected = { ...upstream, capabilities: { tools: capabilities.tools } };
    for (const client of [a, b, cached]) {
      assert.deepEqual((await client.response('init')).result, expected);
    }
    assert.deepEqual(upstream, original);
    assert.equal(r.children.length, 1);
    assert.equal(r.children[0].requests('initialize').length, 1);
    assert.equal(r.children[0].requests('notifications/initialized').length, 1);
    assert.equal(r.initializations.length, 1);
    assert.equal(r.responses.length, 0);
    a.call(1, { explicitInput: true });
    r.children[0].reply(r.children[0].requests('tools/call')[0], { accepted: true });
    assert.equal((await a.response(1)).result.accepted, true);
    assert.deepEqual(r.responses, ['server']);
    assert.equal(r.failures.length, 0);
  }
});

test('server capability projection never invents tools when upstream advertises only unexposed capabilities', async (t) => {
  const r = new Rig(t, { automaticInit: false });
  const [a, b] = await r.initializeClients({ capabilities: {
    prompts: { listChanged: true }, resources: { subscribe: true }, logging: {}, completions: {},
    tasks: { requests: { tools: { call: {} } } }, experimental: {},
  } });
  assert.deepEqual((await a.response('init')).result.capabilities, {});
  assert.deepEqual((await b.response('init')).result.capabilities, {});
  a.call(1);
  a.send('tools/list', 2);
  r.failure(await a.response(1), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  r.failure(await a.response(2), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
  const peer = r.children[0];
  assert.equal(peer.requests('tools/call').length, 0);
  assert.equal(peer.requests('tools/list').length, 0);
  b.send('ping', 1);
  peer.reply(peer.requests('ping')[0], {});
  assert.deepEqual((await b.response(1)).result, {});
  assert.equal(r.manager.inspect('server').members, 2);
  assert.equal(r.failures.length, 0);
});

test('server capability projection rejects unknown extensions and malformed capability records before admitting clients', async (t) => {
  const invalid = [
    null, [], true, 1, 'tools',
    { unknown: {} }, { roots: {} }, { sampling: {} }, { elicitation: {} },
    { experimental: { extension: {} } },
    { tools: { listChanged: 'false' } }, { tools: { extension: {} } },
    { prompts: { listChanged: 0 } }, { resources: { subscribe: null } }, { resources: { listChanged: [] } },
    { logging: { extension: {} } }, { completions: { extension: {} } },
    { tasks: { list: false } }, { tasks: { cancel: null } }, { tasks: { requests: [] } },
    { tasks: { requests: { tools: null } } }, { tasks: { requests: { tools: { call: [] } } } },
    { tasks: { requests: { sampling: {} } } }, { tasks: { extension: {} } },
    JSON.parse('{"__proto__":{}}'),
  ];
  for (const capability of ['tools', 'prompts', 'resources', 'logging', 'completions', 'tasks', 'experimental']) {
    for (const value of [null, [], true, 1, 'invalid']) invalid.push({ [capability]: value });
  }
  for (const capabilities of invalid) {
    const r = new Rig(t, { automaticInit: false });
    const pending = [r.acquire(), r.acquire()].map((promise) => assert.rejects(promise, (error) => {
      assert.equal(error.code, 'SHARED_INIT_INCOMPATIBLE', JSON.stringify(capabilities));
      assert.equal(error.data.phase, 'initialize');
      assert.equal(error.data.execution, 'unsent');
      return true;
    }));
    await r.turn();
    r.children[0].initialize(undefined, { capabilities });
    await Promise.all(pending);
    assert.equal(r.children[0].requests('notifications/initialized').length, 0);
    assert.equal(r.manager.inspect('server'), null);
    assert.equal(r.initializations.length, 0);
    assert.equal(r.responses.length, 0);
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
  }
});

test('supported upstream version negotiation retains the actual selection for concurrent and cached clients', async (t) => {
  const versions = ['2025-03-26', '2025-06-18', '2025-11-25'];
  for (const requested of versions) {
    for (const selected of versions) {
      const r = new Rig(t, { automaticInit: false });
      const params = { ...PARAMS, protocolVersion: requested };
      const [a, b] = await r.initializeClients({ protocolVersion: selected }, params);
      const cached = await r.attach(params);
      for (const client of [a, b, cached]) {
        assert.equal((await client.response('init')).result.protocolVersion, selected);
      }
      const peer = r.children[0];
      assert.equal(peer.requests('initialize')[0].params.protocolVersion, requested);
      assert.equal(peer.requests('initialize').length, 1);
      assert.equal(peer.requests('notifications/initialized').length, 1);
      assert.equal(r.initializations.length, 1);
      if (selected !== requested) {
        await assert.rejects(() => r.acquire({ ...PARAMS, protocolVersion: selected }), /SHARED_INCOMPATIBLE/);
      }
      a.call(1);
      peer.reply(peer.requests('tools/call')[0], { selected });
      assert.equal((await a.response(1)).result.selected, selected);
      assert.equal(r.children.length, 1);
      assert.equal(r.failures.length, 0);
    }
  }
});

test('unsupported upstream version negotiation fails all waiters without acknowledging or fabricating a supported version', async (t) => {
  for (const protocolVersion of ['2024-11-05', '2026-07-28', '', null, 1, undefined]) {
    const r = new Rig(t, { automaticInit: false });
    const pending = [r.acquire(), r.acquire()].map((promise) =>
      assert.rejects(promise, /SHARED_INIT_INCOMPATIBLE/));
    await r.turn();
    r.children[0].initialize(undefined, { protocolVersion });
    await Promise.all(pending);
    assert.equal(r.children[0].requests('notifications/initialized').length, 0);
    assert.equal(r.manager.inspect('server'), null);
    assert.equal(r.initializations.length, 0);
    assert.equal(r.responses.length, 0);
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
  }
});

test('projected capabilities never enable non-tools methods, task augmentation or unsupported callbacks', async (t) => {
  for (const callback of ['roots/list', 'sampling/createMessage', 'elicitation/create']) {
    const r = new Rig(t, { automaticInit: false });
    const [a, b] = await r.initializeClients({ capabilities: {
      tools: { listChanged: false }, prompts: {}, resources: { subscribe: true }, logging: {},
      completions: {}, tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } },
    } });
    const methods = ['resources/list', 'resources/read', 'resources/subscribe', 'prompts/list', 'prompts/get',
      'logging/setLevel', 'completion/complete', 'tasks/list', 'tasks/get', 'tasks/result', 'tasks/cancel'];
    for (const [id, method] of methods.entries()) {
      a.send(method, id, {});
      r.failure(await a.response(id), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
    }
    a.call(20, {}, { task: { ttl: 1000 } });
    r.failure(await a.response(20), 'SHARED_UNSUPPORTED_METHOD', 'unsent');
    const peer = r.children[0];
    assert.equal(peer.requests('tools/call').length, 0);
    for (const method of methods) assert.equal(peer.requests(method).length, 0);
    a.call(21);
    b.call(21);
    peer.send({ id: peer.requests('tools/call')[0].id, method: callback, params: {} });
    r.failure(await a.response(21), 'SHARED_UNSUPPORTED_CALLBACK', 'potentially-executed');
    r.failure(await b.response(21), 'SHARED_UNSUPPORTED_CALLBACK', 'potentially-executed');
    assert.equal(r.responses.length, 0);
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
  }
});

test('unexposed catalog notifications are diagnosed and dropped without broadcasting, cancelling or failing active tools', async (t) => {
  for (const optional of [{}, { resources: { listChanged: true }, prompts: { listChanged: true } }]) {
    const r = new Rig(t, { automaticInit: false });
    const [a, b] = await r.initializeClients({ capabilities: { tools: { listChanged: true }, ...optional } });
    a.call(1);
    b.call(1);
    const peer = r.children[0];
    for (const method of ['notifications/resources/list_changed', 'notifications/prompts/list_changed']) {
      peer.send({ method, params: { privateCatalog: 'must-not-appear-in-output-or-logs' } });
    }
    await r.turn();
    assert.equal(a.messages.length, 1);
    assert.equal(b.messages.length, 1);
    assert.equal(r.manager.inspect('server').state, 'ready');
    assert.equal(r.manager.inspect('server').unresolved, 2);
    assert.equal(r.failures.length, 0);
    assert.equal(r.kills.length, 0);
    assert.equal(r.responses.length, 0);
    assert.equal(peer.requests('notifications/cancelled').length, 0);
    assert.deepEqual(r.logs, [
      { name: 'server', text: 'shared: unexposed catalog notification dropped: notifications/resources/list_changed' },
      { name: 'server', text: 'shared: unexposed catalog notification dropped: notifications/prompts/list_changed' },
    ]);
    peer.send({ method: 'notifications/tools/list_changed' });
    assert.equal(a.messages.at(-1).method, 'notifications/tools/list_changed');
    assert.equal(b.messages.at(-1).method, 'notifications/tools/list_changed');
    peer.reply(peer.requests('tools/call')[1], { owner: 'b' });
    peer.reply(peer.requests('tools/call')[0], { owner: 'a' });
    assert.equal((await a.response(1)).result.owner, 'a');
    assert.equal((await b.response(1)).result.owner, 'b');
    a.call(2);
    b.call(2);
    peer.send({ method: 'notifications/unknown_extension', params: {} });
    await r.turn();
    for (const client of [a, b]) {
      const response = client.messages.find((message) => message.id === 2);
      assert.ok(response, 'unknown notifications must fail active callers immediately');
      r.failure(response, 'SHARED_UNSUPPORTED_NOTIFICATION', 'potentially-executed');
    }
    assert.equal(r.failures.length, 1);
    assert.equal(r.kills.length, 1);
    assert.equal(peer.requests('tools/call').length, 4);
  }
});
