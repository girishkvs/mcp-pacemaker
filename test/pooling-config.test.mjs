import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import childProcess from 'node:child_process';
import {
  PoolingConfigStore, PoolingConfigError, MAX_MIN_WARM, MAX_CONFIG_BYTES,
} from '../bin/pooling-config.mjs';

const BASE = '{"echo":{"command":"node"}}\n';
const HELPER = fileURLToPath(new URL('../bin/windows/PoolingSecurityHelper.exe', import.meta.url));

class Fixture {
  constructor(t, text = BASE) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'mcp-pooling-config-'));
    this.path = join(this.dir, 'servers.json');
    this.previous = join(this.dir, 'servers.previous.json');
    fs.writeFileSync(this.path, text, { mode: 0o600 });
    this.store = new PoolingConfigStore(this.path);
    t.after(() => {
      this.store.close();
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  apply(options = {}) {
    return this.store.apply({ name: 'echo', mode: 'pool', revision: this.store.revision(), ...options });
  }

  undo(result, options = {}) {
    return this.store.undo({ name: 'echo', undoId: result.undoId, revision: result.revision, ...options });
  }

  bytes() { return fs.readFileSync(this.path); }
  text() { return this.bytes().toString('utf8'); }
  hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

  error(action, statusCode, code) {
    assert.throws(action, (error) => {
      assert.ok(error instanceof PoolingConfigError);
      assert.equal(error.statusCode, statusCode);
      assert.equal(error.code, code);
      for (const secret of ['secret-value', 'SECRET_PATH', 'servers.json', 'node-secret']) {
        assert.equal(error.message.includes(secret), false);
      }
      assert.equal(error.cause, undefined);
      return true;
    });
  }

  unchanged(text = BASE) {
    assert.equal(this.text(), text);
    assert.equal(fs.existsSync(this.previous), false);
    assert.equal(fs.existsSync(join(this.dir, 'servers.pending.json')), false);
  }
}

test('Windows calls only the package-relative batch helper, with fixed timeout and bounded expected fields', {
  skip: process.platform !== 'win32',
}, (t) => {
  const f = new Fixture(t);
  const calls = [];
  const original = childProcess.spawnSync;
  t.mock.method(childProcess, 'spawnSync', (command, args, options) => {
    assert.equal(command, HELPER);
    assert.equal(options.shell, false);
    assert.equal(options.timeout, 10000);
    assert.ok(['inspect-access', 'stage', 'move-no-replace'].includes(args[0]));
    assert.equal(args.length, 1);
    if (args[0] !== 'inspect-access') {
      const input = JSON.parse(options.input);
      assert.deepEqual(Object.keys(input.expected).sort(), ['identity', 'revision', 'security']);
    }
    if (args[0] === 'stage') assert.equal(fs.existsSync(options.env.MCP_POOL_TEMP), false);
    calls.push(args[0]);
    return original(command, args, options);
  });
  const applied = f.apply();
  f.undo(applied);
  assert.equal(calls.filter((call) => call === 'stage').length, 2);
  assert.equal(calls.filter((call) => call === 'move-no-replace').length, 4);
  assert.equal(f.text(), BASE);
});

test('snapshot is private, hashes exact bytes and never opts in', (t) => {
  const text = '{"echo":{"command":"node-secret","env":{"TOKEN":"secret-value"}}}\r\n';
  const f = new Fixture(t, text);
  const snapshot = f.store.snapshot();
  assert.deepEqual(snapshot, { revision: f.hash(Buffer.from(text)), servers: JSON.parse(text) });
  snapshot.servers.echo.sharing = 'pool';
  assert.equal(f.store.snapshot().servers.echo.sharing, undefined);
  assert.deepEqual(Object.keys(f.store), []);
  f.unchanged(text);
});

test('compatibility apply/undo restore full preimages and return their existing receipt shape', (t) => {
  const f = new Fixture(t);
  const applied = f.apply({ minWarm: 3 });
  assert.deepEqual(applied, {
    ok: true, name: 'echo', mode: 'pool', minWarm: 3,
    revision: f.hash(f.bytes()), undoId: applied.undoId,
  });
  assert.equal(applied.undoId.length, 36);
  assert.equal(fs.readFileSync(f.previous, 'utf8'), BASE);
  const pooled = f.bytes();
  const disabled = f.apply({ mode: 'isolated' });
  assert.deepEqual(JSON.parse(f.text()).echo, { command: 'node', sharing: 'isolated' });
  assert.deepEqual(fs.readFileSync(f.previous), pooled);
  assert.equal(f.undo(disabled).revision, applied.revision);
  const restored = f.undo(applied);
  assert.deepEqual(restored, {
    ok: true, name: 'echo', mode: 'isolated', revision: f.hash(Buffer.from(BASE)),
  });
  assert.equal(f.text(), BASE);
  f.error(() => f.undo(applied), 409, 'UNDO_CONFLICT');
});

const preservationCases = [
  [
    String.raw`{"echo":{"command":"node","env":{"sharing":"pool","minWarm":99,"TOKEN":"secret-value","s":"quotes: \" } , \\ \u0061"},"args":[{"minWarm":88},"sharing"],"shar\u0069ng":"isolated","min\u0057arm":2},"other":{"type":"http","url":"https://example.test","headers":{"Auth":"secret-value"}}}`,
    String.raw`{"echo":{"command":"node","env":{"sharing":"pool","minWarm":99,"TOKEN":"secret-value","s":"quotes: \" } , \\ \u0061"},"args":[{"minWarm":88},"sharing"],"shar\u0069ng":"pool","min\u0057arm":4},"other":{"type":"http","url":"https://example.test","headers":{"Auth":"secret-value"}}}`,
  ],
  [
    '{\n\t"echo" : {\n\t\t"command" : "node",\n\t\t"env": {"x":"é😀","n":1e+02}\n\t},\n\t"other":{"command":"python"}\n}\n',
    '{\n\t"echo" : {\n\t\t"command" : "node",\n\t\t"env": {"x":"é😀","n":1e+02},\n\t\t"sharing" : "pool",\n\t\t"minWarm" : 4\n\t},\n\t"other":{"command":"python"}\n}\n',
  ],
  [
    '{\r\n  "echo": {\r\n    "command": "node"\r\n  }\r\n}\r\n',
    '{\r\n  "echo": {\r\n    "command": "node",\r\n    "sharing": "pool",\r\n    "minWarm": 4\r\n  }\r\n}\r\n',
  ],
  [
    ' \t{ "z": {"url":"https://example.test"}, "echo": { "command" : "node" }, "a": {"command":"node"} }\r\n',
    ' \t{ "z": {"url":"https://example.test"}, "echo": { "command" : "node", "sharing" : "pool", "minWarm" : 4 }, "a": {"command":"node"} }\r\n',
  ],
];

for (const [index, [before, after]] of preservationCases.entries()) {
  test(`span editor preserves every unrequested byte (${index})`, (t) => {
    const f = new Fixture(t, before);
    const result = f.apply({ minWarm: 4 });
    assert.equal(f.text(), after);
    assert.equal(fs.readFileSync(f.previous, 'utf8'), before);
    assert.deepEqual(Object.keys(result).sort(), ['minWarm', 'mode', 'name', 'ok', 'revision', 'undoId']);
    assert.equal(JSON.stringify(result).includes('secret-value'), false);
    f.undo(result);
    assert.equal(f.text(), before);
  });
}

for (const [properties, expected] of [
  ['"minWarm":3, "command":"node", "sharing":"pool"', '"command":"node", "sharing":"isolated"'],
  ['"command":"node", "minWarm":3, "sharing":"pool"', '"command":"node", "sharing":"isolated"'],
  ['"command":"node", "sharing":"pool", "minWarm":3', '"command":"node", "sharing":"isolated"'],
]) {
  test(`disable removes the exact minWarm span: ${properties}`, (t) => {
    const before = `{"echo":{ ${properties} }}\n`;
    const f = new Fixture(t, before);
    const result = f.apply({ mode: 'isolated' });
    assert.equal(f.text(), `{"echo":{ ${expected} }}\n`);
    f.undo(result);
    assert.equal(f.text(), before);
  });
}

test('no-op does not create files or consume an existing Undo', (t) => {
  const f = new Fixture(t);
  assert.deepEqual(f.apply({ mode: 'isolated' }), {
    ok: true, name: 'echo', mode: 'isolated', revision: f.store.revision(),
  });
  f.unchanged();
  const applied = f.apply();
  const stat = fs.statSync(f.path);
  assert.equal(f.apply().undoId, undefined);
  assert.equal(fs.statSync(f.path).mtimeMs, stat.mtimeMs);
  f.undo(applied);
  assert.equal(f.text(), BASE);
});

test('escaped equivalent values are not normalized, and defaults stay bounded', (t) => {
  const before = String.raw`{"echo":{"command":"node","sharing":"\u0070ool","minWarm":1e0}}`;
  const f = new Fixture(t, before);
  assert.equal(f.apply({ minWarm: 1 }).undoId, undefined);
  f.unchanged(before);
  assert.equal(f.apply({ minWarm: MAX_MIN_WARM }).minWarm, MAX_MIN_WARM);
  assert.equal(f.apply().minWarm, MAX_MIN_WARM);
});

test('stale content wins before security inspection or parsing external malformed data', (t) => {
  const f = new Fixture(t);
  const revision = f.store.revision();
  fs.writeFileSync(f.path, '{secret-value');
  const mock = t.mock.method(childProcess, 'spawnSync', () => { throw new Error('Not expected'); });
  f.error(() => f.store.apply({ name: 'echo', mode: 'pool', revision }), 409, 'REVISION_CONFLICT');
  assert.equal(mock.mock.callCount(), 0);
  f.unchanged('{secret-value');
});

test('stale Undo rejects both an old receipt and a fresh revision after an external edit', (t) => {
  const f = new Fixture(t);
  const applied = f.apply();
  const edited = f.text() + ' ';
  fs.writeFileSync(f.path, edited);
  f.error(() => f.undo(applied), 409, 'REVISION_CONFLICT');
  f.error(() => f.undo(applied, { revision: f.store.revision() }), 409, 'REVISION_CONFLICT');
  assert.equal(f.text(), edited);
});

test('names are exact decoded JSON keys, not paths or URL-decoded strings', (t) => {
  const name = '../a%2Fb/é."[*]';
  const text = JSON.stringify({ [name]: { command: 'node' }, 'a/b': { command: 'other' } });
  const f = new Fixture(t, text);
  const result = f.apply({ name });
  assert.equal(f.store.snapshot().servers[name].sharing, 'pool');
  assert.equal(f.store.snapshot().servers['a/b'].sharing, undefined);
  f.undo(result, { name });
  assert.equal(f.text(), text);
  f.error(() => f.apply({ name: 'a%2Fb' }), 404, 'SERVER_NOT_FOUND');
});

test('strict requests reject accessors, prototype transfers, extra fields and invalid bounds', (t) => {
  const f = new Fixture(t);
  const valid = { name: 'echo', mode: 'pool', revision: f.store.revision() };
  for (const request of [null, undefined, [], 'pool', 1, Object.create(valid)]) {
    f.error(() => f.store.apply(request), 400, 'INVALID_REQUEST');
  }
  for (const mode of [undefined, 'shared', true, 1, 'POOL']) {
    f.error(() => f.store.apply({ ...valid, mode }), 400, 'INVALID_REQUEST');
  }
  for (const name of ['', null, '__proto__', 'constructor', 'prototype', 'a\nb', '\x7f', '\x85', 'x'.repeat(257)]) {
    f.error(() => f.apply({ name }), 400, 'INVALID_REQUEST');
  }
  for (const revision of [undefined, '', 'abc', 'A'.repeat(64), 123]) {
    f.error(() => f.store.apply({ ...valid, revision }), 400, 'INVALID_REQUEST');
  }
  for (const minWarm of [undefined, null, 0, -1, 1.5, '1', true, NaN, Infinity, MAX_MIN_WARM + 1]) {
    f.error(() => f.apply({ minWarm }), 400, 'INVALID_REQUEST');
  }
  for (const key of ['command', 'env', 'auth', 'sharing', 'configPath', 'url']) {
    f.error(() => f.apply({ [key]: 'secret-value' }), 400, 'INVALID_REQUEST');
  }
  f.error(() => f.apply({ mode: 'isolated', minWarm: 1 }), 400, 'INVALID_REQUEST');
  f.error(() => f.store.apply({ ...valid, get minWarm() { throw new Error('secret-value'); } }), 400, 'INVALID_REQUEST');
  f.error(() => f.store.apply({ ...valid, [Symbol('secret-value')]: true }), 400, 'INVALID_REQUEST');
  f.error(() => f.store.undo({ name: 'echo', revision: valid.revision, undoId: 'x' }), 400, 'INVALID_REQUEST');
  f.unchanged();
});

test('strict UTF-8, JSON syntax, root, duplicate keys and depth remain enforced', (t) => {
  const f = new Fixture(t);
  for (const bytes of [
    '', '{secret-value', '[]', 'null', 'true', '"secret-value"',
    '{"echo":{"command":"node",}}', '{/*comment*/"echo":{"command":"node"}}',
    '{"echo":{"command":"node"},"echo":{"command":"other"}}',
    String.raw`{"echo":{"command":"node","sharing":"pool","shar\u0069ng":"isolated"}}`,
    '{"echo":{"command":"node","env":{"TOKEN":1,"TOKEN":2}}}',
    '{"echo":{"command":"node","args":[{"x":1,"x":2}]}}',
    '\ufeff' + BASE, Buffer.from([0xff, 0xfe]),
    '{"echo":{"command":"node","args":' + '['.repeat(130) + '0' + ']'.repeat(130) + '}}',
  ]) {
    fs.writeFileSync(f.path, bytes);
    f.error(() => f.store.snapshot(), 400, 'INVALID_CONFIG');
    f.error(() => f.store.apply({ name: 'echo', mode: 'pool', revision: f.hash(Buffer.from(bytes)) }), 400, 'INVALID_CONFIG');
    assert.deepEqual(f.bytes(), Buffer.from(bytes));
  }
});

test('malformed, shared and non-stdio definitions cannot be pooled', (t) => {
  const f = new Fixture(t);
  for (const server of [
    null, [], 'node', {}, { command: '' }, { command: 1 },
    { type: 'http', url: 'https://example.test', command: 'node' },
    { url: 'https://example.test', command: 'node' },
    { type: 'sse', command: 'node' }, { command: 'node', sharing: 'shared' },
  ]) {
    const text = JSON.stringify({ echo: server });
    fs.writeFileSync(f.path, text);
    for (const mode of ['pool', 'isolated']) f.error(() => f.apply({ mode }), 400, 'UNSUPPORTED_SERVER');
    f.unchanged(text);
  }
});

test('all server definitions, not just the changed server, are validated', (t) => {
  const f = new Fixture(t, '{"echo":{"command":"node"},"bad":{}}');
  f.error(() => f.apply(), 400, 'INVALID_CONFIG');
  f.unchanged('{"echo":{"command":"node"},"bad":{}}');
});

test('file type, path, size and hardlink bounds are retained', (t) => {
  const f = new Fixture(t);
  f.error(() => new PoolingConfigStore(''), 400, 'INVALID_PATH');
  f.error(() => new PoolingConfigStore('SECRET_PATH\0'), 400, 'INVALID_PATH');
  f.error(() => new PoolingConfigStore(f.dir).snapshot(), 400, 'UNSUPPORTED_FILE');
  const link = join(f.dir, 'link.json');
  fs.linkSync(f.path, link);
  f.error(() => f.store.snapshot(), 400, 'UNSUPPORTED_FILE');
  fs.unlinkSync(link);
  fs.writeFileSync(f.path, BASE + ' '.repeat(MAX_CONFIG_BYTES - Buffer.byteLength(BASE)));
  f.error(() => f.apply(), 400, 'UNSUPPORTED_FILE');
  fs.writeFileSync(f.path, ' '.repeat(MAX_CONFIG_BYTES + 1));
  f.error(() => f.store.snapshot(), 400, 'UNSUPPORTED_FILE');
  fs.unlinkSync(f.path);
  f.error(() => f.store.snapshot(), 404, 'CONFIG_NOT_FOUND');
});

test('legacy unsafe minWarm is restored privately but never echoed through receipts', (t) => {
  const f = new Fixture(t);
  for (const minWarm of [undefined, null, 'secret-value', { token: 'secret-value' }, 0, MAX_MIN_WARM + 1]) {
    const text = JSON.stringify({ echo: { command: 'node', sharing: 'pool', minWarm } });
    fs.writeFileSync(f.path, text);
    const disabled = f.apply({ mode: 'isolated' });
    const restored = f.undo(disabled);
    assert.equal(f.text(), text);
    assert.deepEqual(restored, {
      ok: true, name: 'echo', mode: 'pool', revision: f.hash(Buffer.from(text)),
    });
  }
});

test('I/O failures and malformed helper output are sanitized', (t) => {
  const f = new Fixture(t);
  const mock = t.mock.method(fs, 'readSync', () => {
    throw Object.assign(new Error('SECRET_PATH secret-value'), { code: 'EACCES' });
  });
  f.error(() => f.store.snapshot(), 500, 'IO_ERROR');
  mock.mock.restore();
  if (process.platform === 'win32') {
    t.mock.method(childProcess, 'spawnSync', () => ({ status: 0, stdout: 'invalid', stderr: '' }));
    f.error(() => f.apply(), 500, 'IO_ERROR');
  }
});
