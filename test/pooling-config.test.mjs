import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import childProcess, { spawnSync } from 'node:child_process';
import {
  PoolingConfigStore, PoolingConfigError, MAX_MIN_WARM,
  MAX_UNDO_ENTRIES, MAX_UNDO_BYTES, MAX_CONFIG_BYTES,
} from '../bin/pooling-config.mjs';

const BASE = '{"echo":{"command":"node"}}\n';

class Fixture {
  constructor(t, text = BASE) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'mcp-pooling-config-'));
    this.path = join(this.dir, 'servers.json');
    t.after(() => fs.rmSync(this.dir, { recursive: true, force: true }));
    fs.writeFileSync(this.path, text, { mode: 0o600 });
    this.store = new PoolingConfigStore(this.path);
  }

  apply(options = {}) {
    return this.store.apply({ name: 'echo', mode: 'pool', revision: this.store.revision(), ...options });
  }

  undo(result, options = {}) {
    return this.store.undo({ name: 'echo', undoId: result.undoId, revision: result.revision, ...options });
  }

  bytes() {
    return fs.readFileSync(this.path);
  }

  text() {
    return this.bytes().toString('utf8');
  }

  hash(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
  }

  error(action, statusCode, code) {
    assert.throws(action, (error) => {
      assert.ok(error instanceof PoolingConfigError);
      assert.equal(error.statusCode, statusCode);
      assert.equal(error.code, code);
      assert.doesNotMatch(error.message, /secret-value|SECRET_PATH|servers\.json|node-secret/);
      assert.equal(error.cause, undefined);
      return true;
    });
  }

  clean() {
    assert.deepEqual(fs.readdirSync(this.dir).filter((name) => name.endsWith('.tmp')), []);
  }

  unchanged(text = BASE) {
    assert.equal(this.text(), text);
    assert.equal(fs.existsSync(`${this.path}.bak`), false);
    this.clean();
  }

  windowsAcl(protect = false) {
    const script = `
$ErrorActionPreference = 'Stop'
$acl = [System.IO.File]::GetAccessControl($env:MCP_POOL_SOURCE)
if ($env:MCP_POOL_PROTECT -eq '1') {
  $acl.SetAccessRuleProtection($true, $false)
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
  $acl.AddAccessRule($rule)
  [System.IO.File]::SetAccessControl($env:MCP_POOL_SOURCE, $acl)
}
$section = [System.Security.AccessControl.AccessControlSections]'Access, Owner, Group'
foreach ($path in @($env:MCP_POOL_SOURCE, $env:MCP_POOL_SOURCE + '.bak')) {
  if ([System.IO.File]::Exists($path)) {
    [System.IO.File]::GetAccessControl($path).GetSecurityDescriptorSddlForm($section)
  }
}`;
    return this.windowsCommand(script, { MCP_POOL_PROTECT: protect ? '1' : '0' }).split(/\r?\n/);
  }

  windowsCommand(script, environment = {}) {
    const result = spawnSync(join(process.env.SystemRoot,
      'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
      env: { ...process.env, MCP_POOL_SOURCE: this.path, ...environment },
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  }

  auditAvailable() {
    return this.windowsCommand(`
$ErrorActionPreference = 'Stop'
try {
  [System.IO.File]::GetAccessControl($env:MCP_POOL_SOURCE, [Security.AccessControl.AccessControlSections]::Audit) | Out-Null
  'yes'
} catch [Security.AccessControl.PrivilegeNotHeldException] { 'no'
} catch [UnauthorizedAccessException] { 'no' }
`) === 'yes';
  }

  windowsAudit(add = false, failure = false) {
    return this.windowsCommand(`
$ErrorActionPreference = 'Stop'
$section = [Security.AccessControl.AccessControlSections]::Audit
$acl = [System.IO.File]::GetAccessControl($env:MCP_POOL_SOURCE, $section)
if ($env:MCP_POOL_ADD_AUDIT -eq '1') {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $rights = [Security.AccessControl.FileSystemRights]::ReadData
  $flags = [Security.AccessControl.AuditFlags]::Success
  if ($env:MCP_POOL_AUDIT_FAILURE -eq '1') {
    $rights = [Security.AccessControl.FileSystemRights]::WriteData
    $flags = [Security.AccessControl.AuditFlags]::Failure
  }
  $rule = [Security.AccessControl.FileSystemAuditRule]::new($sid, $rights, $flags)
  $acl.AddAuditRule($rule)
  [System.IO.File]::SetAccessControl($env:MCP_POOL_SOURCE, $acl)
}
[System.IO.File]::GetAccessControl($env:MCP_POOL_SOURCE, $section).GetSecurityDescriptorSddlForm($section)
`, { MCP_POOL_ADD_AUDIT: add ? '1' : '0', MCP_POOL_AUDIT_FAILURE: failure ? '1' : '0' });
  }

  inheritAuditPolicy() {
    const bytes = this.bytes();
    fs.unlinkSync(this.path);
    this.windowsCommand(`
$ErrorActionPreference = 'Stop'
$directory = [IO.Path]::GetDirectoryName($env:MCP_POOL_SOURCE)
$acl = [IO.Directory]::GetAccessControl($directory, [Security.AccessControl.AccessControlSections]::Audit)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$rule = [Security.AccessControl.FileSystemAuditRule]::new($sid,
  [Security.AccessControl.FileSystemRights]::ReadData, $inheritance,
  [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AuditFlags]::Success)
$acl.AddAuditRule($rule)
[IO.Directory]::SetAccessControl($directory, $acl)
`);
    fs.writeFileSync(this.path, bytes);
  }

  denyAuditInspection(t) {
    const originalSpawn = childProcess.spawnSync;
    t.mock.method(childProcess, 'spawnSync', (command, args, options) => {
      const script = args.at(-1).replace(
        '$audit = [System.IO.File]::GetAccessControl($Path, $auditSection).GetSecurityDescriptorBinaryForm()',
        "throw [System.Security.AccessControl.PrivilegeNotHeldException]::new('SeSecurityPrivilege')");
      return originalSpawn(command, [...args.slice(0, -1), script], options);
    });
  }
}

test('snapshot is internal, revision hashes exact bytes, and reads never opt in', (t) => {
  const text = '{"echo":{"command":"node-secret","env":{"TOKEN":"secret-value"}}}\r\n';
  const fixture = new Fixture(t, text);
  const snapshot = fixture.store.snapshot();
  assert.deepEqual(snapshot, { revision: fixture.hash(Buffer.from(text)), servers: JSON.parse(text) });
  assert.equal(fixture.store.revision(), snapshot.revision);
  snapshot.servers.echo.sharing = 'pool';
  assert.equal(fixture.store.snapshot().servers.echo.sharing, undefined);
  assert.deepEqual(Object.keys(fixture.store), []);
  fixture.unchanged(text);
});

test('apply then disable and undo restore each full preimage including property absence', (t) => {
  const fixture = new Fixture(t);
  const applied = fixture.apply({ minWarm: 3 });
  assert.deepEqual(applied, {
    ok: true, name: 'echo', mode: 'pool', minWarm: 3,
    revision: fixture.hash(fixture.bytes()), undoId: applied.undoId,
  });
  assert.match(applied.undoId, /^[0-9a-f-]{36}$/);
  assert.equal(applied.revision, fixture.hash(fixture.bytes()));
  assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
  const pooled = fixture.bytes();
  const disabled = fixture.apply({ mode: 'isolated' });
  assert.deepEqual(disabled, {
    ok: true, name: 'echo', mode: 'isolated', revision: disabled.revision, undoId: disabled.undoId,
  });
  assert.deepEqual(JSON.parse(fixture.text()).echo, { command: 'node', sharing: 'isolated' });
  assert.deepEqual(fs.readFileSync(`${fixture.path}.bak`), pooled);
  const restoredPool = fixture.undo(disabled);
  assert.deepEqual(fixture.bytes(), pooled);
  assert.equal(restoredPool.revision, applied.revision);
  assert.equal(Object.hasOwn(restoredPool, 'undoId'), false);
  const restored = fixture.undo(applied);
  assert.equal(fixture.text(), BASE);
  assert.deepEqual(restored, {
    ok: true, name: 'echo', mode: 'isolated', revision: fixture.hash(Buffer.from(BASE)),
  });
  assert.equal(Object.hasOwn(fixture.store.snapshot().servers.echo, 'sharing'), false);
  fixture.error(() => fixture.undo(applied), 409, 'UNDO_CONFLICT');
  fixture.clean();
});

const preservationCases = [
  {
    label: 'compact escaped strings and nested lookalikes',
    before: String.raw`{"echo":{"command":"node","env":{"sharing":"pool","minWarm":99,"TOKEN":"secret-value","s":"quotes: \" } , \\ \u0061"},"args":[{"minWarm":88},"sharing"],"shar\u0069ng":"isolated","min\u0057arm":2},"other":{"type":"http","url":"https://example.test","headers":{"Auth":"secret-value"}}}`,
    after: String.raw`{"echo":{"command":"node","env":{"sharing":"pool","minWarm":99,"TOKEN":"secret-value","s":"quotes: \" } , \\ \u0061"},"args":[{"minWarm":88},"sharing"],"shar\u0069ng":"pool","min\u0057arm":4},"other":{"type":"http","url":"https://example.test","headers":{"Auth":"secret-value"}}}`,
  },
  {
    label: 'pretty LF with tabs and spaces around colons',
    before: '{\n\t"echo" : {\n\t\t"command" : "node",\n\t\t"env": {"x":"é😀","n":1e+02}\n\t},\n\t"other":{"command":"python"}\n}\n',
    after: '{\n\t"echo" : {\n\t\t"command" : "node",\n\t\t"env": {"x":"é😀","n":1e+02},\n\t\t"sharing" : "pool",\n\t\t"minWarm" : 4\n\t},\n\t"other":{"command":"python"}\n}\n',
  },
  {
    label: 'pretty CRLF',
    before: '{\r\n  "echo": {\r\n    "command": "node"\r\n  }\r\n}\r\n',
    after: '{\r\n  "echo": {\r\n    "command": "node",\r\n    "sharing": "pool",\r\n    "minWarm": 4\r\n  }\r\n}\r\n',
  },
  {
    label: 'compact outer whitespace and original key order',
    before: ' \t{ "z": {}, "echo": { "command" : "node" }, "a": {} }\r\n',
    after: ' \t{ "z": {}, "echo": { "command" : "node", "sharing" : "pool", "minWarm" : 4 }, "a": {} }\r\n',
  },
];

for (const sample of preservationCases) {
  test(`byte preservation: ${sample.label}`, (t) => {
    const fixture = new Fixture(t, sample.before);
    const result = fixture.apply({ minWarm: 4 });
    assert.equal(fixture.text(), sample.after);
    assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), sample.before);
    assert.deepEqual(Object.keys(result).sort(), ['minWarm', 'mode', 'name', 'ok', 'revision', 'undoId']);
    assert.doesNotMatch(JSON.stringify(result), /secret-value|command|headers|Auth/);
    fixture.undo(result);
    assert.deepEqual(fixture.bytes(), Buffer.from(sample.before));
    fixture.clean();
  });
}

for (const [position, properties, expected] of [
  ['first', '"minWarm":3, "command":"node", "sharing":"pool"', '"command":"node", "sharing":"isolated"'],
  ['middle', '"command":"node", "minWarm":3, "sharing":"pool"', '"command":"node", "sharing":"isolated"'],
  ['last', '"command":"node", "sharing":"pool", "minWarm":3', '"command":"node", "sharing":"isolated"'],
]) {
  test(`disable removes minWarm in ${position} position without touching other bytes`, (t) => {
    const original = `{"echo":{ ${properties} }}\n`;
    const fixture = new Fixture(t, original);
    const result = fixture.apply({ mode: 'isolated' });
    assert.equal(fixture.text(), `{"echo":{ ${expected} }}\n`);
    fixture.undo(result);
    assert.equal(fixture.text(), original);
  });
}

test('disable preserves absent sharing when only removing a dormant minWarm', (t) => {
  const text = '{"echo":{"command":"node","minWarm":4}}';
  const fixture = new Fixture(t, text);
  const result = fixture.apply({ mode: 'isolated' });
  assert.equal(fixture.text(), '{"echo":{"command":"node"}}');
  fixture.undo(result);
  assert.equal(fixture.text(), text);
});

test('no-op neither writes a backup nor consumes an existing undo', (t) => {
  const fixture = new Fixture(t);
  const revision = fixture.store.revision();
  assert.deepEqual(fixture.apply({ mode: 'isolated' }), {
    ok: true, name: 'echo', mode: 'isolated', revision,
  });
  fixture.unchanged();
  const applied = fixture.apply();
  const before = fs.statSync(fixture.path);
  const noOp = fixture.apply();
  assert.deepEqual(noOp, {
    ok: true, name: 'echo', mode: 'pool', minWarm: 1, revision: applied.revision,
  });
  assert.equal(noOp.revision, applied.revision);
  assert.equal(fs.statSync(fixture.path).mtimeMs, before.mtimeMs);
  assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
  fixture.undo(applied);
  assert.equal(fixture.text(), BASE);
});

test('equivalent escaped values are not normalized on no-op', (t) => {
  const text = String.raw`{"echo":{"command":"node","sharing":"\u0070ool","minWarm":1e0}}`;
  const fixture = new Fixture(t, text);
  assert.equal(Object.hasOwn(fixture.apply({ minWarm: 1 }), 'undoId'), false);
  fixture.unchanged(text);
});

test('pool defaults to one, preserves a valid existing target, and accepts the bound', (t) => {
  const fixture = new Fixture(t);
  assert.equal(fixture.apply().minWarm, 1);
  assert.equal(fixture.apply({ minWarm: MAX_MIN_WARM }).minWarm, MAX_MIN_WARM);
  assert.equal(fixture.apply().minWarm, MAX_MIN_WARM);
});

test('stale apply must not overwrite an external edit, including a would-be no-op', (t) => {
  const fixture = new Fixture(t);
  const revision = fixture.store.revision();
  const edited = '{"echo":{"command":"node","env":{"TOKEN":"secret-value"}}}\n';
  fs.writeFileSync(fixture.path, edited);
  fixture.error(() => fixture.apply({ revision }), 409, 'REVISION_CONFLICT');
  fixture.error(() => fixture.apply({ revision, mode: 'isolated' }), 409, 'REVISION_CONFLICT');
  fixture.unchanged(edited);
});

test('stale revision wins over parsing an external malformed edit', (t) => {
  const fixture = new Fixture(t);
  const revision = fixture.store.revision();
  fs.writeFileSync(fixture.path, '{secret-value');
  fixture.error(() => fixture.store.apply({ name: 'echo', mode: 'pool', revision }), 409, 'REVISION_CONFLICT');
  fixture.unchanged('{secret-value');
});

test('concurrent same-revision requests across stores have one winner', async (t) => {
  const fixture = new Fixture(t);
  const other = new PoolingConfigStore(fixture.path);
  const revision = fixture.store.revision();
  const requests = [fixture.store, other].map((store, index) => Promise.resolve().then(() =>
    store.apply({ name: 'echo', mode: 'pool', minWarm: index + 1, revision })));
  const results = await Promise.allSettled(requests);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(results.find((result) => result.status === 'rejected').reason.statusCode, 409);
  assert.equal(fixture.store.snapshot().servers.echo.minWarm, 1);
  assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
  fixture.clean();
});

test('stale undo refuses both an old UI revision and a fresh revision after another edit', (t) => {
  const fixture = new Fixture(t);
  const applied = fixture.apply();
  const edited = fixture.text() + ' ';
  fs.writeFileSync(fixture.path, edited);
  fixture.error(() => fixture.undo(applied), 409, 'REVISION_CONFLICT');
  fixture.error(() => fixture.undo(applied, { revision: fixture.store.revision() }), 409, 'REVISION_CONFLICT');
  assert.equal(fixture.text(), edited);
  assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
  fixture.clean();
});

test('undo cannot be transferred to another server or another store', (t) => {
  const fixture = new Fixture(t, '{"echo":{"command":"node"},"other":{"command":"node"}}');
  const applied = fixture.apply();
  fixture.error(() => fixture.undo(applied, { name: 'other' }), 409, 'UNDO_CONFLICT');
  const restarted = new PoolingConfigStore(fixture.path);
  fixture.error(() => restarted.undo({
    name: 'echo', revision: applied.revision, undoId: applied.undoId,
  }), 409, 'UNDO_CONFLICT');
  fixture.undo(applied);
});

test('names are exact JSON keys, never paths, regexes, or URL-decoded strings', (t) => {
  const name = '../a%2Fb/é."[*]';
  const text = JSON.stringify({ [name]: { command: 'node' }, 'a/b': { command: 'other' } });
  const fixture = new Fixture(t, text);
  const result = fixture.apply({ name });
  assert.equal(fixture.store.snapshot().servers[name].sharing, 'pool');
  assert.equal(fixture.store.snapshot().servers['a/b'].sharing, undefined);
  fixture.undo(result, { name });
  assert.equal(fixture.text(), text);
  fixture.error(() => fixture.apply({ name: 'a%2Fb' }), 404, 'SERVER_NOT_FOUND');
  fixture.clean();
});

test('escaped server keys are located by their decoded exact value', (t) => {
  const text = String.raw`{"ec\u0068o":{"command":"node"},"other":{"command":"python"}}`;
  const fixture = new Fixture(t, text);
  const result = fixture.apply();
  assert.match(fixture.text(), /ec\\u0068o/);
  assert.equal(fixture.store.snapshot().servers.echo.sharing, 'pool');
  fixture.undo(result);
  assert.equal(fixture.text(), text);
});

test('extra keys reject arbitrary command, env and auth edits on apply and undo', (t) => {
  const fixture = new Fixture(t);
  for (const extra of ['command', 'env', 'auth', 'sharing', 'configPath', 'url']) {
    fixture.error(() => fixture.apply({ [extra]: 'secret-value' }), 400, 'INVALID_REQUEST');
  }
  const applied = fixture.apply();
  const bytes = fixture.bytes();
  fixture.error(() => fixture.undo(applied, { auth: 'secret-value' }), 400, 'INVALID_REQUEST');
  assert.deepEqual(fixture.bytes(), bytes);
  fixture.undo(applied);
});

test('invalid request objects, modes, names, revisions and minWarm are rejected', (t) => {
  const fixture = new Fixture(t);
  const valid = { name: 'echo', mode: 'pool', revision: fixture.store.revision() };
  for (const request of [null, undefined, [], 'pool', 1, Object.create(valid)]) {
    fixture.error(() => fixture.store.apply(request), 400, 'INVALID_REQUEST');
  }
  for (const mode of [undefined, 'shared', true, 1, 'POOL']) {
    fixture.error(() => fixture.store.apply({ ...valid, mode }), 400, 'INVALID_REQUEST');
  }
  for (const name of ['', null, '__proto__', 'constructor', 'prototype', 'a\nb', '\x7f', '\x85', 'x'.repeat(257)]) {
    fixture.error(() => fixture.apply({ name }), 400, 'INVALID_REQUEST');
  }
  for (const revision of [undefined, '', 'abc', 'A'.repeat(64), 123]) {
    fixture.error(() => fixture.store.apply({ ...valid, revision }), 400, 'INVALID_REQUEST');
  }
  for (const minWarm of [undefined, null, 0, -1, 1.5, '1', true, NaN, Infinity, MAX_MIN_WARM + 1, Number.MAX_SAFE_INTEGER + 1]) {
    fixture.error(() => fixture.apply({ minWarm }), 400, 'INVALID_REQUEST');
  }
  fixture.error(() => fixture.apply({ mode: 'isolated', minWarm: 1 }), 400, 'INVALID_REQUEST');
  fixture.error(() => fixture.apply({ name: 'toString' }), 404, 'SERVER_NOT_FOUND');
  fixture.error(() => fixture.store.undo({ name: 'echo', revision: valid.revision, undoId: 'x' }), 400, 'INVALID_REQUEST');
  const accessor = { ...valid, get minWarm() { throw new Error('secret-value'); } };
  fixture.error(() => fixture.store.apply(accessor), 400, 'INVALID_REQUEST');
  fixture.error(() => fixture.store.apply({ ...valid, [Symbol('secret-value')]: true }), 400, 'INVALID_REQUEST');
  fixture.unchanged();
});

test('malformed JSON, JSONC, non-object roots, duplicate and excessively nested keys reject', (t) => {
  const fixture = new Fixture(t);
  const invalid = [
    '', '{secret-value', '[]', 'null', 'true', '"secret-value"',
    '{"echo":{"command":"node",}}', '{/* secret-value */"echo":{"command":"node"}}',
    '{"echo":{"command":"node"},"echo":{"command":"other"}}',
    String.raw`{"echo":{"command":"node","sharing":"pool","shar\u0069ng":"isolated"}}`,
    '{"echo":{"command":"node","env":{"TOKEN":1,"TOKEN":2}}}',
    '{"echo":{"command":"node","args":[{"x":1,"x":2}]}}',
    '\ufeff' + BASE,
    Buffer.from([0xff, 0xfe]),
    '{"echo":{"command":"node","args":' + '['.repeat(130) + '0' + ']'.repeat(130) + '}}',
  ];
  for (const bytes of invalid) {
    fs.writeFileSync(fixture.path, bytes);
    fixture.error(() => fixture.store.snapshot(), 400, 'INVALID_CONFIG');
    fixture.error(() => fixture.store.apply({
      name: 'echo', mode: 'pool', revision: fixture.hash(Buffer.from(bytes)),
    }), 400, 'INVALID_CONFIG');
    assert.deepEqual(fixture.bytes(), Buffer.from(bytes));
  }
  assert.equal(fs.existsSync(`${fixture.path}.bak`), false);
  fixture.clean();
});

test('unknown, malformed, and HTTP server definitions cannot be pooled or disabled', (t) => {
  const fixture = new Fixture(t);
  for (const server of [
    null, [], 'node', {}, { command: '' }, { command: 1 },
    { type: 'http', url: 'https://example.test', command: 'node' },
    { url: 'https://example.test', command: 'node' },
    { type: 'sse', command: 'node' },
  ]) {
    const text = JSON.stringify({ echo: server });
    fs.writeFileSync(fixture.path, text);
    for (const mode of ['pool', 'isolated']) {
      fixture.error(() => fixture.apply({ mode }), 400, 'UNSUPPORTED_SERVER');
      fixture.unchanged(text);
    }
  }
  fs.writeFileSync(fixture.path, '{"echo":{"type":"stdio","command":"node"}}');
  assert.equal(fixture.apply().mode, 'pool');
});

test('existing unsafe minWarm is not silently retained when pool target is omitted', (t) => {
  const fixture = new Fixture(t, '{"echo":{"command":"node","minWarm":1000}}');
  fixture.error(() => fixture.apply(), 400, 'INVALID_REQUEST');
  assert.equal(fixture.apply({ minWarm: 2 }).minWarm, 2);
});

test('missing config is explicit and is never created by reads or apply', (t) => {
  const fixture = new Fixture(t);
  const revision = fixture.store.revision();
  fs.unlinkSync(fixture.path);
  fixture.error(() => fixture.store.snapshot(), 404, 'CONFIG_NOT_FOUND');
  fixture.error(() => fixture.store.apply({ name: 'echo', mode: 'pool', revision }), 404, 'CONFIG_NOT_FOUND');
  assert.deepEqual(fs.readdirSync(fixture.dir), []);
});

test('non-file, hardlinked, oversized and invalid config paths are rejected', (t) => {
  const fixture = new Fixture(t);
  fixture.error(() => new PoolingConfigStore('').snapshot(), 400, 'INVALID_PATH');
  fixture.error(() => new PoolingConfigStore('SECRET_PATH\0').snapshot(), 400, 'INVALID_PATH');
  fixture.error(() => new PoolingConfigStore(fixture.dir).snapshot(), 400, 'UNSUPPORTED_FILE');
  const link = join(fixture.dir, 'hardlink.json');
  fs.linkSync(fixture.path, link);
  fixture.error(() => fixture.store.snapshot(), 400, 'UNSUPPORTED_FILE');
  fs.unlinkSync(link);
  fs.writeFileSync(fixture.path, ' '.repeat(MAX_CONFIG_BYTES + 1));
  fixture.error(() => fixture.store.snapshot(), 400, 'UNSUPPORTED_FILE');
});

test('a config cannot grow past the readable size limit', (t) => {
  const text = BASE + ' '.repeat(MAX_CONFIG_BYTES - Buffer.byteLength(BASE));
  const fixture = new Fixture(t, text);
  fixture.error(() => fixture.apply(), 400, 'UNSUPPORTED_FILE');
  fixture.unchanged(text);
});

test('symlink configs are rejected without changing their targets', (t) => {
  const fixture = new Fixture(t);
  const link = join(fixture.dir, 'symlink.json');
  try {
    fs.symlinkSync(fixture.path, link);
  } catch (error) {
    if (process.platform === 'win32' &&
        error.code === 'EPERM') {
      t.skip('This Windows account cannot create symlinks.');
      return;
    }
    throw error;
  }
  fixture.error(() => new PoolingConfigStore(link).snapshot(), 400, 'UNSUPPORTED_FILE');
  fixture.unchanged();
});

test('undo records are bounded by count and evicted records cannot write', (t) => {
  const fixture = new Fixture(t);
  const oldest = fixture.apply();
  const oldestBytes = fixture.bytes();
  let latest;
  for (let index = 0; index < MAX_UNDO_ENTRIES; index++) {
    latest = fixture.apply({ minWarm: index % 2 + 2 });
  }
  fixture.undo(latest);
  fs.writeFileSync(fixture.path, oldestBytes);
  fixture.error(() => fixture.undo(oldest), 409, 'UNDO_CONFLICT');
  assert.deepEqual(fixture.bytes(), oldestBytes);
  fixture.clean();
});

test('undo records are bounded by retained preimage bytes, not just count', (t) => {
  const size = MAX_CONFIG_BYTES - 1024;
  const text = JSON.stringify({ echo: { command: 'node' }, padding: 'x'.repeat(size) });
  const fixture = new Fixture(t, text);
  const oldest = fixture.apply();
  const oldestBytes = fixture.bytes();
  const edits = Math.floor(MAX_UNDO_BYTES / Buffer.byteLength(text)) + 1;
  assert.ok(edits < MAX_UNDO_ENTRIES);
  for (let index = 0; index < edits; index++) {
    fixture.apply({ minWarm: index % 2 + 2 });
  }
  fs.writeFileSync(fixture.path, oldestBytes);
  fixture.error(() => fixture.undo(oldest), 409, 'UNDO_CONFLICT');
  fixture.clean();
});

test('backup is flushed before replacement and a last-check conflict never overwrites an editor', (t) => {
  const fixture = new Fixture(t);
  const originalRename = fs.renameSync;
  const originalSync = fs.fsyncSync;
  const events = [];
  const external = '{"echo":{"command":"node","args":["secret-value"]}}\r\n';
  t.mock.method(fs, 'fsyncSync', (...args) => {
    events.push('flush');
    return originalSync(...args);
  });
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === `${fixture.path}.bak`) {
      assert.equal(events.filter((event) => event === 'flush').length, 2);
      assert.equal(fs.readFileSync(from, 'utf8'), BASE);
      events.push('backup');
      originalRename(from, to);
      fs.writeFileSync(fixture.path, external);
      return;
    }
    events.push('replace');
    return originalRename(from, to);
  });
  fixture.error(() => fixture.apply(), 409, 'REVISION_CONFLICT');
  mock.mock.restore();
  assert.equal(fixture.text(), external);
  assert.equal(events.includes('replace'), false);
  assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
  fixture.clean();
});

test('undo also checks for external edits immediately before replacement', (t) => {
  const fixture = new Fixture(t);
  const applied = fixture.apply();
  const originalRename = fs.renameSync;
  const external = '{"echo":{"command":"node","args":["edited"]}}';
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    originalRename(from, to);
    if (to === `${fixture.path}.bak`) {
      fs.writeFileSync(fixture.path, external);
    }
  });
  fixture.error(() => fixture.undo(applied), 409, 'REVISION_CONFLICT');
  mock.mock.restore();
  assert.equal(fixture.text(), external);
  fixture.clean();
});

test('transactions use exclusive same-directory files and preserve config and backup permissions', (t) => {
  const fixture = new Fixture(t);
  if (process.platform !== 'win32') {
    fs.chmodSync(fixture.path, 0o640);
  }
  const permissions = fs.statSync(fixture.path);
  const originalOpen = fs.openSync;
  const originalRename = fs.renameSync;
  const originalWrite = fs.writeFileSync;
  const creations = [];
  const writes = [];
  t.mock.method(fs, 'openSync', (path, flags, mode) => {
    if (flags === 'wx') {
      assert.equal(dirname(path), fixture.dir);
      assert.equal(mode, 0o600);
      creations.push(path);
    }
    return originalOpen(path, flags, mode);
  });
  t.mock.method(fs, 'writeFileSync', (path, ...args) => {
    assert.equal(typeof path, 'number');
    writes.push(path);
    return originalWrite(path, ...args);
  });
  t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === fixture.path) {
      assert.equal(fs.readFileSync(`${fixture.path}.bak`, 'utf8'), BASE);
      assert.equal(fixture.text(), BASE);
    }
    return originalRename(from, to);
  });
  fixture.apply();
  assert.equal(creations.length, 2);
  assert.equal(writes.length, 2);
  for (const path of [fixture.path, `${fixture.path}.bak`]) {
    const actual = fs.statSync(path);
    assert.equal(actual.mode, permissions.mode);
    assert.equal(actual.uid, permissions.uid);
    assert.equal(actual.gid, permissions.gid);
  }
  fixture.clean();
});

test('Windows restrictive DACL, owner and group survive apply, backup and undo', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  const [expected] = fixture.windowsAcl(true);
  const applied = fixture.apply();
  assert.deepEqual(fixture.windowsAcl(), [expected, expected]);
  fixture.undo(applied);
  assert.deepEqual(fixture.windowsAcl(), [expected, expected]);
  fixture.clean();
});

test('permission-copy failure writes no source data and leaves no temporary files', (t) => {
  const fixture = new Fixture(t);
  const target = process.platform === 'win32' ? childProcess : fs;
  const method = process.platform === 'win32' ? 'spawnSync' : 'fchmodSync';
  const mock = t.mock.method(target, method, () => {
    throw new Error('SECRET_PATH secret-value');
  });
  fixture.error(() => fixture.apply(), 500, 'IO_ERROR');
  mock.mock.restore();
  fixture.unchanged();
});

test('a same-content file replacement during staging still conflicts', (t) => {
  const fixture = new Fixture(t);
  const replacement = join(fixture.dir, 'editor.json');
  fs.writeFileSync(replacement, BASE);
  const originalSync = fs.fsyncSync;
  let replaced = false;
  t.mock.method(fs, 'fsyncSync', (fd) => {
    originalSync(fd);
    if (!replaced) {
      fs.renameSync(replacement, fixture.path);
      replaced = true;
    }
  });
  fixture.error(() => fixture.apply(), 409, 'REVISION_CONFLICT');
  fixture.unchanged();
});

for (const action of ['apply', 'undo']) {
  test(`Windows ${action} accepts a real access-time refresh without changing config identity or permissions`, {
    skip: process.platform !== 'win32',
  }, (t) => {
    const fixture = new Fixture(t);
    if (!fixture.auditAvailable()) {
      t.skip('Full audit state is not readable under this account');
      return;
    }
    const applied = action === 'undo' ? fixture.apply() : null;
    const original = fixture.bytes();
    const [acl] = fixture.windowsAcl();
    const originalSync = fs.fsyncSync;
    let refreshed = false;
    t.mock.method(fs, 'fsyncSync', (fd) => {
      originalSync(fd);
      if (refreshed) return;
      refreshed = true;
      const before = fs.statSync(fixture.path);
      fixture.windowsCommand(`
$ErrorActionPreference = 'Stop'
[System.IO.File]::SetLastAccessTimeUtc($env:MCP_POOL_SOURCE, [DateTime]::UtcNow)
`);
      const after = fs.statSync(fixture.path);
      assert.notEqual(after.ctimeMs, before.ctimeMs, 'the real filesystem must report the metadata change');
      for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeMs']) {
        assert.equal(after[key], before[key], `${key} must remain unchanged`);
      }
      assert.deepEqual(fixture.bytes(), original);
      assert.equal(fixture.windowsAcl()[0], acl);
    });
    let result;
    assert.doesNotThrow(() => {
      result = action === 'apply' ? fixture.apply() : fixture.undo(applied);
    }, 'access-time metadata alone must not produce a configuration conflict');
    assert.equal(refreshed, true);
    assert.equal(result.ok, true);
    assert.deepEqual(fixture.windowsAcl(), [acl, acl]);
    if (action === 'undo') assert.equal(fixture.text(), BASE);
    else assert.equal(JSON.parse(fixture.text()).echo.sharing, 'pool');
    fixture.clean();
  });
}

for (const stage of ['before-copy', 'after-copy', 'after-backup']) {
  test(`Windows ACL change ${stage} still conflicts and preserves the changed permissions`, {
    skip: process.platform !== 'win32',
  }, (t) => {
    const fixture = new Fixture(t);
    const originalBytes = fixture.bytes();
    const originalAcl = fixture.windowsAcl()[0];
    let changedAcl;
    let changed = false;
    const mutate = () => {
      if (changed) return;
      changed = true;
      [changedAcl] = fixture.windowsAcl(true);
      assert.notEqual(changedAcl, originalAcl);
    };
    const method = stage === 'before-copy' ? 'openSync' : stage === 'after-copy' ? 'fsyncSync' : 'renameSync';
    const original = fs[method];
    t.mock.method(fs, method, (...args) => {
      const result = original(...args);
      const trigger = stage === 'before-copy' ? args[1] === 'wx'
        : stage === 'after-copy' || args[1] === `${fixture.path}.bak`;
      if (trigger) mutate();
      return result;
    });
    fixture.error(() => fixture.apply(), 409, 'REVISION_CONFLICT');
    assert.equal(changed, true);
    assert.deepEqual(fixture.bytes(), originalBytes);
    assert.equal(fixture.windowsAcl()[0], changedAcl);
    fixture.clean();
  });
}

test('Windows file attribute changes during staging still conflict', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  let changed = false;
  const originalSync = fs.fsyncSync;
  t.mock.method(fs, 'fsyncSync', (fd) => {
    originalSync(fd);
    if (changed) return;
    changed = true;
    fixture.windowsCommand(`
$ErrorActionPreference = 'Stop'
$attributes = [System.IO.File]::GetAttributes($env:MCP_POOL_SOURCE)
[System.IO.File]::SetAttributes($env:MCP_POOL_SOURCE, $attributes -bor [System.IO.FileAttributes]::Hidden)
`);
  });
  fixture.error(() => fixture.apply(), 409, 'REVISION_CONFLICT');
  assert.equal(changed, true);
  fixture.unchanged();
});

for (const action of ['apply', 'undo']) {
  test(`Windows ${action} rejects a concurrent audit-policy change without discarding it`, {
    skip: process.platform !== 'win32',
  }, (t) => {
    const fixture = new Fixture(t);
    if (!fixture.auditAvailable()) {
      t.skip('Audit-rule changes are not authorized under this account');
      return;
    }
    const applied = action === 'undo' ? fixture.apply() : null;
    const originalBytes = fixture.bytes();
    const originalAcl = fixture.windowsAcl()[0];
    const originalAudit = fixture.windowsAudit();
    let audit;
    let changed = false;
    const originalSync = fs.fsyncSync;
    t.mock.method(fs, 'fsyncSync', (fd) => {
      originalSync(fd);
      if (changed) return;
      changed = true;
      audit = fixture.windowsAudit(true);
      assert.notEqual(audit, originalAudit);
      assert.equal(fixture.windowsAcl()[0], originalAcl, 'DACL, owner and group do not expose this change');
    });
    fixture.error(() => action === 'apply' ? fixture.apply() : fixture.undo(applied), 409, 'REVISION_CONFLICT');
    assert.equal(changed, true);
    assert.deepEqual(fixture.bytes(), originalBytes);
    assert.equal(fixture.windowsAudit(), audit);
    fixture.clean();
  });
}

test('Windows refuses unreadable audit policy before staging any config data', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  fixture.denyAuditInspection(t);
  const originalOpen = fs.openSync;
  let staged = false;
  t.mock.method(fs, 'openSync', (...args) => {
    if (args[1] === 'wx') staged = true;
    return originalOpen(...args);
  });
  assert.throws(() => fixture.apply(), (error) => {
    assert.equal(error.statusCode, 403);
    assert.equal(error.code, 'SECURITY_UNAVAILABLE');
    return true;
  });
  assert.equal(staged, false);
  fixture.unchanged();
});

for (const action of ['apply', 'undo']) {
  test(`Windows partial inspection cannot let ${action} drop an existing explicit audit rule`, {
    skip: process.platform !== 'win32',
  }, (t) => {
    const fixture = new Fixture(t);
    if (!fixture.auditAvailable()) {
      t.skip('Audit fixture creation requires assigned audit rights');
      return;
    }
    fixture.inheritAuditPolicy();
    const applied = action === 'undo' ? fixture.apply() : null;
    const audit = fixture.windowsAudit(true, true);
    const bytes = fixture.bytes();
    const backupExists = fs.existsSync(`${fixture.path}.bak`);
    const backup = backupExists ? fs.readFileSync(`${fixture.path}.bak`) : null;
    const backupAcl = backupExists ? fixture.windowsAcl()[1] : null;
    fixture.denyAuditInspection(t);
    fixture.error(() => action === 'apply' ? fixture.apply() : fixture.undo(applied), 403, 'SECURITY_UNAVAILABLE');
    assert.deepEqual(fixture.bytes(), bytes);
    assert.equal(fixture.windowsAudit(), audit);
    assert.equal(fs.existsSync(`${fixture.path}.bak`), backupExists);
    if (backupExists) {
      assert.deepEqual(fs.readFileSync(`${fixture.path}.bak`), backup);
      assert.equal(fixture.windowsAcl()[1], backupAcl);
    }
    fixture.clean();
  });
}

test('Windows refuses to replace an existing audit policy that staging cannot preserve', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  if (!fixture.auditAvailable()) {
    t.skip('Audit-rule changes are not authorized under this account');
    return;
  }
  const audit = fixture.windowsAudit(true);
  fixture.error(() => fixture.apply(), 500, 'IO_ERROR');
  assert.equal(fixture.windowsAudit(), audit);
  fixture.unchanged();
});

test('Windows rejects an integrity-label change that leaves the DACL unchanged', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  if (!fixture.auditAvailable()) {
    t.skip('This integrity-label fixture requires the assigned administrative test rights');
    return;
  }
  fs.unlinkSync(fixture.path);
  fixture.windowsCommand(`
$ErrorActionPreference = 'Stop'
$directory = [System.IO.Path]::GetDirectoryName($env:MCP_POOL_SOURCE)
$output = & icacls.exe $directory /setintegritylevel '(OI)(CI)H'
if ($LASTEXITCODE -ne 0) { throw "Fixture integrity setup failed: $output" }
`);
  fs.writeFileSync(fixture.path, BASE);
  const originalAcl = fixture.windowsAcl()[0];
  let changed = false;
  const originalSync = fs.fsyncSync;
  t.mock.method(fs, 'fsyncSync', (fd) => {
    originalSync(fd);
    if (changed) return;
    changed = true;
    fixture.windowsCommand(`
$output = & icacls.exe $env:MCP_POOL_SOURCE /setintegritylevel M
if ($LASTEXITCODE -ne 0) { throw "Fixture integrity update failed: $output" }
`);
    assert.equal(fixture.windowsAcl()[0], originalAcl);
  });
  fixture.error(() => fixture.apply(), 409, 'REVISION_CONFLICT');
  assert.equal(changed, true);
  fixture.unchanged();
});

for (const fields of [['ctimeMs'], ['mode'], ['uid', 'gid']]) {
  test(`metadata conflicts report exactly ${fields.join(', ')} without weakening the guard`, {
    skip: process.platform === 'win32' && fields.includes('ctimeMs'),
  }, (t) => {
    const fixture = new Fixture(t);
    const revision = fixture.store.revision();
    const sourceStat = fs.statSync(fixture.path);
    const originalStat = fs.fstatSync;
    const originalOpen = fs.openSync;
    let staging = false;
    t.mock.method(fs, 'openSync', (...args) => {
      const fd = originalOpen(...args);
      if (args[1] === 'wx') staging = true;
      return fd;
    });
    const mock = t.mock.method(fs, 'fstatSync', (...args) => {
      const stat = originalStat(...args);
      if (stat.dev === sourceStat.dev &&
          stat.ino === sourceStat.ino) {
        if (staging) {
          for (const field of fields) {
            stat[field]++;
          }
        }
      }
      return stat;
    });
    assert.throws(() => fixture.store.apply({ name: 'echo', mode: 'pool', revision }), (error) => {
      assert.ok(error instanceof PoolingConfigError);
      assert.equal(error.statusCode, 409);
      assert.equal(error.code, 'REVISION_CONFLICT');
      assert.equal(error.message,
        `Config file or permissions changed (${fields.join(', ')}). Reread the config.`);
      return true;
    });
    mock.mock.restore();
    fixture.unchanged();
  });
}

for (const operation of [
  'openSync', 'secondOpen', 'writeFileSync', 'backupWrite',
  'fsyncSync', 'closeSync', 'renameBackup', 'renameConfig',
]) {
  test(`disk failure at ${operation} is explicit, preserves source, and cleans temporary files`, (t) => {
    const fixture = new Fixture(t);
    const revision = fixture.store.revision();
    const method = {
      secondOpen: 'openSync', backupWrite: 'writeFileSync',
      renameBackup: 'renameSync', renameConfig: 'renameSync',
    }[operation] ?? operation;
    const original = fs[method];
    let failed = false;
    let stageOpened = false;
    let calls = 0;
    const originalOpen = fs.openSync;
    if (method !== 'openSync') {
      t.mock.method(fs, 'openSync', (...args) => {
        const fd = originalOpen(...args);
        if (args[1] === 'wx') {
          stageOpened = true;
        }
        return fd;
      });
    }
    const mock = t.mock.method(fs, method, (...args) => {
      let atFailure = true;
      if (method === 'openSync') {
        atFailure = args[1] === 'wx';
        if (atFailure) {
          calls++;
          atFailure = operation !== 'secondOpen' || calls === 2;
        }
      } else if (operation === 'backupWrite') {
        atFailure = ++calls === 2;
      } else if (method === 'closeSync') {
        atFailure = stageOpened;
      } else if (operation === 'renameBackup') {
        atFailure = args[1] === `${fixture.path}.bak`;
      } else if (operation === 'renameConfig') {
        atFailure = args[1] === fixture.path;
      }
      if (!failed &&
          atFailure) {
        failed = true;
        throw Object.assign(new Error('SECRET_PATH secret-value'), { code: 'EACCES' });
      }
      return original(...args);
    });
    fixture.error(() => fixture.store.apply({ name: 'echo', mode: 'pool', revision }), 500, 'IO_ERROR');
    mock.mock.restore();
    assert.equal(failed, true);
    assert.equal(fixture.text(), BASE);
    fixture.clean();
    assert.match(fixture.apply().undoId, /^[0-9a-f-]{36}$/);
  });
}

test('unwritable backup destination fails before replacing config', (t) => {
  const fixture = new Fixture(t);
  fs.mkdirSync(`${fixture.path}.bak`);
  fixture.error(() => fixture.apply(), 500, 'IO_ERROR');
  assert.equal(fixture.text(), BASE);
  fixture.clean();
});

test('stale writes reject before starting permission inspection', (t) => {
  const fixture = new Fixture(t);
  const revision = fixture.store.revision();
  const applied = fixture.apply();
  fs.writeFileSync(fixture.path, fixture.text() + '\n');
  const mock = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('Permission inspection must not start for stale content');
  });
  fixture.error(() => fixture.store.apply({ name: 'echo', mode: 'pool', revision }), 409, 'REVISION_CONFLICT');
  fixture.error(() => fixture.undo(applied), 409, 'REVISION_CONFLICT');
  assert.equal(mock.mock.callCount(), 0);
});

test('Windows unreadable security fingerprints fail before staging any config data', {
  skip: process.platform !== 'win32',
}, (t) => {
  const fixture = new Fixture(t);
  t.mock.method(childProcess, 'spawnSync', () => ({ status: 0, stdout: 'invalid', stderr: '' }));
  fixture.error(() => fixture.apply(), 500, 'IO_ERROR');
  fixture.unchanged();
});

test('read errors do not leak paths or raw filesystem messages', (t) => {
  const fixture = new Fixture(t);
  const mock = t.mock.method(fs, 'readFileSync', () => {
    throw Object.assign(new Error('SECRET_PATH secret-value'), { code: 'EACCES' });
  });
  fixture.error(() => fixture.store.snapshot(), 500, 'IO_ERROR');
  mock.mock.restore();
  fixture.unchanged();
});

test('failed undo keeps its token for a safe retry', (t) => {
  const fixture = new Fixture(t);
  const applied = fixture.apply();
  const bytes = fixture.bytes();
  const originalRename = fs.renameSync;
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === fixture.path) {
      throw new Error('SECRET_PATH secret-value');
    }
    return originalRename(from, to);
  });
  fixture.error(() => fixture.undo(applied), 500, 'IO_ERROR');
  mock.mock.restore();
  assert.deepEqual(fixture.bytes(), bytes);
  fixture.clean();
  fixture.undo(applied);
  assert.equal(fixture.text(), BASE);
});

test('undo restores legacy bytes without returning absent or unsafe minWarm values', (t) => {
  const fixture = new Fixture(t);
  for (const minWarm of [undefined, null, 'secret-value', { token: 'secret-value' }, 0, MAX_MIN_WARM + 1]) {
    const text = JSON.stringify({ echo: { command: 'node', sharing: 'pool', minWarm } });
    fs.writeFileSync(fixture.path, text);
    const disabled = fixture.apply({ mode: 'isolated' });
    const restored = fixture.undo(disabled);
    assert.equal(fixture.text(), text);
    assert.deepEqual(restored, {
      ok: true, name: 'echo', mode: 'pool', revision: fixture.hash(Buffer.from(text)),
    });
    assert.doesNotMatch(JSON.stringify(restored), /secret-value|token|command/);
  }
  fixture.clean();
});

test('regression proofs fail when guards or byte preservation are removed in disposable copies', (t) => {
  const fixture = new Fixture(t);
  const source = fs.readFileSync(new URL('../bin/pooling-config.mjs', import.meta.url), 'utf8')
    .replaceAll('\r\n', '\n');
  const tests = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const mutations = [
    {
      name: 'revision guard',
      from: 'if (actual !== expected) {',
      to: 'if (false) {',
      filter: '^stale apply must not overwrite',
    },
    {
      name: 'byte preservation',
      from: 'return Buffer.from(text);',
      to: 'return Buffer.from(JSON.stringify(JSON.parse(text)));',
      filter: '^byte preservation: pretty CRLF',
    },
    {
      name: 'extra-key guard',
      from: '!allowed.includes(key) ||',
      to: 'false ||',
      filter: '^extra keys reject arbitrary',
    },
    {
      name: 'last revision check',
      from: "this.#checkCurrent(current);\n      fs.renameSync(files[0].path, this.#configPath);",
      to: "fs.renameSync(files[0].path, this.#configPath);",
      filter: '^backup is flushed before replacement',
    },
    {
      name: 'safe result fields',
      from: 'if (hasSafeMinWarm) {',
      to: "if (state.mode === 'pool') {",
      filter: '^undo restores legacy bytes',
    },
    {
      name: 'metadata conflict diagnostic',
      from: "`Config file or permissions changed (${changedFields.join(', ')}). Reread the config.`",
      to: "'Config file or permissions changed. Reread the config.'",
      filter: '^metadata conflicts report exactly mode',
    },
  ];
  if (process.platform === 'win32') {
    mutations.push({
      name: 'Windows conservative audit fallback',
      from: "if (process.platform === 'win32' &&\n        !current.security.startsWith('F:')) {",
      to: 'if (false) {',
      filter: '^Windows refuses unreadable audit policy before staging',
    });
  }
  if (process.platform === 'win32' &&
      fixture.auditAvailable()) {
    mutations.push(
      {
        name: 'Windows metadata tolerance',
        from: 'security !== expected.security',
        to: 'true',
        filter: '^Windows apply accepts a real access-time',
      },
      {
        name: 'Windows security conflict protection',
        from: 'security !== expected.security',
        to: 'false',
        filter: '^Windows ACL change after-copy',
      },
    );
  }
  for (const [index, mutation] of mutations.entries()) {
    assert.equal(source.split(mutation.from).length, 2, `${mutation.name} must target exactly one source span`);
    const root = join(fixture.dir, String(index));
    fs.mkdirSync(join(root, 'bin'), { recursive: true });
    fs.mkdirSync(join(root, 'test'));
    fs.writeFileSync(join(root, 'bin', 'pooling-config.mjs'), source.replace(mutation.from, mutation.to));
    const testPath = join(root, 'test', 'pooling-config.test.mjs');
    fs.writeFileSync(testPath, tests);
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ['--test', '--test-name-pattern', mutation.filter, testPath], {
      encoding: 'utf8', timeout: 30000, windowsHide: true, env,
    });
    assert.equal(result.error, undefined, `${mutation.name}: child must run normally`);
    assert.equal(result.status, 1, `${mutation.name}: regression must fail, not pass or crash\n${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /ERR_ASSERTION|AssertionError/);
    t.diagnostic(`${mutation.name}: isolated broken copy fails the targeted regression (exit 1)`);
  }
});
