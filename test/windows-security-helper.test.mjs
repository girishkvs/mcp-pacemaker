import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HELPER_ROOT = join(ROOT, 'bin', 'windows');
const HELPER = join(HELPER_ROOT, 'PoolingSecurityHelper.exe');
const SOURCES = ['AssemblyInfo.cs', 'PoolingSecurityHelper.cs', 'PoolingSecurityReader.cs'];
const WINDOWS = { skip: process.platform !== 'win32' };

test('packaged helper binary and normalized build inputs match recorded hashes', () => {
  const metadata = JSON.parse(fs.readFileSync(join(HELPER_ROOT, 'PoolingSecurityHelper.build.json'), 'utf8'));
  assert.equal(metadata.schemaVersion, 1);
  assert.equal(metadata.binary, 'PoolingSecurityHelper.exe');
  assert.equal(metadata.inputs.targetFramework, '.NETFramework,Version=v4.6.2');
  assert.equal(metadata.inputs.platform, 'AnyCPU');
  assert.deepEqual(Object.keys(metadata.inputs.sourceSha256).sort(), SOURCES);
  assert.equal(createHash('sha256').update(fs.readFileSync(HELPER)).digest('hex'), metadata.binarySha256);

  const inputs = SOURCES.map((name) => [
    join(HELPER_ROOT, 'src', name), metadata.inputs.sourceSha256[name],
  ]);
  inputs.push([
    join(ROOT, 'tools', 'windows-security-helper', 'build.ps1'), metadata.inputs.buildScriptSha256,
  ]);
  for (const [path, expected] of inputs) {
    const source = fs.readFileSync(path, 'utf8').replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    assert.equal(createHash('sha256').update(source).digest('hex'), expected, path);
  }
});

test('helper asset directory contains only the production executable, metadata and source', () => {
  assert.deepEqual(fs.readdirSync(HELPER_ROOT).sort(), [
    'PoolingSecurityHelper.build.json', 'PoolingSecurityHelper.exe', 'src',
  ]);
  assert.deepEqual(fs.readdirSync(join(HELPER_ROOT, 'src')).sort(), SOURCES);
});

class HelperFixture {
  constructor(t) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'mcp-helper-'));
    this.source = join(this.dir, 'private-config.json');
    this.temp = join(this.dir, 'replacement.tmp');
    this.backup = join(this.dir, 'backup.tmp');
    t.after(() => fs.rmSync(this.dir, { recursive: true, force: true }));
    fs.writeFileSync(this.source, '{"private":"secret-value"}\n', { mode: 0o600 });
    fs.writeFileSync(this.temp, '', { mode: 0o600 });
    fs.writeFileSync(this.backup, '', { mode: 0o600 });
  }

  run(args, environment = {}) {
    const result = spawnSync(HELPER, args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: 10000,
      env: {
        ...process.env,
        MCP_POOL_SOURCE: this.source,
        MCP_POOL_TEMP: this.temp,
        MCP_POOL_BACKUP: this.backup,
        ...environment,
      },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    return result;
  }

  inspect(path = this.source) {
    const result = this.run(['inspect'], { MCP_POOL_SOURCE: path });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const fingerprint = result.stdout.trim();
    assert.equal(fingerprint.length, 46);
    assert.ok(fingerprint.startsWith('F:') || fingerprint.startsWith('P:'));
    const hash = Buffer.from(fingerprint.slice(2), 'base64');
    assert.equal(hash.length, 32);
    assert.equal(hash.toString('base64'), fingerprint.slice(2));
    return fingerprint;
  }

  unchanged() {
    assert.equal(fs.readFileSync(this.source, 'utf8'), '{"private":"secret-value"}\n');
    assert.equal(fs.readFileSync(this.temp, 'utf8'), '');
    assert.equal(fs.readFileSync(this.backup, 'utf8'), '');
  }
}

test('real helper inspection emits only one fingerprint and does not change file contents', WINDOWS, (t) => {
  const fixture = new HelperFixture(t);
  fixture.inspect();
  fixture.unchanged();
});

test('real helper prepares both files with matching security without writing config data', WINDOWS, (t) => {
  const fixture = new HelperFixture(t);
  const fingerprint = fixture.inspect();
  const result = fixture.run(['copy'], { MCP_POOL_SECURITY: fingerprint });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  assert.equal(fixture.inspect(fixture.temp), fingerprint);
  assert.equal(fixture.inspect(fixture.backup), fingerprint);
  assert.equal(fixture.inspect(), fingerprint);
  fixture.unchanged();
});

test('real helper refuses a stale fingerprint without writing config data', WINDOWS, (t) => {
  const fixture = new HelperFixture(t);
  const stale = `F:${Buffer.alloc(32).toString('base64')}`;
  assert.notEqual(fixture.inspect(), stale);
  const result = fixture.run(['copy'], { MCP_POOL_SECURITY: stale });
  assert.equal(result.status, 3);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  fixture.unchanged();
});

test('missing helper source reports failure without exposing paths or content', WINDOWS, (t) => {
  const fixture = new HelperFixture(t);
  const result = fixture.run(['inspect'], { MCP_POOL_SOURCE: join(fixture.dir, 'missing-private.json') });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.ok(result.stderr.startsWith('MCPERR type='));
  for (const sensitive of [fixture.dir, 'missing-private.json', 'secret-value']) {
    assert.equal(result.stderr.includes(sensitive), false);
  }
  fixture.unchanged();
});

for (const args of [[], ['unknown'], ['inspect', 'extra']]) {
  test(`helper rejects invalid action ${JSON.stringify(args)}`, WINDOWS, (t) => {
    const fixture = new HelperFixture(t);
    const result = fixture.run(args);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'MCPERR type=ArgumentException');
    fixture.unchanged();
  });
}
