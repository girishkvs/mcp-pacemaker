import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

export const originalBytes = Buffer.from('{"private":"synthetic-secret","minWarm":0}\n');
export const editedBytes = Buffer.from('{"private":"synthetic-secret","minWarm":2}\n');

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function expected(descriptor) {
  const { identity, revision, security } = descriptor;
  return { identity, revision, security };
}

export class NativeFixture {
  constructor(helper, directory) {
    this.helper = helper;
    this.directory = directory;
    this.source = join(directory, 'active.json');
    this.candidate = join(directory, 'candidate.json');
    this.previous = join(directory, 'previous.json');
  }

  run(action, source = this.source, destination = this.candidate, input) {
    const result = spawnSync(this.helper, [action], {
      windowsHide: true,
      encoding: 'utf8',
      timeout: 10000,
      input: Buffer.isBuffer(input) ? input : JSON.stringify(input),
      env: { ...process.env, MCP_POOL_SOURCE: source, MCP_POOL_TEMP: destination },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    for (const secret of [source, destination, 'synthetic-secret']) {
      assert.equal(result.stdout.includes(secret), false);
      assert.equal(result.stderr.includes(secret), false);
    }
    return result;
  }

  success(result, bytes) {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const descriptor = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(descriptor).sort(), ['identity', 'revision', 'security', 'size']);
    assert.equal(typeof descriptor.identity, 'string');
    assert.equal(descriptor.identity.split(':').length, 2);
    for (const key of ['revision', 'security']) {
      const hash = Buffer.from(descriptor[key], 'hex');
      assert.equal(hash.length, 32);
      assert.equal(hash.toString('hex'), descriptor[key]);
    }
    if (bytes !== undefined) {
      assert.equal(descriptor.revision, digest(bytes));
      assert.equal(descriptor.size, bytes.length);
    }
    return descriptor;
  }

  inspect(path = this.source) {
    return this.success(this.run('inspect-access', path), fs.readFileSync(path));
  }

  stage(descriptor, bytes = editedBytes, destination = this.candidate) {
    return this.run('stage', this.source, destination, {
      expected: expected(descriptor), bytes: bytes.toString('base64'),
    });
  }

  move(source, destination, descriptor) {
    return this.run('move-no-replace', source, destination, { expected: expected(descriptor) });
  }

  failure(result, status, type, nativeError) {
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout, '');
    const lines = result.stderr.trim().split('\n').map((line) => line.trim());
    const wanted = [`MCPERR type=${type}`];
    if (nativeError !== undefined) wanted.push(`MCPERR nativeError=${nativeError}`);
    assert.deepEqual(lines, wanted);
  }
}
