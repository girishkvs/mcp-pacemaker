import assert from 'node:assert/strict';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { physical, sha256 } from './local-inputs.mjs';

const SECTIONS = new Set(['include', 'includeif', 'filter', 'alias', 'diff', 'merge']);
const KEYS = new Set([
  'core.worktree', 'extensions.worktreeconfig', 'core.sshcommand', 'core.gitproxy',
  'core.hookspath', 'core.fsmonitor', 'core.attributesfile',
]);

export class LocalGitConfig {
  constructor(root, scratch, run) {
    this.root = physical(root);
    this.path = join(this.root, '.git/config');
    const directory = join(this.root, '.git');
    if (!existsSync(directory)) return;
    physical(directory);
    assert.ok(lstatSync(directory).isDirectory(), 'A real isolated Git directory is required');
    this.bytes = this.read();
    // Parse only this bounded file from a private non-repository directory, without following includes.
    const output = run(['-C', physical(scratch), '-c', 'extensions.worktreeConfig=false',
      'config', '--no-includes', '--null', '--name-only', '--file', this.path, '--list']);
    this.verify();
    assert.equal(typeof output, 'string');
    assert.ok(output.length <= 1024 * 1024, 'Git configuration key output exceeds its bound');
    const keys = output.split('\0');
    assert.equal(keys.pop(), '', 'Incomplete Git configuration key output');
    for (const key of keys) {
      assert.ok(key.length > 0, 'Empty Git configuration key');
      const normalized = key.toLowerCase();
      const section = normalized.slice(0, normalized.indexOf('.'));
      assert.ok(!SECTIONS.has(section) &&
        !KEYS.has(normalized), `Inherited executable Git configuration is not allowed: ${key}`);
    }
  }

  read() {
    physical(this.path);
    const info = lstatSync(this.path);
    assert.ok(info.isFile() &&
      info.size <= 128 * 1024, 'Linked, special or oversized Git configuration');
    const bytes = readFileSync(this.path);
    assert.equal(bytes.length, info.size, 'Git configuration changed while reading');
    return bytes;
  }

  verify() {
    if (this.bytes) {
      assert.equal(sha256(this.read()), sha256(this.bytes), 'Git configuration changed during command');
    }
  }

  options() {
    return ['-c', `core.worktree=${this.root}`, '-c', 'extensions.worktreeConfig=false'];
  }
}
