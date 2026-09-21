import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, lstatSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LocalGitConfig } from './local-git.mjs';
import { physical, safeName } from './local-inputs.mjs';
import { localHash, localCommitment } from './local-regression.mjs';

export function treeEntries(output) {
  assert.equal(typeof output, 'string');
  const rows = output.split('\0');
  assert.equal(rows.pop(), '', 'Incomplete Git tree inventory');
  const seen = new Set();
  const entries = rows.map(row => {
    assert.ok(row.indexOf('\t') === 52 &&
      row.slice(6, 12) === ' blob ', 'Only regular committed files are supported');
    const mode = row.slice(0, 6);
    const blob = row.slice(12, 52);
    const path = row.slice(53);
    assert.ok(blob.length === 40 &&
      [...blob].every(character => '0123456789abcdef'.includes(character)), 'Invalid Git blob identity');
    assert.ok(['100644', '100755'].includes(mode), 'Linked or special committed input');
    safeName(path);
    assert.equal(seen.has(path.toLowerCase()), false, 'Case-colliding committed source');
    seen.add(path.toLowerCase());
    return { path, mode, blob };
  });
  assert.ok(entries.length > 0 &&
    entries.length <= 10_000);
  return entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

export function captureSourceIdentity(root, git, { requireClean = false } = {}) {
  physical(root);
  const head = git(['rev-parse', 'HEAD']).trim();
  const tree = git(['rev-parse', 'HEAD^{tree}']).trim();
  const clean = git(['status', '--porcelain=v1', '--untracked-files=all']).trim() === '';
  if (requireClean) assert.equal(clean, true, 'Local evidence requires clean final source HEADs');
  const entries = treeEntries(git(['ls-tree', '-rz', '--full-tree', 'HEAD']));
  const names = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'])
    .split('\0').filter(name => name &&
      existsSync(join(root, name))).sort();
  if (clean) assert.deepEqual(names, entries.map(item => item.path));
  let total = 0;
  const files = names.map(path => {
    safeName(path);
    const file = physical(join(root, path));
    const stat = lstatSync(file);
    assert.ok(stat.isFile() &&
      stat.nlink === 1 &&
      stat.size <= 128 * 1024 ** 2, 'Linked, special or oversized source');
    total += stat.size;
    assert.ok(total <= 512 * 1024 ** 2);
    const bytes = readFileSync(file);
    assert.equal(bytes.length, stat.size);
    return { path, size: bytes.length, sha256: localHash(bytes) };
  });
  if (clean) {
    assert.equal(existsSync(join(root, '.git/info/attributes')), false,
      'Uncommitted Git attribute overrides cannot bind publication source');
    for (const entry of entries) {
      const attributes = git(['check-attr', '--source=HEAD', '-z', 'filter', 'working-tree-encoding', '--', entry.path]).split('\0');
      assert.deepEqual(attributes, [entry.path, 'filter', 'unspecified',
        entry.path, 'working-tree-encoding', 'unspecified', ''],
      'Unreviewed source conversion; do not run a filter or normalize bytes by guesswork');
      assert.equal(git(['hash-object', `--path=${entry.path}`, '--', entry.path]).trim(), entry.blob,
        'Checkout bytes do not clean to the exact committed blob');
    }
  }
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  assert.equal(git(['rev-parse', 'HEAD']).trim(), head, 'Source HEAD changed during identity read');
  assert.equal(git(['rev-parse', 'HEAD^{tree}']).trim(), tree);
  assert.equal(git(['status', '--porcelain=v1', '--untracked-files=all']).trim() === '', clean);
  return { schemaVersion: 1, version, head, tree, clean, entries, files };
}

export function validateSourceSubject(identity, statement) {
  assert.equal(identity.schemaVersion, 1);
  assert.equal(identity.clean, true, 'Dirty regression output is not release-applicable');
  const subject = statement.subjects.find(item => item.version === identity.version);
  assert.ok(subject);
  assert.equal(identity.head, subject.commit);
  assert.equal(identity.tree, subject.tree);
  assert.equal(localCommitment(identity.entries), subject.treeEntriesSha256);
  return subject;
}

export class LocalSourceReader {
  constructor(root, gitExecutable = 'git') {
    this.root = physical(root);
    this.executable = gitExecutable === 'git' ? gitExecutable : physical(gitExecutable);
    this.env = {};
    for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
      if (process.env[key]) this.env[key] = process.env[key];
    }
    Object.assign(this.env, { GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never' });
  }

  execute(args, binary = false) {
    const result = spawnSync(this.executable, ['--no-optional-locks', ...args], {
      cwd: this.root, env: this.env, encoding: binary ? null : 'utf8', shell: false, windowsHide: true,
      timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(result.error, undefined, 'Local source Git operation failed');
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, 'Local source Git operation rejected');
    return result.stdout;
  }

  git(args, binary = false) {
    const config = new LocalGitConfig(this.root, realpathSync.native(tmpdir()),
      options => this.execute(options));
    try {
      return this.execute([...config.options(), '-c', 'core.autocrlf=false',
        '-c', 'core.hooksPath=', '-c', 'credential.helper=', '-c', 'core.fsmonitor=false',
        '-c', 'core.attributesFile=', '-C', this.root, ...args], binary);
    } finally { config.verify(); }
  }

  capture() {
    return captureSourceIdentity(this.root, args => this.git(args), { requireClean: true });
  }
}
