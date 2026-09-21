import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

export class PackagedCheckoutFixture {
  constructor(t, source, attributes = readFileSync(join(source, '.gitattributes'))) {
    this.source = source;
    this.base = realpathSync.native(mkdtempSync(join(tmpdir(), 'canonical-package-')));
    t.after(() => rmSync(this.base, { recursive: true, force: true }));
    this.root = join(this.base, 'seed');
    this.empty = join(this.base, 'empty');
    mkdirSync(this.root);
    mkdirSync(this.empty);
    this.commands = [];
    this.env = {};
    for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
      if (process.env[key]) this.env[key] = process.env[key];
    }
    Object.assign(this.env, { HOME: this.empty, USERPROFILE: this.empty,
      GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never',
      GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' });
    this.pkg = JSON.parse(readFileSync(join(source, 'package.json')));
    const paths = new Set(['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md']);
    for (const name of this.pkg.files) {
      if (name.endsWith('/')) {
        for (const path of this.filesUnder(source, name.slice(0, -1))) paths.add(path);
      } else paths.add(name);
    }
    this.paths = [...paths].sort();
    for (const path of this.paths) this.write(path, readFileSync(join(source, path)));
    this.write('.gitattributes', attributes);
    this.write('ui/index.html', readFileSync(join(source, 'ui/index.html')));
    for (const name of ['LICENSE', 'THIRD_PARTY_NOTICES.txt']) {
      this.write(`nested/${name}`, 'SYNTHETIC UNIT SUBDIRECTORY CONTROL\n');
    }
    this.git(['init', '--quiet', '--initial-branch=fixture']);
    this.git(['add', '--all', '--', '.']);
    this.git(['commit', '--quiet', '-m', 'Synthetic canonical package checkout fixture']);
  }

  filesUnder(root, directory) {
    return readdirSync(join(root, directory), { withFileTypes: true }).flatMap(entry => {
      const path = `${directory}/${entry.name}`;
      assert.equal(entry.isSymbolicLink(), false);
      if (entry.isDirectory()) return this.filesUnder(root, path);
      assert.ok(entry.isFile());
      return [path];
    });
  }

  write(path, bytes) {
    assert.ok(path.split('/').every(part => part &&
      part !== '.' &&
      part !== '..'));
    const target = join(this.root, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes, { flag: 'wx' });
  }

  git(args, root = this.root) {
    const argv = ['--no-pager', '--no-optional-locks',
      '-c', `core.hooksPath=${this.empty}`, '-c', `init.templateDir=${this.empty}`,
      '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', '-c', 'core.attributesFile=',
      '-c', 'core.fsmonitor=false', '-c', 'credential.helper=', '-c', 'commit.gpgsign=false',
      '-c', 'maintenance.auto=false', '-c', 'gc.auto=0',
      '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
      '-c', 'user.name=SYNTHETIC UNIT FIXTURE', '-c', 'user.email=synthetic@example.invalid', ...args];
    const started = Date.now();
    const result = spawnSync('git', argv, { cwd: root, env: this.env, shell: false,
      windowsHide: true, timeout: 30_000, maxBuffer: 4 * 1024 ** 2 });
    this.commands.push({ executable: 'git', args: argv, cwd: root, timeoutMs: 30_000,
      elapsedMs: Date.now() - started, exitCode: result.status, signal: result.signal,
      error: result.error?.code ?? null, encoding: 'base64',
      stdout: (result.stdout ?? Buffer.alloc(0)).toString('base64'),
      stderr: (result.stderr ?? Buffer.alloc(0)).toString('base64') });
    assert.equal(result.error, undefined, 'Real Git must be available on the sanitized PATH');
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr?.toString());
    return result.stdout;
  }

  checkout(name, autocrlf, eol) {
    const target = join(this.base, name);
    this.git(['clone', '--quiet', '--no-hardlinks', '--no-checkout', this.root, target]);
    this.git(['-c', `core.autocrlf=${autocrlf}`, '-c', `core.eol=${eol}`,
      'checkout', '--force', 'HEAD', '--', '.'], target);
    return target;
  }

  inventory(root) {
    return this.paths.map(path => {
      const target = join(root, path);
      assert.ok(lstatSync(target).isFile() &&
        !lstatSync(target).isSymbolicLink());
      const bytes = readFileSync(target);
      return { path, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    });
  }

  mismatches(frozen, checkout) {
    const before = this.inventory(frozen);
    const after = this.inventory(checkout);
    return before.filter((entry, index) => entry.size !== after[index].size ||
      entry.sha256 !== after[index].sha256).map(entry => entry.path);
  }

  controls(frozen, checkout) {
    for (const path of ['autostart/windows/launcher.vbs', 'autostart/windows/register-task.ps1', 'ui/index.html']) {
      const bytes = readFileSync(join(checkout, path));
      assert.deepEqual(bytes, readFileSync(join(frozen, path)));
      assert.ok(bytes.includes(Buffer.from('\r\n')), `Explicit CRLF control: ${path}`);
    }
    for (const path of this.paths.filter(path => path.startsWith('ui/dist/') || path.endsWith('.exe'))) {
      assert.deepEqual(readFileSync(join(checkout, path)), readFileSync(join(this.source, path)),
        `Declared binary/build artifact changed: ${path}`);
    }
    for (const name of ['LICENSE', 'THIRD_PARTY_NOTICES.txt']) {
      assert.equal(readFileSync(join(frozen, 'nested', name), 'utf8'), 'SYNTHETIC UNIT SUBDIRECTORY CONTROL\n');
      assert.equal(readFileSync(join(checkout, 'nested', name), 'utf8'), 'SYNTHETIC UNIT SUBDIRECTORY CONTROL\r\n');
    }
  }
}
