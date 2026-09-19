import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { LocalGate } from '../../tools/npm-publication/local-gate.mjs';
import { LocalSourceReader } from '../../tools/npm-publication/local-source.mjs';
import * as contract from '../../tools/npm-publication/stage-proof-contract.mjs';
import { stageProofFixture } from './stage-proof-fixture.mjs';
import { treeEntries } from '../../tools/npm-publication/local-source.mjs';
import { LOCAL_CONTROLLER, localHash } from '../../tools/npm-publication/local-regression.mjs';

class BoundedCheckoutGate extends LocalGate {
  command(label, executable, args, cwd, binary = false, timeout, environment = this.env) {
    return super.command(label, executable, args, cwd, binary, 30_000, environment);
  }
}

export class CheckoutProofFixture {
  constructor(t, version = '2.0.1') {
    this.base = mkdtempSync(join(tmpdir(), 'checkout-proof-unit-'));
    t.after(() => rmSync(this.base, { recursive: true, force: true, maxRetries: 3 }));
    this.root = join(this.base, 'source');
    this.empty = join(this.base, 'empty');
    mkdirSync(this.root);
    mkdirSync(this.empty);
    this.version = version;
    this.executable = 'git';
    this.env = {};
    for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
      if (process.env[key]) this.env[key] = process.env[key];
    }
    Object.assign(this.env, { HOME: this.empty, USERPROFILE: this.empty,
      GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never',
      GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' });
  }

  git(args, root = this.root) {
    const started = Date.now();
    const result = spawnSync(this.executable, ['--no-optional-locks',
      '-c', `core.hooksPath=${this.empty}`, '-c', `init.templateDir=${this.empty}`,
      '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', '-c', 'commit.gpgsign=false',
      '-c', 'core.attributesFile=',
      '-c', 'credential.helper=', '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always', ...args], {
      cwd: root, env: this.env, shell: false, windowsHide: true, timeout: 30_000, maxBuffer: 4 * 1024 ** 2,
    });
    if (process.env.CHECKOUT_PROOF_PROGRESS) {
      appendFileSync(process.env.CHECKOUT_PROOF_PROGRESS, `${JSON.stringify({
        kind: 'owned-unit-git', args, root, exitCode: result.status, elapsedMs: Date.now() - started,
      })}\n`);
    }
    assert.equal(result.error, undefined,
      `Git is required on the sanitized PATH${result.error?.code ? ` (${result.error.code})` : ''}`);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr?.toString());
    return result.stdout;
  }

  write(path, bytes) {
    const target = join(this.root, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }

  create({ binary = false } = {}) {
    this.git(['init', '--quiet', '--initial-branch=fixture']);
    this.git(['config', 'user.name', 'SYNTHETIC UNIT FIXTURE']);
    this.git(['config', 'user.email', 'synthetic@example.invalid']);
    this.write('.gitattributes', '* text=auto\n*.mjs text eol=lf\n*.json text eol=lf\n');
    this.write('.gitignore', 'node_modules/\nui/node_modules/\n');
    this.write('package.json', JSON.stringify({ name: 'mcp-pacemaker', version: this.version }));
    for (const path of contract.STAGE_PROOF_FILES) {
      const text = path.endsWith('.json') ? '{"synthetic":true}\n' : '// SYNTHETIC UNIT SOURCE; NOT EXECUTED\nexport {};\n';
      const crlf = ['tools/npm-publication/stage-capture.mjs', 'tools/npm-publication/stage-sdk-pins.json'].includes(path);
      this.write(path, crlf ? text.replaceAll('\n', '\r\n') : text);
    }
    if (binary) {
      this.binaryPath = 'tools/npm-publication/stage-sdk-pins.json';
      this.binaryBytes = Buffer.from([0, 13, 10, 65, 10, 255]);
      this.write(this.binaryPath, this.binaryBytes);
      this.write('.gitattributes', '* text=auto\n*.mjs text eol=lf\n*.json text eol=lf\n' +
        `${this.binaryPath} -text !eol\n`);
    }
    this.git(['add', '--all', '--', '.']);
    this.git(['commit', '--quiet', '-m', 'Synthetic checkout proof unit fixture']);
    mkdirSync(join(this.root, 'node_modules'));
    mkdirSync(join(this.root, 'ui/node_modules'), { recursive: true });
    const npm = join(this.base, 'synthetic-npm');
    mkdirSync(join(npm, 'bin'), { recursive: true });
    writeFileSync(join(npm, 'package.json'), '{"name":"npm","version":"12.0.2"}');
    writeFileSync(join(npm, 'bin/npm-cli.js'), 'throw new Error("UNIT fixture forbids npm execution");\n');
    this.gate = new BoundedCheckoutGate({ root: this.root, output: join(this.base, 'receipts'),
      workRoot: join(this.base, 'work'), npmCli: join(npm, 'bin/npm-cli.js'),
      publisherNode: process.execPath, parentEnvironment: this.env });
    this.identityReader = new LocalSourceReader(this.root, this.executable);
    this.identity = this.readIdentity();
    this.snapshot = this.gate.snapshot();
    this.checkout = this.gate.checkout(this.snapshot, 'false');
    this.invocation = { root: this.checkout, cli: join(npm, 'bin/npm-cli.js'),
      node: process.execPath, home: join(this.base, 'synthetic-proof') };
    this.report = stageProofFixture(this.checkout, this.version, this.invocation);
    return this;
  }

  binding() {
    return contract.bindStageProofCheckout?.({ root: this.root, identity: this.identity,
      readGit: args => this.git(args) });
  }

  verify() {
    return contract.validateStageProof(this.report, { root: this.root, version: this.version,
      invocation: this.invocation, sourceHead: this.identity.head, checkout: this.binding() });
  }

  changedAttributeIdentity(attributes) {
    this.write('.gitattributes', attributes);
    this.git(['add', '--', '.gitattributes']);
    this.git(['commit', '--quiet', '-m', 'Synthetic attribute negative control']);
    return this.readIdentity(false);
  }

  readIdentity(requireClean = true) {
    if (requireClean) assert.equal(this.git(['status', '--porcelain=v1', '--untracked-files=all']).length, 0);
    const head = this.git(['rev-parse', 'HEAD']).toString().trim();
    const tree = this.git(['rev-parse', 'HEAD^{tree}']).toString().trim();
    const entries = treeEntries(this.git(['ls-tree', '-rz', '--full-tree', head]).toString());
    // Deliberately claim clean in these negative inputs. Actual committed Git
    // attributes must still reject unsupported conversion before any filters run.
    return { schemaVersion: 1, clean: true, version: this.version, head, tree, entries,
      files: entries.map(({ path }) => {
        const bytes = readFileSync(join(this.root, path));
        return { path, size: bytes.length, sha256: localHash(bytes) };
      }) };
  }
}

for (const version of ['1.3.1', '2.0.1']) {
  test(`checkout proof: raw CRLF source binds actual declared-LF Git checkout ${version}`, t => {
    const fixture = new CheckoutProofFixture(t, version).create();
    for (const path of ['tools/npm-publication/stage-capture.mjs', 'tools/npm-publication/stage-sdk-pins.json']) {
      assert.ok(readFileSync(join(fixture.root, path)).includes(Buffer.from('\r\n')));
      assert.equal(readFileSync(join(fixture.checkout, path)).includes(Buffer.from('\r\n')), false);
    }
    const unchanged = 'tools/npm-publication/stage-proof-contract.mjs';
    assert.deepEqual(readFileSync(join(fixture.root, unchanged)), readFileSync(join(fixture.checkout, unchanged)));
    contract.validateStageProof(fixture.report, { root: fixture.checkout, version, invocation: fixture.invocation });
    assert.doesNotThrow(() => fixture.verify());
    assert.throws(() => contract.validateStageProof(fixture.report, {
      root: fixture.root, version, invocation: fixture.invocation,
    }), 'Standalone producer validation must still compare exact raw root bytes');
  });
}

test('checkout proof: bindings reject source/report mutations and cannot be supplied as hash lists', async t => {
  const fixture = new CheckoutProofFixture(t).create();
  const checkout = fixture.binding();
  assert.ok(checkout);
  const options = { root: fixture.root, version: fixture.version, invocation: fixture.invocation,
    sourceHead: fixture.identity.head, checkout };
  for (const [name, mutate] of [
    ['changed hash', value => { value.files[0].sha256 = '0'.repeat(64); }],
    ['missing file', value => { value.files.pop(); }],
    ['extra file', value => { value.files.push({ path: 'extra.mjs', sha256: '0'.repeat(64) }); }],
    ['reordered files', value => { value.files.reverse(); }],
  ]) {
    await t.test(name, () => {
      const value = structuredClone(fixture.report);
      mutate(value);
      assert.throws(() => contract.validateStageProof(value, options));
    });
  }
  assert.throws(() => contract.validateStageProof(fixture.report, { ...options,
    checkout: { files: fixture.report.files } }), /verified Git checkout binding/);
  assert.throws(() => contract.validateStageProof(fixture.report, { ...options,
    checkout: JSON.parse(JSON.stringify(checkout)) }), /verified Git checkout binding/);
  assert.throws(() => contract.validateStageProof(fixture.report, { ...options,
    sourceHead: '0'.repeat(40) }));
  for (const path of ['tools/npm-publication/stage-capture.mjs', '.gitattributes']) {
    await t.test(`changed frozen ${path}`, () => {
      const original = readFileSync(join(fixture.root, path));
      fixture.write(path, Buffer.concat([original, Buffer.from('\nchanged\n')]));
      try {
        assert.throws(() => contract.validateStageProof(fixture.report, options), /Frozen source\/attributes changed/);
      } finally { fixture.write(path, original); }
    });
  }
  const original = readFileSync(join(fixture.root, '.gitattributes'));
  rmSync(join(fixture.root, '.gitattributes'));
  assert.throws(() => contract.validateStageProof(fixture.report, options));
  fixture.write('.gitattributes', original);
  assert.throws(() => contract.bindStageProofCheckout({
    root: fixture.root, identity: fixture.identity,
    readGit: args => {
      const output = fixture.git(args);
      return args[0] === 'cat-file' && args[1] === 'blob' ? Buffer.concat([output, Buffer.from('x')]) : output;
    },
  }), /Git blob identity mismatch/);
  const override = join(fixture.root, '.git/info/attributes');
  mkdirSync(dirname(override), { recursive: true });
  writeFileSync(override, '*.mjs eol=crlf\n', { flag: 'wx' });
  assert.throws(() => contract.validateStageProof(fixture.report, options), /Uncommitted attribute overrides/);
  rmSync(override);
});

test('checkout proof: committed attributes, not guessed normalization, control admission', async t => {
  const fixture = new CheckoutProofFixture(t).create();
  const base = '* text=auto\n*.mjs text eol=lf\n*.json text eol=lf\n';
  for (const [name, attributes, message] of [
    ['missing text declarations', '', /Missing declared/],
    ['unsupported filter', `${base}*.mjs filter=synthetic-forbidden\n`, /conversion: filter/],
    ['unsupported encoding', `${base}*.mjs working-tree-encoding=UTF-16\n`, /conversion: working-tree-encoding/],
    ['unsupported ident', `${base}*.mjs ident\n`, /conversion: ident/],
  ]) {
    await t.test(name, () => {
      const identity = fixture.changedAttributeIdentity(attributes);
      let filters = 0;
      assert.throws(() => contract.bindStageProofCheckout({ root: fixture.root, identity,
        readGit: args => {
          if (args.includes('--filters')) filters++;
          return fixture.git(args);
        } }), message);
      assert.equal(filters, 0, 'Unsupported conversion must stop before Git filters are requested');
    });
  }
  await t.test('changed declared EOL rejects the old executed-byte report', () => {
    const identity = fixture.changedAttributeIdentity(`${base}*.mjs text eol=crlf\n`);
    const checkout = contract.bindStageProofCheckout({ root: fixture.root, identity,
      readGit: args => fixture.git(args) });
    assert.throws(() => contract.validateStageProof(fixture.report, {
      root: fixture.root, version: fixture.version, invocation: fixture.invocation,
      checkout, sourceHead: identity.head,
    }));
  });
});

test('checkout proof: declared binary bytes are never line-ending normalized', t => {
  const fixture = new CheckoutProofFixture(t).create({ binary: true });
  const entry = fixture.identity.entries.find(value => value.path === fixture.binaryPath);
  assert.deepEqual(fixture.identityReader.git(['cat-file', 'blob', entry.blob], true), fixture.binaryBytes);
  assert.deepEqual(readFileSync(join(fixture.checkout, fixture.binaryPath)), fixture.binaryBytes);
  assert.doesNotThrow(() => fixture.verify());
  const changed = structuredClone(fixture.report);
  changed.files.find(value => value.path === fixture.binaryPath).sha256 =
    localHash(Buffer.from(fixture.binaryBytes.toString('latin1').replaceAll('\r\n', '\n'), 'latin1'));
  assert.throws(() => contract.validateStageProof(changed, { root: fixture.root, version: fixture.version,
    invocation: fixture.invocation, checkout: fixture.binding(), sourceHead: fixture.identity.head }));
});

test('checkout proof: every affected production verifier is already controller-bound', () => {
  for (const name of ['local-source.mjs', 'stage-proof-contract.mjs', 'local-gate.mjs',
    'local-case-evidence.mjs', 'verify-local.mjs']) {
    assert.ok(LOCAL_CONTROLLER.includes(`tools/npm-publication/${name}`));
  }
});

test('checkout proof: Git selection follows the sanitized PATH using real Git', t => {
  const fixture = new CheckoutProofFixture(t);
  const reference = spawnSync('git', ['--exec-path'], {
    cwd: fixture.root, env: fixture.env, shell: false, windowsHide: true,
    timeout: 30_000, maxBuffer: 4 * 1024 ** 2,
  });
  assert.equal(reference.error, undefined, 'Real Git must be available on the sanitized PATH');
  assert.equal(reference.signal, null);
  assert.equal(reference.status, 0, reference.stderr?.toString());
  const selected = fixture.git(['--exec-path']);
  assert.deepEqual(selected, reference.stdout, 'Fixture Git must be the real Git selected by its sanitized PATH');
  console.log(JSON.stringify({ kind: 'real-git-path-selection', execPath: selected.toString().trim() }));
});

test('checkout proof: Git selection rejects a missing PATH executable without installed-path fallback', t => {
  const fixture = new CheckoutProofFixture(t);
  fixture.env.PATH = fixture.empty;
  fixture.env.Path = fixture.empty;
  assert.throws(() => fixture.git(['--version']), /Git is required on the sanitized PATH.*ENOENT/);
});
