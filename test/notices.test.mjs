import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { PackagedCheckoutFixture } from './helpers/packaged-checkout-fixture.mjs';
import {
  BundleInventory, MANIFEST_FILE, NOTICE_FILE, artifactRecords, jsonText,
  normalizeText, noticeComments, relativeFile, renderNotices, sha256, verifyArtifacts,
} from '../tools/third-party-notices/inventory.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MIT = normalizeText(fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8'));

test('canonical package checkout: disposable Git commands suppress automatic maintenance', t => {
  class TracedFixture extends PackagedCheckoutFixture {
    git(args, root = this.root) {
      this.env.GIT_TRACE2_EVENT = path.join(this.base, 'git-trace.jsonl');
      return super.git(args, root);
    }
  }

  const fixture = new TracedFixture(t, ROOT);
  fixture.git(['config', 'maintenance.auto', 'true']);
  fixture.git(['config', 'gc.auto', '1']);
  assert.equal(fixture.git(['config', '--get', 'maintenance.auto']).toString().trim(), 'false');
  assert.equal(fixture.git(['config', '--get', 'gc.auto']).toString().trim(), '0');
  fixture.write('maintenance-control.txt', 'SYNTHETIC UNIT MAINTENANCE CONTROL\n');
  fixture.git(['add', '--', 'maintenance-control.txt']);
  fixture.git(['commit', '--quiet', '-m', 'Synthetic maintenance control']);
  const frozen = fixture.checkout('lf-input', 'false', 'lf');
  const checkout = fixture.checkout('windows', 'false', 'crlf');
  assert.deepEqual(fixture.mismatches(frozen, checkout), []);
  fixture.controls(frozen, checkout);
  const events = fs.readFileSync(path.join(fixture.base, 'git-trace.jsonl'), 'utf8')
    .trim().split('\n').map(line => JSON.parse(line));
  for (const command of ['commit', 'clone', 'checkout']) {
    assert.ok(events.some(event => event.event === 'start' &&
      event.argv.includes(command)), `Real Git trace must include ${command}`);
  }
  const automatic = events.filter(event => event.event === 'child_start' &&
    ['maintenance', 'gc'].includes(event.argv[1]));
  assert.deepEqual(automatic.map(event => event.argv), [], 'Disposable repositories must not launch automatic maintenance');
});

for (const autocrlf of ['false', 'true']) {
  test(`canonical package checkout: complete packed inventory matches LF input with autocrlf=${autocrlf}`, t => {
    const fixture = new PackagedCheckoutFixture(t, ROOT);
    const frozen = fixture.checkout('lf-input', 'false', 'lf');
    const checkout = fixture.checkout('windows', autocrlf, 'crlf');
    assert.deepEqual(fixture.mismatches(frozen, checkout), [], 'All canonical packed files must retain exact source bytes');
    for (const name of ['LICENSE', 'THIRD_PARTY_NOTICES.txt']) {
      assert.equal(fs.readFileSync(path.join(checkout, name)).includes(Buffer.from('\r')), false);
    }
    fixture.controls(frozen, checkout);
  });

  test(`canonical package checkout: missing root rules reproduce both metadata mismatches with autocrlf=${autocrlf}`, t => {
    const attributes = fs.readFileSync(path.join(ROOT, '.gitattributes'), 'utf8')
      .replace(/^\/(?:LICENSE|THIRD_PARTY_NOTICES\.txt)[ \t]+text[ \t]+eol=lf\r?\n/gm, '');
    const fixture = new PackagedCheckoutFixture(t, ROOT, attributes);
    const frozen = fixture.checkout('lf-input', 'false', 'lf');
    const checkout = fixture.checkout('windows', autocrlf, 'crlf');
    assert.deepEqual(fixture.mismatches(frozen, checkout), ['LICENSE', 'THIRD_PARTY_NOTICES.txt']);
    fixture.controls(frozen, checkout);
  });
}

class NoticeFixture {
  constructor(t, tempRoot = tmpdir()) {
    this.root = fs.realpathSync.native(fs.mkdtempSync(path.join(tempRoot, 'mcp-notices-')));
    this.ui = path.join(this.root, 'ui');
    this.policy = {};
    this.lock = { lockfileVersion: 3, packages: {} };
    fs.mkdirSync(this.ui);
    t.after(() => fs.rmSync(this.root, { recursive: true, force: true }));
    this.write('LICENSE', MIT);
  }

  write(file, value) {
    const target = path.join(this.root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, value);
    return target;
  }

  git(args, autocrlf = 'false', eol = 'lf') {
    const result = spawnSync('git', ['-c', `core.autocrlf=${autocrlf}`, '-c', `core.eol=${eol}`,
      '-c', 'core.attributesFile=', '-c', 'core.hooksPath=', '-C', this.root, ...args], {
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
        HOME: this.root, USERPROFILE: this.root, GIT_CONFIG_NOSYSTEM: '1',
        GIT_ATTR_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null' },
    });
    assert.equal(result.status, 0, 'Offline HTML checkout fixture Git command failed');
  }

  package(name, { version = '1.0.0', license = 'MIT', files = { LICENSE: MIT } } = {}) {
    const lockPath = `node_modules/${name}`;
    this.lock.packages[lockPath] = { version, license };
    this.write(`ui/${lockPath}/package.json`, jsonText({ name, version, license }));
    this.policy[`${name}@${version}`] = {
      license,
      files: Object.fromEntries(Object.entries(files).map(([file, text]) => [file, sha256(normalizeText(text))])),
    };
    for (const [file, text] of Object.entries(files)) this.write(`ui/${lockPath}/${file}`, text);
    return this.write(`ui/${lockPath}/index.js`, '/*! Copyright fixture contributor; retain this notice. */\nexport const x = 1;\n');
  }

  inventory() {
    this.write('ui/package-lock.json', jsonText(this.lock));
    return new BundleInventory(this.ui, this.policy);
  }

  bundle(modules) {
    return {
      'assets/ui.js': {
        type: 'chunk', fileName: 'assets/ui.js', code: 'console.log(1);\n', modules,
      },
    };
  }

  artifacts() {
    const file = this.package('included');
    const inventory = this.inventory();
    const bundle = this.bundle({ [file]: { renderedLength: 20 } });
    const chunks = inventory.collect(bundle);
    const packages = inventory.packageRecords();
    const runtime = [{ ...packages[0], name: 'runtime-fixture', distribution: 'separately-installed' }];
    const notices = renderNotices(packages, runtime);
    const manifest = {
      schemaVersion: 1,
      chunks,
      sources: inventory.sourceRecords(),
      packages,
      runtimeNotices: runtime,
      artifacts: artifactRecords(bundle),
      projectLicenseSha256: sha256(MIT),
      noticesSha256: sha256(notices),
    };
    this.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
    this.write(`ui/dist/${NOTICE_FILE}`, notices);
    this.write(NOTICE_FILE, notices);
    this.write('ui/dist/assets/ui.js', bundle['assets/ui.js'].code);
    return manifest;
  }
}

test('bundled notice fixture root uses native canonical spelling', (t) => {
  const fixture = new NoticeFixture(t);
  assert.equal(fixture.root, fs.realpathSync.native(fixture.root));
});

for (const [autocrlf, eol] of [['false', 'lf'], ['true', 'crlf']]) {
  test(`source HTML checkout preserves bundled bytes with autocrlf=${autocrlf}, eol=${eol}`, (t) => {
    const fixture = new NoticeFixture(t);
    const source = normalizeText(fs.readFileSync(path.join(ROOT, 'ui/index.html'), 'utf8'));
    const bundled = fs.readFileSync(path.join(ROOT, 'ui/dist/index.html'));
    fixture.write('.gitattributes', fs.readFileSync(path.join(ROOT, '.gitattributes')));
    const sourceFile = fixture.write('ui/index.html', source);
    const bundledFile = fixture.write('ui/dist/index.html', bundled);
    fixture.git(['init', '--quiet']);
    fixture.git(['add', '--', '.gitattributes', 'ui/index.html', 'ui/dist/index.html']);
    fs.unlinkSync(sourceFile);
    fs.unlinkSync(bundledFile);
    fixture.git(['checkout-index', '--all'], autocrlf, eol);
    assert.equal(fs.readFileSync(sourceFile, 'utf8'), source.replaceAll('\n', '\r\n'));
    assert.deepEqual(fs.readFileSync(bundledFile), bundled);
  });
}

test('bundled notice fixtures canonicalize an aliased temporary parent', (t) => {
  const sandbox = fs.realpathSync.native(fs.mkdtempSync(path.join(tmpdir(), 'mcp-notices-alias-')));
  t.after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
  const target = path.join(sandbox, 'physical');
  const alias = path.join(sandbox, 'alias');
  fs.mkdirSync(target);
  fs.symlinkSync(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    assert.notEqual(fs.realpathSync.native(alias), path.resolve(alias));
    const fixture = new NoticeFixture(t, alias);
    const manifest = fixture.artifacts();
    assert.equal(fixture.root, fs.realpathSync.native(fixture.root));
    assert.equal(path.dirname(fixture.root), target);
    assert.deepEqual(verifyArtifacts(fixture.root), manifest);
  } finally {
    fs.unlinkSync(alias);
  }
  assert.equal(fs.lstatSync(alias, { throwIfNoEntry: false }), undefined);
  assert.ok(fs.existsSync(target));
});

for (const lockPath of ['node_modules/included', 'node_modules']) {
  test(`bundled notice inventory rejects linked ${lockPath}`, (t) => {
    const fixture = new NoticeFixture(t);
    const file = fixture.package('included');
    const bundle = fixture.bundle({ [file]: { renderedLength: 20 } });
    assert.equal(fixture.inventory().collect(bundle)[0].modules[0].package, 'included@1.0.0');
    const directory = path.join(fixture.ui, lockPath);
    const target = path.join(fixture.root, 'linked-producer-target');
    fs.renameSync(directory, target);
    fs.symlinkSync(target, directory, process.platform === 'win32' ? 'junction' : 'dir');
    try {
      assert.ok(fs.lstatSync(directory).isSymbolicLink());
      assert.throws(() => fixture.inventory().collect(bundle), /Linked producer packages require notice review/);
    } finally {
      fs.unlinkSync(directory);
    }
    assert.equal(fs.lstatSync(directory, { throwIfNoEntry: false }), undefined);
    assert.ok(fs.existsSync(target));
  });
}

test('only rendered modules are attributed, not installed or tree-shaken dependencies', (t) => {
  const fixture = new NoticeFixture(t);
  const included = fixture.package('included');
  const excluded = fixture.package('excluded');
  delete fixture.policy['excluded@1.0.0'];
  const inventory = fixture.inventory();
  const chunks = inventory.collect(fixture.bundle({
    [excluded]: { renderedLength: 0 },
    [included]: { renderedLength: 20 },
  }));
  assert.deepEqual(inventory.packageRecords().map(({ name }) => name), ['included']);
  assert.equal(chunks[0].modules.length, 1);
  const serialized = jsonText(chunks);
  assert.ok(!serialized.includes(fixture.root));
  assert.ok(!serialized.includes('\\'));
});

test('missing, changed, additional and unknown license inputs fail closed', (t) => {
  const fixture = new NoticeFixture(t);
  const file = fixture.package('included');
  const collect = () => fixture.inventory().collect(fixture.bundle({ [file]: { renderedLength: 20 } }));
  fixture.write('ui/node_modules/included/LICENSE', 'changed terms\n');
  assert.throws(collect, /Changed license\/NOTICE text/);
  fixture.write('ui/node_modules/included/LICENSE', MIT);
  fixture.write('ui/node_modules/included/NOTICE', 'new notice\n');
  assert.throws(collect, /Missing or unreviewed license\/NOTICE/);
  fs.unlinkSync(path.join(fixture.ui, 'node_modules/included/NOTICE'));
  fs.unlinkSync(path.join(fixture.ui, 'node_modules/included/LICENSE'));
  assert.throws(collect, /Missing or unreviewed license\/NOTICE/);
  fixture.write('ui/node_modules/included/LICENSE', MIT);
  delete fixture.policy['included@1.0.0'];
  assert.throws(collect, /Unreviewed bundled package\/license/);
});

test('an installed version or license differing from the producer lock fails', (t) => {
  const fixture = new NoticeFixture(t);
  const file = fixture.package('included');
  fixture.lock.packages['node_modules/included'].version = '1.0.1';
  assert.throws(() => fixture.inventory().collect(fixture.bundle({
    [file]: { renderedLength: 20 },
  })), /Installed producer differs/);
});

test('Apache NOTICE, nested license files and source copyright notices are preserved in full', (t) => {
  const fixture = new NoticeFixture(t);
  const terms = 'Apache-2.0 test fixture terms.\nAll fixture terms retained.\n';
  const notice = 'Attribution from the upstream test fixture.\n';
  const file = fixture.package('apache-fixture', {
    license: 'Apache-2.0',
    files: { LICENSE: terms, NOTICE: notice, 'component/LICENSE.txt': MIT },
  });
  const inventory = fixture.inventory();
  inventory.collect(fixture.bundle({ [file]: { renderedLength: 20 } }));
  const text = renderNotices(inventory.packageRecords());
  assert.ok(text.includes(terms));
  assert.ok(text.includes(notice));
  assert.ok(text.includes(MIT.trimEnd()));
  assert.ok(text.includes('Copyright fixture contributor; retain this notice.'));
  assert.equal(text, renderNotices(inventory.packageRecords()));
});

test('unrecognized generated modules fail rather than losing their attribution', (t) => {
  const fixture = new NoticeFixture(t);
  assert.throws(() => fixture.inventory().module('\0unknown-helper.js'), /Unknown virtual/);
  assert.throws(() => relativeFile(fixture.ui, path.join(fixture.root, 'external.js')), /inside/);
});

test('source notice extraction preserves license blocks without inventing copyright', () => {
  assert.deepEqual(noticeComments('/* normal comment */\n/*! license text */\n/* @license Exact text */'), [
    '/* @license Exact text */', '/*! license text */',
  ]);
  assert.deepEqual(noticeComments('export const x = 1;'), []);
});

test('notice-like source names are not license files, and reviewed sections stay complete', (t) => {
  const fixture = new NoticeFixture(t);
  const text = `# Core license\n${MIT}\n# Unbundled tooling\nOther terms\n`;
  const file = fixture.package('producer', { files: { 'LICENSE.md': text } });
  fixture.write('ui/node_modules/producer/copyright.js', 'export const icon = 1;\n');
  fixture.policy['producer@1.0.0'].sections = { 'LICENSE.md': ['# Core license'] };
  const inventory = fixture.inventory();
  inventory.collect(fixture.bundle({ [file]: { renderedLength: 20 } }));
  const notices = renderNotices(inventory.packageRecords());
  assert.ok(notices.includes(MIT.trimEnd()));
  assert.ok(!notices.includes('Other terms'));
  assert.ok(!notices.includes('export const icon'));
});

test('CommonJS wrapper IDs stay distinct without absolute producer paths', (t) => {
  const fixture = new NoticeFixture(t);
  const file = fixture.package('included');
  const inventory = fixture.inventory();
  const plain = inventory.module(file);
  const wrapper = inventory.module(`\0${file}?commonjs-es-import`);
  assert.notEqual(plain.id, wrapper.id);
  assert.equal(wrapper.id, 'commonjs:node_modules/included/index.js?commonjs-es-import');
});

test('source hashes use fixed path and sha256 fields instead of filename keys', (t) => {
  const fixture = new NoticeFixture(t);
  const source = 'export const ready = 1;\n';
  const first = fixture.write('ui/src/generated-api.ts', source);
  const last = fixture.write('ui/src/z.ts', source);
  const inventory = fixture.inventory();
  inventory.source(last);
  inventory.source(first);
  const records = inventory.sourceRecords();
  assert.deepEqual(records, [
    { path: 'src/generated-api.ts', sha256: sha256(source) },
    { path: 'src/z.ts', sha256: sha256(source) },
  ]);
  assert.ok(records.every((record) => /^[0-9a-f]{64}$/.test(record.sha256)));
  assert.ok(records.every((record) => Object.keys(record).join(',') === 'path,sha256'));
  assert.equal(jsonText(records), jsonText(inventory.sourceRecords()));
});

test('source hashes use decoded UTF-8 with LF line endings, not raw file bytes', (t) => {
  const fixture = new NoticeFixture(t);
  const source = 'export const ready = 1;\nexport const done = 2;\n';
  const expected = sha256(Buffer.from(source, 'utf8'));
  const variants = [
    ['lf', source],
    ['crlf', source.replaceAll('\n', '\r\n')],
    ['cr', source.replaceAll('\n', '\r')],
    ['bom', `\uFEFF${source}`],
  ];
  const inventory = fixture.inventory();
  for (const [name, text] of variants) {
    const bytes = Buffer.from(text, 'utf8');
    const relative = `src/${name}.ts`;
    inventory.source(fixture.write(`ui/${relative}`, bytes));
    assert.equal(inventory.sources.get(relative), expected);
    assert.equal(sha256(bytes) === expected, name === 'lf');
  }
  inventory.source(fixture.write('ui/src/changed.ts', source.replace('ready', 'different')));
  assert.notEqual(inventory.sources.get('src/changed.ts'), expected);
});

test('packed artifact verification needs no installed dependencies', (t) => {
  const fixture = new NoticeFixture(t);
  fixture.artifacts();
  fs.rmSync(path.join(fixture.ui, 'node_modules'), { recursive: true });
  assert.equal(verifyArtifacts(fixture.root).packages[0].name, 'included');
});

test('negative controls reject omitted notices, altered UI, extra assets and changed project license', (t) => {
  const fixture = new NoticeFixture(t);
  fixture.artifacts();
  fixture.write(NOTICE_FILE, 'omitted license text\n');
  assert.throws(() => verifyArtifacts(fixture.root), /notices are missing or stale/);
  fixture.artifacts();
  fixture.write('ui/dist/assets/ui.js', 'tampered\n');
  assert.throws(() => verifyArtifacts(fixture.root), /UI artifact differs/);
  fixture.artifacts();
  fixture.write('ui/dist/extra.js', 'unrecorded\n');
  assert.throws(() => verifyArtifacts(fixture.root), /closure differs/);
  fs.unlinkSync(path.join(fixture.ui, 'dist/extra.js'));
  fixture.write('LICENSE', 'different project license\n');
  assert.throws(() => verifyArtifacts(fixture.root), /Project LICENSE differs/);
});

test('packed manifest rejects removed or changed license text and unattributed modules', (t) => {
  const fixture = new NoticeFixture(t);
  let manifest = fixture.artifacts();
  manifest.packages[0].licenses = [];
  fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
  assert.throws(() => verifyArtifacts(fixture.root), /Incomplete bundled package license/);
  manifest = fixture.artifacts();
  manifest.packages[0].licenses[0].text = 'different terms';
  fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
  assert.throws(() => verifyArtifacts(fixture.root), /Missing or changed bundled license/);
  manifest = fixture.artifacts();
  manifest.chunks[0].modules[0].package = 'unattributed@1.0.0';
  fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
  assert.throws(() => verifyArtifacts(fixture.root), /no matching package license/);
  manifest = fixture.artifacts();
  manifest.runtimeNotices = [];
  fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
  assert.throws(() => verifyArtifacts(fixture.root), /runtime license supplement/);
  manifest = fixture.artifacts();
  manifest.runtimeNotices[0].distribution = 'ui-bundled';
  fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
  assert.throws(() => verifyArtifacts(fixture.root), /runtime license supplement/);
});

test('packed source hashes reject filename keys, shortened digests and invalid paths or fields', (t) => {
  const fixture = new NoticeFixture(t);
  const manifest = fixture.artifacts();
  const [source] = manifest.sources;
  const invalidRecords = [
    Object.fromEntries(manifest.sources.map(({ path, sha256 }) => [path, sha256])),
    [],
    [null],
    [{ ...source, sha256: source.sha256.slice(0, 12) }],
    [{ ...source, filename: source.path }],
    [source, source],
    [{ ...source, path: '../external.js' }],
    [{ ...source, path: `./${source.path}` }],
  ];
  for (const sources of invalidRecords) {
    manifest.sources = sources;
    fixture.write(`ui/dist/${MANIFEST_FILE}`, jsonText(manifest));
    assert.throws(() => verifyArtifacts(fixture.root), /source|Source/);
  }
});
