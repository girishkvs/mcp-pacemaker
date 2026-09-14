import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { jsonText, readText, renderNotices, sha256 } from '../tools/third-party-notices/inventory.mjs';
import { runtimeNotices } from '../tools/third-party-notices/runtime.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MIT = readText(path.join(ROOT, 'LICENSE'));

test('dashboard CI restores the root runtime before building its license supplement', () => {
  const workflow = readText(path.join(ROOT, '.github/workflows/ci.yml'));
  const uiJob = workflow.slice(workflow.indexOf('\n  ui:\n'));
  const restore = uiJob.indexOf('- name: Install CLI dependencies\n        run: npm ci');
  const build = uiJob.indexOf('working-directory: ui\n        run: |');
  assert.ok(restore >= 0, 'The UI job must restore root runtime dependencies');
  assert.ok(build >= 0, 'The UI build step must remain explicit');
  assert.ok(restore < build, 'Runtime notice inputs must exist before the dashboard build');
});

class RuntimeFixture {
  constructor(t) {
    this.root = fs.mkdtempSync(path.join(tmpdir(), 'mcp-runtime-notices-'));
    t.after(() => fs.rmSync(this.root, { recursive: true, force: true }));
    const source = '/** @license MIT fixture notice */\nexport default 1;\n';
    this.entry = {
      name: 'runtime-fixture',
      resolution: { version: '1.0.0', license: 'MIT', resolved: 'https://registry.npmjs.org/runtime-fixture/-/runtime-fixture-1.0.0.tgz', integrity: 'sha512-fixture' },
      upstreamCommit: 'a'.repeat(40),
      upstreamSourceSha256: { 'src/index.ts': sha256(source) },
      licenseFile: 'upstream/LICENSE.txt',
      licenseSha256: sha256(MIT),
      licenseSourceUrl: `https://example.test/${'a'.repeat(40)}/LICENSE`,
    };
    const lock = { packages: { 'node_modules/runtime-fixture': this.entry.resolution } };
    this.write('package-lock.json', jsonText(lock));
    this.write('node_modules/.package-lock.json', jsonText(lock));
    this.write('node_modules/runtime-fixture/package.json', jsonText({ name: 'runtime-fixture', version: '1.0.0', license: 'MIT' }));
    this.write('node_modules/runtime-fixture/src/index.ts', source);
    this.write('upstream/LICENSE.txt', MIT);
  }

  write(file, value) {
    const target = path.join(this.root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, value);
  }

  records() {
    return runtimeNotices(this.root, [this.entry], this.root);
  }
}

test('runtime MIT supplement retains full terms and source notice without claiming UI bundling', (t) => {
  const fixture = new RuntimeFixture(t);
  const records = fixture.records();
  assert.equal(records[0].distribution, 'separately-installed');
  assert.deepEqual(records[0].resolution, fixture.entry.resolution);
  assert.equal(records[0].licenses[0].text, MIT);
  const text = renderNotices([], records);
  assert.ok(text.includes('Separately installed runtime supplements (not UI-bundled)'));
  assert.ok(text.includes(MIT.trimEnd()));
  assert.ok(text.includes('@license MIT fixture notice'));
  assert.ok(!text.includes('Bundled dashboard code'));
  assert.ok(!jsonText(records).includes(fixture.root));
});

test('changed producer lock, installed lock and package identity each fail', (t) => {
  const fixture = new RuntimeFixture(t);
  const lock = JSON.parse(readText(path.join(fixture.root, 'package-lock.json')));
  lock.packages['node_modules/runtime-fixture'].integrity = 'sha512-changed';
  fixture.write('package-lock.json', jsonText(lock));
  assert.throws(() => fixture.records(), /matching root\/installed locks/);
  lock.packages['node_modules/runtime-fixture'] = fixture.entry.resolution;
  fixture.write('package-lock.json', jsonText(lock));
  fixture.write('node_modules/.package-lock.json', jsonText({ packages: {} }));
  assert.throws(() => fixture.records(), /matching root\/installed locks/);
  fixture.write('node_modules/.package-lock.json', jsonText(lock));
  fixture.write('node_modules/runtime-fixture/package.json', jsonText({ name: 'runtime-fixture', version: '2.0.0', license: 'MIT' }));
  assert.throws(() => fixture.records(), /identity differs/);
});

test('missing or changed upstream MIT text and changed upstream-matched source fail', (t) => {
  const fixture = new RuntimeFixture(t);
  fixture.write('upstream/LICENSE.txt', 'changed terms\n');
  assert.throws(() => fixture.records(), /MIT text is missing or changed/);
  fs.unlinkSync(path.join(fixture.root, 'upstream/LICENSE.txt'));
  assert.throws(() => fixture.records(), /ENOENT/);
  fixture.write('upstream/LICENSE.txt', MIT);
  fixture.write('node_modules/runtime-fixture/src/index.ts', 'different source\n');
  assert.throws(() => fixture.records(), /immutable license reference/);
});

test('Yoga supplement is pinned to the matching immutable 3.2.1 upstream MIT license', () => {
  const directory = path.join(ROOT, 'tools/third-party-notices');
  const [entry] = JSON.parse(readText(path.join(directory, 'reviewed-runtime.json')));
  assert.equal(entry.name, 'yoga-layout');
  assert.equal(entry.resolution.version, '3.2.1');
  assert.equal(entry.upstreamCommit, '042f5013152eb81c1552dec945b88f7b95ca350f');
  assert.equal(entry.upstreamPackagePath, 'javascript');
  assert.equal(entry.licenseSourceUrl, `https://raw.githubusercontent.com/facebook/yoga/${entry.upstreamCommit}/LICENSE`);
  assert.equal(sha256(readText(path.join(directory, entry.licenseFile))), entry.licenseSha256);
  assert.equal(Object.keys(entry.upstreamSourceSha256).length, 4);
});
