import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { workspace } from '../tools/publication-scanners/core.mjs';
import { diagnosticLocations } from '../tools/publication-scanners/locations.mjs';
import { diagnoseSource } from '../tools/publication-scanners/secrets.mjs';
import { diagnosticOutputPath, main } from '../tools/publication-scanners/diagnose.mjs';

function findings(root) {
  const material = ['do', 'not', 'serialize'].join('-');
  return {
    material,
    gitleaks: { stdout: JSON.stringify([{ RuleID: 'fixture-rule', File: join(root, 'test', 'fixture.mjs'),
      StartLine: 12, Secret: material, Match: material, Commit: material, Message: material }]), stderr: material },
    trufflehog: { stdout: JSON.stringify({ DetectorName: 'FixtureDetector', Raw: material, RawV2: material,
      Redacted: material, ExtraData: { material }, Verified: false,
      SourceMetadata: { Data: { Filesystem: { file: join(root, 'test', 'fixture.mjs'), line: 12 } } } }),
    stderr: material },
  };
}

test('T22/T42: local diagnostics emit only detector, inventory-relative path, line and unassessed classification',
  async () => workspace(async root => {
    const input = findings(root);
    const entries = [{ path: 'test/fixture.mjs' }];
    for (const name of ['gitleaks', 'trufflehog']) {
      const output = diagnosticLocations(name, input[name], root, entries);
      assert.deepEqual(output, [{ detector: name === 'gitleaks' ? 'fixture-rule' : 'FixtureDetector',
        path: 'test/fixture.mjs', line: 12, synthetic: 'not-assessed' }]);
      assert.ok(!JSON.stringify(output).includes(input.material));
      assert.ok(!JSON.stringify(output).includes(root));
      assert.ok(!JSON.stringify(output).includes('SourceMetadata'));
    }
    const relativeFinding = JSON.parse(input.gitleaks.stdout)[0];
    relativeFinding.File = 'test/fixture.mjs';
    relativeFinding.StartLine = 0;
    assert.equal(diagnosticLocations('gitleaks', { stdout: JSON.stringify([relativeFinding]) },
      root, entries)[0].line, null, 'Unavailable line numbers are not fabricated');
  }));

test('T22/T42: unowned paths, unsafe metadata and invalid line numbers cannot become diagnostic output',
  async () => workspace(async root => {
    const input = findings(root);
    const entries = [{ path: 'test/fixture.mjs' }];
    const original = JSON.parse(input.gitleaks.stdout)[0];
    for (const change of [
      { File: join(root, '..', 'outside-file') }, { File: '../outside-file' },
      { File: join(root, 'not-in-the-snapshot') }, { File: 'test/control\nfixture.mjs' },
      { RuleID: 'unsafe\nmetadata' }, { StartLine: -1 }, { StartLine: 1.5 }, { StartLine: 'unsafe' },
    ]) {
      assert.throws(() => diagnosticLocations('gitleaks', {
        stdout: JSON.stringify([{ ...original, ...change }]),
      }, root, entries));
    }
    const unowned = JSON.parse(input.trufflehog.stdout);
    unowned.SourceMetadata.Data.Filesystem.file = join(root, '..', 'outside-file');
    assert.throws(() => diagnosticLocations('trufflehog', {
      stdout: JSON.stringify(unowned),
    }, root, entries), /diagnostic-path-outside-snapshot/);
    assert.throws(() => diagnosticLocations('unknown', input.gitleaks, root, entries),
      /unsupported-diagnostic-tool/);
    for (const change of [{ RuleID: input.material }, { File: `${input.material}.mjs` }]) {
      assert.throws(() => diagnosticLocations('gitleaks', {
        stdout: JSON.stringify([{ ...original, ...change }]),
      }, root, [...entries, { path: `${input.material}.mjs` }]), /diagnostic-metadata-contains-finding-material/);
    }
    const leaked = JSON.parse(input.trufflehog.stdout);
    leaked.DetectorName = input.material;
    assert.throws(() => diagnosticLocations('trufflehog', { stdout: JSON.stringify(leaked) }, root, entries),
      /diagnostic-metadata-contains-finding-material/);
  }));

test('T42: diagnostic destinations must be outside the scanned root and every other Git checkout',
  async () => workspace(async root => {
    const current = join(root, 'current');
    const legacy = join(root, 'legacy');
    await mkdir(current);
    await mkdir(legacy);
    await mkdir(join(current, '.git'));
    await writeFile(join(legacy, '.git'), 'owned fixture marker');
    assert.equal(await diagnosticOutputPath(join(root, 'report.json'), current), join(root, 'report.json'));
    await assert.rejects(() => diagnosticOutputPath(join(current, 'report.json'), current),
      /diagnostic-output-inside-candidate/);
    await assert.rejects(() => diagnosticOutputPath(join(legacy, 'report.json'), current),
      /diagnostic-output-inside-git-checkout/);
    await assert.rejects(() => diagnosticOutputPath('relative-report.json', current),
      /diagnostic-absolute-paths-required/);
  }));

test('T42: diagnostics require explicit local opt-in, reject CI, and never overwrite original evidence',
  async () => workspace(async root => {
    const previous = process.env.CI;
    try {
      delete process.env.CI;
      const source = join(root, 'source');
      await mkdir(source);
      const output = join(root, 'original-report.json');
      const original = 'preserved fixture evidence';
      await writeFile(output, original);
      assert.equal((await main(['--root', source, '--output', output])).error, 'local-diagnostics-not-for-ci');
      assert.equal((await diagnoseSource({ root: source, tools: {} })).error, 'local-diagnostics-not-for-ci');
      assert.equal((await main(['--local-only', '--root', source, '--output', output])).error,
        'diagnostic-output-exists');
      assert.equal(await readFile(output, 'utf8'), original);
      process.env.CI = 'true';
      assert.equal((await main(['--local-only', '--root', source, '--output', output])).error,
        'local-diagnostics-not-for-ci');
      assert.equal((await diagnoseSource({ root: source, tools: {}, localOnly: true })).error,
        'local-diagnostics-not-for-ci');
    } finally {
      if (previous === undefined) delete process.env.CI;
      else process.env.CI = previous;
    }
  }));
