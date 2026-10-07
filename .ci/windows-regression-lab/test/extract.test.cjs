const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const generator = [
  'import json,sys,zipfile',
  'with zipfile.ZipFile(sys.argv[1],"w") as z:',
  ' for item in json.loads(sys.argv[2]):',
  '  info=zipfile.ZipInfo(item["name"])',
  '  info.external_attr=item.get("attributes",0)',
  '  z.writestr(info,item.get("data","synthetic"))'
].join('\n');

test('extractor accepts the approved shape and rejects unsafe archive names and links', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-zip-test-'));
  const cases = [
    { name: 'valid', files: [{ name: 'run.ps1', data: 'exit 0' }, { name: 'src/data.txt' }], ok: true },
    { name: 'traversal', files: [{ name: 'run.ps1' }, { name: '../outside.txt' }], ok: false },
    { name: 'absolute', files: [{ name: 'run.ps1' }, { name: 'C:/outside.txt' }], ok: false },
    { name: 'case-duplicate', files: [{ name: 'run.ps1' }, { name: 'RUN.PS1' }], ok: false },
    { name: 'device', files: [{ name: 'run.ps1' }, { name: 'NUL.txt' }], ok: false },
    { name: 'trailing-dot', files: [{ name: 'run.ps1' }, { name: 'alias.' }], ok: false },
    { name: 'symlink', files: [{ name: 'run.ps1' }, { name: 'link', attributes: 0xa1ff0000 }], ok: false },
    { name: 'no-entrypoint', files: [{ name: 'other.ps1' }], ok: false }
  ];
  try {
    for (const item of cases) {
      const archive = path.join(root, item.name + '.zip');
      const destination = path.join(root, item.name);
      const made = spawnSync('python', ['-c', generator, archive, JSON.stringify(item.files)], { encoding: 'utf8' });
      assert.equal(made.status, 0, item.name + ': fixture generation');
      const extracted = spawnSync('pwsh', [
        '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, '..', 'extract-bundle.ps1'),
        '-Archive', archive, '-Destination', destination
      ], { encoding: 'utf8', timeout: 15000 });
      assert.equal(extracted.status === 0, item.ok, item.name + ': ' + extracted.stderr);
      if (!item.ok) {
        assert.equal(fs.existsSync(destination), false, item.name);
      }
    }
    assert.equal(fs.existsSync(path.join(root, 'outside.txt')), false);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
