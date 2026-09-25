import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const inside = (root, path) => {
  const name = relative(root, resolve(path));
  return name === '' ||
    (!name.startsWith(`..${sep}`) &&
      name !== '..' &&
      !name.includes(':'));
};

export function npmLoaderInventory(root) {
  const files = [];
  let bytes = 0;
  const visit = (directory, prefix = '') => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      // npm install creates OS-specific command shims here. They are never
      // permitted loader destinations; all package manifests and source remain bound.
      if (prefix === 'node_modules/' &&
          entry.name === '.bin') continue;
      const path = `${prefix}${entry.name}`;
      const full = join(directory, entry.name);
      const stat = lstatSync(full);
      assert.equal(stat.isSymbolicLink(), false, 'Linked npm loader input is forbidden');
      if (stat.isDirectory()) visit(full, `${path}/`);
      else {
        assert.ok(stat.isFile(), 'Special npm loader input is forbidden');
        bytes += stat.size;
        assert.ok(bytes <= 64 * 1024 * 1024 &&
          files.length < 5000, 'Unexpected npm distribution size');
        files.push({ path, bytes: stat.size, sha256: hash(readFileSync(full)) });
      }
    }
  };
  visit(root);
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { files: files.length, bytes, sha256: hash(JSON.stringify(files)) };
}

export function validateStageLoader(cli) {
  const entry = realpathSync.native(cli);
  const root = resolve(dirname(entry), '..');
  assert.equal(entry, join(root, 'bin/npm-cli.js'));
  const require = createRequire(entry);
  assert.ok(!Object.getOwnPropertyNames(require.cache).some(path => inside(root, path)),
    'Pinned npm must start with an empty module cache before any critical library loads');
  const binding = JSON.parse(readFileSync(new URL('./stage-sdk-loader.json', import.meta.url)));
  assert.equal(binding.schemaVersion, 1);
  assert.deepEqual(npmLoaderInventory(root), binding.inventory,
    'Pinned npm loader distribution changed (including manifests, exports and delegates)');
  for (const item of binding.resolutions) {
    const caller = createRequire(join(root, item.from));
    const actual = caller.resolve(item.request);
    const expected = join(root, item.path);
    assert.equal(actual, expected, 'npm require.resolve differs from the reviewed entrypoint');
    assert.equal(realpathSync.native(actual), expected, 'Resolved npm entrypoint is not physical');
    assert.ok(!item.path.split('/').includes('.bin'));
  }
  for (const [path, name, version] of [
    ['package.json', 'npm', '12.0.2'],
    ['node_modules/libnpmpublish/package.json', 'libnpmpublish', '12.0.0'],
    ['node_modules/sigstore/package.json', 'sigstore', '5.0.0'],
    ['node_modules/@sigstore/sign/package.json', '@sigstore/sign', '5.0.0'],
  ]) {
    const pkg = JSON.parse(readFileSync(join(root, path), 'utf8'));
    assert.equal(pkg.name, name);
    assert.equal(pkg.version, version);
  }
  return { entry, root, require };
}
