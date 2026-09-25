import assert from 'node:assert/strict';
import { lstatSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { digest, validatePackage } from './policy.mjs';

function readTarball(bytes, approval) {
  assert.ok(bytes.length <= 32 * 1024 * 1024, 'Unexpectedly large package');
  const tar = gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 });
  const files = [];
  const contents = new Map();
  const seen = new Set();
  let pkg;
  let offset = 0;
  let ended = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) {
      assert.ok(tar.subarray(offset).every(value => value === 0), 'Data after tar terminator');
      ended = true;
      break;
    }
    const text = (start, size) => header.subarray(start, start + size).toString('utf8').replace(/\0.*$/s, '');
    const octal = (start, size) => {
      const value = text(start, size).trim();
      assert.match(value, /^[0-7]+$/, 'Unsupported tar numeric encoding');
      return Number.parseInt(value, 8);
    };
    const checksum = [...header].reduce((sum, value, index) =>
      sum + (index >= 148 && index < 156 ? 32 : value), 0);
    assert.equal(octal(148, 8), checksum, 'Invalid tar header checksum');
    const prefix = text(345, 155);
    const path = `${prefix ? `${prefix}/` : ''}${text(0, 100)}`;
    const type = text(156, 1);
    const size = octal(124, 12);
    assert.ok(['', '0', '5'].includes(type), 'Links, PAX overrides and special tar entries are not reviewed');
    assert.match(path, /^package\/[A-Za-z0-9_./@+-]+$/, 'Unsafe tar path');
    const relative = path.slice('package/'.length).replace(/\/$/, '');
    assert.ok(relative.split('/').every(part => part !== '' &&
      part !== '.' &&
      part !== '..'), 'Tar path traversal');
    assert.ok(!seen.has(relative.toLowerCase()), 'Duplicate or case-colliding tar entry');
    seen.add(relative.toLowerCase());
    offset += 512;
    assert.ok(offset + size <= tar.length, 'Truncated tar entry');
    const data = tar.subarray(offset, offset + size);
    if (type === '5') {
      assert.equal(size, 0);
    } else {
      assert.ok(!/(^|\/)(?:\.git|\.npmrc|\.env(?:\..*)?|node_modules|package-lock\.json|npm-shrinkwrap\.json)(\/|$)/i.test(relative),
        'Forbidden package payload');
      const mode = octal(100, 8);
      assert.ok([0o644, 0o755].includes(mode), 'Unexpected tar file mode');
      files.push({ path: relative, size, mode, sha256: digest(data).sha256 });
      contents.set(relative, data);
      if (relative === 'package.json') pkg = JSON.parse(data.toString('utf8'));
    }
    offset += Math.ceil(size / 512) * 512;
  }
  assert.ok(ended, 'Missing tar terminator');
  assert.ok(pkg, 'Missing actual packed package.json');
  validatePackage(pkg, approval);
  const always = ['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md'];
  assert.ok(Array.isArray(pkg.files), 'Explicit package file allowlist required');
  for (const file of files) {
    const allowed = always.includes(file.path) ||
      pkg.files.some(entry => entry.endsWith('/') ? file.path.startsWith(entry) : file.path === entry);
    assert.ok(allowed, `File outside package allowlist: ${file.path}`);
  }
  const requiredFiles = [
    'bin/cli.mjs', 'bin/mcp-bridge.mjs', 'ui/dist/index.html', 'LICENSE',
    'THIRD_PARTY_NOTICES.txt', 'ui/dist/THIRD_PARTY_NOTICES.txt', 'ui/dist/third-party-manifest.json',
  ];
  for (const path of requiredFiles) {
    const file = files.find(file => file.path === path);
    assert.ok(file, `Missing runtime or notice file: ${path}`);
    assert.ok(file.size > 0, `Empty runtime or notice file: ${path}`);
  }
  return { package: pkg, files: files.sort((a, b) => a.path.localeCompare(b.path)), contents };
}

export function inspectTarball(bytes, approval) {
  const { contents, ...inspection } = readTarball(bytes, approval);
  return inspection;
}

export function extractTarball(bytes, approval, destination) {
  const { contents, ...inspection } = readTarball(bytes, approval);
  const stat = lstatSync(destination);
  assert.ok(stat.isDirectory() &&
    !stat.isSymbolicLink(), 'Extraction destination must be an owned real directory');
  assert.deepEqual(readdirSync(destination), [], 'Extraction destination must be empty');
  for (const file of inspection.files) {
    const path = join(destination, file.path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents.get(file.path), { flag: 'wx', mode: file.mode });
  }
  return inspection;
}
