import assert from 'node:assert/strict';
import { lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { InputSnapshot, physical, safeName } from './local-inputs.mjs';
import { LOCAL_CASES, LOCAL_CONTROLLER, LOCAL_VERSIONS, localHash, localCommitment } from './local-regression.mjs';

export function readLocalBytes(path, limit = 32 * 1024 ** 2) {
  physical(path);
  const stat = lstatSync(path);
  assert.ok(stat.isFile() &&
    stat.nlink === 1 &&
    stat.size > 0 &&
    stat.size <= limit, 'Missing, linked, empty or oversized local evidence');
  const bytes = readFileSync(path);
  assert.equal(bytes.length, stat.size, 'Evidence changed during read');
  return bytes;
}

export function readLocalJson(path, limit) {
  return JSON.parse(readLocalBytes(path, limit).toString('utf8'));
}

export function controllerBinding(root) {
  const files = LOCAL_CONTROLLER.map(path => ({ path, sha256: localHash(readLocalBytes(join(root, path))) }));
  return { files, sha256: localCommitment(files) };
}

export function evidenceInventory(root) {
  const expected = ['result.json', 'evidence-manifest.json', 'commands', 'controller', 'runtime', 'docker-config',
    ...LOCAL_VERSIONS.map(version => `inputs-${version}`),
    ...LOCAL_CASES.flatMap(item => [item.name, `${item.name}-storage-admission.json`])];
  const actual = readdirSync(physical(root)).filter(name => name !== 'evidence-manifest.json').sort();
  assert.deepEqual(actual, expected.filter(name => name !== 'evidence-manifest.json').sort(),
    'Missing or unexpected local run members');
  assert.deepEqual(readdirSync(physical(join(root, 'docker-config'))), [], 'Unexpected private Docker configuration');
  const snapshot = new InputSnapshot(root, { maxBytes: 2 * 1024 ** 3, maxFiles: 100_000 });
  for (const path of ['result.json', 'commands', 'controller', 'runtime',
    ...LOCAL_VERSIONS.map(version => `inputs-${version}/manifest.json`),
    ...LOCAL_CASES.flatMap(item => [item.name, `${item.name}-storage-admission.json`])]) snapshot.add(path);
  for (const file of snapshot.files) {
    assert.equal(lstatSync(join(root, file.path)).nlink, 1, 'Hardlinked evidence is not independent');
  }
  return { schemaVersion: 1, files: snapshot.files, directories: snapshot.directories };
}

export function writeEvidenceInventory(root) {
  const manifest = evidenceInventory(root);
  writeFileSync(join(root, 'evidence-manifest.json'), `${JSON.stringify(manifest)}\n`,
    { flag: 'wx', flush: true });
}

// Read only: never extract or execute archive content.
export function evidenceTar(bytes) {
  assert.ok(Buffer.isBuffer(bytes) &&
    bytes.length <= 128 * 1024 ** 2);
  const files = [];
  const directories = [];
  const seen = new Set();
  let offset = 0;
  let pax;
  let ended = false;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) {
      assert.ok(bytes.subarray(offset).every(value => value === 0));
      ended = true;
      break;
    }
    const text = (start, length) => {
      const value = header.subarray(start, start + length).toString('utf8');
      const terminator = value.indexOf('\0');
      return terminator === -1 ? value : value.slice(0, terminator);
    };
    const octal = (start, length) => {
      const value = text(start, length).trim();
      assert.ok(value.length > 0 &&
        [...value].every(character => character >= '0' &&
          character <= '7'), 'Unsupported TAR octal field');
      const number = Number.parseInt(value, 8);
      assert.ok(Number.isSafeInteger(number));
      return number;
    };
    const checksum = [...header].reduce((sum, value, index) =>
      sum + (index >= 148 && index < 156 ? 32 : value), 0);
    assert.equal(octal(148, 8), checksum, 'Invalid evidence TAR checksum');
    const type = text(156, 1);
    const size = octal(124, 12);
    assert.ok(size <= 32 * 1024 ** 2);
    offset += 512;
    assert.ok(offset + size <= bytes.length);
    const data = bytes.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;
    if (type === 'x') {
      assert.equal(pax, undefined, 'Repeated PAX header');
      pax = {};
      let at = 0;
      while (at < data.length) {
        const space = data.indexOf(32, at);
        assert.ok(space > at);
        const lengthText = data.subarray(at, space).toString('ascii');
        assert.match(lengthText, /^[1-9][0-9]*$/);
        const length = Number(lengthText);
        assert.ok(Number.isSafeInteger(length) &&
          length > space - at + 2 &&
          at + length <= data.length);
        const field = data.subarray(space + 1, at + length).toString('utf8');
        assert.equal(field.at(-1), '\n');
        const equals = field.indexOf('=');
        const key = field.slice(0, equals);
        assert.ok(['path', 'mtime', 'atime', 'ctime'].includes(key) &&
          !Object.hasOwn(pax, key), 'Unreviewed PAX override');
        pax[key] = field.slice(equals + 1, -1);
        at += length;
      }
      continue;
    }
    assert.ok(['', '0', '5'].includes(type), 'Linked or special evidence TAR member');
    const prefix = text(345, 155);
    const path = (pax?.path ?? `${prefix ? `${prefix}/` : ''}${text(0, 100)}`).replace(/\/$/, '');
    pax = undefined;
    safeName(path);
    assert.ok(path === 'output' ||
      path.startsWith('output/'));
    assert.equal(seen.has(path.toLowerCase()), false, 'Duplicate evidence TAR path');
    seen.add(path.toLowerCase());
    assert.ok(seen.size <= 10_000);
    if (type === '5') {
      assert.equal(size, 0);
      if (path !== 'output') directories.push(path.slice(7));
    } else {
      assert.notEqual(path, 'output');
      files.push({ path: path.slice(7), size, sha256: localHash(data) });
    }
  }
  assert.ok(ended &&
    pax === undefined, 'Incomplete evidence TAR');
  return { files: files.sort((a, b) => a.path.localeCompare(b.path)), directories: directories.sort() };
}
