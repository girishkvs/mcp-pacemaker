import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';

const hash = value => createHash('sha256').update(value).digest('hex');
const NAME = '(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*';
const PACKAGE_PATH = new RegExp(`^node_modules/(?:${NAME}/node_modules/)*${NAME}$`);
const LIMIT = 8 * 1024 * 1024;
const FILE_LIMIT = 1024 * 1024;
const reviewed = JSON.parse(readFileSync(new URL('../third-party-notices/reviewed-runtime.json', import.meta.url)));
export const licenseFileName = name => /^(?:licen[sc]e|copying|copyright)(?:[._-].*)?$/i.test(name);

function keys(value, expected) {
  assert.ok(value &&
    typeof value === 'object' &&
    !Array.isArray(value), 'Missing consumer license evidence');
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), 'Unexpected consumer license evidence fields');
}

function coordinate(item) {
  assert.ok(typeof item.path === 'string' &&
    item.path.length <= 2048 &&
    PACKAGE_PATH.exec(item.path)?.[0] === item.path, 'Invalid consumer package path');
  assert.ok(typeof item.name === 'string' &&
    item.name.length <= 214 &&
    new RegExp(`^${NAME}$`).exec(item.name)?.[0] === item.name, 'Invalid consumer license name');
  assert.equal(item.path.slice(item.path.lastIndexOf('node_modules/') + 13), item.name,
    'Consumer package path/name mismatch');
  assert.match(item.version ?? '', /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/);
  assert.ok(item.version.length <= 128 &&
    !/[\r\n]/.test(item.version));
  const sri = /^sha(1|256|384|512)-([A-Za-z0-9+/]+={0,2})$/.exec(item.integrity ?? '');
  assert.ok(sri, 'Consumer license evidence requires dependency integrity');
  assert.equal(sri[0], item.integrity, 'Noncanonical dependency integrity');
  const bytes = Buffer.from(sri[2], 'base64');
  assert.equal(bytes.length, { 1: 20, 256: 32, 384: 48, 512: 64 }[sri[1]]);
  assert.equal(bytes.toString('base64'), sri[2], 'Noncanonical dependency integrity');
}

function safePath(path) {
  assert.ok(typeof path === 'string' &&
    path.length <= 256 &&
    path.split('/').every(part => /^[A-Za-z0-9][A-Za-z0-9._ -]*$/.exec(part)?.[0] === part),
  'Invalid consumer license file path');
}

function fileRecord(file, textRequired) {
  keys(file, textRequired ? ['path', 'sha256', 'text'] : ['path', 'sha256']);
  safePath(file.path);
  assert.match(file.sha256 ?? '', /^[a-f0-9]{64}$/);
  if (textRequired) {
    assert.ok(typeof file.text === 'string' &&
      Buffer.byteLength(file.text) <= FILE_LIMIT &&
      !file.text.includes('\0'), 'Invalid consumer license text');
    assert.equal(hash(file.text), file.sha256, 'Consumer license evidence hash mismatch');
  }
}

function uniqueFiles(files, textRequired) {
  assert.ok(Array.isArray(files) &&
    files.length <= 32, 'Invalid consumer license files');
  const paths = new Set();
  for (const file of files) {
    fileRecord(file, textRequired);
    assert.ok(!paths.has(file.path.toLowerCase()), 'Duplicate consumer license file');
    paths.add(file.path.toLowerCase());
  }
  assert.deepEqual(files.map(file => file.path), files.map(file => file.path).sort(),
    'Consumer license files must be ordered');
}

export function licenseIdentity(item) {
  return JSON.stringify({ integrity: item.integrity, packageJson: item.packageJson.sha256,
    files: item.files.map(({ path, sha256 }) => ({ path, sha256 })), reviewedSources: item.reviewedSources });
}

export function validateConsumerLicenseEvidence(consumer) {
  assert.equal(consumer.schemaVersion, 2, 'Fresh consumer schema 2 license evidence is required');
  const evidence = consumer.licenseEvidence;
  keys(evidence, ['schemaVersion', 'packages']);
  assert.equal(evidence.schemaVersion, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(evidence)) <= LIMIT, 'Consumer license evidence exceeds limit');
  assert.ok(Array.isArray(consumer.dependencies) &&
    consumer.dependencies.length > 0 &&
    consumer.dependencies.length <= 512, 'Invalid consumer license graph');
  assert.ok(Array.isArray(evidence.packages));
  assert.equal(evidence.packages.length, consumer.dependencies.length, 'Incomplete consumer license coverage');
  const paths = new Set();
  const identities = new Map();
  for (let index = 0; index < consumer.dependencies.length; index++) {
    const dependency = consumer.dependencies[index];
    keys(dependency, ['path', 'name', 'version', 'integrity']);
    coordinate(dependency);
    assert.ok(!paths.has(dependency.path.toLowerCase()), 'Duplicate consumer package path');
    paths.add(dependency.path.toLowerCase());
    const item = evidence.packages[index];
    keys(item, ['path', 'name', 'version', 'integrity', 'packageJson', 'files', 'reviewedSources']);
    for (const field of ['path', 'name', 'version', 'integrity']) {
      assert.equal(item[field], dependency[field], 'Consumer license coordinate/integrity mismatch');
    }
    fileRecord(item.packageJson, true);
    assert.equal(item.packageJson.path, 'package.json');
    const pkg = JSON.parse(item.packageJson.text);
    assert.equal(pkg.name, item.name, 'Consumer license package identity mismatch');
    assert.equal(pkg.version, item.version, 'Consumer license package identity mismatch');
    uniqueFiles(item.files, true);
    for (const file of item.files) {
      assert.ok(!file.path.includes('/') &&
        licenseFileName(file.path), 'Unexpected consumer license file');
    }
    uniqueFiles(item.reviewedSources, false);
    const supplement = reviewed.find(entry => entry.name === item.name &&
      entry.resolution.version === item.version);
    assert.deepEqual(item.reviewedSources.map(file => file.path),
      Object.keys(supplement?.upstreamSourceSha256 ?? {}).sort(), 'Unexpected reviewed consumer sources');
    const key = `${item.name}@${item.version}`;
    const identity = licenseIdentity(item);
    if (identities.has(key)) {
      assert.equal(identity, identities.get(key), 'Conflicting consumer license coordinate');
    }
    identities.set(key, identity);
  }
  return evidence;
}

function installedFile(root, path, includeText = true) {
  safePath(path);
  let file = root;
  const parts = path.split('/');
  for (let index = 0; index < parts.length; index++) {
    file = join(file, parts[index]);
    const stat = lstatSync(file);
    assert.ok(!stat.isSymbolicLink() &&
      realpathSync(file) === resolve(file), 'Linked consumer license evidence');
    assert.ok(index === parts.length - 1 ? stat.isFile() : stat.isDirectory(),
      'Non-file consumer license evidence');
  }
  assert.ok(lstatSync(file).size <= FILE_LIMIT, 'Consumer license file exceeds limit');
  const bytes = readFileSync(file);
  assert.ok(bytes.length <= FILE_LIMIT);
  if (!includeText) return { path, sha256: hash(bytes) };
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  assert.deepEqual(Buffer.from(text), bytes, 'Consumer license text encoding changed');
  return { path, sha256: hash(bytes), text };
}

// Runs only against the fresh consumer install, before its owned directory is removed.
export function captureConsumerLicenseEvidence(project, dependencies) {
  assert.equal(realpathSync(project), resolve(project), 'Linked consumer project');
  const packages = dependencies.map(item => {
    coordinate(item);
    let root = project;
    for (const part of item.path.split('/')) {
      root = join(root, part);
      assert.ok(lstatSync(root).isDirectory() &&
        realpathSync(root) === resolve(root), 'Linked consumer package path');
    }
    const supplement = reviewed.find(entry => entry.name === item.name &&
      entry.resolution.version === item.version);
    return {
      ...item, packageJson: installedFile(root, 'package.json'),
      files: readdirSync(root).filter(licenseFileName).sort().map(path => installedFile(root, path)),
      reviewedSources: Object.keys(supplement?.upstreamSourceSha256 ?? {}).sort()
        .map(path => installedFile(root, path, false)),
    };
  });
  const evidence = { schemaVersion: 1, packages };
  validateConsumerLicenseEvidence({ schemaVersion: 2, dependencies, licenseEvidence: evidence });
  return evidence;
}
