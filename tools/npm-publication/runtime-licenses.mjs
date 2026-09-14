import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { runtimeNotices } from '../third-party-notices/runtime.mjs';

export const REVIEWED_LICENSES = Object.freeze([
  'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'CC0-1.0',
  '(MIT OR CC0-1.0)', '(MIT AND CC0-1.0)',
]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const key = pkg => `${pkg.name}@${pkg.version}`;

function requireReview(condition, message) {
  if (!condition) throw new Error(message);
}

function localFile(root, file) {
  const path = relative(resolve(root), resolve(file));
  requireReview(path &&
    path !== '..' &&
    !path.startsWith(`..${sep}`) &&
    !isAbsolute(path), 'License evidence must remain inside its package');
  requireReview(realpathSync(file) === resolve(file) &&
    lstatSync(file).isFile(), 'Linked or non-file license evidence requires review');
  return { path: path.split(sep).join('/'), sha256: hash(readFileSync(file)) };
}

function declaration(pkg) {
  requireReview(REVIEWED_LICENSES.includes(pkg.license),
    `Exact-version license review required: ${key(pkg)} (unknown or missing declaration)`);
  return pkg.license;
}

function licenseFiles(root, pkg) {
  const files = readdirSync(root).filter(name => /^(?:licen[sc]e|copying|copyright)(?:[._-].*)?$/i.test(name));
  const records = files.map(name => {
    const file = join(root, name);
    const record = localFile(root, file);
    const text = readFileSync(file, 'utf8');
    requireReview(text.trim().length >= 100 &&
      !text.includes('\0'), `Exact-version license text review required: ${key(pkg)}`);
    return { ...record, text };
  });
  if (!records.length) return [];
  const text = records.map(item => item.text).join('\n');
  const markers = {
    MIT: /permission is hereby granted/i,
    ISC: /permission to use, copy, modify, and(?:\/or)? distribute/i,
    'BSD-2-Clause': /redistribution and use in source and binary forms/i,
    'BSD-3-Clause': /redistribution and use in source and binary forms/i,
    'Apache-2.0': /Apache License[\s\S]*Version 2\.0/i,
    'CC0-1.0': /CC0|Creative Commons[\s\S]*Universal/i,
  };
  const identifiers = pkg.license.match(/MIT|ISC|BSD-[23]-Clause|Apache-2\.0|CC0-1\.0/g);
  const matches = identifiers.map(id => markers[id].test(text));
  requireReview(pkg.license.includes(' OR ') ? matches.some(Boolean) : matches.every(Boolean),
    `Exact-version license text review required: ${key(pkg)} (text does not support declaration)`);
  return records.map(({ text: ignored, ...record }) => record);
}

function installedPackages(sourceRoot) {
  const packages = [];
  const visit = directory => {
    requireReview(realpathSync(directory) === resolve(directory) &&
      lstatSync(directory).isDirectory(), 'Linked installed dependency requires license review');
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const path = join(directory, entry.name);
      requireReview(!entry.isSymbolicLink(), 'Linked installed dependency requires license review');
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('@')) {
        visit(path);
        continue;
      }
      localFile(sourceRoot, join(path, 'package.json'));
      const pkg = JSON.parse(readFileSync(join(path, 'package.json'), 'utf8'));
      packages.push({ root: path, pkg });
      if (readdirSync(path).includes('node_modules')) visit(join(path, 'node_modules'));
    }
  };
  visit(join(sourceRoot, 'node_modules'));
  return packages;
}

// No install or registry access. Consumer resolution remains independent of producer locks.
export async function inspectRuntimeLicenses({
  sourceRoot, extractedRoot, consumers, name, version,
}, { verifyNotices = verifyArtifacts, readSupplements = runtimeNotices } = {}) {
  requireReview(Array.isArray(consumers) &&
    consumers.length > 0, 'Actual consumer graphs are required for license coverage');
  const manifest = await verifyNotices(extractedRoot);
  for (const pkg of [...(manifest.packages ?? []), ...manifest.runtimeNotices]) declaration(pkg);
  const needed = new Map();
  for (const consumer of consumers) {
    requireReview(consumer.producerLockCopied === false &&
      Array.isArray(consumer.dependencies) &&
      consumer.dependencies.length > 0, 'License coverage requires fresh consumer graphs');
    for (const pkg of consumer.dependencies) {
      requireReview(/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(pkg.name) &&
        /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(pkg.version), 'Invalid license coordinate');
      needed.set(key(pkg), { name: pkg.name, version: pkg.version });
    }
  }
  needed.set(`${name}@${version}`, { name, version });
  const installed = installedPackages(sourceRoot);
  let supplements;
  const packages = [];
  for (const coordinate of [...needed.values()].sort((a, b) => key(a).localeCompare(key(b)))) {
    const candidate = coordinate.name === name &&
      coordinate.version === version;
    const matches = candidate
      ? [{ root: extractedRoot, pkg: JSON.parse(readFileSync(join(extractedRoot, 'package.json'), 'utf8')) }]
      : installed.filter(item => key(item.pkg) === key(coordinate));
    requireReview(matches.length > 0,
      `Exact-version license review required: ${key(coordinate)} (not installed in producer evidence; restore/review this exact version separately)`);
    for (const { root, pkg } of matches) {
      requireReview(key(pkg) === key(coordinate), 'Candidate license identity mismatch');
      const license = declaration(pkg);
      const files = licenseFiles(root, pkg);
      let source = candidate ? 'extracted-candidate' : 'installed-producer-exact-version';
      if (candidate) {
        requireReview(files.some(file => file.path === 'LICENSE'), 'Candidate LICENSE is required');
      } else if (!files.length) {
        requireReview(pkg.name === 'yoga-layout',
          `Exact-version license review required: ${key(pkg)} (no standalone license text)`);
        supplements ??= await readSupplements(sourceRoot);
        const actual = supplements.find(item => key(item) === key(pkg));
        const packed = manifest.runtimeNotices.find(item => key(item) === key(pkg));
        requireReview(actual &&
          packed &&
          JSON.stringify(actual) === JSON.stringify(packed) &&
          packed.license === license &&
          packed.distribution === 'separately-installed',
        `Exact-version license review required: ${key(pkg)} (missing or changed reviewed packed supplement)`);
        for (const item of packed.licenses) {
          requireReview(hash(item.text) === item.sha256, 'Runtime supplement hash mismatch');
          files.push({ path: `ui/dist/third-party-manifest.json#runtimeNotices/${key(pkg)}/${item.file}`,
            sha256: item.sha256 });
        }
        source = 'reviewed-exact-installed-version-and-packed-supplement';
      }
      requireReview(files.length > 0, `Exact-version license review required: ${key(pkg)}`);
      packages.push({ ...coordinate, license, source,
        packageJson: localFile(root, join(root, 'package.json')), files });
    }
  }
  return {
    packages,
    coverage: {
      consumerGraphs: consumers.length, distinctCoordinates: needed.size,
      constraint: 'Every actual consumer name/version must have installed producer exact-version license evidence, or the candidate LICENSE. No producer lock is called a consumer lock.',
      resolution: 'independently-resolved-consumers; no registry queries or installs by this helper',
    },
    notices: ['LICENSE', 'THIRD_PARTY_NOTICES.txt', 'ui/dist/THIRD_PARTY_NOTICES.txt',
      'ui/dist/third-party-manifest.json'].map(file => localFile(extractedRoot, join(extractedRoot, file))),
  };
}
