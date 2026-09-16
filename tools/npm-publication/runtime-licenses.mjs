import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import { runtimeNotices } from '../third-party-notices/runtime.mjs';
import { licenseIdentity, validateConsumerLicenseEvidence } from '../npm-consumer/license-evidence.mjs';

export const REVIEWED_LICENSES = Object.freeze([
  'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'CC0-1.0',
  '(MIT OR CC0-1.0)', '(MIT AND CC0-1.0)',
]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const key = pkg => `${pkg.name}@${pkg.version}`;
export const LICENSE_FAILURE_HINTS = Object.freeze({
  'consumer-platforms': 'Consumer matrix evidence rejected. Verify all six immutable schema 2 reports, both install modes, and exact source/artifact bindings. Rerun fresh consumers for missing or changed evidence.',
  'licenses-notices': 'License evidence rejected. Review exact consumer versions, hashes, declarations, and canonical notices. Do not substitute producer files or reuse changed evidence.',
});

export function safeLicenseDiagnostic(value, gate = 'licenses-notices') {
  if (typeof value !== 'string' ||
      value.length > 512) return undefined;
  if (value === LICENSE_FAILURE_HINTS[gate]) return value;
  if (gate !== 'licenses-notices') return undefined;
  const format = /^Exact-version license (?:text )?review required: (?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?(?: \((?:unknown or missing declaration|text does not support declaration|no standalone license text|missing or changed reviewed packed supplement|conflicting consumer evidence)\))?$/;
  return format.exec(value)?.[0] === value ? value : undefined;
}

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
  const files = readdirSync(root).filter(name => /^(?:licen[sc]e|copying|copyright)(?:[._-].*)?$/i.test(name)).sort();
  const records = files.map(name => {
    const file = join(root, name);
    const record = localFile(root, file);
    const text = readFileSync(file, 'utf8');
    return { ...record, text };
  });
  return reviewedText(records, pkg);
}

function reviewedText(records, pkg) {
  for (const { text } of records) {
    requireReview(text.trim().length >= 100 &&
      !text.includes('\0'), `Exact-version license text review required: ${key(pkg)}`);
  }
  if (!records.length) return [];
  const text = records.map(item => item.text).join('\n');
  const lower = text.toLowerCase();
  const orderedMarkers = (first, last) => {
    const start = lower.indexOf(first);
    return start !== -1 &&
      lower.indexOf(last, start + first.length) !== -1;
  };
  const markers = {
    MIT: /permission is hereby granted/i,
    ISC: /permission to use, copy, modify, and(?:\/or)? distribute/i,
    'BSD-2-Clause': /redistribution and use in source and binary forms/i,
    'BSD-3-Clause': /redistribution and use in source and binary forms/i,
  };
  const identifiers = pkg.license.match(/MIT|ISC|BSD-[23]-Clause|Apache-2\.0|CC0-1\.0/g);
  const matches = identifiers.map(id => {
    if (id === 'Apache-2.0') return orderedMarkers('apache license', 'version 2.0');
    if (id === 'CC0-1.0') return lower.includes('cc0') ||
      orderedMarkers('creative commons', 'universal');
    return markers[id].test(text);
  });
  requireReview(pkg.license.includes(' OR ') ? matches.some(Boolean) : matches.every(Boolean),
    `Exact-version license text review required: ${key(pkg)} (text does not support declaration)`);
  return records.map(({ text: ignored, ...record }) => record);
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
  const captured = new Map();
  for (const consumer of consumers) {
    requireReview(consumer.producerLockCopied === false &&
      Array.isArray(consumer.dependencies) &&
      consumer.dependencies.length > 0, 'License coverage requires fresh consumer graphs');
    const evidence = validateConsumerLicenseEvidence(consumer);
    for (const item of evidence.packages) {
      const previous = captured.get(key(item));
      requireReview(!previous ||
        licenseIdentity(previous) === licenseIdentity(item),
      `Exact-version license review required: ${key(item)} (conflicting consumer evidence)`);
      captured.set(key(item), { ...item, instances: (previous?.instances ?? 0) + 1 });
      needed.set(key(item), { name: item.name, version: item.version });
    }
  }
  needed.set(`${name}@${version}`, { name, version });
  let supplements;
  const packages = [];
  for (const coordinate of [...needed.values()].sort((a, b) => key(a).localeCompare(key(b)))) {
    const candidate = coordinate.name === name &&
      coordinate.version === version;
    const item = captured.get(key(coordinate));
    const pkg = JSON.parse(candidate ? readFileSync(join(extractedRoot, 'package.json'), 'utf8') : item.packageJson.text);
    requireReview(key(pkg) === key(coordinate), 'Candidate license identity mismatch');
    const license = declaration(pkg);
    const files = candidate ? licenseFiles(extractedRoot, pkg) : reviewedText(item.files, pkg);
    let source = candidate ? 'extracted-candidate' : 'fresh-consumer-exact-version';
    if (candidate) {
      requireReview(files.some(file => file.path === 'LICENSE'), 'Candidate LICENSE is required');
      if (item) {
        requireReview(item.packageJson.sha256 === localFile(extractedRoot, join(extractedRoot, 'package.json')).sha256 &&
          JSON.stringify(item.files.map(({ text: ignored, ...file }) => file)) === JSON.stringify(files),
        'Candidate consumer license evidence differs from the canonical tarball');
      }
    } else if (pkg.name === 'yoga-layout') {
      supplements ??= await readSupplements(sourceRoot);
      const actual = supplements.find(entry => key(entry) === key(pkg));
      const packed = manifest.runtimeNotices.find(entry => key(entry) === key(pkg));
      const matchingSupplement = actual &&
        packed &&
        JSON.stringify(actual) === JSON.stringify(packed) &&
        packed.license === license &&
        packed.distribution === 'separately-installed' &&
        packed.resolution.integrity === item.integrity &&
        JSON.stringify(item.reviewedSources) === JSON.stringify(Object.entries(packed.upstreamSourceSha256)
          .sort(([a], [b]) => a.localeCompare(b)).map(([path, sha256]) => ({ path, sha256 })));
      requireReview(matchingSupplement,
        `Exact-version license review required: ${key(pkg)} (missing or changed reviewed packed supplement)`);
      if (!files.length) {
        for (const record of packed.licenses) {
          requireReview(hash(record.text) === record.sha256, 'Runtime supplement hash mismatch');
          files.push({ path: `ui/dist/third-party-manifest.json#runtimeNotices/${key(pkg)}/${record.file}`,
            sha256: record.sha256 });
        }
        source = 'reviewed-exact-consumer-version-and-packed-supplement';
      }
    }
    requireReview(files.length > 0, `Exact-version license review required: ${key(pkg)} (no standalone license text)`);
    packages.push({ ...coordinate, license, source,
      integrity: item?.integrity ?? null, consumerInstances: item?.instances ?? 0,
      packageJson: candidate ? localFile(extractedRoot, join(extractedRoot, 'package.json')) :
        { path: 'package.json', sha256: item.packageJson.sha256 }, files });
  }
  return {
    packages,
    coverage: {
      consumerGraphs: consumers.length, distinctCoordinates: needed.size,
      constraint: 'Every actual consumer path/name/version/integrity requires hash-bound license evidence from that fresh install. Candidate LICENSE comes from the canonical tarball. No producer fallback.',
      resolution: 'independently-resolved-consumers; no registry queries or installs by this helper',
    },
    notices: ['LICENSE', 'THIRD_PARTY_NOTICES.txt', 'ui/dist/THIRD_PARTY_NOTICES.txt',
      'ui/dist/third-party-manifest.json'].map(file => localFile(extractedRoot, join(extractedRoot, file))),
  };
}
