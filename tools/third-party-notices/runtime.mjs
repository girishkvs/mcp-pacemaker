import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { noticeComments, readText, relativeFile, sha256 } from './inventory.mjs';

const DIRECTORY = fileURLToPath(new URL('./', import.meta.url));

export function runtimeNotices(root, reviewed, licenseDirectory = DIRECTORY) {
  reviewed ??= JSON.parse(readText(path.join(DIRECTORY, 'reviewed-runtime.json')));
  const lock = JSON.parse(readText(path.join(root, 'package-lock.json')));
  const installedLock = JSON.parse(readText(path.join(root, 'node_modules', '.package-lock.json')));
  return reviewed.map((entry) => {
    const lockPath = `node_modules/${entry.name}`;
    const locked = lock.packages[lockPath];
    const installed = installedLock.packages[lockPath];
    for (const field of ['version', 'license', 'resolved', 'integrity']) {
      if (locked?.[field] !== entry.resolution[field] ||
          installed?.[field] !== entry.resolution[field]) {
        throw new Error(`Runtime license supplement requires matching root/installed locks: ${entry.name}`);
      }
    }
    const directory = path.resolve(root, lockPath);
    relativeFile(root, directory);
    if (fs.realpathSync(directory) !== directory) {
      throw new Error('Linked runtime package requires license review');
    }
    const metadata = JSON.parse(readText(path.join(directory, 'package.json')));
    if (metadata.name !== entry.name ||
        metadata.version !== entry.resolution.version ||
        metadata.license !== entry.resolution.license) {
      throw new Error(`Installed runtime identity differs from reviewed license: ${entry.name}`);
    }
    const comments = new Set();
    for (const [source, digest] of Object.entries(entry.upstreamSourceSha256)) {
      const file = path.resolve(directory, source);
      relativeFile(directory, file);
      const text = readText(file);
      if (sha256(text) !== digest) {
        throw new Error(`Runtime source differs from immutable license reference: ${entry.name}/${source}`);
      }
      for (const comment of noticeComments(text)) comments.add(comment);
    }
    const licenseFile = path.resolve(licenseDirectory, entry.licenseFile);
    relativeFile(licenseDirectory, licenseFile);
    const text = readText(licenseFile);
    if (sha256(text) !== entry.licenseSha256) {
      throw new Error(`Runtime supplementary MIT text is missing or changed: ${entry.name}`);
    }
    return {
      name: entry.name,
      version: entry.resolution.version,
      license: entry.resolution.license,
      distribution: 'separately-installed',
      lockPath,
      resolution: entry.resolution,
      upstreamCommit: entry.upstreamCommit,
      upstreamPackagePath: entry.upstreamPackagePath,
      upstreamPackageJsonSha256: entry.upstreamPackageJsonSha256,
      upstreamSourceSha256: entry.upstreamSourceSha256,
      licenses: [{
        file: entry.licenseFile,
        sha256: entry.licenseSha256,
        sourceUrl: entry.licenseSourceUrl,
        reason: 'Supplement for the separately npm-installed runtime package, whose published source refers to this upstream LICENSE. This package is not bundled into the dashboard.',
        text,
      }],
      comments: [...comments].sort(),
    };
  });
}
