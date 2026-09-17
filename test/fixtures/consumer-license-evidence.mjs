import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const fixtureMit = 'MIT License\nCopyright Synthetic Fixture\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files.';
export const fixtureIntegrity = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;
const hash = value => createHash('sha256').update(value).digest('hex');
const reviewed = JSON.parse(readFileSync(new URL('../../tools/third-party-notices/reviewed-runtime.json', import.meta.url)));
export const fixtureFile = (path, text) => ({ path, text, sha256: hash(text) });

// Synthetic report fixtures only, never upstream license approval.
export function fixtureLicenseEvidence(dependencies) {
  return { schemaVersion: 1, packages: dependencies.map(item => ({
    ...item, packageJson: fixtureFile('package.json', JSON.stringify({
      name: item.name, version: item.version, license: 'MIT',
    })),
    files: [fixtureFile('LICENSE', fixtureMit)],
    reviewedSources: Object.entries(reviewed.find(entry => entry.name === item.name &&
      entry.resolution.version === item.version)?.upstreamSourceSha256 ?? {})
      .sort(([a], [b]) => a.localeCompare(b)).map(([path, sha256]) => ({ path, sha256 })),
  })) };
}
