// Hash-complete own-source assets for synthetic publication receipts. Never executed here.
import { readFileSync } from 'node:fs';
import { LIFETIME_FILES, LIFETIME_REQUIRED_TESTS, requiresProcessLifetime } from '../../tools/windows-process-lifetime/inventory.mjs';

export function lifetimeFixtureFiles(version) {
  if (!requiresProcessLifetime(version)) return {};
  return Object.fromEntries(LIFETIME_FILES.map((path) =>
    [path, readFileSync(new URL(`../../${path}`, import.meta.url))]));
}

export function lifetimeFixtureNames(version) {
  return requiresProcessLifetime(version) ? [...LIFETIME_REQUIRED_TESTS] : [];
}
