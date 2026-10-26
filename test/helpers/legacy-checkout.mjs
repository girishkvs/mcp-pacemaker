// The 1.x line carries the shared publication tools, but not the 2.x-only files that some tool
// tests read from this checkout. Those tests skip only while those files are missing, and they
// still run in the 2.x checkout.
import { existsSync, readFileSync } from 'node:fs';
import { LOCAL_CONTROLLER, releaseRole } from '../../tools/npm-publication/local-regression.mjs';
import { LIFETIME_FILES, requiresProcessLifetime } from '../../tools/windows-process-lifetime/inventory.mjs';

const ROOT = new URL('../../', import.meta.url);
const pkg = JSON.parse(readFileSync(new URL('package.json', ROOT), 'utf8'));
const isMissing = path => !existsSync(new URL(path, ROOT));

const legacyCheckout = releaseRole(pkg.version) === 'legacy';
const controllerFilesMissing = LOCAL_CONTROLLER.some(isMissing);
const lifetimeFilesMissing = LIFETIME_FILES.some(isMissing);

// The local gate controller hashes every LOCAL_CONTROLLER file, so it runs only from a 2.x checkout.
export const CONTROLLER_SKIP = legacyCheckout &&
  controllerFilesMissing &&
  'The local gate controller runs only from a 2.x checkout';

export function lifetimeSkip(version) {
  return legacyCheckout &&
    requiresProcessLifetime(version) &&
    lifetimeFilesMissing &&
    'The 2.x process lifetime helper files are not in a 1.x checkout';
}
