import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadFixtures } from '../compatibility/fixtures.mjs';

export function compatibilityReport() {
  return loadFixtures();
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(compatibilityReport()));
}
