import { copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dependencyInventory, validateDependencyLock } from '../../bin/upgrade-dependencies.mjs';
import { directoryIdentity } from '../../bin/managed-state.mjs';
import { createHash } from 'node:crypto';

const retained = fileURLToPath(new URL('../../', import.meta.url));

export async function retainedCliDependencies(root) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(retained, 'package-lock.json'), 'utf8'));
  const copy = (path, destination) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('Retained dependency is linked.');
    if (stat.isDirectory()) {
      mkdirSync(destination, { recursive: true });
      for (const name of readdirSync(path)) {
        if (name === '.bin') continue;
        copy(join(path, name), join(destination, name));
      }
    } else copyFileSync(path, destination);
  };
  for (const path of Object.keys(lock.packages)) {
    if (!path ||
        path.slice('node_modules/'.length).includes('/node_modules/')) continue;
    copy(join(retained, path), join(root, path));
  }
  lock.name = pkg.name;
  lock.version = pkg.version;
  lock.packages[''].version = pkg.version;
  lock.packages[''].dependencies = pkg.dependencies;
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify(lock));
  validateDependencyLock(root);
  return dependencyInventory(root);
}

export function ownedPackageSelection(root) {
  const files = [];
  const walk = (relative = '') => {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path);
      else files.push({ path, sha256: createHash('sha256').update(readFileSync(join(root, path))).digest('hex') });
    }
  };
  walk();
  return {
    root, version: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version,
    directoryIdentity: directoryIdentity(root), files,
  };
}
