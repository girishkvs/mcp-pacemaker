import { readFileSync } from 'node:fs';
import { ManagedUpgrader } from '../../bin/managed-upgrade.mjs';
import { retainedCliDependencies } from '../helpers/managed-package.mjs';

const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const upgrader = new ManagedUpgrader({
  acquire: async () => ({ bytes: readFileSync(input.archive), integrity: input.integrity }),
  dependencies: retainedCliDependencies,
  checkpoint: phase => {
    if (phase === input.phase) process.exit(86);
  },
});
await upgrader.execute(input.plan);
throw new Error('Owned crash checkpoint was not reached.');
