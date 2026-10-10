import { readFileSync } from 'node:fs';
import { ManagedUpgrader } from '../../bin/managed-upgrade.mjs';
import { confirmLegacyUpgrade } from '../../bin/legacy-installation.mjs';
import { retainedCliDependencies } from '../helpers/managed-package.mjs';
import { OwnedLegacyTask } from '../helpers/legacy-upgrade-fixture.mjs';

const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));
await confirmLegacyUpgrade(input.plan, { interactive: true, confirm: async () => true });
const upgrader = new ManagedUpgrader({
  acquire: async () => ({ bytes: readFileSync(input.archive), integrity: input.integrity }),
  dependencies: retainedCliDependencies, legacy: { task: new OwnedLegacyTask(input.taskPath) },
  checkpoint: phase => { if (phase === input.phase) process.exit(86); },
});
await upgrader.execute(input.plan);
throw new Error('Owned legacy crash checkpoint was not reached.');
