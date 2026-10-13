import { prepareLegacyProcesses } from '../../../bin/windows-legacy-process.mjs';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const spawn = childProcess.spawn;
childProcess.spawn = (...args) => {
  const child = spawn(...args);
  child.on('spawn', () => process.send({ type: 'broker', pid: child.pid }));
  return child;
};
syncBuiltinESMExports();
setTimeout(() => process.exit(86), 45000);
process.on('disconnect', () => process.exit(87));
process.once('message', async (options) => {
  try {
    const session = await prepareLegacyProcesses(options);
    process.send({ type: 'plan', plan: session.plan });
  } catch (error) {
    process.send({ type: 'error', message: error.message });
  }
});
