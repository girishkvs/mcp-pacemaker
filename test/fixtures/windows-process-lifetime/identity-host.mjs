import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';

const [modulePath, action] = process.argv.slice(2);
setTimeout(() => process.exit(87), 45_000);
const spawn = childProcess.spawn;
childProcess.spawn = (...args) => {
  const child = spawn(...args);
  child.on('spawn', () => process.send({ type: 'child', pid: child.pid }));
  return child;
};
syncBuiltinESMExports();
process.on('disconnect', () => process.exit(88));
process.on('message', async (message) => {
  if (message === 'finish') process.exit(0);
  if (message !== 'start') return;
  try {
    const api = await import(pathToFileURL(modulePath).href);
    const value = action === 'owner'
      ? await api.ensureWindowsProcessLifetime()
      : await (await api.observeWindowsProcessLifetime({
          protocol: 1, ownerPid: process.ppid, ownerCreationTime: '1',
        })).done;
    process.send({ type: 'result', accepted: true, value });
  } catch (error) {
    process.send({ type: 'result', accepted: false, message: error.message });
  }
});
process.send({ type: 'ready' });
