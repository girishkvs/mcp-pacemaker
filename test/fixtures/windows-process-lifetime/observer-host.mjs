import { observeWindowsProcessLifetime } from '../../../bin/windows-process-lifetime.mjs';

setTimeout(() => process.exit(84), 45_000);
process.on('disconnect', () => process.exit(85));
process.once('message', async (identity) => {
  try {
    const observer = await observeWindowsProcessLifetime(identity);
    process.send({ pid: observer.pid });
    await observer.done;
    process.exit(0);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
});
