// Test-only preload (`node --import`) that delays the bridge's handling of every child exit by
// MCP_TEST_CHILD_EXIT_DELAY_MS. A child that has exited has already closed its pipes, so this
// holds open the window in which the bridge still writes to a child that is gone. In production
// that window is short, which is why the crash it exposes was rare.
//
// It patches Node's internal process handle. If a Node release changes that, the window never
// opens and the tests fail instead of passing.
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const delay = Number(process.env.MCP_TEST_CHILD_EXIT_DELAY_MS || 0);
const spawn = childProcess.spawn;
childProcess.spawn = function spawnWithDelayedExit(...args) {
  const child = spawn.apply(this, args);
  const handle = child._handle;
  if (delay > 0 &&
      handle) {
    const onexit = handle.onexit;
    handle.onexit = (...exitArgs) => setTimeout(() => onexit.apply(handle, exitArgs), delay);
  }
  return child;
};
syncBuiltinESMExports();
