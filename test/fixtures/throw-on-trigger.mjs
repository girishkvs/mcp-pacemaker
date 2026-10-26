// Test-only preload (`node --import`) that throws an uncaught error in the bridge once the file
// named by MCP_TEST_THROW_FILE exists. The test creates the file after the bridge is up, so the
// crash happens with the bridge's own error reporting in place.
import { existsSync } from 'node:fs';

const trigger = process.env.MCP_TEST_THROW_FILE;
setInterval(() => {
  if (existsSync(trigger)) throw new Error('fatal-test-marker');
}, 50).unref();
