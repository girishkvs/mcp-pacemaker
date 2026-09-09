import fs from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const [directory, helper, operation] = process.argv.slice(2);
fs.writeFileSync(join(directory, 'entered'), 'slow-helper');
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
const result = spawnSync(helper, [operation], {
  shell: false, windowsHide: true, encoding: 'utf8', timeout: 10000,
  stdio: ['ignore', 'pipe', 'pipe'],
});
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.error) throw result.error;
if (result.status === 0) process.stderr.write('TEST_REAL_HELPER_COMPLETED\n');
process.exitCode = result.status ?? 1;
