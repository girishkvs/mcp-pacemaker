import { readFileSync } from 'node:fs';
import { AccountWorkerSession } from '../../bin/account-worker-session.mjs';
import { backendStatus } from '../../bin/managed-runtime.mjs';

const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const worker = Object.create(AccountWorkerSession.prototype);
worker.binding = input.binding;
worker.original = input.original;
await worker.start(input.binding.port, input.original);
const deadline = Date.now() + 10000;
let error;
while (Date.now() < deadline) {
  try {
    const status = await backendStatus(input.binding.port);
    if (status.version !== '1.3.0') throw new Error('Wrong rollback version.');
    process.exitCode = 0;
    error = undefined;
    break;
  } catch (failure) { error = failure; }
  await new Promise(resolveWait => setTimeout(resolveWait, 100));
}
if (error) throw error;
