// Test-only observation. No bridge, worker, helper or shutdown behavior is replaced.
import { appendFileSync } from 'node:fs';
import { isMainThread, threadId, workerData } from 'node:worker_threads';

appendFileSync(process.env.MCP_REPLACEMENT_RECORD, JSON.stringify({
  pid: process.pid, ppid: process.ppid, entry: process.argv[1],
  threadId, worker: !isMainThread, kind: workerData?.kind,
}) + '\n');
