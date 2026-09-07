#!/usr/bin/env node
// Fixture for warm-pool tests. Behaves like the echo server, plus two ways to die that the
// bridge did not ask for — which is the case the warm pool used to handle badly.
//
//   --exit-after <ms>   exit on a timer, whether or not anyone ever talked to us. Models a
//                       server that self-exits when idle, which is how a pool drains.
//   --code <n>          exit code to use (default 0).
//   --startup-delay <ms>  produce no output at all for this long, then start answering. Models
//                       the package-manager fetch that dominates a real cold start.
//   crash/now           JSON-RPC method: exit(1) immediately. Models a session child dying
//                       under load, used to check the failure is counted once.
import { createInterface } from 'node:readline';

const arg = (flag, dflt) => {
  const i = process.argv.indexOf(flag);
  return i > -1 && process.argv[i + 1] != null ? Number(process.argv[i + 1]) : dflt;
};
const exitAfter = arg('--exit-after', 0);
const exitCode = arg('--code', 0);
const startupDelay = arg('--startup-delay', 0);

if (exitAfter > 0) setTimeout(() => process.exit(exitCode), exitAfter);

const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');

function listen() {
  const rl = createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    const t = line.trim();
    if (!t) return;
    let msg;
    try { msg = JSON.parse(t); } catch { return; }
    if (msg.method === 'crash/now') process.exit(1);
    if (msg.id == null) return;
    if (msg.method === 'initialize') {
      send({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'pool-child', version: '0.0.0' } } });
    } else if (msg.method === 'tools/list') {
      send({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'ping', description: 'ping' }] } });
    } else {
      send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
    }
  });
}

// stdin buffers while we wait, so anything written during the delay is served once we start.
if (startupDelay > 0) setTimeout(listen, startupDelay);
else listen();
