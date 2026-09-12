import { createInterface } from 'node:readline';

const outcome = process.argv[2];
const lines = createInterface({ input: process.stdin });
lines.on('line', (line) => {
  const message = JSON.parse(line);
  if (message.id == null) return;
  if (message.method === 'fixture/exit') process.exit(0);
  const resuming = message.method === 'initialize' &&
    String(message.id).startsWith('bridge-resume-');
  if (resuming &&
      outcome !== 'live') {
    if (outcome === 'signal') return;
    process.exit(outcome === 'zero' ? 0 : 23);
  }
  const result = message.method === 'initialize'
    ? { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'kill-dispatch', version: '1' } }
    : { tools: [] };
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result })}\n`);
});
