#!/usr/bin/env node
// Stdio MCP server fixture that answers a tools/call and then exits, the way a server goes away
// in the middle of a session. The bridge's next write to it lands on a closed pipe.
import { createInterface } from 'node:readline';

const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');
const rl = createInterface({ input: process.stdin });

rl.on('line', (line) => {
  const t = line.trim();
  if (!t) return;
  let msg;
  try { msg = JSON.parse(t); } catch { return; }
  if (msg.id == null) return; // notification -> no response
  if (msg.method === 'initialize') {
    send({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'exit-after-call', version: '0.0.0' } } });
  } else if (msg.method === 'tools/call') {
    send({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'exiting' }] } });
    setTimeout(() => process.exit(0), 50);
  } else {
    send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
  }
});
