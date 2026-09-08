#!/usr/bin/env node
// Like echo-mcp-server, but it does NOT exit when stdin closes.
//
// Many real MCP servers hold handles of their own (token refresh timers, sockets, native
// brokers) and keep running after their stdin pipe breaks. That is what makes the Windows
// cmd.exe wrapper leak observable: killing the wrapper leaves this process orphaned. The
// plain echo fixture self-terminates on stdin EOF and so hides the bug.
//
// With --heartbeat <path> the process rewrites that file continuously. A live heartbeat is a
// far cheaper and more reliable liveness signal than enumerating processes: it cannot be
// confused by pid reuse, and it costs nothing under a loaded parallel test run.
import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';

const hbIndex = process.argv.indexOf('--heartbeat');
if (hbIndex !== -1 && process.argv[hbIndex + 1]) {
  const hb = process.argv[hbIndex + 1];
  const beat = () => { try { writeFileSync(hb, String(Date.now())); } catch { /* ignore */ } };
  beat();
  setInterval(beat, 100);
}

// Safety net: this fixture deliberately survives stdin closing, so a test that fails before
// tearing it down would otherwise leave it running for the rest of the session — and a suite
// run repeatedly leaks one per spawn. Far longer than any test, so it cannot mask a real leak.
// Unconditional: the leak does not depend on --heartbeat, and scoping the timer to that flag is
// what allowed 300+ of these to accumulate on a dev box.
setTimeout(() => process.exit(0), 120_000);

const argValue = (flag) => {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
};
// Simulates a slow cold start: the server exists but takes this long to answer `initialize`.
const INIT_DELAY_MS = Number(argValue('--init-delay') || 0);
// Simulates a slow tool call, so a test can hold a request in flight across an idle timeout.
const CALL_DELAY_MS = Number(argValue('--call-delay') || 0);
// Reported back as serverInfo.name, so a test can tell which definition a child was started from.
const LABEL = argValue('--label') || 'stubborn';

const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');
const rl = createInterface({ input: process.stdin });

// Keep the event loop alive regardless of stdin, and outlive any test timeout.
setInterval(() => {}, 1 << 30);
process.stdin.on('end', () => {});
process.stdin.on('error', () => {});

rl.on('line', (line) => {
  const t = line.trim();
  if (!t) return;
  let msg;
  try { msg = JSON.parse(t); } catch { return; }
  if (msg.id == null) return; // notification -> no response
  // Deliberately never answered, so a test can exercise the request timeout.
  if (msg.method === 'never/answer') return;
  if (msg.method === 'initialize') {
    const reply = () => send({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: LABEL, version: '0.0.0' } } });
    if (INIT_DELAY_MS > 0) setTimeout(reply, INIT_DELAY_MS); else reply();
  } else if (msg.method === 'tools/list') {
    const reply = () => send({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'ping', description: 'ping' }] } });
    if (CALL_DELAY_MS > 0) setTimeout(reply, CALL_DELAY_MS); else reply();
  } else if (msg.method === 'test/error') {
    send({ jsonrpc: '2.0', id: msg.id, error: {
      code: msg.params.code, message: 'Peer-defined error', data: msg.params.data,
    } });
  } else {
    send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
  }
});
