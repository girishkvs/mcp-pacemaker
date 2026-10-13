import { connect } from 'node:net';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

setTimeout(() => process.exit(0), 45000);
const manifestPath = process.argv[3];
const operationId = process.argv[5];
const manifestParent = process.argv[7];
const module = await import(pathToFileURL(process.env.OWNED_CHANNEL_MODULE).href);
const report = frame => { if (process.connected) process.send(frame); };
let caller;
if (process.env.OWNED_CHANNEL_PROTECTED_READ === '1') {
  try {
    const result = await module.readProtectedManifest(manifestPath, { operationId, manifestParent });
    report({ type: 'manifest', result });
    caller = { identity: result.readerIdentity, guardIdentity: result.guardIdentity, helperExit: result.helperExit };
  } catch (error) {
    report({ type: 'manifest-error', message: error.message, guardIdentity: error.guardIdentity });
    process.exitCode = 1;
  }
} else caller = await module.queryTaskChannelCaller();
if (!caller) process.exit(1);
report({ type: 'caller', caller });
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const socket = connect(manifest.endpoint);
socket.setEncoding('utf8');
socket.on('error', error => report({ type: 'socket-error', code: error.code }));
socket.on('close', () => report({ type: 'socket-close' }));
let buffer = '';
socket.on('data', chunk => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf('\n')) >= 0) {
    report({ type: 'received', frame: JSON.parse(buffer.slice(0, newline)) });
    buffer = buffer.slice(newline + 1);
  }
});
socket.on('connect', () => {
  report({ type: 'connected' });
  socket.write(JSON.stringify({ kind: 'hello', claimedPid: 1, challenge: randomBytes(32).toString('hex'),
    ownIdentity: caller.identity }) + '\n');
});
process.on('message', message => {
  if (message.action === 'exit') process.exit(0);
  else if (message.action === 'disconnect') socket.end();
  else if (message.action === 'raw') socket.write(Buffer.from(message.base64, 'base64'));
  else if (message.action === 'frame') socket.write(JSON.stringify(message.frame) + '\n');
  else if (message.action === 'reconnect') {
    const second = connect(manifest.endpoint);
    let cancelled = false;
    const deadline = setTimeout(() => {
      cancelled = true;
      report({ type: 'second-pending-not-connected' });
      second.destroy();
    }, 500);
    second.once('connect', () => { clearTimeout(deadline); report({ type: 'second-connected' }); second.end(); });
    second.once('error', error => {
      clearTimeout(deadline);
      if (!cancelled) report({ type: 'second-error', code: error.code });
    });
  }
});
