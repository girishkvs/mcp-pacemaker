import { connect } from 'node:net';
import { readFileSync } from 'node:fs';
setTimeout(() => process.exit(0), 45000);
const manifest = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const socket = connect(manifest.endpoint);
const report = value => { if (process.connected) process.send(value); };
socket.on('error', error => report({ type: 'socket-error', code: error.code }));
socket.on('connect', () => report({ type: 'connected' }));
socket.on('close', () => report({ type: 'closed' }));
socket.on('data', bytes => report({ type: 'bytes', base64: bytes.toString('base64') }));
process.on('message', message => {
  if (message.action === 'raw') socket.write(Buffer.from(message.base64, 'base64'));
  else if (message.action === 'disconnect') socket.destroy();
  else if (message.action === 'exit') process.exit(0);
});
