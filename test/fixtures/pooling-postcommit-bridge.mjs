// Report the actual OS-assigned port without changing production listener code.
import http from 'node:http';

const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  const ready = args.pop();
  args.push(function (...callbackArgs) {
    ready.apply(this, callbackArgs);
    process.send?.({ ready: true, port: this.address().port });
  });
  return listen.apply(this, args);
};
process.on('message', (message) => {
  if (message.shutdown) process.emit('SIGTERM');
});
try {
  await import('../../bin/mcp-bridge.mjs');
} catch (error) {
  process.send?.({ startupFailure: error.code ?? 'STARTUP_FAILED' }, () => process.exit(1));
}
