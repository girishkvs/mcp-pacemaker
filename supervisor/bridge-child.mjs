// IPC reaches the bridge's existing graceful shutdown handler on Windows too.
let loaded = false;
let stopRequested = false;
function shutdown() {
  stopRequested = true;
  if (loaded) process.emit('SIGTERM');
}
process.on('message', (message) => {
  if (message === 'stop') shutdown();
});
process.on('disconnect', shutdown);
await import('../bin/mcp-bridge.mjs');
loaded = true;
if (stopRequested) shutdown();
