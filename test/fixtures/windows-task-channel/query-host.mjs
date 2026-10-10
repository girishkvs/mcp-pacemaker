import { pathToFileURL } from 'node:url';
setTimeout(() => process.exit(0), 45000);
process.on('message', message => { if (message.action === 'exit') process.exit(0); });
const { inspectTrustedCodeRoot } = await import(pathToFileURL(process.env.OWNED_QUERY_MODULE).href);
try {
  const result = await inspectTrustedCodeRoot(process.env.OWNED_QUERY_ROOT);
  if (process.connected) process.send({ type: 'query-result', result });
} catch (error) {
  if (process.connected) process.send({ type: 'query-error', message: error.message, guardIdentity: error.guardIdentity });
}
