import { createInterface } from 'node:readline';

class DepthPeer {
  constructor() {
    createInterface({ input: process.stdin }).on('line', (line) => this.receive(JSON.parse(line)));
    process.on('message', ({ message, depth }) => {
      const nested = `${'{"nested":'.repeat(depth)}0${'}'.repeat(depth)}`;
      const line = `${JSON.stringify({ jsonrpc: '2.0', ...message }).replace('"__shared_depth_value__"', nested)}\n`;
      setImmediate(() => {
        process.send({ kind: 'wire', bytes: Buffer.byteLength(line), depth });
        process.stdout.write(line);
      });
    });
    process.on('disconnect', () => process.exit(0));
  }

  receive(message) {
    process.send({ kind: 'request', message });
    if (message.method === 'initialize') {
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: {
        protocolVersion: message.params.protocolVersion, capabilities: { tools: {} },
        serverInfo: { name: 'shared-depth-peer', version: '1' },
      } })}\n`);
    }
  }
}

new DepthPeer();
