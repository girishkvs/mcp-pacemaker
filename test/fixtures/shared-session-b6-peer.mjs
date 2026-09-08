import { createInterface } from 'node:readline';

class SharedPeer {
  constructor() {
    this.initializes = 0;
    this.initialized = 0;
    this.calls = 0;
    createInterface({ input: process.stdin }).on('line', (line) => this.receive(JSON.parse(line)));
  }

  send(message) {
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  }

  receive(message) {
    if (message.method === 'initialize') {
      this.initializes++;
      if (this.initializes !== 1) throw new Error('Repeated upstream initialization');
      this.send({ id: message.id, result: {
        protocolVersion: message.params.protocolVersion, capabilities: { tools: {} },
        serverInfo: { name: 'shared-b6-peer', version: '1' }, instructions: 'Fixture instructions',
      } });
    } else if (message.method === 'notifications/initialized') {
      this.initialized++;
      if (this.initialized !== 1) throw new Error('Repeated upstream initialized notification');
    } else if (message.method === 'tools/call') {
      if (this.initialized !== 1) throw new Error('Business request before initialized');
      this.calls++;
      this.send({ id: message.id, result: { content: [{ type: 'text', text: JSON.stringify({
        pid: process.pid, initializes: this.initializes, initialized: this.initialized, calls: this.calls,
        arguments: message.params.arguments,
      }) }] } });
    } else if (message.method === 'ping') {
      this.send({ id: message.id, result: {} });
    } else {
      throw new Error(`Unexpected fixture method: ${message.method}`);
    }
  }
}

new SharedPeer();
