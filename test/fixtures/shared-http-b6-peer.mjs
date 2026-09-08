import { appendFileSync, existsSync, mkdirSync, readFileSync, watch } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

class SharedHttpPeer {
  constructor() {
    this.journal = process.argv[2];
    this.controlsDirectory = join(process.argv[3], String(process.pid));
    this.manualInitialize = process.argv[4] === 'manual';
    this.initializes = 0;
    this.initialized = 0;
    this.pending = new Map();
    this.progressSent = new Set();
    mkdirSync(this.controlsDirectory, { recursive: true });
    this.record({ event: 'spawn' });
    this.watcher = watch(this.controlsDirectory, () => this.controls());
    this.watcher.on('error', (error) => {
      process.stderr.write(`Fixture control watcher failed: ${error.message}\n`);
      process.exit(1);
    });
    const input = createInterface({ input: process.stdin });
    input.on('line', (line) => this.receive(JSON.parse(line)));
    input.on('close', () => this.watcher.close());
  }

  record(entry) {
    appendFileSync(this.journal, `${JSON.stringify({ pid: process.pid, ...entry })}\n`);
  }

  send(message) {
    this.record({ event: 'response', message });
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  }

  initialize(message) {
    const override = join(this.controlsDirectory, 'initialize-result.json');
    const result = existsSync(override) ? JSON.parse(readFileSync(override, 'utf8')) : {
      protocolVersion: message.params.protocolVersion, capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'shared-http-b6-peer', version: '1' },
      instructions: 'Actual shared HTTP fixture initialization result',
    };
    this.send({ id: message.id, result });
    this.initialization = null;
  }

  receive(message) {
    this.record({ event: 'request', message });
    if (Object.hasOwn(message, 'error')) {
      if (message.error.code !== -32601) throw new Error('Unexpected callback response');
      return;
    }
    if (message.method === 'initialize') {
      this.initializes++;
      if (this.initializes !== 1) throw new Error('Repeated upstream initialize');
      this.initialization = message;
      if (!this.manualInitialize) this.initialize(message);
      this.controls();
      return;
    }
    if (message.method === 'notifications/initialized') {
      this.initialized++;
      if (this.initialized !== 1) throw new Error('Repeated upstream initialized notification');
      return;
    }
    if (message.method === 'notifications/cancelled') return;
    if (this.initialized !== 1) throw new Error('Business request before initialized notification');
    if (message.method === 'ping') {
      this.send({ id: message.id, result: {} });
      return;
    }
    if (message.method === 'tools/list') {
      const result = { tools: [{ name: 'echo', inputSchema: { type: 'object' } }] };
      if (message.params?.cursor === undefined) result.nextCursor = 'fixture-server-cursor';
      this.send({ id: message.id, result });
      return;
    }
    if (message.method !== 'tools/call') throw new Error(`Unexpected fixture method: ${message.method}`);
    const args = message.params.arguments;
    if (args.op === 'exit') process.exit(17);
    if (args.op === 'callback') {
      this.send({ id: message.id, method: 'sampling/createMessage', params: { messages: [] } });
      return;
    }
    if (args.op === 'large-result') {
      this.send({ id: message.id, result: { content: [{ type: 'text', text: 'x'.repeat(4096) }] } });
      return;
    }
    if (args.op === 'hold' ||
        args.op === 'sized-hold') {
      if (!/^[a-z0-9-]{1,64}$/.test(args.tag)) throw new Error('Invalid fixture tag');
      this.pending.set(args.tag, message);
      this.controls();
      return;
    }
    this.complete(message);
  }

  complete(message) {
    const text = message.params.arguments.op === 'sized-hold' ? 'x'.repeat(240) : JSON.stringify({
      pid: process.pid, initializes: this.initializes, initialized: this.initialized,
      arguments: message.params.arguments,
    });
    this.send({ id: message.id, result: { content: [{ type: 'text', text }] } });
  }

  controls() {
    if (this.initialization &&
        existsSync(join(this.controlsDirectory, 'initialize'))) {
      this.initialize(this.initialization);
    }
    for (const [tag, message] of this.pending) {
      if (!this.progressSent.has(tag) &&
          existsSync(join(this.controlsDirectory, `progress-${tag}`))) {
        this.progressSent.add(tag);
        this.send({ method: 'notifications/progress', params: {
          progressToken: message.params._meta.progressToken, progress: 1, total: 2, message: tag,
        } });
      }
      if (existsSync(join(this.controlsDirectory, `release-${tag}`))) {
        this.pending.delete(tag);
        this.complete(message);
      }
    }
  }
}

new SharedHttpPeer();
