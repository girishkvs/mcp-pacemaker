import { appendFileSync, existsSync, writeFileSync, renameSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createConnection } from 'node:net';

class Fixture {
  constructor() {
    [this.role, this.directory] = process.argv.slice(2);
    if (!['standin', 'worker'].includes(this.role) ||
        !this.directory) {
      throw new Error('Owned fixture role and directory required');
    }
    this.startedAt = Date.now();
    this.sequence = 0;
  }

  record(name, value) {
    appendFileSync(join(this.directory, name), `${JSON.stringify(value)}\n`);
  }

  beat() {
    this.socket.write(`${JSON.stringify({
      role: this.role,
      pid: process.pid,
      sequence: ++this.sequence,
      at: new Date().toISOString(),
    })}\n`);
  }

  ready() {
    const destination = join(this.directory, `${this.role}.ready.json`);
    writeFileSync(`${destination}.tmp`, JSON.stringify({
      role: this.role,
      pid: process.pid,
      parentPid: process.ppid,
      readyAt: new Date().toISOString(),
      expiresAt: new Date(this.startedAt + 45_000).toISOString(),
      nodeVersion: process.version,
    }));
    renameSync(`${destination}.tmp`, destination);
  }

  waitForGate(name, action) {
    const timer = setInterval(() => {
      if (existsSync(join(this.directory, 'cancel-spawn'))) {
        clearInterval(timer);
        return;
      }
      if (existsSync(join(this.directory, name))) {
        clearInterval(timer);
        action();
      }
    }, 50);
  }

  startInner() {
    const parts = [process.execPath, fileURLToPath(import.meta.url), 'worker', this.directory];
    if (parts.some((part) => /["%!&|<>\r\n]/.test(part))) {
      throw new Error('Fixture path not safe for its narrow cmd quoting');
    }
    const command = `"${parts.map((part) => `"${part}"`).join(' ')}"`;
    const child = spawn(process.env.ComSpec, ['/d', '/s', '/c', command], {
      cwd: this.directory,
      env: process.env,
      stdio: 'inherit',
      windowsVerbatimArguments: true,
      windowsHide: true,
    });
    child.on('error', (error) => {
      this.record('fixture-errors.jsonl', { role: this.role, code: error.code });
      process.exit(71);
    });
    child.on('exit', (code) => process.exit(code ?? 72));
  }

  send(message) {
    this.record('worker.stdout.jsonl', message);
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }

  startWorker() {
    const lines = createInterface({ input: process.stdin });
    lines.on('line', (line) => {
      const message = JSON.parse(line);
      this.record('worker.stdin.jsonl', message);
      if (message.id == null) return;
      const result = message.method === 'initialize'
        ? {
            protocolVersion: '2025-03-26',
            capabilities: {},
            serverInfo: { name: 'owned-nested-fixture', version: '0.0.0' },
          }
        : {};
      this.send({ jsonrpc: '2.0', id: message.id, result });
    });
    lines.on('close', () => this.record('fixture-events.jsonl', {
      role: this.role, event: 'stdin-eof', at: new Date().toISOString(),
    }));
  }

  run() {
    // The fixture deliberately stays alive on EOF, as a server with its own timers can.
    // This does not model npm implementation details or diagnose a real crash trigger.
    setTimeout(() => {
      this.record('fixture-events.jsonl', {
        role: this.role, event: 'self-expiry', at: new Date().toISOString(),
      });
      process.exit(73);
    }, 45_000);
    for (const stream of [process.stdin, process.stdout, process.stderr]) {
      stream.on('error', (error) => this.record('fixture-events.jsonl', {
        role: this.role, event: 'stdio-error', code: error.code,
      }));
    }
    this.socket = createConnection({
      host: '127.0.0.1',
      port: Number(process.env.PROBE_HEARTBEAT_PORT),
    });
    this.socket.setNoDelay(true);
    this.socket.on('error', (error) => {
      this.record('fixture-errors.jsonl', {
        role: this.role, event: 'heartbeat-socket-error', code: error.code,
      });
      process.exit(75);
    });
    this.socket.on('connect', () => {
      this.ready();
      this.beat();
      setInterval(() => this.beat(), 200);
      this.waitForGate(
        this.role === 'standin' ? 'allow-inner' : 'allow-worker',
        () => this.role === 'standin' ? this.startInner() : this.startWorker(),
      );
    });
  }
}

new Fixture().run();
