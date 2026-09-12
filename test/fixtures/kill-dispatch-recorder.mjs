// Test-only transport interception. No numeric PID is forwarded to taskkill.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { once } from 'node:events';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const bridge = fileURLToPath(new URL('../../bin/mcp-bridge.mjs', import.meta.url));
const serverFixture = fileURLToPath(new URL('./kill-dispatch-server.mjs', import.meta.url));

class KillDispatchRecorder {
  constructor() {
    this.mode = process.argv[2];
    this.outcome = process.argv[3];
    this.originalSpawn = childProcess.spawn;
    this.originalExit = process.exit.bind(process);
    this.children = [];
    this.calls = [];
    this.probes = [];
    this.attempts = 0;
    this.blockedCalls = 0;
    this.rpcId = 0;
    this.holdCallbacks = false;
    this.exitRequested = new Promise((resolve) => { this.onExitRequested = resolve; });
    this.directory = mkdtempSync(join(tmpdir(), 'mcpka-kill-dispatch-'));
  }

  async install() {
    this.asyncTransport = (command, args, callback) => {
      this.record('async', command, args);
      if (!this.holdCallbacks) setImmediate(() => callback(null, '', ''));
    };
    this.syncTransport = (command, args) => {
      this.record('sync', command, args);
      return Buffer.alloc(0);
    };
    childProcess.execFile = this.asyncTransport;
    childProcess.execFileSync = this.syncTransport;
    childProcess.spawn = (...args) => this.spawn(...args);
    const blocked = () => {
      this.blockedCalls++;
      throw new Error('Unexpected process transport in the no-op fixture');
    };
    childProcess.exec = blocked;
    childProcess.execSync = blocked;
    childProcess.spawnSync = blocked;
    syncBuiltinESMExports();

    const bindings = await import('node:child_process');
    assert.equal(bindings.execFile, this.asyncTransport);
    assert.equal(bindings.execFileSync, this.syncTransport);
    this.probing = true;
    const args = ['/PID', String(process.pid), '/T', '/F'];
    bindings.execFileSync('taskkill', args);
    await new Promise((resolve) => bindings.execFile('taskkill', args, resolve));
    this.probing = false;
    assert.deepEqual(this.probes, ['sync', 'async']);
    this.recorderActive = true;

    // Keep the process alive only long enough to collect synchronous shutdown dispatch
    // and close our owned handles. The production shutdown body is otherwise unchanged.
    process.exit = (code = 0) => {
      this.requestedExitCode = code;
      this.onExitRequested(code);
    };
    process.on('message', (message) => {
      if (message.cleanup) this.finish(new Error('Parent requested fixture cleanup'));
    });
  }

  record(transport, command, args) {
    if (!this.probing) this.attempts++;
    assert.equal(command, 'taskkill');
    assert.deepEqual(args.slice(0, 1), ['/PID']);
    assert.deepEqual(args.slice(2), ['/T', '/F']);
    assert.equal(childProcess.execFile, this.asyncTransport);
    assert.equal(childProcess.execFileSync, this.syncTransport);
    if (this.probing) {
      assert.equal(Number(args[1]), process.pid);
      this.probes.push(transport);
      return;
    }
    assert.equal(this.recorderActive, true);
    const entry = this.children.findLast((item) => item.child.pid === Number(args[1]));
    assert.ok(entry, 'a recorded PID must belong to a child spawned by this fixture');
    const stack = new Error().stack;
    this.calls.push({
      transport, child: entry.index, pid: entry.child.pid,
      exitCode: entry.child.exitCode, signalCode: entry.child.signalCode,
      marked: Boolean(entry.child.__bridgeKilled),
      restoreSession: stack.includes('at restoreSession '),
      shutdown: /\bat (?:process\.)?shutdown \(/.test(stack),
    });
  }

  spawn(command, args, options) {
    assert.equal(command, process.execPath);
    assert.ok(args[0] === serverFixture || args[0] === '-e',
      'only the dedicated MCP fixture or an owned Node control may start');
    const child = this.originalSpawn(command, args, options);
    const entry = {
      child, index: this.children.length, kill: child.kill.bind(child),
      closed: once(child, 'close'), resumedInitialize: false,
    };
    this.children.push(entry);
    const write = child.stdin.write.bind(child.stdin);
    child.stdin.write = (...input) => {
      const result = write(...input);
      for (const line of String(input[0]).trim().split('\n')) {
        let message;
        try { message = JSON.parse(line); } catch { continue; }
        const resuming = message.method === 'initialize' &&
          String(message.id).startsWith('bridge-resume-');
        if (!resuming) continue;
        entry.resumedInitialize = true;
        if (this.outcome === 'signal') queueMicrotask(() => entry.kill('SIGKILL'));
      }
      return result;
    };
    return child;
  }

  async wait(promise) {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('Owned fixture event did not arrive')), 8000);
        }),
      ]);
    } finally { clearTimeout(timer); }
  }

  request(method, path, message, headers = {}) {
    return new Promise((resolve, reject) => {
      const request = http.request({
        host: '127.0.0.1', port: this.port, method, path, agent: false,
        headers: { 'content-type': 'application/json', ...headers },
      }, (response) => {
        let body = '';
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
      });
      request.setTimeout(10000, () => request.destroy(new Error('Owned fixture HTTP deadline')));
      request.on('error', reject);
      request.end(message ? JSON.stringify(message) : undefined);
    });
  }

  rpc(method, session) {
    const headers = session ? { 'mcp-session-id': session } : {};
    return this.request('POST', '/echo/mcp', {
      jsonrpc: '2.0', id: ++this.rpcId, method,
      params: method === 'initialize'
        ? { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'kill-dispatch', version: '1' } }
        : {},
    }, headers);
  }

  async initialize() {
    const response = await this.rpc('initialize');
    assert.equal(response.status, 200, response.body);
    const session = response.headers['mcp-session-id'];
    assert.ok(session);
    const initialized = await this.request('POST', '/echo/mcp', {
      jsonrpc: '2.0', method: 'notifications/initialized',
    }, { 'mcp-session-id': session });
    assert.equal(initialized.status, 202);
    return session;
  }

  async startBridge() {
    const path = join(this.directory, 'servers.json');
    writeFileSync(path, JSON.stringify({
      echo: {
        command: process.execPath, args: [serverFixture, this.outcome],
        ...(this.mode === 'shared' ? { sharing: 'shared' } : {}),
      },
    }));
    process.argv = [process.execPath, bridge, '--port', '0', '--config', path];
    Object.assign(process.env, {
      MCP_CONFIG_WATCH: '0', MCP_IDLE_TIMEOUT_MS: '0', MCP_RECYCLE_MINUTES: '0',
      MCP_HEALTH_INTERVAL_MS: '0', MCP_RESUME: '1',
    });
    const listening = new Promise((resolve) => {
      const listen = http.Server.prototype.listen;
      http.Server.prototype.listen = function (...args) {
        const ready = args.pop();
        args.push(function (...callbackArgs) {
          ready.apply(this, callbackArgs);
          resolve(this.address().port);
        });
        return listen.apply(this, args);
      };
    });
    await import('../../bin/mcp-bridge.mjs');
    this.started = true;
    this.port = await this.wait(listening);
    this.session = await this.initialize();
  }

  async run() {
    await this.install();
    if (this.mode === 'helper') {
      const { killBridge } = await import('../helpers/kill-bridge.mjs');
      const live = this.outcome === 'live' || this.outcome === 'signal';
      const script = live ? 'process.stdin.resume()' : `process.exit(${this.outcome === 'zero' ? 0 : 23})`;
      this.spawn(process.execPath, ['-e', script], { stdio: ['pipe', 'ignore', 'ignore'] });
      const entry = this.children[0];
      if (this.outcome === 'signal') entry.kill('SIGKILL');
      if (this.outcome !== 'live') await this.wait(entry.closed);
      killBridge(entry.child);
      await this.wait(entry.closed);
    } else {
      await this.startBridge();
      if (this.mode === 'resume') {
        await this.rpc('fixture/exit', this.session);
        await this.wait(this.children[0].closed);
        const resumed = await this.rpc('tools/list', this.session);
        assert.equal(resumed.status, 200, resumed.body);
        const failure = JSON.parse(resumed.body).error;
        assert.equal(failure.code, -32000);
        assert.match(failure.message, /server exited .* before answering/);
        assert.equal(this.children.length, 2);
        await this.wait(this.children[1].closed);
        assert.equal(this.children[1].resumedInitialize, true);
      } else if (this.mode === 'shutdown') {
        this.holdCallbacks = true;
        const nonce = readFileSync(join(this.directory, 'admin.nonce'), 'utf8').trim();
        const recycled = await this.request('POST', '/admin/recycle/echo', undefined, { 'x-mcp-nonce': nonce });
        assert.equal(recycled.status, 200);
        process.emit('SIGTERM');
        assert.equal(await this.wait(this.exitRequested), 0);
      } else {
        assert.equal(this.mode, 'shared');
        const second = await this.initialize();
        const removed = await this.request('DELETE', '/echo/mcp', undefined, { 'mcp-session-id': this.session });
        assert.equal(removed.status, 204);
        const survivor = await this.rpc('tools/list', second);
        assert.equal(survivor.status, 200, survivor.body);
        assert.match(survivor.body, /"tools":\[\]/);
        assert.equal(this.children.length, 1);
        assert.equal(this.children[0].child.exitCode, null);
        assert.equal(this.children[0].child.signalCode, null);
      }
    }
    this.scenario = this.snapshot();
  }

  snapshot() {
    return {
      recorderActive: this.recorderActive, probes: this.probes, calls: this.calls.slice(),
      attempts: this.attempts, blockedCalls: this.blockedCalls,
      children: this.children.map((entry) => ({
        child: entry.index, pid: entry.child.pid,
        exitCode: entry.child.exitCode, signalCode: entry.child.signalCode,
        resumedInitialize: entry.resumedInitialize,
      })),
    };
  }

  async finish(error) {
    if (this.finishing) return;
    this.finishing = true;
    let cleanupError;
    try {
      if (this.started &&
          this.requestedExitCode == null) {
        process.emit('SIGTERM');
        await this.wait(this.exitRequested);
      }
      for (const entry of this.children) {
        if (entry.child.exitCode == null &&
            entry.child.signalCode == null) entry.kill('SIGKILL');
        await this.wait(entry.closed);
      }
      rmSync(this.directory, { recursive: true, force: true });
    } catch (failure) { cleanupError = failure.stack; }
    const result = {
      mode: this.mode, outcome: this.outcome, scenario: this.scenario ?? this.snapshot(),
      cleanup: this.snapshot(), directory: this.directory,
      directoryRemoved: !existsSync(this.directory),
      error: error?.stack, cleanupError,
    };
    await new Promise((resolve) => process.stdout.write(`${JSON.stringify(result)}\n`, resolve));
    this.originalExit(error || cleanupError ? 1 : 0);
  }
}

const recorder = new KillDispatchRecorder();
try {
  await recorder.run();
  await recorder.finish();
} catch (error) {
  await recorder.finish(error);
}
