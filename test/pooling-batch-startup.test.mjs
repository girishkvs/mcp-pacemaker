// This file owns port 8880.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { killBridge } from './helpers/kill-bridge.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const port = 8880;

class Fixture {
  constructor(t, filename) {
    this.dir = fs.mkdtempSync(join(tmpdir(), 'pooling-startup-'));
    this.path = join(this.dir, filename);
    this.children = [];
    this.original = JSON.stringify({
      alpha: { command: process.execPath, args: [join(root, 'test', 'fixtures', 'echo-mcp-server.mjs')] },
    }) + '\n';
    fs.writeFileSync(this.path, this.original);
    t.after(async () => {
      for (const { child, exit } of this.children) {
        if (child.exitCode === null &&
            child.signalCode === null) killBridge(child);
        await exit;
      }
      fs.rmSync(this.dir, { recursive: true, force: true });
    });
  }

  launch(args) {
    const child = spawn(process.execPath, args, {
      cwd: this.dir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, MCP_CONFIG_WATCH: '0', MCP_RECYCLE_MINUTES: '0',
        MCP_IDLE_TIMEOUT_MS: '0', MCP_HEALTH_INTERVAL_MS: '0', MCP_RESUME: '0' },
    });
    const exit = once(child, 'exit');
    this.children.push({ child, exit });
    return { child, exit };
  }

  describeState() {
    const files = [];
    const states = [];
    try {
      const names = fs.readdirSync(this.dir);
      for (const name of names.slice(0, 16)) {
        const stat = fs.lstatSync(join(this.dir, name), { bigint: true });
        files.push({ name, size: String(stat.size), dev: String(stat.dev), ino: String(stat.ino) });
      }
      const directory = `${this.path}.pooling-transaction`;
      let stat;
      try {
        stat = fs.lstatSync(directory);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      if (stat) {
        if (!stat.isDirectory() ||
            stat.isSymbolicLink()) throw new Error('Unsupported diagnostic journal directory');
        for (const name of fs.readdirSync(directory).slice(0, 16)) {
          if (!/^state-\d+\.json$/.test(name)) continue;
          const path = join(directory, name);
          const stat = fs.lstatSync(path);
          if (!stat.isFile() ||
              stat.isSymbolicLink() ||
              stat.size > 8192) throw new Error('Unsupported diagnostic journal record');
          const record = JSON.parse(fs.readFileSync(path, 'utf8'));
          const phase = record.state?.phase;
          states.push({
            name,
            phase: ['idle', 'pending', 'updating', 'prepared', 'entered', 'failed'].includes(phase)
              ? phase : 'unrecognized',
          });
        }
      }
      return { files, states, truncated: names.length > 16 };
    } catch (error) {
      return { files, states, probeError: error.code ?? error.name };
    }
  }

  async interrupt() {
    const { child, exit } = this.launch([join(root, 'test', 'fixtures', 'pooling-batch-crash.mjs'),
      this.path, 'between']);
    await new Promise((resolve, reject) => {
      let output = '';
      let errors = '';
      let exitInfo;
      let checkpointReached = false;
      let nativeLine = '';
      let nativeLineTruncated = false;
      let nativeMetadataTruncated = false;
      const nativeFailures = [];
      child.stderr.on('data', (bytes) => {
        const text = String(bytes);
        errors = (errors + text).slice(-8192);
        const parts = text.split('\n');
        for (let index = 0; index < parts.length; index++) {
          const available = 1024 - nativeLine.length;
          nativeLine += parts[index].slice(0, available);
          nativeLineTruncated ||= parts[index].length > available;
          if (index === parts.length - 1) continue;
          if (nativeLine.startsWith('NATIVE_FAILURE ')) {
            nativeFailures.push(nativeLine + (nativeLineTruncated ? ' [truncated]' : ''));
            nativeMetadataTruncated ||= nativeLineTruncated;
            if (nativeFailures.length > 16) {
              nativeFailures.shift();
              nativeMetadataTruncated = true;
            }
          }
          nativeLine = '';
          nativeLineTruncated = false;
        }
      });
      const details = () => [
        `pid=${child.pid}`, `exit=${JSON.stringify(exitInfo)}`, `at=${new Date().toISOString()}`,
        `nativeMetadataTruncated=${nativeMetadataTruncated}`, `native=${nativeFailures.join('\n')}`,
        `nativePartial=${nativeLine.startsWith('NATIVE_FAILURE ') ? nativeLine : ''}`,
        `state=${JSON.stringify(this.describeState())}`, `stderr=${errors}`,
      ].join('; ');
      const timer = setTimeout(() => reject(new Error(
        `Startup crash checkpoint was not reached; ${details()}`)), 10000);
      child.stdout.on('data', (bytes) => {
        output = (output + bytes).slice(-8192);
        if (output.includes('CHECKPOINT\n') &&
            !exitInfo) {
          checkpointReached = true;
          clearTimeout(timer);
          resolve();
        }
      });
      child.once('exit', (code, signal) => {
        exitInfo = { code, signal, at: new Date().toISOString() };
      });
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        if (checkpointReached) return;
        reject(new Error(
          `Owned crash process exited before its checkpoint (code=${code}, signal=${signal}, close=${new Date().toISOString()}, checkpointSeen=${output.includes('CHECKPOINT\n')}); ${details()}`));
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
    child.kill('SIGKILL');
    await exit;
    assert.equal(fs.existsSync(this.path), false);
  }

  async start(explicitPath) {
    const args = [join(root, 'bin', 'mcp-bridge.mjs'), '--port', String(port)];
    if (explicitPath) args.push('--config', this.path);
    const { child } = this.launch(args);
    child.stdout.resume();
    child.stderr.resume();
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/api/status`,
          { signal: AbortSignal.timeout(10000) });
        assert.equal(response.status, 200);
        return response.json();
      } catch (error) {
        if (error.cause?.code !== 'ECONNREFUSED') throw error;
        await delay(30);
      }
    }
    throw new Error('Bridge did not start after its owned transaction recovery');
  }
}

test('startup diagnostics retain the child exit and drained stderr before cleanup', async (t) => {
  const f = new Fixture(t, 'servers.json');
  const launch = f.launch.bind(f);
  t.mock.method(f, 'launch', () => launch(['-e',
    'process.stderr.write("CONTROLLED_STARTUP_FAILURE\\n"); process.exitCode = 23;']));
  await assert.rejects(f.interrupt(), (error) => {
    assert.match(error.message, /code=23/);
    assert.match(error.message, /pid=\d+/);
    assert.match(error.message, /close=/);
    assert.match(error.message, /CONTROLLED_STARTUP_FAILURE/);
    assert.match(error.message, /servers\.json/);
    return true;
  });
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
});

test('startup diagnostics retain the child PID on checkpoint timeout', async (t) => {
  const f = new Fixture(t, 'servers.json');
  const launch = f.launch.bind(f);
  t.mock.method(f, 'launch', () => launch(['-e', 'setInterval(() => {}, 1000);']));
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = f.interrupt();
  const { child } = f.children[0];
  await once(child, 'spawn');
  const rejected = assert.rejects(pending, (error) => {
    assert.ok(error.message.includes(`pid=${child.pid}`));
    assert.match(error.message, /Startup crash checkpoint was not reached/);
    return true;
  });
  t.mock.timers.tick(10000);
  await rejected;
});

test('startup diagnostics retain failed native action details', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const f = new Fixture(t, 'servers.json');
  const launch = f.launch.bind(f);
  const fixture = new URL('./fixtures/pooling-batch-crash.mjs', import.meta.url).href;
  const script = `
    import childProcess from 'node:child_process';
    childProcess.spawnSync = (command) => {
      if (!String(command).endsWith('PoolingSecurityHelper.exe')) throw new Error('Unexpected fixture command');
      return {
        pid: process.pid, status: null, signal: 'SIGTERM', error: { code: 'ETIMEDOUT' }, stdout: '',
        stderr: 'MCPERR nativeError=5\\n' + 'X'.repeat(12000),
      };
    };
    process.argv = [process.execPath, 'fixture', ${JSON.stringify(f.path)}, 'between'];
    await import(${JSON.stringify(fixture)});
  `;
  t.mock.method(f, 'launch', () => launch(['--input-type=module', '-e', script]));
  await assert.rejects(f.interrupt(), (error) => {
    assert.match(error.message, /NATIVE_FAILURE/);
    assert.match(error.message, /"action":"inspect-access"/);
    assert.match(error.message, /"pid":\d+/);
    assert.match(error.message, /"status":null/);
    assert.match(error.message, /"errorCode":"ETIMEDOUT"/);
    assert.match(error.message, /"nativeError":"5"/);
    return true;
  });
  assert.equal(fs.readFileSync(f.path, 'utf8'), f.original);
});

for (const filename of ['servers.json', 'custom settings.配置.json']) {
  test(`startup recovers the missing active file before reading ${filename}`, async (t) => {
    const f = new Fixture(t, filename);
    await f.interrupt();
    const snapshot = await f.start(filename !== 'servers.json');
    assert.equal(snapshot.servers.find((server) => server.name === 'alpha').minWarm, 2);
    assert.equal(JSON.parse(fs.readFileSync(f.path, 'utf8')).alpha.minWarm, 2);
    const previous = filename === 'servers.json' ? 'servers.previous.json' : 'custom settings.配置.previous.json';
    assert.equal(fs.readFileSync(join(f.dir, previous), 'utf8'), f.original);
    assert.ok(Number.isSafeInteger(snapshot.snapshotVersion));
    assert.ok(snapshot.snapshotVersion > 0);
  });
}
