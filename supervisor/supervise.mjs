import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { servicePaths, assertDurableRoot } from '../bin/service-control.mjs';

const { values } = parseArgs({
  options: { port: { type: 'string', default: '8791' }, config: { type: 'string' } },
});
const port = Number(values.port);
const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
const config = resolve(values.config || join(homedir(), '.mcp-pacemaker', 'servers.json'));
const paths = servicePaths(config, port);
assertDurableRoot(root);
if (Number(process.versions.node.split('.')[0]) < 20) throw new Error('Node.js >=20 is required.');

if (existsSync(paths.hold)) {
  console.log(`Service :${port} is held stopped. Use the matching CLI start --port ${port} to resume deliberately.`);
} else {
  await supervise();
}

async function supervise() {
  const identity = {
    protocol: 1, root, config, port, socket: paths.socket, pid: process.pid, execPath: process.execPath,
    id: randomUUID(), token: randomBytes(32).toString('hex'),
    version: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version,
  };
  let child;
  let childExit;
  let retry;
  let stopping;
  let stopRequested = false;
  let holdRequested = false;
  const clients = new Set();
  const server = createServer((socket) => {
    clients.add(socket);
    socket.on('close', () => clients.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.setTimeout(15000, () => socket.destroy());
    let data = '';
    let handled = false;
    socket.on('data', (chunk) => {
      if (handled) return;
      data += chunk;
      if (data.length > 4096) { socket.destroy(); return; }
      if (!data.includes('\n')) return;
      handled = true;
      let request;
      try { request = JSON.parse(data.slice(0, data.indexOf('\n'))); }
      catch { socket.destroy(); return; }
      if (request.id !== identity.id ||
          request.token !== identity.token ||
          request.action !== 'stop') {
        socket.destroy();
        return;
      }
      stop().then(() => {
        socket.end(JSON.stringify({ id: identity.id, stopped: true, autostartHeld: true }) + '\n');
      }, (error) => {
        console.error(error.message);
        socket.end(JSON.stringify({ id: identity.id, stopped: false }) + '\n');
      });
    });
  });

  mkdirSync(dirname(config), { recursive: true, mode: 0o700 });
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(paths.socket, resolveListen);
  });
  server.on('error', (error) => { console.error(error.message); process.exitCode = 1; });
  try {
    writeFileSync(paths.record, JSON.stringify(identity) + '\n', { mode: 0o600 });
    if (existsSync(paths.hold)) {
      server.close();
      return;
    }
    launch();
  } catch (error) {
    server.close();
    throw error;
  }
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  function launch() {
    if (stopRequested ||
        existsSync(paths.hold)) {
      server.close();
      return;
    }
    child = fork(join(root, 'supervisor', 'bridge-child.mjs'), ['--port', String(port), '--config', config], {
      execPath: process.execPath, execArgv: [], stdio: ['ignore', 'inherit', 'inherit', 'ipc'], windowsHide: true,
    });
    childExit = new Promise((resolveExit, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => {
        child = undefined;
        resolveExit();
        if (stopRequested) return;
        if (code === 3) server.close();
        else retry = setTimeout(launch, 2000);
      });
    });
    childExit.catch((error) => {
      console.error(`Bridge launch failed: ${error.message}`);
      process.exitCode = 1;
      server.close();
    });
  }

  async function stop(hold = true) {
    // Persist before touching the child so logon/unlock and OS retries cannot restart it.
    if (hold &&
        !holdRequested) {
      writeFileSync(paths.hold, JSON.stringify({ id: identity.id, root, config, port }) + '\n', { mode: 0o600 });
      holdRequested = true;
    }
    if (stopping) return stopping;
    stopRequested = true;
    clearTimeout(retry);
    stopping = (async () => {
      if (child) {
        if (child.connected) {
          try {
            await new Promise((resolveSend, reject) => child.send('stop', (error) => error ? reject(error) : resolveSend()));
          } catch (error) {
            if (error.code !== 'ERR_IPC_CHANNEL_CLOSED' &&
                error.code !== 'EPIPE') throw error;
          }
        }
        let timeout;
        try {
          await Promise.race([
            childExit,
            new Promise((_, reject) => {
              timeout = setTimeout(() => reject(new Error('Bridge did not exit; do not replace its root. No force-kill attempted.')), 10000);
            }),
          ]);
        } finally {
          clearTimeout(timeout);
        }
      }
      if (holdRequested) {
        writeFileSync(paths.hold, JSON.stringify({ id: identity.id, root, config, port, stopped: true }) + '\n', { mode: 0o600 });
      }
      server.close();
      process.removeListener('SIGINT', onSignal);
      process.removeListener('SIGTERM', onSignal);
    })().catch((error) => {
      // Keep restart suppressed, but let a later explicit stop verify the real child exit.
      // A timeout must not write a completed receipt or permanently poison reconciliation.
      stopping = undefined;
      throw error;
    });
    return stopping;
  }

  function onSignal() {
    stop(false).then(() => {
      for (const socket of clients) socket.destroy();
    }, (error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
  }
}
