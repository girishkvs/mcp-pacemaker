import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { servicePaths, assertDurableRoot } from '../bin/service-control.mjs';

const { values } = parseArgs({
  options: { port: { type: 'string', default: '8791' }, config: { type: 'string' }, cwd: { type: 'string' } },
});
let port = Number(values.port);
const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
const config = resolve(values.config || join(homedir(), '.mcp-pacemaker', 'servers.json'));
let paths = port === 0 && process.connected && process.env.MCP_PACEMAKER_MANAGED_INSTANCE
  ? undefined : servicePaths(config, port);
assertDurableRoot(root);
if (Number(process.versions.node.split('.')[0]) < 20) throw new Error('Node.js >=20 is required.');

if (paths && existsSync(paths.hold)) {
  console.log(`Service :${port} is held stopped. Use the matching CLI start --port ${port} to resume deliberately.`);
} else {
  await supervise();
}

async function supervise() {
  const identity = {
    protocol: 1, root, config, port, socket: paths?.socket, pid: process.pid, execPath: process.execPath,
    id: randomUUID(), token: randomBytes(32).toString('hex'),
    version: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version,
    upgradeProtocol: 1, managedInstance: process.env.MCP_PACEMAKER_MANAGED_INSTANCE,
  };
  let child;
  let childExit;
  let retry;
  let stopping;
  let stopRequested = false;
  let holdRequested = false;
  const clients = new Set();
  const pending = new Map();
  let readiness;
  const failStartup = process.env.MCP_PACEMAKER_UPGRADE_PENDING === '1';
  let initialStartup = failStartup;
  let pendingStart = failStartup || Boolean(paths && existsSync(paths.admissionHold));
  let quiescedInstanceId;
  let stopAuthorization;
  const lifetimes = [];
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
          !['stop', 'inspect', 'quiesce', 'activate', 'resume'].includes(request.action)) {
        socket.destroy();
        return;
      }
      if (request.action !== 'stop') {
        if (request.action === 'quiesce') {
          pendingStart = true;
          writeFileSync(paths.admissionHold, JSON.stringify({ id: identity.id, root, config, port }) + '\n',
            { mode: 0o600, flush: true });
        }
        bridgeRequest(request).then((result) => {
          if (result.ok &&
              result.instanceId === readiness?.instanceId) {
            if (request.action === 'quiesce' &&
                result.held) quiescedInstanceId = result.instanceId;
            if (['activate', 'resume'].includes(request.action)) {
              if (existsSync(paths.admissionHold)) unlinkSync(paths.admissionHold);
              pendingStart = false;
              initialStartup = false;
              quiescedInstanceId = undefined;
            }
          }
          socket.end(JSON.stringify({ ...result, id: identity.id }) + '\n');
        }, (error) => socket.end(JSON.stringify({ id: identity.id, ok: false, error: error.message }) + '\n'));
        return;
      }
      if (request.quiescedInstanceId !== undefined) {
        const heldGeneration = !child ||
          readiness?.instanceId === quiescedInstanceId ||
          readiness?.held === true;
        if (!pendingStart ||
            request.quiescedInstanceId !== quiescedInstanceId ||
            !heldGeneration) {
          socket.end(JSON.stringify({ id: identity.id, stopped: false }) + '\n');
          return;
        }
        stopAuthorization = request.quiescedInstanceId;
      }
      stop().then(() => {
        socket.end(JSON.stringify({ id: identity.id, stopped: true, autostartHeld: true,
          ...(stopAuthorization ? { quiescedInstanceId: stopAuthorization } : {}) }) + '\n');
      }, (error) => {
        console.error(error.message);
        socket.end(JSON.stringify({ id: identity.id, stopped: false }) + '\n');
      });
    });
  });

  mkdirSync(dirname(config), { recursive: true, mode: 0o700 });
  if (paths) await listen();
  server.on('error', (error) => { console.error(error.message); process.exitCode = 1; });
  try {
    if (paths) writeFileSync(paths.record, JSON.stringify(identity) + '\n', { mode: 0o600 });
    if (paths && existsSync(paths.hold)) {
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
  process.on('message', (message) => { if (message === 'stop') onSignal(); });
  process.on('disconnect', onSignal);

  function listen() {
    return new Promise((resolveListen, reject) => {
      server.once('error', reject);
      server.listen(paths.socket, resolveListen);
    });
  }

  function bridgeRequest(request) {
    if (!child?.connected ||
        !readiness) return Promise.reject(new Error('Bridge has no verified managed readiness.'));
    const requestId = randomUUID();
    const requestedChild = child;
    return new Promise((resolveRequest, reject) => {
      const timer = setTimeout(() => {
        pending.delete(requestId);
        reject(new Error('Bridge admission result is uncertain; recovery required.'));
      }, 11000);
      pending.set(requestId, (message) => {
        clearTimeout(timer);
        if (requestedChild !== child) {
          reject(new Error('Bridge generation changed during admission; hold remains in effect.'));
          return;
        }
        resolveRequest(message);
      });
      child.send({
        type: 'upgrade-control', requestId, action: request.action, timeoutMs: 8000,
        expectedAuthority: request.expectedAuthority, expectedSessionState: request.expectedSessionState,
      });
    });
  }

  function observeLifetime(identity) {
    return (async () => {
      const { observeWindowsProcessLifetime } = await import('../bin/windows-process-lifetime.mjs');
      return observeWindowsProcessLifetime(identity);
    })();
  }

  function launch() {
    if (stopRequested ||
        (paths && existsSync(paths.hold))) {
      server.close();
      return;
    }
    let completeLifetime;
    let failLifetime;
    let lifetimeArmed;
    if (process.platform === 'win32') {
      const requiredLifetime = new Promise((resolveLifetime, rejectLifetime) => {
        completeLifetime = resolveLifetime;
        failLifetime = rejectLifetime;
      });
      const proof = requiredLifetime.then(observer => observer.done);
      proof.catch(() => {});
      lifetimes.push(proof);
    }
    const armLifetime = identity => {
      lifetimeArmed = observeLifetime(identity);
      if (completeLifetime) lifetimeArmed.then(completeLifetime, failLifetime);
      return lifetimeArmed;
    };
    readiness = undefined;
    const launched = fork(join(root, 'supervisor', 'bridge-child.mjs'), [
      '--port', String(port), '--config', config, ...(values.cwd ? ['--cwd', values.cwd] : []),
    ], {
      execPath: process.execPath, execArgv: [], stdio: ['ignore', 'inherit', 'inherit', 'ipc'], windowsHide: true,
      env: { ...process.env, MCP_PACEMAKER_UPGRADE_PENDING: pendingStart ? '1' : '0' },
    });
    child = launched;
    launched.on('message', async (message) => {
      if (message?.type === 'upgrade-lifetime') {
        if (lifetimeArmed) return;
        armLifetime(message.lifetime);
        lifetimeArmed.then(() => {
          if (launched.connected) launched.send('upgrade-lifetime-observed');
        }, error => {
          console.error(error.message);
          onSignal();
        });
        return;
      }
      if (message?.type === 'upgrade-result') {
        pending.get(message.requestId)?.(message);
        pending.delete(message.requestId);
      }
      if (message?.type !== 'upgrade-ready') return;
      try {
        if (process.platform === 'win32' &&
            !lifetimeArmed &&
            message.lifetime) armLifetime(message.lifetime);
        if (process.platform === 'win32' &&
            !lifetimeArmed) throw new Error('Windows backend lacks verified process containment observation.');
        if (lifetimeArmed) await lifetimeArmed;
        if (stopRequested ||
            launched !== child) return;
        if (message.protocol !== 1 ||
            message.version !== identity.version ||
            !Number.isInteger(message.port) ||
            message.port < 1 ||
            (port !== 0 && port !== message.port)) throw new Error('Bridge readiness identity mismatch.');
        if (port === 0) {
          port = message.port;
          paths = servicePaths(config, port);
          identity.port = port;
          identity.socket = paths.socket;
          await listen();
        }
        readiness = message;
        identity.instanceId = message.instanceId;
        writeFileSync(paths.record, JSON.stringify(identity) + '\n', { mode: 0o600 });
        if (process.connected) process.send({ ...message, type: 'supervisor-ready', supervisorId: identity.id });
      } catch (error) {
        console.error(error.message);
        await stop(false);
      }
    });
    childExit = new Promise((resolveExit, reject) => {
      launched.once('error', error => {
        failLifetime?.(error);
        reject(error);
      });
      launched.once('exit', (code) => {
        child = undefined;
        resolveExit();
        if (process.platform === 'win32' &&
            !lifetimeArmed) {
          failLifetime(new Error('Current Windows bridge exited without lifetime ownership proof. Older unsupported protocols require separately verified shutdown; no completed receipt is available.'));
          if (!stopRequested) {
            process.exitCode = 1;
            server.close();
            if (process.connected) process.disconnect();
          }
          return;
        }
        if (stopRequested) return;
        if (code === 3 ||
            initialStartup) {
          process.exitCode = code || 1;
          stop(false).then(() => {
            if (process.connected) process.disconnect();
          }, error => { console.error(error.message); process.exitCode = 1; });
        }
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
      let timeout;
      try {
        await Promise.race([
          (async () => {
            if (child?.connected) {
              try {
                await new Promise((resolveSend, reject) => child.send('stop', error => error ? reject(error) : resolveSend()));
              } catch (error) {
                if (error.code !== 'ERR_IPC_CHANNEL_CLOSED' &&
                    error.code !== 'EPIPE') throw error;
              }
            }
            const [, ...receipts] = await Promise.all([childExit, ...lifetimes]);
            for (const receipt of receipts) {
              if (receipt?.verified !== true ||
                  receipt.ownerExited !== true ||
                  receipt.activeProcesses !== 0) throw new Error('Windows descendant teardown was not verified; retain the installation.');
            }
          })(),
          new Promise((_, reject) => {
            timeout = setTimeout(() => reject(new Error('Bridge did not exit; do not replace its root. No force-kill attempted.')), 10000);
          }),
        ]);
      } finally {
        clearTimeout(timeout);
      }
      if (holdRequested) {
        writeFileSync(paths.hold, JSON.stringify({ id: identity.id, root, config, port, stopped: true,
          ...(stopAuthorization ? { quiescedInstanceId: stopAuthorization } : {}) }) + '\n', { mode: 0o600, flush: true });
      }
      if (process.connected) {
        await new Promise((resolveSent, reject) => {
          process.send({ type: 'supervisor-stopped', id: identity.id, stopped: true },
            error => error ? reject(error) : resolveSent());
        });
        process.disconnect();
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
