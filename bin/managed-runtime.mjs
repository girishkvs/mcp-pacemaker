import { fork } from 'node:child_process';
import { closeSync, existsSync, openSync } from 'node:fs';
import { get } from 'node:http';
import { connect } from 'node:net';
import { join } from 'node:path';
import { loadInstance, readManagedJson } from './managed-state.mjs';
import { controlManagedService, resumeService, servicePaths, stopManagedService, validateServiceRecord } from './service-control.mjs';

const launches = new Map();

export function listenerOpen(port) {
  return new Promise((resolveProbe, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolveProbe(true); });
    socket.once('error', error => {
      if (error.code === 'ECONNREFUSED') resolveProbe(false);
      else reject(error);
    });
    socket.setTimeout(2000, () => socket.destroy(new Error('Listener identity probe timed out.')));
  });
}

export function backendStatus(port) {
  return new Promise((resolveStatus, reject) => {
    const request = get(`http://127.0.0.1:${port}/api/status`, response => {
      let body = '';
      response.on('data', bytes => {
        body += bytes;
        if (body.length > 4 * 1024 * 1024) request.destroy(new Error('Oversized backend status.'));
      });
      response.on('end', () => {
        try {
          if (response.statusCode !== 200) throw new Error('Backend not ready.');
          resolveStatus(JSON.parse(body));
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.setTimeout(2000, () => request.destroy(new Error('Backend readiness timed out.')));
  });
}

export function serviceSelection(instance) {
  return { root: instance.active.root, config: instance.config, port: instance.port };
}

function assertInstanceService(instance) {
  const record = validateServiceRecord(
    readManagedJson(servicePaths(instance.config, instance.port).record), serviceSelection(instance));
  if (record.managedInstance !== instance.directory) {
    throw new Error('Supervisor belongs to a different managed instance; no service action was sent.');
  }
}

export async function startInstance(directory, { pending = false, token } = {}) {
  let instance = loadInstance(directory);
  const journalPath = join(directory, 'journal.json');
  if (existsSync(journalPath)) {
    const journal = readManagedJson(journalPath);
    const legacyStart = journal.phase === 'legacy-launching' &&
      journal.legacy?.protocol === 1 &&
      journal.legacy.acknowledged === 'restart-with-uncertain-http-and-partial-tree-v1';
    const authorized = (['launching', 'rollback-launching'].includes(journal.phase) || legacyStart) &&
      journal.launchToken === token &&
      pending;
    if (!['committed', 'rolled-back', 'aborted'].includes(journal.phase) &&
        !authorized) throw new Error('Unfinished upgrade journal blocks start; use explicit recovery.');
  }
  if (instance.port !== 0 &&
      await listenerOpen(instance.port)) throw new Error('Selected port is busy; no listener was adopted.');
  if (instance.port) resumeService(instance.config, instance.port);
  const log = openSync(join(directory, 'launcher.log'), 'a', 0o600);
  const child = fork(join(directory, 'stable-launcher.mjs'), [], {
    execPath: instance.node, execArgv: [], detached: true, windowsHide: true,
    stdio: ['ignore', log, log, 'ipc'],
    env: {
      ...process.env, MCP_PACEMAKER_UPGRADE_PENDING: pending ? '1' : '0',
      MCP_PACEMAKER_UPGRADE_TOKEN: token ?? '',
    },
  });
  closeSync(log);
  const exited = new Promise(resolveExit => child.once('exit', resolveExit));
  const running = launches.get(directory) ?? [];
  running.push({ child, exited });
  launches.set(directory, running);
  let timer;
  let startupStopped = false;
  let startupStopId;
  child.on('message', message => {
    if (message?.type === 'supervisor-stopped' &&
        message.stopped === true) {
      startupStopped = true;
      startupStopId = message.id;
    }
  });
  try {
    const ready = await new Promise((resolveReady, reject) => {
      child.once('error', reject);
      child.once('exit', () => reject(new Error(`Managed startup failed. Inspect ${join(directory, 'launcher.log')}.`)));
      child.on('message', message => {
        if (message?.type === 'supervisor-ready') resolveReady(message);
      });
      timer = setTimeout(() => reject(new Error('Managed startup readiness timed out.')), 15000);
    });
    instance = loadInstance(directory, { verifyFiles: false });
    const valid = ready.version === instance.active.version &&
      ready.port === instance.port &&
      ready.held === pending;
    if (!valid) throw new Error('Started backend identity does not match the active selection.');
    const status = await backendStatus(instance.port);
    if (status.service !== 'mcp-pacemaker' ||
        status.version !== ready.version ||
        status.instanceId !== ready.instanceId) throw new Error('Actual listener did not verify the started backend.');
    return { instance, ready };
  } catch (error) {
    if (child.connected) {
      child.send('stop');
      await new Promise((resolveExit, reject) => {
        if (child.exitCode !== null) { resolveExit(); return; }
        const deadline = setTimeout(() => reject(new Error('Failed startup shutdown is unverified; retain journal and package.')), 12000);
        child.once('exit', () => { clearTimeout(deadline); resolveExit(); });
      });
    }
    error.startupStopped = startupStopped;
    if (startupStopped) error.startupProof = {
      supervisorId: startupStopId, root: instance.active.root, config: instance.config,
      port: instance.port, launchToken: token,
    };
    if (!startupStopped) error.cleanupUnverified = true;
    throw error;
  } finally {
    clearTimeout(timer);
    if (child.connected) child.disconnect();
    child.unref();
  }
}

export async function stopInstance(instance, quiescedInstanceId) {
  assertInstanceService(instance);
  const selection = serviceSelection(instance);
  const stopped = await stopManagedService({ ...selection, quiescedInstanceId });
  if (await listenerOpen(instance.port)) throw new Error('Stopped supervisor still has a live listener; recovery required.');
  await waitForInstanceExit(instance.directory);
  return stopped;
}

export async function waitForInstanceExit(directory) {
  const running = launches.get(directory) ?? [];
  let timeout;
  try {
    await Promise.race([
      Promise.all(running.map(entry => entry.exited)),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('Owned stable launcher did not exit; retain its files.')), 12000);
      }),
    ]);
    launches.delete(directory);
  } finally { clearTimeout(timeout); }
}

export async function inspectInstance(instance, action = 'inspect', expected = {}) {
  assertInstanceService(instance);
  const response = await controlManagedService(serviceSelection(instance), action, expected);
  const status = await backendStatus(instance.port);
  if (status.version !== response.version ||
      status.instanceId !== response.instanceId) throw new Error('Listener and managed supervisor identity disagree.');
  return response;
}
