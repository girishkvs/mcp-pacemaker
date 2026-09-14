import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, unlinkSync } from 'node:fs';
import { connect } from 'node:net';
import { dirname, join, resolve } from 'node:path';

export function servicePaths(config, port) {
  if (!Number.isInteger(port) ||
      port < 1 ||
      port > 65535) {
    throw new Error('Service port must be an integer from 1 to 65535.');
  }
  const directory = dirname(resolve(config));
  const key = createHash('sha256').update(`${directory}\n${port}`).digest('hex').slice(0, 32);
  const socket = process.platform === 'win32'
    ? `\\\\.\\pipe\\mcp-pacemaker-${key}`
    : join(directory, `service-${port}.sock`);
  if (process.platform !== 'win32' &&
      Buffer.byteLength(socket) > 103) {
    throw new Error('Service socket path exceeds the POSIX limit of 103 UTF-8 bytes. Use a shorter config directory; no alternate endpoint was selected.');
  }
  return {
    record: join(directory, `service-${port}.json`),
    hold: join(directory, `service-${port}.stopped`),
    socket,
  };
}

export function assertDurableRoot(root) {
  if (/(^|[/\\])_npx([/\\]|$)/i.test(root)) {
    throw new Error('Cache-backed npx roots cannot host an unattended service. Install in a durable root, then register autostart there. Use --no-autostart --no-start for wiring only.');
  }
}

export function backendDescription(cliVersion, backend, action) {
  const version = typeof backend?.version === 'string' ? backend.version : 'unknown';
  const instance = typeof backend?.instanceId === 'string' ? backend.instanceId : 'unknown';
  return `installed CLI ${cliVersion}; running backend ${version}; instance ${instance} — ${action}` +
    (version !== cliVersion ? ' (version mismatch; adoption does not upgrade the backend)' : '');
}

export function resumeService(config, port) {
  try {
    unlinkSync(servicePaths(config, port).hold);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export function validateServiceRecord(record, { root, config, port }) {
  const matches = record?.protocol === 1 &&
    record.root === realpathSync(root) &&
    record.config === resolve(config) &&
    record.port === port &&
    record.socket === servicePaths(config, port).socket &&
    typeof record.id === 'string' &&
    /^[a-f0-9-]{36}$/.test(record.id) &&
    typeof record.token === 'string' &&
    /^[a-f0-9]{64}$/.test(record.token);
  if (!matches) {
    throw new Error('Managed service identity does not match this installation root, config, port and endpoint. Use the matching installation CLI; no process was stopped.');
  }
  return record;
}

export function requestService(socket, request) {
  return new Promise((resolveRequest, reject) => {
    const client = connect(socket);
    let data = '';
    const finish = (error, response) => {
      client.destroy();
      if (error) reject(error);
      else resolveRequest(response);
    };
    client.setTimeout(12000, () => finish(new Error('Supervisor response timed out; shutdown is not verified.')));
    client.on('error', () => finish(new Error('Managed supervisor is unavailable; shutdown is not verified. Older or unmanaged services require verified OS-service shutdown.')));
    client.on('connect', () => client.write(JSON.stringify(request) + '\n'));
    client.on('data', (chunk) => {
      data += chunk;
      if (data.length > 16384) {
        finish(new Error('Invalid supervisor response.'));
        return;
      }
      if (!data.includes('\n')) return;
      let response;
      try { response = JSON.parse(data.slice(0, data.indexOf('\n'))); }
      catch { finish(new Error('Invalid supervisor response.')); return; }
      finish(null, response);
    });
    client.on('end', () => finish(new Error('Supervisor closed before acknowledging shutdown.')));
  });
}

export async function stopManagedService({ root, config, port, request = requestService }) {
  const paths = servicePaths(config, port);
  let record;
  try {
    record = JSON.parse(readFileSync(paths.record, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    throw new Error(`No managed supervisor record for :${port}. Older or direct bridges require verified OS-service shutdown and disabled autostart; no process was stopped.`);
  }
  validateServiceRecord(record, { root, config, port });
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(paths.hold, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const completed = receipt?.stopped === true &&
    receipt.id === record.id &&
    receipt.root === record.root &&
    receipt.config === record.config &&
    receipt.port === record.port;
  if (completed) {
    return { root: record.root, config: record.config, port, supervisorId: record.id, alreadyStopped: true };
  }
  const response = await request(paths.socket, { action: 'stop', id: record.id, token: record.token });
  if (response?.id !== record.id ||
      response.stopped !== true ||
      response.autostartHeld !== true) {
    throw new Error('Supervisor did not verify shutdown and its autostart hold. Do not replace the installation root.');
  }
  return { root: record.root, config: record.config, port, supervisorId: record.id };
}
