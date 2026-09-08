import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function portNumber(value) {
  const port = Number(value);
  if (!Number.isInteger(port) ||
      port < 1 ||
      port > 65535) {
    throw new Error('Port must be an integer between 1 and 65535');
  }
  return port;
}

async function jsonRequest(port, path, options = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    ...options,
    signal: AbortSignal.timeout(10_000),
  });
  if (response.status === 401) {
    throw new Error('Admin nonce was rejected. Check --config points to the running bridge, then retry.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Bridge on :${port} returned a non-JSON response (${response.status})`);
  }
  if (!response.ok) {
    throw new Error(result.error || `Bridge on :${port} rejected the request (${response.status})`);
  }
  return result;
}

export function formatPrewarm(snapshot) {
  const seconds = (ms) => ms == null ? '-' : `${(ms / 1000).toFixed(1)}s`;
  const rows = [
    ['SERVER', 'MODE', 'WARM/TARGET', 'STARTS', 'COLD P50', 'P95', 'SUGGESTED', 'SHARED CHILD'],
    ...snapshot.servers.filter((server) => server.type === 'stdio').map((server) => [
      server.name,
      server.sharing,
      server.sharing === 'shared' ? '-' : `${server.warm}/${server.minWarm}`,
      String(server.spawn?.total ?? '-'),
      seconds(server.spawn?.p50Ms),
      seconds(server.spawn?.p95Ms),
      server.prewarming?.eligible ? String(server.prewarming.suggestedMinWarm) : '-',
      server.sharing === 'shared' ? server.shared
        ? `${server.shared.state}: ${server.shared.members} sessions, ${server.shared.unresolved} pending, ${server.shared.queued} queued`
        : 'not active' : '-',
    ]),
  ];
  const widths = rows[0].map((_, column) => Math.max(...rows.map((row) => row[column].length)));
  return [
    `Pre-warming on :${snapshot.port} (process counters since ${snapshot.startedAt || 'bridge start'})`,
    ...rows.map((row) => row.map((cell, column) => cell.padEnd(widths[column])).join('  ').trimEnd()),
    'Pre-warming is opt-in. Each warm slot holds one additional resident process.',
    'Shared mode is separately opt-in: compatible stateless tools sessions reuse one initialized child.',
  ].join('\n');
}

function shellArgument(text) {
  if (process.platform === 'win32') return `"${text}"`;
  return `'${text.replaceAll("'", "'\\''")}'`;
}

export function formatUndoCommand(port, name, undoId, config) {
  const executable = process.execPath;
  const entry = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const values = [executable, entry, name, undoId, ...(config ? [config] : [])];
  const needsExplicitShell = process.platform === 'win32' &&
    values.some((value) => /[%!$`"^\r\n]|\\$/.test(value));
  if (needsExplicitShell) {
    const quote = (value) => `'${value.replaceAll("'", "''")}'`;
    const configArg = config ? ` --config ${quote(config)}` : '';
    const command = `& ${quote(executable)} ${quote(entry)} prewarm --port ${port}${configArg} --server ${quote(name)} --undo ${quote(undoId)}`;
    return `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(command, 'utf16le').toString('base64')}`;
  }
  const configArg = config ? ` --config ${shellArgument(config)}` : '';
  const node = process.platform === 'win32' ? 'node.exe' : shellArgument(executable);
  return `${node} ${shellArgument(entry)} prewarm --port ${port}${configArg} --server ${shellArgument(name)} --undo ${undoId}`;
}

export async function runPrewarm(options, { configPath, ports, write = console.log } = {}) {
  const selectedPorts = options.port ? [portNumber(options.port)] : ports.map(portNumber);
  const actionCount = [options.enable, options.disable, options.undo].filter(Boolean).length;
  if (actionCount > 1) throw new Error('Choose only one of --enable, --disable or --undo');
  if (actionCount &&
      selectedPorts.length !== 1) {
    throw new Error('Choose --port when changing a server on a multi-bridge setup');
  }
  if (options.count &&
      !options.enable) {
    throw new Error('--count requires --enable');
  }
  if (options.undo &&
      !options.server) {
    throw new Error('--undo requires --server');
  }

  const snapshots = [];
  for (const port of selectedPorts) {
    const snapshot = await jsonRequest(port, '/api/status');
    if (snapshot.service !== 'mcp-pacemaker') throw new Error(`:${port} is not a pacemaker bridge`);
    snapshots.push(snapshot);
  }

  if (!actionCount) {
    if (options.json) {
      write(JSON.stringify(snapshots.length === 1 ? snapshots[0] : snapshots));
    } else {
      for (const snapshot of snapshots) write(formatPrewarm(snapshot));
    }
    return;
  }

  const snapshot = snapshots[0];
  if (!snapshot.prewarm) throw new Error('The running bridge does not support pooling changes; update and restart it first');
  const name = options.enable || options.disable || options.server;
  const server = snapshot.servers.find((candidate) => candidate.name === name);
  if (!server) throw new Error(`Unknown server: ${name}`);
  if (server.type !== 'stdio') throw new Error('HTTP proxies have no local child to pre-warm');
  const body = { revision: snapshot.prewarm.revision };
  if (options.undo) {
    body.undoId = options.undo;
  } else {
    body.mode = options.enable ? 'pool' : 'isolated';
    if (options.enable) {
      if (!server.prewarming?.eligible) throw new Error(server.prewarming?.reason || 'Server is not eligible for pre-warming');
      body.minWarm = options.count === undefined ? server.prewarming.suggestedMinWarm : Number(options.count);
      if (!Number.isSafeInteger(body.minWarm) ||
          body.minWarm < 1 ||
          body.minWarm > snapshot.prewarm.maxWarm) {
        throw new Error(`--count must be an integer between 1 and ${snapshot.prewarm.maxWarm}`);
      }
    }
  }
  const nonce = (await readFile(join(dirname(options.config || configPath), 'admin.nonce'), 'utf8')).trim();
  const result = await jsonRequest(snapshot.port, `/admin/servers/${encodeURIComponent(name)}/pooling`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-mcp-nonce': nonce },
    body: JSON.stringify(body),
  });
  if (result.ok !== true) throw new Error(result.error || 'Bridge did not confirm the pooling change');
  if (options.json) {
    write(JSON.stringify(result));
  } else {
    write(`${name}: ${options.undo ? 'restored previous pooling settings' : body.mode === 'pool' ? `enabled ${body.minWarm} warm slot(s)` : 'disabled pre-warming'}`);
    if (result.undoId) {
      write(`Undo: ${formatUndoCommand(snapshot.port, name, result.undoId, options.config)}`);
    }
  }
}
