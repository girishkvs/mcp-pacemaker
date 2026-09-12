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
  return { status: response.status, body: result };
}

function validatePendingReceipt(receipt, name, port) {
  const invalid = 'Bridge returned an invalid HTTP 202 receipt. Reread settings before retrying.';
  const nonempty = (value) => typeof value === 'string' && value.length > 0;
  const fieldsValid = receipt?.ok === true && receipt.pending === true &&
    receipt.name === name && nonempty(receipt.batchId) &&
    nonempty(receipt.undoId) && nonempty(receipt.revision);
  if (!fieldsValid) throw new Error(invalid);

  const snapshot = receipt.snapshot;
  const snapshotValid = snapshot?.service === 'mcp-pacemaker' &&
    snapshot.port === port && nonempty(snapshot.instanceId) &&
    Number.isSafeInteger(snapshot.snapshotVersion) && snapshot.snapshotVersion > 0 &&
    Array.isArray(snapshot.servers) && snapshot.servers.some((server) => server?.name === name) &&
    snapshot.prewarm?.revision === receipt.revision &&
    Number.isSafeInteger(snapshot.prewarm.maxWarm) && snapshot.prewarm.maxWarm > 0 &&
    Number.isFinite(snapshot.prewarm.batchDelayMs) && snapshot.prewarm.batchDelayMs > 0 &&
    Array.isArray(snapshot.prewarm.batches);
  if (!snapshotValid) throw new Error(invalid);

  const batch = snapshot.prewarm.batches.find((candidate) => candidate?.id === receipt.batchId);
  const timingValid = batch?.status === 'pending' ? Number.isFinite(batch.applyAt)
    : batch?.status === 'applying' && batch.applyAt === null;
  const changesValid = Array.isArray(batch?.changes) && batch.changes.length > 0 &&
    batch.changes.some((change) => change?.name === name) &&
    batch.changes.every((change) => nonempty(change?.name) &&
      (change.mode === 'pool'
        ? change.minWarm === undefined ||
          Number.isSafeInteger(change.minWarm) && change.minWarm >= 1 && change.minWarm <= snapshot.prewarm.maxWarm
        : change.mode === 'isolated' && change.minWarm === undefined));
  if (!timingValid ||
      !changesValid ||
      batch.revision !== receipt.revision) {
    throw new Error(invalid);
  }
}

export function formatPrewarm(snapshot, now = Date.now()) {
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
  const history = snapshot.prewarm?.batches ?? [];
  const latestFinished = history.find((batch) => ['applied', 'failed', 'cancelled'].includes(batch.status));
  const batches = history
    .filter((batch) => ['pending', 'applying'].includes(batch.status) ||
      batch === latestFinished && batch.status === 'failed')
    .map((batch) => {
      const changes = batch.changes.map((change) => {
        const target = change.minWarm === undefined
          ? 'pooling with configured target' : `${change.minWarm} warm slot(s)`;
        return `${change.name}: ${change.mode === 'pool' ? target : 'pre-warming off'}`;
      }).join(', ');
      if (batch.status === 'failed') return `Batch failed (${changes}): ${batch.error || 'Reread settings before retrying.'}`;
      if (batch.status === 'applying') return `Applying batch: ${changes}.`;
      const secondsLeft = Math.max(0, Math.ceil((batch.applyAt - now) / 1000));
      return `Pending batch (reload in ${secondsLeft}s): ${changes}. Active settings above have not changed.`;
    });
  return [
    `Pre-warming on :${snapshot.port} (process counters since ${snapshot.startedAt || 'bridge start'})`,
    ...rows.map((row) => row.map((cell, column) => cell.padEnd(widths[column])).join('  ').trimEnd()),
    'Pre-warming is opt-in. Each warm slot holds one additional resident process.',
    'Shared mode is separately opt-in: compatible stateless tools sessions reuse one initialized child.',
    ...(typeof snapshot.prewarm?.saveWarning === 'string'
      ? [`File save notice: ${snapshot.prewarm.saveWarning}`] : []),
    ...batches,
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
    const { body: snapshot } = await jsonRequest(port, '/api/status');
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
  if (!options.json &&
      typeof snapshot.prewarm.saveWarning === 'string') {
    write(`File save notice: ${snapshot.prewarm.saveWarning}`);
  }
  const response = await jsonRequest(snapshot.port, `/admin/servers/${encodeURIComponent(name)}/pooling`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-mcp-nonce': nonce, 'x-mcp-pooling-batch': '1' },
    body: JSON.stringify(body),
  });
  const result = response.body;
  if (response.status === 202) {
    validatePendingReceipt(result, name, snapshot.port);
  } else if (response.status !== 200 ||
             result?.pending === true) {
    throw new Error('Bridge returned an unexpected pooling response status. Reread settings before retrying.');
  }
  if (result?.ok !== true) throw new Error(result?.error || 'Bridge did not confirm the pooling change');
  if (options.json) {
    write(JSON.stringify(result));
  } else if (result.pending) {
    const batch = result.snapshot?.prewarm?.batches?.find((candidate) => candidate.id === result.batchId);
    const scope = batch?.changes.map((change) => change.name).join(', ') || name;
    const secondsLeft = batch?.applyAt == null ? null : Math.max(0, Math.ceil((batch.applyAt - Date.now()) / 1000));
    const timing = secondsLeft === null ? '' : ` in ${secondsLeft}s`;
    let action;
    if (options.undo) action = 'previous batch configuration staged';
    else if (body.mode === 'pool') action = `${body.minWarm} warm slot(s) staged`;
    else action = 'pre-warming disable staged';
    write(`${name}: ${action}. Pending reload${timing}; not active yet.`);
    if (result.undoId) {
      write(`Cancel while pending / undo after apply (entire batch: ${scope}): ${formatUndoCommand(snapshot.port, name, result.undoId, options.config)}`);
    }
  } else if (result.cancelled) {
    write(`${name}: pending batch cancelled. Active settings were not changed.`);
  } else {
    write(`${name}: ${options.undo ? 'restored previous pooling settings' : body.mode === 'pool' ? `enabled ${body.minWarm} warm slot(s)` : 'disabled pre-warming'}`);
    if (result.undoId) {
      write(`Undo: ${formatUndoCommand(snapshot.port, name, result.undoId, options.config)}`);
    }
  }
}
