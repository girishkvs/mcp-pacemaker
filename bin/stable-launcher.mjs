#!/usr/bin/env node
import { fork } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { durableJson, loadInstance, readManagedJson } from './managed-state.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const instance = loadInstance(directory);
let boundPort = instance.port;
const journalPath = join(directory, 'journal.json');
if (existsSync(journalPath)) {
  const journal = readManagedJson(journalPath);
  const legacyStart = journal.phase === 'legacy-launching' &&
    journal.legacy?.protocol === 1 &&
    journal.legacy.acknowledged === 'restart-with-uncertain-http-and-partial-tree-v1';
  const authorizedStart = (['launching', 'rollback-launching'].includes(journal.phase) || legacyStart) &&
    journal.launchToken === process.env.MCP_PACEMAKER_UPGRADE_TOKEN &&
    process.env.MCP_PACEMAKER_UPGRADE_PENDING === '1';
  if (!['committed', 'rolled-back', 'aborted'].includes(journal.phase) &&
      !authorizedStart) {
    throw new Error('Upgrade recovery required; stable autostart remains held. Run upgrade --recover --instance <directory>.');
  }
}
if (existsSync(join(directory, 'stopped'))) {
  console.log('Managed instance is held stopped. Use an explicit start.');
} else {
  const child = fork(join(instance.active.root, 'supervisor', 'supervise.mjs'), [
    '--port', String(instance.port), '--config', instance.config, '--cwd', instance.cwd,
  ], {
    execPath: instance.node, execArgv: [], windowsHide: true,
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    env: { ...process.env, MCP_PACEMAKER_MANAGED_INSTANCE: directory },
  });
  child.on('message', (message) => {
    if (message?.type === 'supervisor-ready' &&
        boundPort === 0) {
      const current = readManagedJson(join(directory, 'instance.json'));
      if (current.id !== instance.id ||
          current.port !== 0) throw new Error('Managed port identity changed during allocation.');
      durableJson(join(directory, 'instance.json'), { ...current, port: message.port });
      boundPort = message.port;
    }
    if (message?.type === 'supervisor-ready' &&
        message.port !== boundPort) throw new Error('Managed restart changed the persisted listener port.');
    if (process.connected) process.send(message);
  });
  process.on('message', (message) => { if (child.connected) child.send(message); });
  const shutdown = () => { if (child.connected) child.send('stop'); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  child.on('error', (error) => { console.error(error.message); process.exitCode = 1; });
  child.on('exit', (code) => { process.exitCode = code ?? 1; if (process.connected) process.disconnect(); });
}
