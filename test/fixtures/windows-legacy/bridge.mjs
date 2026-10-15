import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const mode = process.argv[2];
setTimeout(() => process.exit(0), 45000);
if (mode === '--worker') {
  writeFileSync(process.argv[3], JSON.stringify({ pid: process.pid, parentPid: process.ppid }));
  process.stdin.on('error', () => {});
  setInterval(() => {}, 200);
} else if (mode === '--prepare') {
  // An upgrade started from a process inside the bridge's own tree.
  const [resultPath, modulePath, port, root] = process.argv.slice(3);
  try {
    const api = await import(pathToFileURL(modulePath).href);
    const session = await api.prepareLegacyProcesses({ port: Number(port), root });
    await session.close();
    writeFileSync(resultPath, JSON.stringify({ ok: true }));
  } catch (error) {
    writeFileSync(resultPath, JSON.stringify({ ok: false, message: error.message, reason: error.detail?.reason ?? null }));
  }
  process.exit(0);
} else {
  const port = Number(process.argv[3]);
  const directory = process.env.OWNED_LEGACY_DIRECTORY;
  const children = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/spawn') {
      const path = join(directory, `worker-${children.length}.json`);
      const child = spawn(process.execPath, [process.argv[1], '--worker', path], {
        detached: true, stdio: 'ignore', windowsHide: true,
      });
      child.unref();
      children.push({ pid: child.pid, path });
      child.on('error', () => {});
    }
    if (url.pathname === '/spawn-wrapped') {
      // 1.3 runs a bare server command through a non-detached cmd.exe wrapper with stdio pipes.
      // Node's job object ends that wrapper together with this process.
      const path = join(directory, `wrapped-${children.length}.json`);
      const line = [process.execPath, process.argv[1], '--worker', path].map((value) => `"${value}"`).join(' ');
      const child = spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `"${line}"`], {
        stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, windowsVerbatimArguments: true,
      });
      children.push({ pid: child.pid, path, wrapped: true });
      child.on('error', () => {});
    }
    if (url.pathname === '/spawn-prepare') {
      const path = join(directory, `prepare-${children.length}.json`);
      const child = spawn(process.execPath, [process.argv[1], '--prepare', path,
        url.searchParams.get('module'), String(port), url.searchParams.get('root')], { stdio: 'ignore', windowsHide: true });
      children.push({ pid: child.pid, path, prepare: true });
      child.on('error', () => {});
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ fixture: 'owned-legacy-broker', pid: process.pid, script: process.argv[1], children }));
  });
  server.listen(port, '127.0.0.1', () => {
    writeFileSync(join(directory, 'ready.json'), JSON.stringify({ pid: process.pid, port: server.address().port }));
  });
}
