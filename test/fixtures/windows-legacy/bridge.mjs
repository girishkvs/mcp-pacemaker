import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const mode = process.argv[2];
setTimeout(() => process.exit(0), 45000);
if (mode === '--worker') {
  writeFileSync(process.argv[3], JSON.stringify({ pid: process.pid, parentPid: process.ppid }));
  process.stdin.on('error', () => {});
  setInterval(() => {}, 200);
} else {
  const port = Number(process.argv[3]);
  const directory = process.env.OWNED_LEGACY_DIRECTORY;
  const children = [];
  const server = createServer((request, response) => {
    if (request.url === '/spawn') {
      const path = join(directory, `worker-${children.length}.json`);
      const child = spawn(process.execPath, [process.argv[1], '--worker', path], {
        detached: true, stdio: 'ignore', windowsHide: true,
      });
      child.unref();
      children.push({ pid: child.pid, path });
      child.on('error', () => {});
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ fixture: 'owned-legacy-broker', pid: process.pid, script: process.argv[1], children }));
  });
  server.listen(port, '127.0.0.1', () => {
    writeFileSync(join(directory, 'ready.json'), JSON.stringify({ pid: process.pid, port: server.address().port }));
  });
}
