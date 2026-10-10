import { spawn, execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

if (process.argv[2] === 'worker') {
  const identity = execFileSync('pwsh', [
    '-NoProfile', '-File', fileURLToPath(new URL('./windows-process-lifetime/identity.ps1', import.meta.url)),
    '-ProcessId', String(process.pid),
  ], { encoding: 'utf8', windowsHide: true });
  writeFileSync(process.argv[3], identity);
  setInterval(() => writeFileSync(`${process.argv[3]}.heartbeat`, String(Date.now())), 50);
} else {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'worker', process.argv[2]], {
    detached: true, windowsHide: true, stdio: 'ignore',
  });
  child.unref();
  const deadline = Date.now() + 10000;
  const timer = setInterval(() => {
    if (existsSync(process.argv[2])) {
      clearInterval(timer);
      process.exit(0);
    }
    if (Date.now() >= deadline) throw new Error('Owned orphan did not record its identity.');
  }, 10);
}
