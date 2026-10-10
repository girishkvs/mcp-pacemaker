import { spawn } from 'node:child_process';
import { ensureWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';

const lifetime = await ensureWindowsProcessLifetime();
process.on('disconnect', () => process.exit(0));
process.on('message', message => {
  if (message.action === 'close') process.exit(0);
  if (message.action === 'launch-worker') {
    const worker = spawn(process.execPath, message.args, {
      cwd: message.cwd, env: message.env, windowsHide: true, stdio: ['ignore', 'inherit', 'inherit'],
    });
    worker.once('error', error => process.send({ id: message.id, error: error.message }));
    worker.once('exit', code => process.send({ id: message.id, code }));
    return;
  }
  if (message.action !== 'launch') throw new Error('Unknown owned fixture action.');
  const child = spawn('pwsh.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', message.script, '-Port', String(message.port),
  ], {
    cwd: message.cwd, env: message.env, windowsHide: true, stdio: ['ignore', 'inherit', 'inherit'],
  });
  child.once('error', error => process.send({ id: message.id, error: error.message }));
  child.once('spawn', () => process.send({ id: message.id, pid: child.pid }));
});
process.send({ type: 'ready', lifetime });
