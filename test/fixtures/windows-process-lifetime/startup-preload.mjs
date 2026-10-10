// TEST-ONLY startup transport barrier. No production hook or environment override.
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const helper = fileURLToPath(new URL('../../../bin/windows-lifetime/ProcessLifetimeHelper.exe', import.meta.url));
const originalSpawn = childProcess.spawn;
let assigned = false;
let released = false;
setTimeout(() => process.exit(79), 45_000);

childProcess.spawn = (command, args, options) => {
  if (command !== helper) {
    if (!assigned) throw new Error('TEST: attempted workload before containment acknowledgement');
    const child = originalSpawn(command, args, options);
    child.once('spawn', () => process.send({ event: 'workload', pid: child.pid }));
    return child;
  }
  const pending = new EventEmitter();
  pending.stdout = new PassThrough();
  pending.stderr = new PassThrough();
  pending.exitCode = null;
  pending.signalCode = null;
  let actual;
  let nativeOutput = '';
  pending.kill = () => actual ? actual.kill() : false;
  process.once('message', (message) => {
    if (message !== 'release') throw new Error('Invalid owned startup control');
    released = true;
    const mode = process.env.PROBE_STARTUP_MODE;
    const target = mode === 'missing' ? `${helper}.missing`
      : mode === 'assignment-failure' ? process.env.PROBE_FAILURE_HELPER : helper;
    actual = originalSpawn(target, mode === 'invalid' ? ['invalid'] : args, options);
    pending.pid = actual.pid;
    actual.once('spawn', () => process.send({ event: 'owner', pid: actual.pid }));
    actual.on('error', (error) => pending.emit('error', error));
    actual.stdout.on('data', (data) => {
      nativeOutput += data;
      const identity = /^MCP_JOB_READY ([1-9][0-9]*) ([1-9][0-9]*)\r?\n$/.exec(nativeOutput);
      if (identity) {
        assigned = true;
        process.send({ event: 'lifetime',
          identity: { protocol: 1, ownerPid: Number(identity[1]), ownerCreationTime: identity[2] } });
      }
      pending.stdout.write(data);
    });
    actual.stderr.pipe(pending.stderr);
    actual.once('exit', (code, signal) => {
      pending.exitCode = code;
      pending.signalCode = signal;
      pending.emit('exit', code, signal);
    });
  });
  process.send({ event: 'before-assignment', released, assigned });
  return pending;
};
syncBuiltinESMExports();

const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  const ready = args.pop();
  args.push(function (...values) {
    ready.apply(this, values);
    process.send({ event: 'listening', port: this.address().port, assigned, released });
  });
  return listen.apply(this, args);
};
