import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

export class TestProcess {
  constructor({ stdout = process.stdout, stderr = process.stderr, launch = spawn } = {}) {
    Object.assign(this, { stdout, stderr, launch });
  }

  run(contract, { cwd, env, signal } = {}) {
    assert.ok(Number.isSafeInteger(contract.timeoutMs) &&
      contract.timeoutMs > 0 &&
      contract.timeoutMs <= 60 * 60 * 1000, 'Invalid test process deadline');
    signal?.throwIfAborted();
    return new Promise((resolve, reject) => {
      const child = this.launch(process.execPath, contract.args, {
        cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const captured = [];
      let bytes = 0;
      let failure;
      let settled = false;
      let forceTimer;
      let closeTimer;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        clearTimeout(forceTimer);
        clearTimeout(closeTimer);
        process.off('SIGINT', interrupt);
        process.off('SIGTERM', terminate);
        signal?.removeEventListener('abort', abort);
        this.stdout.off('error', stop);
        this.stderr.off('error', stop);
        child.stdout.unpipe(this.stdout);
        child.stderr.unpipe(this.stderr);
        if (error) reject(error);
        else resolve(value);
      };
      const kill = requestedSignal => {
        try { child.kill(requestedSignal); }
        catch (error) { failure = new AggregateError([failure, error], 'Test child termination failed'); }
      };
      const stop = error => {
        if (failure ||
            settled) return;
        failure = error;
        kill('SIGTERM');
        forceTimer = setTimeout(() => kill('SIGKILL'), 5000);
        closeTimer = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
          child.unref();
          finish(new Error(`Test child ${child.pid} shutdown or output closure is unverified`, { cause: failure }));
        }, 10000);
      };
      const interrupt = () => stop(new Error('Test contract cancelled by SIGINT'));
      const terminate = () => stop(new Error('Test contract cancelled by SIGTERM'));
      const abort = () => stop(signal.reason ?? new Error('Test contract cancelled'));
      const deadline = setTimeout(() => stop(new Error(`Test contract exceeded ${contract.timeoutMs} ms`)),
        contract.timeoutMs);
      process.on('SIGINT', interrupt);
      process.on('SIGTERM', terminate);
      signal?.addEventListener('abort', abort, { once: true });
      this.stdout.on('error', stop);
      this.stderr.on('error', stop);
      child.stdout.pipe(this.stdout, { end: false });
      child.stderr.pipe(this.stderr, { end: false });
      if (contract.name === 'audit') {
        for (const stream of [child.stdout, child.stderr]) {
          stream.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > 16 * 1024 * 1024) stop(new Error('Privileged audit output exceeded 16 MiB'));
            else if (stream === child.stdout) captured.push(chunk);
          });
        }
      }
      child.stdout.on('error', stop);
      child.stderr.on('error', stop);
      child.once('error', error => {
        if (child.pid) stop(error);
        else finish(error);
      });
      child.once('close', (code, exitSignal) => {
        if (failure) finish(failure);
        else if (exitSignal ||
                 code !== 0) finish(new Error(`Test contract failed (${exitSignal ?? code})`));
        else finish(null, { stdout: Buffer.concat(captured).toString('utf8'), code, signal: exitSignal });
      });
    });
  }
}
