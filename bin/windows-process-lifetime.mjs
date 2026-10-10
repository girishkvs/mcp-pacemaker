import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HELPER = fileURLToPath(new URL('./windows-lifetime/ProcessLifetimeHelper.exe', import.meta.url));
const METADATA = fileURLToPath(new URL('./windows-lifetime/ProcessLifetimeHelper.build.json', import.meta.url));

class WindowsProcessLifetime {
  identityFailure(reason) {
    const error = new Error(`Windows packaged helper identity check failed: ${reason}`);
    error.code = 'MCP_HELPER_IDENTITY';
    return error;
  }

  verifyHelper() {
    try {
      const bytes = readFileSync(METADATA);
      if (bytes.length > 64 * 1024) throw this.identityFailure('oversized metadata');
      const metadata = JSON.parse(bytes);
      const digest = metadata.binarySha256;
      const valid = metadata.schemaVersion === 1 &&
        metadata.binary === 'ProcessLifetimeHelper.exe' &&
        typeof digest === 'string' &&
        digest.length === 64 &&
        [...digest].every((character) => '0123456789abcdef'.includes(character));
      if (!valid) throw this.identityFailure('invalid recorded SHA256');
      const file = statSync(HELPER);
      if (!file.isFile() ||
          file.size === 0 ||
          file.size > 4 * 1024 * 1024) {
        throw this.identityFailure('invalid binary');
      }
      const actual = createHash('sha256').update(readFileSync(HELPER)).digest('hex');
      if (actual !== digest) throw this.identityFailure('binary SHA256 mismatch');
    } catch (error) {
      if (error.code === 'MCP_HELPER_IDENTITY') throw error;
      throw this.identityFailure(error.code || 'unreadable metadata or binary');
    }
  }

  decimal(value, maximumLength) {
    return typeof value === 'string' &&
      value.length > 0 &&
      value.length <= maximumLength &&
      value[0] !== '0' &&
      [...value].every((character) => character >= '0' && character <= '9');
  }

  async start() {
    this.verifyHelper();
    const child = spawn(HELPER, ['watch-parent', String(process.pid)], {
      detached: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let ready = false;
    let stdout = '';
    let stderr = '';
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        const fail = (detail) => {
          const error = new Error(`Windows process containment failed: ${detail}`);
          if (ready) {
            console.error(error.message);
            process.exit(1);
          }
          reject(error);
        };
        child.on('error', (error) => fail(error.code || 'helper launch error'));
        child.stderr.on('data', (chunk) => {
          stderr = (stderr + chunk).slice(-2048);
        });
        child.stdout.on('error', (error) => fail(error.code || 'helper stdout error'));
        child.stderr.on('error', (error) => fail(error.code || 'helper stderr error'));
        child.stdout.on('data', (chunk) => {
          stdout += chunk;
          if (stdout.length > 128) {
            fail('invalid helper readiness response');
            return;
          }
          if (!stdout.endsWith('\n')) return;
          let line = stdout.slice(0, -1);
          if (line.endsWith('\r')) line = line.slice(0, -1);
          const identity = line.split(' ');
          const valid = identity.length === 3 &&
            identity[0] === 'MCP_JOB_READY' &&
            this.decimal(identity[1], 10) &&
            this.decimal(identity[2], 19) &&
            Number(identity[1]) === child.pid;
          if (valid) {
            ready = true;
            child.unref?.();
            child.stdout.unref?.();
            child.stderr.unref?.();
            resolve({ protocol: 1, ownerPid: child.pid, ownerCreationTime: identity[2] });
          } else {
            fail('invalid helper readiness response');
          }
        });
        child.on('exit', (code, signal) => {
          if (!ready) {
            fail(`${stderr.trim() || 'helper exited before assignment'} (code ${code}, signal ${signal})`);
          } else {
            // Normally the job closes before this callback can run. Never keep
            // serving if its sole lifetime owner has unexpectedly exited.
            console.error('Windows process containment owner exited; stopping bridge.');
            process.exit(1);
          }
        });
        timer = setTimeout(() => fail('helper readiness deadline exceeded'), 5000);
      });
    } catch (error) {
      if (child.exitCode == null &&
          child.signalCode == null) child.kill();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async observe(identity) {
    const valid = identity?.protocol === 1 &&
      Number.isSafeInteger(identity.ownerPid) &&
      identity.ownerPid > 0 &&
      this.decimal(identity.ownerCreationTime, 19);
    if (!valid) throw new Error('Invalid Windows lifetime owner identity');
    this.verifyHelper();
    const child = spawn(HELPER, ['observe-owner', String(identity.ownerPid), identity.ownerCreationTime], {
      detached: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let ready = false;
    let drained = false;
    let stdout = '';
    let stderr = '';
    let timer;
    let resolveReady;
    let rejectReady;
    let resolveDone;
    let rejectDone;
    const armed = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
    const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
    // The same error is surfaced by armed when failure precedes API return.
    // Keep done rejectable for callers without a premature unhandled rejection.
    done.catch(() => {});
    const fail = (detail) => {
      const error = new Error(`Windows lifetime verification failed: ${detail}`);
      rejectReady(error);
      rejectDone(error);
      if (child.exitCode == null &&
          child.signalCode == null) child.kill();
    };
    child.on('error', (error) => fail(error.code || 'observer launch error'));
    child.stdout.on('error', (error) => fail(error.code || 'observer stdout error'));
    child.stderr.on('error', (error) => fail(error.code || 'observer stderr error'));
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-2048); });
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > 256) {
        fail('invalid observer response');
        child.kill();
        return;
      }
      let newline;
      while ((newline = stdout.indexOf('\n')) !== -1) {
        let line = stdout.slice(0, newline);
        if (line.endsWith('\r')) line = line.slice(0, -1);
        stdout = stdout.slice(newline + 1);
        if (!ready &&
            line === 'MCP_JOB_OBSERVER_READY') {
          ready = true;
          resolveReady();
        } else if (ready &&
            !drained &&
            line === 'MCP_JOB_DRAINED') {
          drained = true;
        } else {
          fail('invalid observer protocol');
          child.kill();
        }
      }
    });
    child.on('close', (code, signal) => {
      if (code === 0 &&
          signal === null &&
          ready &&
          drained &&
          stdout === '' &&
          stderr === '') {
        resolveDone({ verified: true, ownerExited: true, activeProcesses: 0 });
      } else {
        fail(`${stderr.trim() || 'no verified job drain'} (code ${code}, signal ${signal})`);
      }
    });
    timer = setTimeout(() => fail('observer readiness deadline exceeded'), 5000);
    try {
      await armed;
      return { done, pid: child.pid };
    } catch (error) {
      if (child.exitCode == null &&
          child.signalCode == null) child.kill();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

export async function ensureWindowsProcessLifetime() {
  return process.platform === 'win32' ? new WindowsProcessLifetime().start() : null;
}

export async function observeWindowsProcessLifetime(identity) {
  return process.platform === 'win32' ? new WindowsProcessLifetime().observe(identity) : null;
}
