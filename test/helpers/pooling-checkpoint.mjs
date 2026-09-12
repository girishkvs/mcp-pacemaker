import fs from 'node:fs';
import { join } from 'node:path';
import { setTimeout, clearTimeout } from 'node:timers';

export const FIXTURE_DEADLOCK_MS = 30000;

export class PoolingFixtureGuard {
  constructor(phase, milliseconds = FIXTURE_DEADLOCK_MS) {
    this.controller = new AbortController();
    this.signal = this.controller.signal;
    this.pending = new Set();
    this.signal.addEventListener('abort', () => {
      for (const abort of this.pending) abort();
    }, { once: true });
    this.timer = setTimeout(() => this.controller.abort(
      new Error(`Fixture deadlock guard expired (${phase})`)), milliseconds);
    this.timer.unref();
  }

  wait(operation) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        this.pending.delete(abort);
        if (error) reject(error);
        else resolve(value);
      };
      const abort = () => finish(this.signal.reason);
      Promise.resolve(operation).then((value) => finish(undefined, value), (error) => finish(error));
      if (this.signal.aborted) abort();
      else this.pending.add(abort);
    });
  }

  dispose() {
    clearTimeout(this.timer);
  }
}

export class PoolingCheckpoint {
  constructor(directory, phase, signal) {
    this.directory = directory;
    this.path = join(directory, 'entered');
    this.phase = phase;
    this.signal = signal;
  }

  wait(operation) {
    if (typeof operation?.then !== 'function') {
      return Promise.reject(new TypeError('Checkpoint wait requires the operation being observed'));
    }
    return new Promise((resolve, reject) => {
      let watcher;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        watcher?.close();
        this.signal.removeEventListener('abort', aborted);
        if (error) reject(error);
        else resolve();
      };
      const observe = () => {
        if (settled) return true;
        let phase;
        try {
          phase = fs.readFileSync(this.path, 'utf8');
        } catch (error) {
          if (error.code === 'ENOENT') return false;
          finish(error);
          return true;
        }
        finish(phase === this.phase ? undefined
          : new Error(`Expected checkpoint ${this.phase}, received ${phase}`));
        return true;
      };
      const aborted = () => finish(this.signal.reason);

      // Completion can arrive before delivery of the filesystem notification.
      Promise.resolve(operation).then(() => {
        if (!observe()) finish(new Error(`Operation completed before checkpoint ${this.phase}`));
      }, (error) => {
        if (!observe()) finish(error);
      });
      this.signal.addEventListener('abort', aborted, { once: true });
      if (this.signal.aborted) {
        aborted();
        return;
      }
      try {
        watcher = fs.watch(this.directory, (_event, filename) => {
          if (filename === null ||
              filename.toString() === 'entered') observe();
        });
        watcher.on('error', finish);
      } catch (error) {
        finish(error);
        return;
      }
      observe();
    });
  }
}
