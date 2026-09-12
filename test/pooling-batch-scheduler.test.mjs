import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PoolingBatchScheduler, POOLING_RELOAD_DELAY_MS } from '../bin/pooling-batch-scheduler.mjs';

class Clock {
  time = 0;
  wallOffset = 1000000;
  sequence = 0;
  timers = new Map();

  now() { return this.time; }
  wallNow() { return this.wallOffset + this.time; }

  setTimeout(callback, delay) {
    const id = ++this.sequence;
    this.timers.set(id, { callback, at: this.time + delay });
    return id;
  }

  clearTimeout(id) {
    this.timers.delete(id);
  }

  advance(ms) {
    this.time += ms;
    while (true) {
      const due = [...this.timers].filter(([, timer]) => timer.at <= this.time)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) return;
      this.timers.delete(due[0]);
      due[1].callback();
    }
  }
}

class Fixture {
  clock = new Clock();
  reloads = [];
  errors = [];
  behavior = async (generation) => ({ applied: generation });
  scheduler;

  constructor({ onError } = {}) {
    this.scheduler = new PoolingBatchScheduler({
      clock: this.clock,
      reload: (generation) => {
        this.reloads.push(generation);
        return this.behavior(generation);
      },
      onError: (error, generation) => {
        this.errors.push({ error, generation });
        return onError?.(error, generation);
      },
    });
  }

  async tick(ms) {
    this.clock.advance(ms);
    await new Promise((resolve) => setImmediate(resolve));
    this.clock.advance(0);
    await new Promise((resolve) => setImmediate(resolve));
  }

  gate() {
    let release;
    const promise = new Promise((resolve) => { release = resolve; });
    return { promise, release };
  }
}

test('one accepted change waits the full five seconds before one reload', async () => {
  const f = new Fixture();
  assert.equal(POOLING_RELOAD_DELAY_MS, 5000);
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
  f.scheduler.schedule('first');
  assert.equal(f.scheduler.snapshot().pending.remainingMs, 5000);
  await f.tick(4999);
  assert.deepEqual(f.reloads, []);
  assert.equal(f.scheduler.snapshot().pending.remainingMs, 1);
  await f.tick(1);
  assert.deepEqual(f.reloads, ['first']);
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});

test('an accepted edit at three seconds resets the batch deadline to eight seconds', async () => {
  const f = new Fixture();
  f.scheduler.schedule('first');
  await f.tick(3000);
  f.scheduler.schedule('merged');
  assert.equal(f.scheduler.snapshot().pending.applyAt, 1008000);
  await f.tick(4999);
  assert.deepEqual(f.reloads, []);
  await f.tick(1);
  assert.deepEqual(f.reloads, ['merged']);
});

test('invalid scheduling does not replace the accepted generation or reset its timer', async () => {
  const f = new Fixture();
  f.scheduler.schedule('valid');
  await f.tick(3000);
  assert.throws(() => f.scheduler.schedule(undefined), TypeError);
  assert.equal(f.scheduler.snapshot().pending.remainingMs, 2000);
  await f.tick(2000);
  assert.deepEqual(f.reloads, ['valid']);
});

test('reload now applies once and cancels the scheduled duplicate', async () => {
  const f = new Fixture();
  f.scheduler.schedule('first');
  await f.tick(1000);
  assert.deepEqual(await f.scheduler.reloadNow(), { applied: 'first' });
  await f.tick(5000);
  assert.deepEqual(f.reloads, ['first']);
  assert.equal(f.clock.timers.size, 0);
});

test('a later batch waits for the current reload and is not lost or run concurrently', async () => {
  const f = new Fixture();
  const gate = f.gate();
  f.behavior = (generation) => generation === 'first' ? gate.promise : Promise.resolve(generation);
  f.scheduler.schedule('first');
  await f.tick(5000);
  assert.equal(f.scheduler.snapshot().applying, 'first');
  f.scheduler.schedule('next');
  await f.tick(5000);
  assert.deepEqual(f.reloads, ['first']);
  assert.equal(f.scheduler.snapshot().pending.remainingMs, 0);
  gate.release('first');
  await f.tick(0);
  assert.deepEqual(f.reloads, ['first', 'next']);
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});

test('concurrent reload-now requests share the in-flight reload', async () => {
  const f = new Fixture();
  const gate = f.gate();
  f.behavior = () => gate.promise;
  f.scheduler.schedule('first');
  const first = f.scheduler.reloadNow();
  const second = f.scheduler.reloadNow();
  await f.tick(0);
  assert.deepEqual(f.reloads, ['first']);
  gate.release('applied');
  assert.deepEqual(await Promise.all([first, second]), ['applied', 'applied']);
});

test('a failed automatic reload is reported once and never retried automatically', async () => {
  const f = new Fixture();
  const error = new Error('conflicting edit');
  f.behavior = async () => { throw error; };
  f.scheduler.schedule('first');
  await f.tick(5000);
  assert.deepEqual(f.errors, [{ error, generation: 'first' }]);
  await f.tick(30000);
  assert.deepEqual(f.reloads, ['first']);
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});

test('an explicit reload surfaces its failure to its caller as well as the error observer', async () => {
  const f = new Fixture();
  const error = new Error('write failed');
  f.behavior = async () => { throw error; };
  f.scheduler.schedule('first');
  await assert.rejects(f.scheduler.reloadNow(), (actual) => actual === error);
  assert.deepEqual(f.errors, [{ error, generation: 'first' }]);
});

test('cancelling an uncommitted batch prevents its timer from applying it', async () => {
  const f = new Fixture();
  f.scheduler.schedule('first');
  assert.equal(f.scheduler.cancelPending(), true);
  assert.equal(f.scheduler.cancelPending(), false);
  await f.tick(5000);
  assert.deepEqual(f.reloads, []);
});

test('shutdown drops a pending next batch but waits for a reload that already started', async () => {
  const f = new Fixture();
  const gate = f.gate();
  f.behavior = () => gate.promise;
  f.scheduler.schedule('first');
  await f.tick(5000);
  f.scheduler.schedule('next');
  let closed = false;
  const closing = f.scheduler.close().then(() => { closed = true; });
  await f.tick(10000);
  assert.equal(closed, false);
  assert.deepEqual(f.reloads, ['first']);
  gate.release('done');
  await closing;
  assert.throws(() => f.scheduler.schedule('third'));
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
  assert.equal(f.clock.timers.size, 0);
});

test('wall-clock changes do not shorten the monotonic debounce delay', async () => {
  const f = new Fixture();
  f.scheduler.schedule('first');
  f.clock.wallOffset += 3600000;
  assert.equal(f.scheduler.snapshot().pending.remainingMs, 5000);
  assert.equal(f.scheduler.snapshot().pending.applyAt, 4605000);
  await f.tick(4999);
  assert.deepEqual(f.reloads, []);
  await f.tick(1);
  assert.deepEqual(f.reloads, ['first']);
});

test('observer: synchronous reporting failure does not replace the reload error', async (t) => {
  const warnings = [];
  t.mock.method(process, 'emitWarning', (...args) => warnings.push(args));
  const original = new Error('reload failed');
  const f = new Fixture({ onError: () => { throw new Error('observer failed'); } });
  f.behavior = async () => { throw original; };
  f.scheduler.schedule('first');
  await assert.rejects(f.scheduler.reloadNow(), (error) => error === original);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0][1].code, 'MCP_POOLING_ERROR_OBSERVER_FAILED');
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});

test('observer: rejected reporting promise is handled without an unhandled rejection', async (t) => {
  const warnings = [];
  t.mock.method(process, 'emitWarning', (...args) => warnings.push(args));
  const original = new Error('reload failed');
  const f = new Fixture({ onError: async () => { throw new Error('observer failed'); } });
  f.behavior = async () => { throw original; };
  f.scheduler.schedule('first');
  await f.tick(5000);
  assert.deepEqual(f.errors, [{ error: original, generation: 'first' }]);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0][1].code, 'MCP_POOLING_ERROR_OBSERVER_FAILED');
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});

test('observer: a pending observer promise cannot hold reload completion open', async () => {
  const original = new Error('reload failed');
  const f = new Fixture({ onError: () => new Promise(() => {}) });
  f.behavior = async () => { throw original; };
  f.scheduler.schedule('first');
  await assert.rejects(f.scheduler.reloadNow(), (error) => error === original);
  assert.deepEqual(f.scheduler.snapshot(), { pending: null, applying: null });
});
