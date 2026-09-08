import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { appendFileSync, mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setImmediate as yieldTurn } from 'node:timers/promises';
import { runLogs } from '../bin/logs.mjs';

const MODULE = new URL('../bin/logs.mjs', import.meta.url);
const TIME = '2026-09-07T12:00:00.000Z';

class Capture extends Writable {
  constructor() {
    super();
    this.chunks = [];
  }

  _write(chunk, encoding, callback) {
    this.chunks.push(Buffer.from(chunk));
    this.emit('written');
    callback();
  }

  get text() {
    return Buffer.concat(this.chunks).toString('utf8');
  }

  async includes(text) {
    while (!this.text.includes(text)) {
      await once(this, 'written', { signal: AbortSignal.timeout(10000) });
    }
  }
}

class LogsFixture {
  constructor(t) {
    this.root = mkdtempSync(join(tmpdir(), 'logs-'));
    this.config = join(this.root, 'alternate.json');
    this.log = join(this.root, 'bridge.log');
    this.archive = `${this.log}.1`;
    this.runs = [];
    this.children = [];
    t.after(async () => {
      for (const run of this.runs) run.controller.abort();
      await Promise.allSettled(this.runs.map((run) => run.done));
      for (const child of this.children) {
        if (child.process.exitCode === null &&
            child.process.signalCode === null) child.process.kill('SIGKILL');
        await child.exit;
      }
      rmSync(this.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
    });
  }

  header(server, message, time = TIME) {
    return `[mcp-bridge] ${time} ${server === null ? '' : `[${server}] `}${message}\n`;
  }

  async dump(options = {}, implementation = runLogs) {
    const stdout = new Capture();
    const stderr = new Capture();
    await implementation({ config: this.config, stdout, stderr, ...options });
    return stdout.text;
  }

  follow(options = {}, implementation = runLogs) {
    const stdout = options.stdout ?? new Capture();
    const stderr = new Capture();
    const controller = new AbortController();
    const events = new EventEmitter();
    const run = { stdout, stderr, controller, idleCount: 0 };
    run.idle = async (after = run.idleCount) => {
      while (run.idleCount <= after) {
        await once(events, 'idle', { signal: AbortSignal.timeout(10000) });
      }
    };
    run.done = implementation({
      config: this.config, follow: true, stdout, stderr,
      signal: controller.signal, pollIntervalMs: 10, ...options,
      onIdle: () => {
        run.idleCount++;
        events.emit('idle');
        options.onIdle?.();
      },
    });
    // A failed test still owns this promise and must stop it in t.after.
    run.done.catch(() => {});
    this.runs.push(run);
    return run;
  }

  async stop(run) {
    run.controller.abort();
    await run.done;
  }

  async mutant(name, before, after) {
    const source = readFileSync(MODULE, 'utf8').replace(/\r\n/g, '\n');
    assert.equal(source.split(before).length, 2, 'mutation must change exactly one known site');
    const path = join(this.root, `logs-mutant-${name}.mjs`);
    writeFileSync(path, source.replace(before, after));
    return (await import(pathToFileURL(path).href)).runLogs;
  }

  child(options = {}, env = {}) {
    return this.script(`
      import { runLogs } from ${JSON.stringify(MODULE.href)};
      const options = ${JSON.stringify(options)};
      const relay = (message) => { if (message.signal) process.emit(message.signal); };
      process.on('message', relay);
      let ready = false;
      try {
        await runLogs({ ...options, onIdle() {
          if (!ready) { ready = true; process.send({ type: 'ready' }); }
        } });
        process.send({
          type: 'done',
          sigint: process.listenerCount('SIGINT'),
          sigterm: process.listenerCount('SIGTERM'),
        });
      } catch (error) {
        process.stderr.write(error.stack + '\\n');
        process.exitCode = 1;
      } finally {
        process.removeListener('message', relay);
        process.disconnect();
      }
    `, env);
  }

  script(source, env = {}) {
    const path = join(this.root, `logs-runner-${this.children.length}.mjs`);
    writeFileSync(path, source);
    const child = spawn(process.execPath, [path], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    const events = new EventEmitter();
    const result = { process: child, messages: [], stdout: '', stderr: '' };
    child.stdout.on('data', (data) => { result.stdout += data; });
    child.stderr.on('data', (data) => { result.stderr += data; });
    child.on('message', (message) => {
      result.messages.push(message);
      events.emit('message');
    });
    result.message = async (type) => {
      while (!result.messages.some((message) => message.type === type)) {
        await once(events, 'message', { signal: AbortSignal.timeout(10000) });
      }
      return result.messages.find((message) => message.type === type);
    };
    result.exit = once(child, 'close');
    this.children.push(result);
    return result;
  }

  async lateWriteRegression(scenario = 'EPIPE', module = MODULE.href) {
    writeFileSync(this.log, this.header('alpha', 'blocked output'));
    const config = scenario === 'stderr' ? join(this.root, 'logs-missing', 'servers.json') : this.config;
    const child = this.script(`
      import assert from 'node:assert/strict';
      import { Writable } from 'node:stream';
      import { setImmediate as yieldTurn } from 'node:timers/promises';
      import { runLogs } from ${JSON.stringify(module)};
      const scenario = ${JSON.stringify(scenario)};
      const controller = new AbortController();
      let release;
      let releaseDestroy;
      let didBlock;
      let didDestroy;
      const blocked = new Promise((resolve) => { didBlock = resolve; });
      const destroying = new Promise((resolve) => { didDestroy = resolve; });
      const output = new Writable({
        autoDestroy: scenario !== 'no-close',
        write(chunk, encoding, callback) {
          release = callback;
          didBlock();
        },
        destroy(error, callback) {
          if (scenario === 'delayed-destroy') {
            releaseDestroy = () => callback(error);
            didDestroy();
          } else {
            callback(error);
          }
        },
      });
      const quiet = new Writable({ write(chunk, encoding, callback) { callback(); } });
      const beforeInt = process.listenerCount('SIGINT');
      const beforeTerm = process.listenerCount('SIGTERM');
      const done = runLogs({
        config: ${JSON.stringify(config)}, follow: true, signal: controller.signal,
        stdout: scenario === 'stderr' ? quiet : output,
        stderr: scenario === 'stderr' ? output : quiet,
      });
      await blocked;
      controller.abort();
      await done;
      assert.equal(output.destroyed, false, 'runLogs must not destroy caller-owned output');
      assert.equal(quiet.listenerCount('error'), 0, 'the idle stream must detach immediately');
      assert.equal(quiet.listenerCount('close'), 0);
      assert.equal(process.listenerCount('SIGINT'), beforeInt);
      assert.equal(process.listenerCount('SIGTERM'), beforeTerm);

      // No test error listener or uncaughtException handler: a missing production
      // guard must crash this isolated child rather than be hidden by the test.
      const closed = new Promise((resolve) => output.once('close', resolve));
      const code = scenario === 'EIO' ? 'EIO' : 'EPIPE';
      const error = Object.assign(new Error('delayed downstream failure'), { code });
      const warnings = [];
      let warned;
      const warning = new Promise((resolve) => { warned = resolve; });
      const onWarning = (entry) => {
        if (entry.code === 'MCP_PACEMAKER_LOGS_WRITE_ERROR') {
          warnings.push(entry);
          warned();
        }
      };
      process.on('warning', onWarning);
      if (scenario === 'closed-first') {
        output.destroy();
        await closed;
      }
      release(error);
      if (scenario === 'delayed-destroy') {
        await destroying;
        await yieldTurn();
        assert.equal(output.listenerCount('error'), 1, 'keep protection until asynchronous error emission');
        releaseDestroy();
      }
      if (scenario !== 'no-close') await closed;
      if (scenario === 'EIO') await warning;
      await yieldTurn();
      assert.equal(output.listenerCount('error'), 0, 'settled write must release its error guard');
      // The no-close case still owns the observer installed by this test.
      assert.equal(output.listenerCount('close'), scenario === 'no-close' ? 1 : 0);
      assert.equal(warnings.length, scenario === 'EIO' ? 1 : 0, 'callback + error event report once');
      if (scenario === 'EIO') assert.match(warnings[0].message, /Late stdout write failure.*EIO.*delayed downstream failure/);
      process.removeListener('warning', onWarning);
      output.removeAllListeners('close');
      process.disconnect();
    `);
    assert.deepEqual(await child.exit, [0, null], child.stderr);
    return child;
  }

  async contextRegression(implementation = runLogs) {
    const wanted = this.header('alpha', 'stderr: first line') +
      '  detail before\n  failure [LITERAL].*(a+)+$\n  detail after\n';
    writeFileSync(this.archive, this.header('beta', 'archived'));
    writeFileSync(this.log,
      this.header('beta', 'do not attribute [alpha] to this server') +
      '  [alpha] failure [LITERAL].*(a+)+$\n' +
      wanted +
      this.header(null, 'global') + '  failure [LITERAL].*(a+)+$\n' +
      this.header('alpha', 'no match') + '  clean\n');
    assert.equal(await this.dump({ server: 'alpha', grep: '[literal].*(A+)+$' }, implementation), wanted);
  }

  async utf8Regression(implementation = runLogs) {
    const initial = this.header('alpha', 'ready');
    writeFileSync(this.log, initial);
    const run = this.follow({}, implementation);
    await run.idle(0);
    const next = this.header('alpha', 'stderr: café 🧪 complete');
    const bytes = Buffer.from(next);
    const split = bytes.indexOf(Buffer.from('🧪')) + 2;
    appendFileSync(this.log, bytes.subarray(0, split));
    await run.idle();
    assert.equal(run.stdout.text, initial, 'partial bytes/lines must not be emitted');
    appendFileSync(this.log, bytes.subarray(split, bytes.length - 1));
    await run.idle();
    assert.equal(run.stdout.text, initial, 'a complete UTF-8 character is not yet a complete line');
    appendFileSync(this.log, '\n');
    await run.idle();
    await this.stop(run);
    assert.equal(run.stdout.text, initial + next);
  }

  async rotationRegression(implementation = runLogs) {
    const history = this.header('alpha', 'history');
    const initial = this.header('alpha', 'initial');
    const unread = this.header('alpha', 'append immediately before rollover') + '  context\n';
    const next = this.header('alpha', 'new generation');
    writeFileSync(this.archive, history);
    writeFileSync(this.log, initial);
    const run = this.follow({}, implementation);
    await run.idle(0);
    assert.equal(run.stdout.text, history + initial);
    // No await between these writes: the old generation must be drained after rename.
    appendFileSync(this.log, unread);
    renameSync(this.log, this.archive);
    writeFileSync(this.log, next);
    await run.idle();
    await run.idle();
    await this.stop(run);
    assert.equal(run.stdout.text, history + initial + unread + next);
  }

  async regrowRegression(implementation = runLogs) {
    const initial = this.header('alpha', 'old');
    const replacement = this.header('beta', 'rewritten and already larger than the old cursor');
    writeFileSync(this.log, initial);
    const run = this.follow({}, implementation);
    await run.idle(0);
    writeFileSync(this.log, replacement);
    await run.idle();
    await this.stop(run);
    assert.equal(run.stdout.text, initial + replacement);
    assert.match(run.stderr.text, /truncated or rewritten/i);
  }
}

test('finite dump reads only bridge.log.1 and bridge.log beside --config, in order', async (t) => {
  const fixture = new LogsFixture(t);
  const old = fixture.header('alpha', 'old');
  const current = fixture.header('beta', 'current');
  writeFileSync(fixture.archive, old);
  writeFileSync(fixture.log, current);
  writeFileSync(`${fixture.log}.2`, 'unrelated older file\n');
  writeFileSync(join(fixture.root, 'stderr.log'), 'unrelated stderr\n');
  writeFileSync(fixture.config, 'Not JSON. Logs must not evaluate or require the config content.');
  assert.equal(await fixture.dump(), old + current);
  assert.equal(readFileSync(fixture.archive, 'utf8'), old);
  assert.equal(readFileSync(fixture.log, 'utf8'), current);
});

test('default path is under the isolated home, not the working directory', async (t) => {
  const fixture = new LogsFixture(t);
  const home = join(fixture.root, 'logs-home');
  const directory = join(home, '.mcp-pacemaker');
  mkdirSync(directory, { recursive: true });
  const line = fixture.header('alpha', 'default path');
  writeFileSync(join(directory, 'bridge.log'), line);
  const child = fixture.child({}, { HOME: home, USERPROFILE: home });
  assert.deepEqual(await child.exit, [0, null], child.stderr);
  assert.equal(child.stdout, line);
});

test('server and literal case-insensitive grep retain the entire matching record', async (t) => {
  await new LogsFixture(t).contextRegression();
});

test('since is inclusive, understands ISO offsets, and applies to continuations', async (t) => {
  const fixture = new LogsFixture(t);
  const boundary = fixture.header('alpha', 'boundary', '2026-09-07T12:00:00.000Z') + '  no timestamp here\n';
  writeFileSync(fixture.log,
    fixture.header('alpha', 'old', '2026-09-07T11:59:59.999Z') + '  old context\n' +
    boundary + fixture.header('beta', 'later', '2026-09-07T12:00:01Z'));
  assert.equal(await fixture.dump({ since: '2026-09-07T14:00:00+02:00', server: 'alpha' }), boundary);
});

test('since accepts s/m/h/d durations and valid leap-day ISO timestamps', async (t) => {
  const fixture = new LogsFixture(t);
  const now = Date.now();
  const recent = fixture.header('alpha', 'recent', new Date(now - 1000).toISOString());
  const old = fixture.header('alpha', 'old', new Date(now - 3 * 86400000).toISOString());
  writeFileSync(fixture.log, old + recent);
  for (const since of ['120s', '5m', '2h', '1d', '0.5h']) {
    assert.equal(await fixture.dump({ since }), recent, since);
  }
  assert.equal(await fixture.dump({ since: '2024-02-29T00:00:00.1Z' }), old + recent);
});

test('invalid since values fail explicitly instead of Date.parse normalization', async (t) => {
  const fixture = new LogsFixture(t);
  for (const since of [
    '', 'yesterday', '2H', '2w', '-1h', '1e3h', ' 2h', '2h ', 'Infinityh',
    '9'.repeat(400) + 'd', '2026-09-07', '2026-09-07T12:00:00',
    '2026-02-30T12:00:00Z', '2025-02-29T00:00:00Z', '2026-13-01T00:00:00Z',
    '2026-01-00T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z',
    '2026-01-01T00:00:60Z', '2026-01-01T00:00:00+24:00', 123, true,
  ]) {
    await assert.rejects(fixture.dump({ since }), /Invalid --since/, String(since));
  }
});

test('unrelated, malformed and global headers cannot borrow a prior server or timestamp', async (t) => {
  const fixture = new LogsFixture(t);
  const selected = fixture.header('alpha', 'selected') + '  selected context [beta]\n';
  writeFileSync(fixture.log,
    'orphan [alpha]\n' + selected +
    fixture.header(null, 'global') + '  global [alpha]\n' +
    fixture.header('beta', 'other') + '  other [alpha]\n' +
    '[mcp-bridge] not-a-time [alpha] invalid\n  invalid context\n');
  assert.equal(await fixture.dump({ server: 'alpha', since: TIME }), selected);
});

test('finite dump preserves CRLF, UTF-8 and the final unterminated line', async (t) => {
  const fixture = new LogsFixture(t);
  const text = fixture.header('alpha', 'café 🧪').replace('\n', '\r\n') + '  final continuation';
  writeFileSync(fixture.log, text);
  assert.equal(await fixture.dump({ grep: 'FINAL' }), text);
});

test('grep replays a large record without keeping it all in memory', async (t) => {
  const fixture = new LogsFixture(t);
  const text = fixture.header('alpha', 'large record') +
    ('  context ' + 'x'.repeat(1000) + '\n').repeat(2500) + '  match at the end\n';
  writeFileSync(fixture.log, text + fixture.header('beta', 'unmatched'));
  assert.equal(await fixture.dump({ grep: 'MATCH AT THE END' }), text);
});

test('oversized individual lines error explicitly rather than being silently cut', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'x'.repeat(1024 * 1024)));
  await assert.rejects(fixture.dump(), /line exceeds.*safety limit/);
});

test('finite missing current log errors even when an archive is present', async (t) => {
  const fixture = new LogsFixture(t);
  await assert.rejects(fixture.dump(), /Log file not found:.*bridge\.log/);
  const archived = fixture.header('alpha', 'retained history');
  writeFileSync(fixture.archive, archived);
  await assert.rejects(fixture.dump(), /Log file not found:.*bridge\.log/);
});

test('non-regular log paths error rather than reading other files', async (t) => {
  const fixture = new LogsFixture(t);
  mkdirSync(fixture.log);
  await assert.rejects(fixture.dump(), /not a regular file/);
});

test('follow waits with one explicit diagnostic, then observes creation', async (t) => {
  const fixture = new LogsFixture(t);
  const run = fixture.follow();
  await run.idle(0);
  await run.idle();
  assert.match(run.stderr.text, /Waiting for .*bridge\.log to be created/);
  assert.equal(run.stderr.text.split('Waiting for').length - 1, 1);
  assert.equal(run.stdout.text, '');
  const line = fixture.header('alpha', 'created');
  writeFileSync(fixture.log, line);
  await run.stdout.includes('created\n');
  await fixture.stop(run);
  assert.equal(run.stdout.text, line);
});

test('follow waits when the config directory itself does not exist', async (t) => {
  const fixture = new LogsFixture(t);
  const directory = join(fixture.root, 'logs-later');
  const run = fixture.follow({ config: join(directory, 'servers.json') });
  await run.idle(0);
  assert.match(run.stderr.text, /Waiting for/);
  mkdirSync(directory);
  const line = fixture.header('alpha', 'directory created');
  writeFileSync(join(directory, 'bridge.log'), line);
  await run.stdout.includes('directory created\n');
  await fixture.stop(run);
  assert.equal(run.stdout.text, line);
});

test('follow dumps a lone archive once while waiting for the current log', async (t) => {
  const fixture = new LogsFixture(t);
  const old = fixture.header('alpha', 'old');
  const current = fixture.header('alpha', 'current');
  writeFileSync(fixture.archive, old);
  const run = fixture.follow();
  await run.idle(0);
  await run.idle();
  assert.equal(run.stdout.text, old);
  assert.match(run.stderr.text, /Waiting for/);
  writeFileSync(fixture.log, current);
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, old + current);
});

test('follow preserves split UTF-8 and partial lines across append scans', async (t) => {
  await new LogsFixture(t).utf8Regression();
});

test('follow preserves UTF-8 across a 64 KiB read boundary', async (t) => {
  const fixture = new LogsFixture(t);
  const prefix = fixture.header('alpha', '').trimEnd();
  const line = prefix + 'x'.repeat(65535 - Buffer.byteLength(prefix)) + '🧪\n';
  writeFileSync(fixture.log, line);
  const run = fixture.follow();
  await run.idle(0);
  await fixture.stop(run);
  assert.equal(run.stdout.text, line);
});

test('follow emits context when a later continuation first matches grep, exactly once', async (t) => {
  const fixture = new LogsFixture(t);
  const start = fixture.header('alpha', 'stderr') + '  before\n';
  writeFileSync(fixture.log, start);
  const run = fixture.follow({ grep: 'match', server: 'alpha' });
  await run.idle(0);
  assert.equal(run.stdout.text, '');
  appendFileSync(fixture.log, '  MATCH\n  after\n  another match\n');
  await run.idle();
  assert.equal(run.stdout.text, start + '  MATCH\n  after\n  another match\n');
  appendFileSync(fixture.log, fixture.header('beta', 'match') + '  match\n');
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, start + '  MATCH\n  after\n  another match\n');
});

test('follow drains the old generation and does not replay .1 on rollover', async (t) => {
  await new LogsFixture(t).rotationRegression();
});

test('follow recovers retained generations and warns when two rolls erase the old cursor', async (t) => {
  const fixture = new LogsFixture(t);
  const first = fixture.header('alpha', 'first');
  const second = fixture.header('alpha', 'second');
  const third = fixture.header('alpha', 'third');
  writeFileSync(fixture.log, first);
  const run = fixture.follow();
  await run.idle(0);
  renameSync(fixture.log, fixture.archive);
  writeFileSync(fixture.log, second);
  renameSync(fixture.log, fixture.archive);
  writeFileSync(fixture.log, third);
  await run.idle();
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, first + second + third);
  assert.match(run.stderr.text, /no longer retained.*may have been lost/);
});

test('follow survives the gap between rename and new-file creation', async (t) => {
  const fixture = new LogsFixture(t);
  const first = fixture.header('alpha', 'before gap');
  const second = fixture.header('alpha', 'after gap');
  writeFileSync(fixture.log, first);
  const run = fixture.follow();
  await run.idle(0);
  renameSync(fixture.log, fixture.archive);
  await run.idle();
  assert.match(run.stderr.text, /Waiting for/);
  assert.equal(run.stdout.text, first);
  writeFileSync(fixture.log, second);
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, first + second);
});

test('combined filters retain matching context across repeated rollovers without replay', async (t) => {
  const fixture = new LogsFixture(t);
  const initial = fixture.header('alpha', 'match initially');
  writeFileSync(fixture.log, initial);
  const run = fixture.follow({ server: 'alpha', since: TIME, grep: 'match' });
  await run.idle(0);
  let expected = initial;
  for (let generation = 1; generation <= 4; generation++) {
    const tail = fixture.header('alpha', `stderr ${generation}`) + '  context\n  MATCH here\n';
    const next = fixture.header('beta', `unselected match ${generation}`) + '  other context\n';
    appendFileSync(fixture.log, tail);
    renameSync(fixture.log, fixture.archive);
    writeFileSync(fixture.log, next);
    await run.idle();
    expected += tail;
    assert.equal(run.stdout.text, expected);
  }
  await fixture.stop(run);
});

test('rotation finishes old partial lines and starts fresh server context', async (t) => {
  const fixture = new LogsFixture(t);
  const first = fixture.header('alpha', 'first');
  writeFileSync(fixture.log, first + '  unfinished');
  const run = fixture.follow({ server: 'alpha' });
  await run.idle(0);
  assert.equal(run.stdout.text, first);
  renameSync(fixture.log, fixture.archive);
  const selected = fixture.header('alpha', 'selected');
  writeFileSync(fixture.log, 'orphan must not inherit alpha\n' + fixture.header('beta', 'other') + selected);
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, first + '  unfinished' + selected);
});

test('truncation resets pending UTF-8, partial lines and record attribution', async (t) => {
  const fixture = new LogsFixture(t);
  const initial = fixture.header('alpha', 'initial');
  writeFileSync(fixture.log, initial + '  abandoned partial 🧪');
  const run = fixture.follow({ server: 'alpha' });
  await run.idle(0);
  writeFileSync(fixture.log, 'orphan\n');
  await run.idle();
  assert.equal(run.stdout.text, initial);
  const selected = fixture.header('alpha', 'after truncate');
  appendFileSync(fixture.log, selected);
  await run.idle();
  await fixture.stop(run);
  assert.equal(run.stdout.text, initial + selected);
  assert.match(run.stderr.text, /truncated or rewritten/);
});

test('truncate-and-regrow past the old cursor is detected using consumed bytes', async (t) => {
  await new LogsFixture(t).regrowRegression();
});

test('AbortSignal closes owned handles and restores listeners without closing caller streams', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'ready'));
  const beforeInt = process.listenerCount('SIGINT');
  const beforeTerm = process.listenerCount('SIGTERM');
  const stdout = new Capture();
  const beforeErrors = stdout.listenerCount('error');
  const run = fixture.follow({ stdout });
  await run.idle(0);
  await fixture.stop(run);
  assert.equal(process.listenerCount('SIGINT'), beforeInt);
  assert.equal(process.listenerCount('SIGTERM'), beforeTerm);
  assert.equal(stdout.listenerCount('error'), beforeErrors);
  assert.equal(stdout.destroyed, false);
  // On Windows this also checks that no exclusive file operation is blocked by a tail handle.
  renameSync(fixture.log, fixture.archive);
});

test('already-aborted follow is a clean no-op', async (t) => {
  const fixture = new LogsFixture(t);
  const controller = new AbortController();
  controller.abort();
  assert.equal(await fixture.dump({ follow: true, signal: controller.signal }), '');
});

test('SIGINT and SIGTERM stop an isolated follower cleanly', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'ready'));
  for (const signal of ['SIGINT', 'SIGTERM']) {
    const child = fixture.child({ config: fixture.config, follow: true });
    await child.message('ready');
    if (process.platform === 'win32') {
      // Windows kill(SIGINT) terminates, rather than delivering a catchable POSIX
      // signal. Relay the signal event in the isolated process on that platform.
      child.process.send({ signal });
    } else {
      child.process.kill(signal);
    }
    const done = await child.message('done');
    assert.equal(done.sigint, 0);
    assert.equal(done.sigterm, 0);
    assert.deepEqual(await child.exit, [0, null], child.stderr);
  }
});

test('backpressure is bounded and cancellation does not hang on a stalled destination', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'first') + fixture.header('alpha', 'second'));
  const events = new EventEmitter();
  let release;
  let writes = 0;
  const stdout = new Writable({
    highWaterMark: 1,
    write(chunk, encoding, callback) {
      writes++;
      release = callback;
      events.emit('blocked');
    },
  });
  t.after(() => release?.());
  const blocked = once(events, 'blocked', { signal: AbortSignal.timeout(10000) });
  const run = fixture.follow({ stdout });
  await blocked;
  assert.equal(writes, 1);
  await fixture.stop(run);
  assert.equal(writes, 1);
  assert.equal(stdout.destroyed, false);
  release();
  release = null;
  await yieldTurn();
  assert.equal(stdout.listenerCount('error'), 0);
  assert.equal(stdout.listenerCount('close'), 0);
});

test('cancellation protects a pending write that later fails with EPIPE', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression();
});

test('late EPIPE protection lasts through asynchronous stream destruction', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression('delayed-destroy');
});

test('a late non-EPIPE failure reports one explicit warning after the promise has returned', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression('EIO');
});

test('a close before the pending callback does not cause early or double cleanup', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression('closed-first');
});

test('late write guards detach after error even when autoDestroy is disabled', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression('no-close');
});

test('pending diagnostic writes have the same late EPIPE protection as stdout', { timeout: 10000 }, async (t) => {
  await new LogsFixture(t).lateWriteRegression('stderr');
});

test('EPIPE resolves cleanly; other output errors reject and restore error listeners', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'ready'));
  for (const code of ['EPIPE', 'EIO']) {
    const stdout = new Writable({
      write(chunk, encoding, callback) {
        callback(Object.assign(new Error(code), { code }));
      },
    });
    if (code === 'EPIPE') {
      await fixture.dump({ stdout, follow: true });
    } else {
      await assert.rejects(fixture.dump({ stdout }), { code });
    }
    assert.equal(stdout.listenerCount('error'), 0);
  }
});

test('an already-closed destination ends follow without opening or waiting for logs', async (t) => {
  const fixture = new LogsFixture(t);
  const stdout = new Capture();
  const closed = once(stdout, 'close');
  stdout.destroy();
  await closed;
  await fixture.dump({ stdout, follow: true });
  assert.equal(stdout.listenerCount('error'), 0);
});

test('closing a real downstream pipe ends follow without an uncaught error', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'first'));
  const child = fixture.child({ config: fixture.config, follow: true });
  await child.message('ready');
  const closed = once(child.process.stdout, 'close');
  child.process.stdout.destroy();
  await closed;
  appendFileSync(fixture.log, fixture.header('alpha', 'after pipe close'));
  await child.message('done');
  assert.deepEqual(await child.exit, [0, null], child.stderr);
  assert.equal(child.stderr, '');
});

test('invalid API text and polling options fail explicitly', async (t) => {
  const fixture = new LogsFixture(t);
  for (const options of [
    { config: '' }, { config: true }, { server: '' }, { server: true }, { grep: true },
    { pollIntervalMs: 0 }, { pollIntervalMs: Infinity }, { pollIntervalMs: 2147483648 },
  ]) {
    await assert.rejects(fixture.dump(options), /Invalid|must/);
  }
});

test('regression proof: context assertions fail when continuations are treated as headers', async (t) => {
  const fixture = new LogsFixture(t);
  const broken = await fixture.mutant('context', "if (text.startsWith('[mcp-bridge] ')) {", 'if (true) {');
  await assert.rejects(fixture.contextRegression(broken), { code: 'ERR_ASSERTION' });
});

test('regression proof: UTF-8 assertions fail when each partial read is decoded separately', async (t) => {
  const fixture = new LogsFixture(t);
  const broken = await fixture.mutant(
    'utf8',
    'part.copy(file.pending, file.pendingBytes - part.length);',
    "Buffer.from(part.toString('utf8')).copy(file.pending, file.pendingBytes - part.length);",
  );
  await assert.rejects(fixture.utf8Regression(broken), { code: 'ERR_ASSERTION' });
});

test('regression proof: rollover assertions fail when reopened generations lose their cursor', async (t) => {
  const fixture = new LogsFixture(t);
  const broken = await fixture.mutant(
    'rotation',
    'active.handle = retained.handle;',
    'active.handle = retained.handle;\n            active.offset = 0;\n            active.anchor = Buffer.alloc(0);',
  );
  await assert.rejects(fixture.rotationRegression(broken), { code: 'ERR_ASSERTION' });
});

test('regression proof: regrow assertions fail when only file size detects truncation', async (t) => {
  const fixture = new LogsFixture(t);
  const broken = await fixture.mutant('regrow', 'changed = bytesRead !== anchor.length || !anchor.equals(file.anchor);', 'changed = false;');
  await assert.rejects(fixture.regrowRegression(broken), { code: 'ERR_ASSERTION' });
});

test('regression proof: strict-date assertions fail when Date.parse normalizes February 30', async (t) => {
  const fixture = new LogsFixture(t);
  writeFileSync(fixture.log, fixture.header('alpha', 'ready'));
  const broken = await fixture.mutant('date', 'if (invalid) return null;', 'if (false) return null;');
  await assert.rejects(
    assert.rejects(fixture.dump({ since: '2026-02-30T00:00:00Z' }, broken), /Invalid --since/),
    { code: 'ERR_ASSERTION' },
  );
});

test('regression proof: eager listener cleanup crashes on EPIPE after cancellation returns', { timeout: 10000 }, async (t) => {
  const fixture = new LogsFixture(t);
  await fixture.mutant(
    'late-write',
    'output.pendingWrites !== 0 ||',
    'false ||',
  );
  const module = pathToFileURL(join(fixture.root, 'logs-mutant-late-write.mjs')).href;
  await assert.rejects(fixture.lateWriteRegression('EPIPE', module), { code: 'ERR_ASSERTION' });
  assert.match(fixture.children[0].stderr, /Unhandled 'error' event/);
  assert.match(fixture.children[0].stderr, /EPIPE/);
});
