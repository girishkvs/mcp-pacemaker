import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { runInNewContext } from 'node:vm';
import { ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import {
  assertDurableRoot, backendDescription, servicePaths, stopManagedService, resumeService,
} from '../bin/service-control.mjs';

test('T31 adoption reports actual backend version and instance, including cross-version control', () => {
  for (const [cli, backend] of [['1.3.1', '2.0.1'], ['2.0.1', '1.3.0'], ['2.0.1', '2.0.1']]) {
    const text = backendDescription(cli, { version: backend, instanceId: 'actual-instance' }, 'adopted');
    assert.match(text, new RegExp(`installed CLI ${cli.replaceAll('.', '\\.')}`));
    assert.match(text, new RegExp(`running backend ${backend.replaceAll('.', '\\.')}`));
    assert.match(text, /instance actual-instance/);
    assert.equal(text.includes('version mismatch'), cli !== backend);
  }
  assert.match(backendDescription('2.0.1', {}, 'observed'), /running backend unknown; instance unknown/);
});

test('T34 cache roots are rejected before unattended setup; durable roots are accepted', () => {
  for (const root of ['/home/test/.npm/_npx/hash/node_modules/mcp-pacemaker', 'C:\\cache\\_NPX\\hash\\package']) {
    assert.throws(() => assertDurableRoot(root), /durable root/);
  }
  assert.doesNotThrow(() => assertDurableRoot('/opt/pacemaker/2.0.1'));
  assert.doesNotThrow(() => assertDurableRoot('C:\\apps with spaces\\pacemaker'));
});

test('T35 service identities are separate by config DIRECTORY and port', () => {
  const first = servicePaths(join(tmpdir(), 'first', 'servers.json'), 12345);
  assert.notEqual(first.socket, servicePaths(join(tmpdir(), 'second', 'servers.json'), 12345).socket);
  assert.notEqual(first.socket, servicePaths(join(tmpdir(), 'first', 'servers.json'), 12346).socket);
  assert.equal(first.socket, servicePaths(join(tmpdir(), 'first', 'another.json'), 12345).socket);
  for (const port of [0, -1, 65536, NaN, 2.5]) {
    assert.throws(() => servicePaths('servers.json', port), /integer/);
  }
});

test('T33 targeted stop requires matching root/config/port and an acknowledged autostart hold', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mcp-service-unit-'));
  const config = join(root, 'servers.json');
  const port = 12345;
  const paths = servicePaths(config, port);
  const record = { protocol: 1, root: realpathSync(root), config, port, socket: paths.socket, id: randomUUID(), token: 'a'.repeat(64) };
  let calls = 0;
  const request = async (socket, payload) => {
    calls++;
    assert.equal(socket, paths.socket);
    assert.deepEqual(payload, { action: 'stop', id: record.id, token: record.token });
    return { id: record.id, stopped: true, autostartHeld: true };
  };
  try {
    await assert.rejects(stopManagedService({ root, config, port, request }), /No managed supervisor/);
    for (const override of [
      { root: 'wrong' }, { config: 'wrong' }, { port: 12346 }, { token: 'bad' }, { protocol: 2 },
      { socket: '/unrelated/control.sock' }, { socket: paths.record }, { socket: undefined },
    ]) {
      writeFileSync(paths.record, JSON.stringify({ ...record, ...override }));
      await assert.rejects(stopManagedService({ root, config, port, request }), /identity does not match/);
    }
    assert.equal(calls, 0);
    writeFileSync(paths.record, JSON.stringify(record));
    for (const response of [
      { id: record.id, stopped: true },
      { id: 'other', stopped: true, autostartHeld: true },
      { id: record.id, stopped: false, autostartHeld: true },
    ]) {
      await assert.rejects(stopManagedService({ root, config, port, request: async () => response }), /did not verify/);
    }
    await assert.rejects(stopManagedService({
      root, config, port, request: async () => { throw new Error('unavailable'); },
    }), /unavailable/);
    const stopped = await stopManagedService({ root, config, port, request });
    assert.equal(stopped.supervisorId, record.id);
    assert.equal(calls, 1);
    writeFileSync(paths.hold, JSON.stringify({ ...record, stopped: true }));
    const repeated = await stopManagedService({
      root, config, port, request: async () => { throw new Error('completed receipt must not reconnect'); },
    });
    assert.equal(repeated.alreadyStopped, true);
    for (const override of [{ id: 'stale' }, { root: 'other' }, { stopped: false }]) {
      writeFileSync(paths.hold, JSON.stringify({ ...record, stopped: true, ...override }));
      await assert.rejects(stopManagedService({
        root, config, port, request: async () => { throw new Error('not verified'); },
      }), /not verified/);
    }
    writeFileSync(paths.hold, 'held');
    resumeService(config, port);
    assert.equal(existsSync(paths.hold), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('regression control: wrong-root stop assertion fails with the identity check removed in an isolated copy', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mcp-service-regression-'));
  try {
    const before = 'record.root === realpathSync(root) &&';
    const source = readFileSync(new URL('../bin/service-control.mjs', import.meta.url), 'utf8');
    assert.equal(source.includes(before), true);
    const path = join(root, 'service-control.mjs');
    writeFileSync(path, source.replace(before, ''));
    const changed = await import(pathToFileURL(path));
    const config = join(root, 'servers.json');
    const record = {
      protocol: 1, root: 'another-root', config, port: 12345,
      socket: servicePaths(config, 12345).socket, id: randomUUID(), token: 'a'.repeat(64),
    };
    writeFileSync(servicePaths(config, record.port).record, JSON.stringify(record));
    await assert.rejects(assert.rejects(changed.stopManagedService({
      root, config, port: record.port,
      request: async () => ({ id: record.id, stopped: true, autostartHeld: true }),
    }), /identity does not match/), { code: 'ERR_ASSERTION' });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function posixPaths(implementation, platform, temp) {
  return runInNewContext(`(${implementation.toString()})`, {
    createHash, Buffer, dirname: posix.dirname, join: posix.join, resolve: posix.resolve,
    process: { platform }, tmpdir: () => temp,
  });
}

function assertStablePosixEndpoint(implementation) {
  for (const platform of ['linux', 'darwin']) {
    const supervisor = posixPaths(implementation, platform, '/private/supervisor-temp');
    const cli = posixPaths(implementation, platform, '/different/cli-temp');
    const config = '/home/test/state/servers.json';
    const first = supervisor(config, 12345);
    const second = cli(config, 12345);
    for (const key of ['record', 'hold', 'socket']) assert.equal(first[key], second[key]);
    assert.equal(first.socket, '/home/test/state/service-12345.sock');
  }
}

test('POSIX endpoint is config-bound and independent of caller TMPDIR on Linux and macOS', () => {
  assertStablePosixEndpoint(servicePaths);
  for (const platform of ['linux', 'darwin']) {
    const paths = posixPaths(servicePaths, platform, '/unused');
    assert.throws(() => paths(`/home/${'long'.repeat(30)}/servers.json`, 12345), /POSIX limit/);
    assert.throws(() => paths(`/home/${'é'.repeat(50)}/servers.json`, 12345), /POSIX limit/);
  }
});

test('regression control: caller-temporary socket selection fails the stable-endpoint oracle', async () => {
  const owned = ownedDirectory();
  try {
    const source = readFileSync(new URL('../bin/service-control.mjs', import.meta.url), 'utf8');
    const fixed = 'join(directory, `service-${port}.sock`)';
    assert.equal(source.includes(fixed), true);
    const path = join(owned.dir, 'caller-temp-endpoint.mjs');
    writeFileSync(path, "import { tmpdir } from 'node:os';\n" +
      source.replace(fixed, 'join(tmpdir(), `mcp-pacemaker-${key}.sock`)'));
    const mutant = await import(pathToFileURL(path));
    assert.throws(() => assertStablePosixEndpoint(mutant.servicePaths), { code: 'ERR_ASSERTION' });
    assertStablePosixEndpoint(servicePaths);
  } finally {
    removeOwnedDirectory(owned);
  }
});

async function shutdownModel(source, root) {
  const config = join(root, 'state', 'servers.json');
  const port = 12345;
  const paths = servicePaths(config, port);
  writeFileSync(join(root, 'package.json'), JSON.stringify({ version: '2.0.1' }));
  const child = new EventEmitter();
  child.connected = true;
  child.send = (_, callback) => callback();
  const supervisorProcess = Object.assign(new EventEmitter(), { pid: process.pid, execPath: process.execPath });
  const timers = new Set();
  let accepts;
  let forks = 0;
  const server = new EventEmitter();
  server.closed = false;
  server.listen = (_, callback) => callback();
  server.close = () => { server.closed = true; };
  const begin = source.indexOf('async function supervise()');
  assert.notEqual(begin, -1, 'Execute the actual production supervisor body');
  await runInNewContext(`(${source.slice(begin)})()`, {
    root, config, port, paths, dirname, join, existsSync, mkdirSync, readFileSync, writeFileSync,
    randomBytes, randomUUID, process: supervisorProcess, console: { error: () => {} },
    fork: () => { forks++; return child; },
    createServer: (handler) => { accepts = handler; return server; },
    setTimeout: (callback, ms) => {
      const timer = { callback, ms };
      timers.add(timer);
      return timer;
    },
    clearTimeout: (timer) => timers.delete(timer),
  });
  const identity = JSON.parse(readFileSync(paths.record, 'utf8'));
  const request = () => new Promise((resolveResponse) => {
    assert.equal(server.closed, false, 'The control endpoint must still accept reconciliation');
    const socket = new EventEmitter();
    socket.setTimeout = () => {};
    socket.destroy = () => socket.emit('close');
    socket.end = (text) => { resolveResponse(JSON.parse(text)); socket.emit('close'); };
    accepts(socket);
    socket.emit('data', JSON.stringify({ action: 'stop', id: identity.id, token: identity.token }) + '\n');
  });
  const expire = () => {
    const pending = [...timers].filter((timer) => timer.ms === 10000);
    assert.equal(pending.length, 1, 'The production 10-second deadline must remain unchanged');
    timers.delete(pending[0]);
    pending[0].callback();
  };
  return { child, server, timers, paths, identity, request, expire, forks: () => forks };
}

async function assertShutdownReconciliation(source, root, attempts = 2) {
  const model = await shutdownModel(source, root);
  const flush = () => new Promise((resolveTurn) => setImmediate(resolveTurn));
  // Two explicit attempts must remain failures while the child has not exited.
  for (let attempt = 0; attempt < attempts; attempt++) {
    const response = model.request();
    await flush();
    model.expire();
    assert.equal((await response).stopped, false);
    assert.equal(model.server.closed, false);
    assert.equal(JSON.parse(readFileSync(model.paths.hold, 'utf8')).stopped, undefined);
  }
  const held = readFileSync(model.paths.hold, 'utf8');
  model.child.emit('exit', 0);
  await flush();
  assert.equal(readFileSync(model.paths.hold, 'utf8'), held, 'A late exit must not silently complete a failed request');
  assert.equal(model.server.closed, false, 'Explicit reconciliation remains available');
  assert.equal(model.forks(), 1);
  assert.equal([...model.timers].some((timer) => timer.ms === 2000), false, 'A timed-out shutdown must not restart the child');
  const reconciled = await model.request();
  assert.equal(reconciled.stopped, true, 'Explicit stop must reconcile the observed child exit');
  assert.equal(reconciled.autostartHeld, true);
  assert.equal(model.server.closed, true);
  const receipt = JSON.parse(readFileSync(model.paths.hold, 'utf8'));
  assert.equal(receipt.stopped, true);
  assert.equal(receipt.id, model.identity.id);
}

test('shutdown deadline stays unverified until an exit event and an explicit reconciliation', async () => {
  const owned = ownedDirectory();
  try {
    await assertShutdownReconciliation(readFileSync(new URL('../supervisor/supervise.mjs', import.meta.url), 'utf8'), owned.dir);
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('regression control: retaining the rejected stop promise fails the production-body oracle', async () => {
  const owned = ownedDirectory();
  try {
    const source = readFileSync(new URL('../supervisor/supervise.mjs', import.meta.url), 'utf8');
    const reset = '      stopping = undefined;';
    assert.equal(source.includes(reset), true);
    const path = join(owned.dir, 'permanently-rejected-supervisor.mjs');
    writeFileSync(path, source.replace(reset, ''));
    await assert.rejects(assertShutdownReconciliation(readFileSync(path, 'utf8'), owned.dir, 1),
      { code: 'ERR_ASSERTION', message: /Explicit stop must reconcile/ });
  } finally {
    removeOwnedDirectory(owned);
  }
});

function setupCommand(source, name) {
  const start = source.indexOf(`async function ${name}(args) {`);
  assert.notEqual(start, -1, 'Use the actual CLI command');
  const end = source.indexOf('\n}', start);
  assert.notEqual(end, -1, 'Use the complete CLI command');
  return source.slice(start, end + 2);
}

function socketSizedConfig(bytes, port = 12345, unicode = false) {
  const padding = bytes - Buffer.byteLength(`/home//service-${port}.sock`);
  const segment = unicode ? 'é'.repeat(Math.floor(padding / 2)) + 'x'.repeat(padding % 2) : 'x'.repeat(padding);
  return `/home/${segment}/servers.json`;
}

function setupModel(source, { platform = 'linux', config, format = 'json', foreignPort } = {}) {
  const effects = [];
  const checks = [];
  const paths = posixPaths(servicePaths, platform, '/unused');
  const note = (name) => () => { effects.push(name); };
  const noop = () => {};
  const identity = (value) => value;
  const servers = { sample: { command: 'fixture-only' } };
  const commands = runInNewContext(
    `${setupCommand(source, 'cmdInstall')}\n${setupCommand(source, 'cmdInit')}\n({ cmdInstall, cmdInit })`,
    {
      CONFIG: config, ROOT: '/opt/fixture-only', DEFAULT_PORT: 12345,
      process: { execPath: '/usr/bin/node', exit: (code) => { throw new Error(`Unexpected exit ${code}`); } },
      servicePaths: (selectedConfig, port) => { checks.push(port); return paths(selectedConfig, port); },
      assertDurableRoot, realpathSync: identity, dirname: posix.dirname,
      defaultClient: (client) => client || 'fixture', detectClients: () => ['fixture'],
      getHost: () => ({ format, label: 'Fixture', bin: 'fixture-only' }), hasBin: () => true,
      probePort: async (port) => port === foreignPort ? 'foreign' : 'free',
      existsSync: () => true, readJson: () => servers,
      computeRewrite: () => ({ path: '/fixture/client.json', cfg: { servers: {} }, key: 'servers', keyFor: {}, servers }),
      buildCodexConfig: () => ({ path: '/fixture/config.toml', text: '', names: ['sample'] }),
      hostEntry: () => ({ type: 'http', url: 'fixture-only' }),
      applyNativeClaude: () => { effects.push('native-write'); return ['sample']; },
      importServers: () => { effects.push('import'); return { imported: 1, skipped: 0, httpNoAuth: 0 }; },
      copyFileSync: note('backup'), mkdirSync: note('mkdir'), writeFileSync: note('file-write'),
      writeJson: note('json-write'), writeState: note('state-write'),
      readState: () => ({ hosts: [] }), upsertHost: (state) => state,
      registerAutostart: note('register'),
      startBridge: async (port) => { effects.push('start'); paths(config, port); },
      ok: noop, info: noop, err: noop, console: { log: noop },
      pc: { bold: identity, cyan: identity, red: identity, green: identity },
      p: {
        intro: noop, outro: noop, cancel: noop, isCancel: () => false,
        log: { info: noop, warn: noop, step: noop, error: noop, success: noop },
        spinner: () => ({ start: noop, stop: noop }),
        text: async () => String(foreignPort + 1), confirm: async () => true,
        multiselect: async () => ['fixture'],
      },
    },
  );
  return { commands, effects, checks };
}

async function assertSetupRejected(model, command, args, error = /POSIX limit of 103 UTF-8 bytes/) {
  await assert.rejects(model.commands[command]({ client: 'fixture', from: 'fixture', port: 12345, yes: true, ...args }), error);
  assert.deepEqual(model.effects, [], 'No imports, backups, host writes, state writes, autostart registration or start');
}

test('install/init preflight rejects long POSIX paths before every setup side effect, including wiring-only mode', async () => {
  const source = readFileSync(new URL('../bin/cli.mjs', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  for (const platform of ['linux', 'darwin']) {
    for (const command of ['cmdInstall', 'cmdInit']) {
      for (const format of ['json', 'toml', 'native']) {
        for (const unicode of [false, true]) {
          for (const flags of [{}, { start: false }, { autostart: false }, { start: false, autostart: false }]) {
            const model = setupModel(source, { platform, format, config: socketSizedConfig(104, 12345, unicode) });
            await assertSetupRejected(model, command, flags);
          }
        }
      }
    }
  }
});

test('install/init preflight rejects invalid service ports before setup writes', async () => {
  const source = readFileSync(new URL('../bin/cli.mjs', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  for (const command of ['cmdInstall', 'cmdInit']) {
    for (const port of ['0', '65536', 'not-a-port']) {
      const model = setupModel(source, { config: socketSizedConfig(46) });
      await assertSetupRejected(model, command, { port }, /integer from 1 to 65535/);
    }
  }
});

test('init preflights a replacement port before import when the extra port digit exceeds the socket limit', async () => {
  const source = readFileSync(new URL('../bin/cli.mjs', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  for (const platform of ['linux', 'darwin']) {
    const config = socketSizedConfig(103, 9999);
    const paths = posixPaths(servicePaths, platform, '/unused');
    assert.equal(Buffer.byteLength(paths(config, 9999).socket), 103);
    const model = setupModel(source, { platform, config, foreignPort: 9999 });
    await assertSetupRejected(model, 'cmdInit', { port: 9999 });
    assert.deepEqual(model.checks, [9999, 10000]);
  }
});

test('supported 46/91/100/103-byte POSIX paths reach actual setup bodies and honor start/autostart flags', async () => {
  const source = readFileSync(new URL('../bin/cli.mjs', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  for (const platform of ['linux', 'darwin']) {
    for (const command of ['cmdInstall', 'cmdInit']) {
      for (const format of ['json', 'toml', 'native']) {
        for (const bytes of [46, 91, 100, 103]) {
          const config = socketSizedConfig(bytes, 12345, true);
          assert.equal(Buffer.byteLength(posixPaths(servicePaths, platform, '/unused')(config, 12345).socket), bytes);
          for (const flags of [{}, { start: false, autostart: false }]) {
            const model = setupModel(source, { platform, config, format });
            await model.commands[command]({ client: 'fixture', from: 'fixture', port: 12345, yes: true, ...flags });
            assert.equal(model.effects.includes('import'), command === 'cmdInit');
            assert.equal(model.effects.includes('backup'), format !== 'native');
            assert.equal(model.effects.includes(`${{ json: 'json', toml: 'file', native: 'native' }[format]}-write`), true);
            assert.equal(model.effects.includes('state-write'), true);
            assert.equal(model.effects.includes('register'), flags.autostart !== false);
            assert.equal(model.effects.includes('start'), flags.start !== false);
          }
        }
      }
    }
  }
});

test('regression controls: removing any install/init address preflight fails the zero-mutation oracle', async () => {
  const source = readFileSync(new URL('../bin/cli.mjs', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  for (const [command, guard, reselected] of [
    ['cmdInstall', '\n  servicePaths(CONFIG, port);', false],
    ['cmdInit', '\n  servicePaths(CONFIG, port);', false],
    ['cmdInit', '\n    servicePaths(CONFIG, port);', true],
  ]) {
    const body = setupCommand(source, command);
    assert.equal(body.includes(guard), true, 'The isolated copy must remove the intended guard');
    const changed = source.replace(body, body.replace(guard, ''));
    const config = reselected ? socketSizedConfig(103, 9999) : socketSizedConfig(104);
    const model = setupModel(changed, { config, foreignPort: reselected ? 9999 : undefined });
    await assert.rejects(assertSetupRejected(model, command, { port: reselected ? 9999 : 12345 }),
      { code: 'ERR_ASSERTION', message: /No imports, backups/ });
    assert.equal(model.effects.length > 0, true, 'The regression must reach a real injected setup side effect');
  }
});
