// Owned local packages/services only. No npm invocation, external HTTP, OS task or fixed port.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { createHash, randomInt, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import {
  copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { connect, createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, dirname, join, posix } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import { acquireInstanceLock, createInstance, durableJson, loadInstance, readInstanceState, readRecoveryContext, readManagedJson, verifySelection } from '../bin/managed-state.mjs';
import { backendStatus, inspectInstance, listenerOpen, startInstance, stopInstance, waitForInstanceExit } from '../bin/managed-runtime.mjs';
import { ManagedUpgrader, describeUpgrade, planUpgrade, upgradeOptions } from '../bin/managed-upgrade.mjs';
import { acquireUpgrade, exactVersion, normalizePackResult, verifyArchive } from '../bin/upgrade-package.mjs';
import { normalizeNpmMetadata } from '../bin/update-check.mjs';
import { PoolingConfigWriter } from '../bin/pooling-writer.mjs';
import { ownedPackageSelection, retainedCliDependencies } from './helpers/managed-package.mjs';
import { normalizeInstanceSelection, registerDefaultCli } from '../bin/cli-dispatch.mjs';
import { validateSelectedCommand } from '../bin/cli-selection.mjs';
import { stageCliDependencies } from '../bin/upgrade-dependencies.mjs';
import { npmCliPath } from '../bin/update-check.mjs';
import { retainedRegistry } from './helpers/managed-registry.mjs';

const source = fileURLToPath(new URL('../', import.meta.url));
const previousRelease = 'a9fd5be23a50d4f3e3b787b678a8e85bdfb45fa2';

class UpgradeFixture {
  constructor() {
    // Darwin's default temporary prefix leaves insufficient room for the bounded Unix socket path.
    const temporary = process.platform === 'darwin' ? '/tmp' : tmpdir();
    this.directory = realpathSync(mkdtempSync(join(temporary, 'mcu-')));
    this.home = join(this.directory, '.mcp-pacemaker');
    mkdirSync(this.home);
    this.config = join(this.home, 'servers.json');
    writeFileSync(this.config, '{}\n', { mode: 0o600 });
    this.original = readFileSync(this.config);
    this.instances = [];
  }

  package(version, modify) {
    const parent = join(this.directory, `package root-${version}-${randomUUID()}`);
    const root = join(parent, 'package');
    mkdirSync(root, { recursive: true });
    for (const path of ['bin', 'supervisor', 'autostart', 'ui/dist']) {
      cpSync(join(source, path), join(root, path), { recursive: true });
    }
    const pkg = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8'));
    writeFileSync(join(root, 'package.json'), JSON.stringify({ ...pkg, version }));
    modify?.(root);
    return { parent, root };
  }

  artifact(version, modify) {
    const pkg = this.package(version, modify);
    const entries = [];
    const walk = (directory, relative = '') => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = relative + entry.name;
        if (entry.isDirectory()) { walk(join(directory, entry.name), `${path}/`); continue; }
        const data = readFileSync(join(directory, entry.name));
        const header = Buffer.alloc(512);
        const name = `package/${path}`;
        if (Buffer.byteLength(name) > 100) throw new Error('Fixture tar name needs a prefix.');
        header.write(name);
        header.write('0000644\0', 100);
        header.write('0000000\0', 108);
        header.write('0000000\0', 116);
        header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
        header.write('00000000000\0', 136);
        header.fill(32, 148, 156);
        header.write('0', 156);
        header.write('ustar\0', 257);
        header.write('00', 263);
        header.write([...header].reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148);
        entries.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
      }
    };
    walk(pkg.root);
    entries.push(Buffer.alloc(1024));
    const bytes = gzipSync(Buffer.concat(entries));
    return { bytes, integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` };
  }

  async start(modify) {
    const pkg = this.package('2.0.2', modify);
    this.initialRoot = pkg.root;
    await retainedCliDependencies(pkg.root);
    const instance = createInstance({
      directory: join(this.home, 'managed', 'main'), root: pkg.root, config: this.config, port: 0,
      selection: ownedPackageSelection(pkg.root),
    });
    this.instances.push(instance.directory);
    registerDefaultCli(this.home, instance);
    const result = await startInstance(instance.directory);
    this.instance = result.instance;
    return result;
  }

  async plan(extra = {}) {
    return planUpgrade({ to: '2.0.3', instance: this.instance.directory, ...extra }, { home: this.home });
  }

  upgrader(artifact = this.artifact('2.0.3'), options = {}) {
    return new ManagedUpgrader({ acquire: async () => artifact, dependencies: retainedCliDependencies, ...options });
  }

  async cleanup() {
    for (const directory of this.instances.reverse()) {
      const instance = loadInstance(directory, { verifyFiles: false });
      if (instance.port &&
          await listenerOpen(instance.port)) await stopInstance(instance);
      await waitForInstanceExit(directory);
    }
    rmSync(this.directory, { recursive: true, force: true });
  }

  snapshot() {
    const result = [];
    const walk = (directory, prefix = '') => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const relative = prefix + entry.name;
        if (entry.isDirectory()) { walk(join(directory, entry.name), `${relative}/`); continue; }
        const path = join(directory, entry.name);
        if (entry.isSocket()) {
          const stat = lstatSync(path, { bigint: true });
          result.push([relative, { type: 'socket', device: String(stat.dev), inode: String(stat.ino) }]);
        } else {
          assert.ok(entry.isFile(), `Unsupported fixture entry: ${relative}`);
          result.push([relative, createHash('sha256').update(readFileSync(path)).digest('hex')]);
        }
      }
    };
    walk(this.directory);
    return result;
  }

  async cli(...args) {
    const result = await promisify(execFile)(process.execPath, [join(source, 'bin', 'cli.mjs'), ...args], {
      encoding: 'utf8', timeout: 180000, windowsHide: true,
      env: { ...process.env, HOME: this.directory, USERPROFILE: this.directory, ...this.npmEnv },
    });
    return result.stdout.trim();
  }

  async executeGeneratedPrewarm(output) {
    const line = output.split('\n').find(value => value.startsWith('Cancel while pending'));
    assert.ok(line, output);
    const command = line.slice(line.indexOf('): ') + 3).trim();
    if (process.platform === 'win32') assert.match(command, /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/);
    const words = process.platform === 'win32' ? command.split(' ') : ['/bin/sh', '-c', command];
    const result = await promisify(execFile)(words[0], words.slice(1), {
      encoding: 'utf8', timeout: 30000, windowsHide: true,
      env: { ...process.env, HOME: this.directory, USERPROFILE: this.directory },
    });
    return result.stdout;
  }
}

test('fixture snapshots retain Unix socket identity without reading sockets as files', {
  skip: process.platform === 'win32',
}, async () => {
  const fixture = new UpgradeFixture();
  const server = createServer();
  const socket = join(fixture.home, 'snapshot.sock');
  try {
    const listening = once(server, 'listening');
    server.listen(socket);
    await listening;
    const before = fixture.snapshot();
    const entry = before.find(([path]) => path === '.mcp-pacemaker/snapshot.sock');
    assert.ok(entry);
    assert.equal(entry[1].type, 'socket');
    assert.deepEqual(fixture.snapshot(), before);
    await new Promise(resolveClose => server.close(resolveClose));
    writeFileSync(socket, 'replacement');
    assert.notDeepEqual(fixture.snapshot(), before);
  } finally {
    if (server.listening) await new Promise(resolveClose => server.close(resolveClose));
    await fixture.cleanup();
  }
});

test('Darwin upgrade fixtures leave room for the longest retained service socket', () => {
  const code = UpgradeFixture.toString();
  const budget = implementation => {
    const Fixture = runInNewContext(`(${implementation})`, {
      process: { platform: 'darwin' },
      tmpdir: () => '/var/folders/36/tjdph2t965j8snz9_vkdnw0r0000gn/T',
      join: posix.join,
      mkdtempSync: prefix => `${prefix}123456`,
      realpathSync: path => path.replace(/^\/tmp\//, '/private/tmp/'),
      mkdirSync: () => {},
      writeFileSync: () => {},
      readFileSync: () => Buffer.from('{}\n'),
    });
    const fixture = new Fixture();
    const socket = posix.join(fixture.home, 'sxs-00000000', 'service-65535.sock');
    assert.ok(Buffer.byteLength(socket) <= 103, socket);
  };
  budget(code);
  const original = code.replace("process.platform === 'darwin' ? '/tmp' : tmpdir()", 'tmpdir()');
  assert.notEqual(original, code);
  assert.throws(() => budget(original), { code: 'ERR_ASSERTION' });
});

test('managed option matrix rejects implicit target, normal port and conflicting guidance', () => {
  for (const options of [
    {}, { to: 'latest' }, { to: '^2.0.3' }, { to: 'v2.0.3' }, { to: '2.0.3-beta.1' },
    { to: '2.0.3', port: '12000' }, { to: '2.0.3', self: true },
    { to: '2.0.3', sxs: true, port: '0' }, { to: '2.0.3', sxs: true, port: '1x' },
    { to: '2.0.3', sxs: true, port: '65536' },
    { recover: true, instance: 'owned', registry: 'https://approved.example.test/' },
  ]) assert.throws(() => upgradeOptions(options));
  assert.equal(upgradeOptions({ to: '2.0.3', sxs: true }).port, 0);
  assert.equal(upgradeOptions({ to: '2.0.3', sxs: true, port: '65535' }).port, 65535);
  assert.equal(exactVersion('12.0.1'), '12.0.1');
});

test('npm12 exact single-result arrays normalize strictly; integrity mismatch rejects', () => {
  assert.deepEqual(normalizeNpmMetadata([{ name: 'mcp-pacemaker', version: '2.0.3' }]),
    { name: 'mcp-pacemaker', version: '2.0.3' });
  for (const value of [[], [{}, {}], [null], 'value', null]) assert.throws(() => normalizeNpmMetadata(value));
  assert.throws(() => verifyArchive(Buffer.from('bad'), `sha512-${Buffer.alloc(64).toString('base64')}`), /integrity mismatch/);
  const packed = { name: 'mcp-pacemaker', version: '2.0.3', filename: 'mcp-pacemaker-2.0.3.tgz' };
  assert.deepEqual(normalizePackResult([packed], '2.0.3'), packed);
  assert.deepEqual(normalizePackResult({ 'mcp-pacemaker': packed }, '2.0.3'), packed);
  for (const value of [[], [packed, packed], { other: packed }, { 'mcp-pacemaker': packed, other: packed },
    { 'mcp-pacemaker': { ...packed, filename: '../escape.tgz' } }]) {
    assert.throws(() => normalizePackResult(value, '2.0.3'));
  }
});

test('acquisition preserves caller npmrc context and policy while isolating archive and cache outputs', async () => {
  const fixture = new UpgradeFixture();
  const directory = join(fixture.directory, 'download');
  mkdirSync(directory);
  const bytes = Buffer.from('owned acquisition bytes');
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const registry = 'https://approved-registry.example.test/npm/';
  const calls = [];
  try {
    const acquired = await acquireUpgrade('2.0.3', directory, {
      registry,
      run: async (executable, args, options) => {
        calls.push(args[1]);
        assert.equal(executable, process.execPath);
        assert.equal(args[args.indexOf('--registry') + 1], registry);
        assert.equal(args[args.indexOf('--cache') + 1], join(directory, 'cache'));
        assert.ok(args.includes('--ignore-scripts'));
        assert.equal(options.env, undefined, 'Keep inherited npm permissions and credentials.');
        assert.equal(args.some(value => /^--(?:allow-|strict-ssl|min-release-age|replace-registry-host)/.test(value)), false);
        if (args[1] === 'view') {
          assert.equal(options.cwd, undefined);
          return { stdout: JSON.stringify([{ name: 'mcp-pacemaker', version: '2.0.3', dist: { integrity } }]) };
        }
        assert.equal(args[1], 'pack');
        assert.equal(options.cwd, process.cwd(), 'Do not discard caller project npmrc by changing to the staging directory.');
        assert.equal(args[args.indexOf('--pack-destination') + 1], directory);
        writeFileSync(join(directory, 'mcp-pacemaker-2.0.3.tgz'), bytes);
        return { stdout: JSON.stringify({ 'mcp-pacemaker': {
          name: 'mcp-pacemaker', version: '2.0.3', filename: 'mcp-pacemaker-2.0.3.tgz',
        } }) };
      },
    });
    assert.deepEqual(calls, ['view', 'pack']);
    assert.deepEqual(acquired, { bytes, integrity });
  } finally { await fixture.cleanup(); }
});

test('upgrade admission sees worker work before publication and keeps failed workers unsafe', async () => {
  const fixture = new UpgradeFixture();
  const writer = new PoolingConfigWriter(fixture.config);
  const failed = new PoolingConfigWriter('invalid\0owned-config');
  try {
    assert.deepEqual(writer.upgradeState(), { pending: 0, failed: false });
    const pending = writer.stageApply({});
    assert.deepEqual(writer.upgradeState(), { pending: 1, failed: false });
    await assert.rejects(pending);
    assert.deepEqual(writer.upgradeState(), { pending: 0, failed: false });
    await assert.rejects(failed.apply({}), { code: 'WRITER_FAILED' });
    assert.equal(failed.upgradeState().failed, true);
  } finally {
    await writer.close();
    await failed.close();
    await fixture.cleanup();
  }
});

test('bootstrap snapshots are immutable, upgrades serialize, and replaced directories fail closed', async () => {
  const fixture = new UpgradeFixture();
  try {
    const pkg = fixture.package('2.0.2');
    await retainedCliDependencies(pkg.root);
    const directory = join(fixture.home, 'managed', 'main');
    const instance = createInstance({ directory, root: pkg.root, config: fixture.config, port: 12345 });
    assert.notEqual(instance.active.root, pkg.root);
    writeFileSync(join(pkg.root, 'bin', 'cli.mjs'), 'source was later replaced');
    assert.equal(loadInstance(directory).active.version, '2.0.2');
    const activePath = join(directory, 'active.json');
    durableJson(activePath, { ...instance.active, files: [] });
    assert.throws(() => loadInstance(directory), /inventory|selection reference/);
    durableJson(activePath, instance.active);
    const release = acquireInstanceLock(directory);
    assert.throws(() => acquireInstanceLock(directory), { code: 'EEXIST' });
    release();
    const path = join(instance.active.root, 'bin', 'cli.mjs');
    const original = readFileSync(path);
    writeFileSync(path, 'immutable bytes were changed');
    assert.throws(() => loadInstance(directory), /Immutable package bytes changed/);
    writeFileSync(path, original);
    const displaced = directory + '-displaced';
    renameSync(directory, displaced);
    cpSync(displaced, directory, { recursive: true });
    assert.throws(() => loadInstance(directory), /identity mismatch/);
  } finally { await fixture.cleanup(); }
});

test('actual retained port-zero listener is persisted and reused after a managed restart', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const first = await fixture.start();
    assert.ok(first.instance.port > 0);
    assert.equal((await backendStatus(first.instance.port)).instanceId, first.ready.instanceId);
    assert.equal(loadInstance(first.instance.directory).port, first.instance.port);
    await stopInstance(first.instance);
    const second = await startInstance(first.instance.directory);
    assert.equal(second.instance.port, first.instance.port);
    assert.notEqual(second.ready.instanceId, first.ready.instanceId);
  } finally { await fixture.cleanup(); }
});

test('normal upgrade replaces actual backend at the same port without config or wiring edits', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const original = await backendStatus(fixture.instance.port);
    assert.equal(await fixture.cli('--version'), '2.0.2');
    const plan = await fixture.plan();
    const stateBefore = readFileSync(join(fixture.instance.directory, 'active.json'));
    assert.match(describeUpgrade(plan), /Short restart/);
    assert.deepEqual(readFileSync(join(fixture.instance.directory, 'active.json')), stateBefore);
    const hooks = [];
    const result = await fixture.upgrader(undefined, {
      beforeInterruption: async (instance, journal) => {
        assert.equal((await backendStatus(instance.port)).instanceId, original.instanceId);
        assert.equal((await inspectInstance(instance)).held, false);
        verifySelection(journal.target);
        hooks.push('staged-before-interruption');
      },
      beforeStop: async instance => {
        assert.equal((await inspectInstance(instance)).held, true);
        hooks.push('drained-before-stop');
      },
      beforeAdmission: async instance => {
        const ready = await inspectInstance(instance);
        assert.equal(ready.version, '2.0.3');
        assert.equal(ready.held, true);
        hooks.push('ready-before-admission');
      },
    }).execute(plan);
    assert.deepEqual(hooks, ['staged-before-interruption', 'drained-before-stop', 'ready-before-admission']);
    assert.equal(result.status, 'upgraded');
    assert.equal(result.port, fixture.instance.port);
    const actual = await backendStatus(result.port);
    assert.equal(actual.version, '2.0.3');
    assert.equal(await fixture.cli('--version'), '2.0.3');
    const oldShim = join(fixture.initialRoot, 'bin', 'old-cli-shim.mjs');
    writeFileSync(oldShim, execFileSync('git', ['show', `${previousRelease}:bin/cli.mjs`], { cwd: source, windowsHide: true }));
    const oldVersion = execFileSync(process.execPath, [oldShim, '--version'], {
      encoding: 'utf8', windowsHide: true, env: { ...process.env, HOME: fixture.directory, USERPROFILE: fixture.directory },
    }).trim();
    assert.throws(() => assert.equal(oldVersion, '2.0.3'), { code: 'ERR_ASSERTION' },
      'RED: the historical shim still executes old CLI bytes after backend replacement.');
    assert.match(await fixture.cli('status'), /installed CLI 2\.0\.3/);
    assert.match(await fixture.cli('upgrade', '--to', '2.0.4', '--plan'), /2\.0\.3 -> 2\.0\.4/);
    const registry = await retainedRegistry(fixture.artifact('2.0.4'), '2.0.4');
    try {
      const userconfig = join(fixture.directory, 'upgrade.npmrc');
      const globalconfig = join(fixture.directory, 'global.npmrc');
      writeFileSync(userconfig, `registry=${registry.url}\nstrict-ssl=true\nmin-release-age=7\nfetch-retries=0\n`);
      writeFileSync(globalconfig, '');
      fixture.npmEnv = {
        npm_execpath: process.env.MCP_UPGRADE_TEST_NPM_CLI || npmCliPath(),
        npm_config_userconfig: userconfig, npm_config_globalconfig: globalconfig,
        npm_config_registry: registry.url, npm_config_cache: join(fixture.directory, 'npm-cache'),
      };
      assert.match(await fixture.cli('upgrade', '--to', '2.0.4', '--yes', '--registry', registry.url), /"status": "upgraded"/);
      assert.ok(registry.requests.some(path => path.startsWith('/archives/')));
    } finally { await registry.close(); }
    assert.equal(await fixture.cli('--version'), '2.0.4');
    assert.notEqual(actual.instanceId, original.instanceId);
    assert.deepEqual(readFileSync(fixture.config), fixture.original);
    assert.equal(readManagedJson(join(fixture.instance.directory, 'journal.json')).phase, 'committed');
    assert.equal(existsSync(fixture.instance.active.root), true);
  } finally { await fixture.cleanup(); }
});

test('actual CLI --plan does not acquire a package or change owned installation files', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  let requests = 0;
  const registry = createServer(socket => { requests++; socket.destroy(); });
  try {
    await fixture.start();
    await new Promise(resolveListen => registry.listen(0, '127.0.0.1', resolveListen));
    const before = fixture.snapshot();
    const { stdout } = await promisify(execFile)(process.execPath, [
      join(source, 'bin', 'cli.mjs'), 'upgrade', '--to', '2.0.3', '--plan',
      '--instance', fixture.instance.directory, '--registry', `http://127.0.0.1:${registry.address().port}/`,
    ], { encoding: 'utf8', windowsHide: true, timeout: 30000 });
    assert.match(stdout, /target major 2/);
    assert.match(stdout, /Short restart/);
    assert.equal(requests, 0);
    assert.deepEqual(fixture.snapshot(), before);
  } finally {
    await new Promise(resolveClose => registry.close(resolveClose));
    await fixture.cleanup();
  }
});

test('unidentified legacy plan refuses before registry/service writes and no maintenance bypass flag is accepted', async () => {
  const fixture = new UpgradeFixture();
  let requests = 0;
  const registry = createServer(socket => { requests++; socket.destroy(); });
  try {
    await new Promise(resolveListen => registry.listen(0, '127.0.0.1', resolveListen));
    const before = fixture.snapshot();
    const env = { ...process.env, HOME: fixture.directory, USERPROFILE: fixture.directory };
    await assert.rejects(promisify(execFile)(process.execPath, [
      join(source, 'bin', 'cli.mjs'), 'upgrade', '--to', '2.0.3', '--plan', '--yes',
      '--registry', `http://127.0.0.1:${registry.address().port}/`,
    ], { env, encoding: 'utf8', windowsHide: true, timeout: 10000 }), error => {
      assert.match(error.stdout, /exact legacy install state|no supported adapter/);
      return error.code === 1;
    });
    await assert.rejects(promisify(execFile)(process.execPath, [
      join(source, 'bin', 'cli.mjs'), 'upgrade', '--to', '2.0.3', '--legacy-maintenance',
    ], { env, encoding: 'utf8', windowsHide: true, timeout: 10000 }), error => {
      assert.match(error.stderr, /unknown option '--legacy-maintenance'/);
      return error.code === 1;
    });
    assert.equal(requests, 0);
    assert.deepEqual(fixture.snapshot(), before);
  } finally {
    await new Promise(resolveClose => registry.close(resolveClose));
    await fixture.cleanup();
  }
});

test('replacing one instance leaves another actual backend, port and config untouched', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const profile = join(fixture.home, 'other');
    mkdirSync(profile);
    const config = join(profile, 'servers.json');
    writeFileSync(config, '{}\n');
    const second = createInstance({
      directory: join(fixture.home, 'managed', 'other'), root: fixture.instance.active.root, config, port: 0,
    });
    fixture.instances.push(second.directory);
    const running = await startInstance(second.directory);
    await fixture.upgrader().execute(await fixture.plan());
    const status = await backendStatus(running.instance.port);
    assert.equal(status.version, '2.0.2');
    assert.equal(status.instanceId, running.ready.instanceId);
    assert.equal(readFileSync(config, 'utf8'), '{}\n');
    assert.equal((await backendStatus(fixture.instance.port)).version, '2.0.3');
  } finally { await fixture.cleanup(); }
});

test('download failure leaves original version and instance running', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const old = await fixture.start();
    const upgrader = new ManagedUpgrader({ acquire: async () => { throw new Error('owned download denied'); } });
    await assert.rejects(upgrader.execute(await fixture.plan()), /download denied/);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    assert.equal(existsSync(join(old.instance.directory, 'journal.json')), false);
    assert.equal(await fixture.cli('--version'), '2.0.2');
    const failedDependencies = fixture.upgrader(undefined, { dependencies: async () => { throw new Error('owned dependency restore denied'); } });
    await assert.rejects(failedDependencies.execute(await fixture.plan()), /dependency restore denied/);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    assert.equal(await fixture.cli('--version'), '2.0.2');
  } finally { await fixture.cleanup(); }
});

test('owned Windows preflight child stops before activation and cannot keep its heartbeat alive', {
  timeout: 300000, skip: process.platform !== 'win32',
}, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const heartbeat = join(fixture.directory, 'preflight-heartbeat');
    const artifact = fixture.artifact('2.0.3', root => {
      const path = join(root, 'bin', 'mcp-bridge.mjs');
      const code = readFileSync(path, 'utf8');
      const program = `const fs = require('node:fs'); fs.appendFileSync(${JSON.stringify(heartbeat)}, 'ready\\n'); process.stdout.write('ready\\n'); setInterval(() => fs.appendFileSync(${JSON.stringify(heartbeat)}, 'beat\\n'), 20);`;
      const insertion = `
if (CONFIG.includes('preflight')) {
  const owned = spawn(process.execPath, ['-e', ${JSON.stringify(program)}], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((ready, reject) => { owned.once('error', reject); owned.stdout.once('data', ready); });
}
`;
      writeFileSync(path, code.replace("const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));",
        insertion + "\nconst servers = JSON.parse(readFileSync(CONFIG, 'utf8'));"));
    });
    const result = await fixture.upgrader(artifact).execute(await fixture.plan());
    assert.equal(result.status, 'upgraded');
    const receipt = readFileSync(heartbeat, 'utf8');
    assert.match(receipt, /ready/);
    await new Promise(resolveWait => setTimeout(resolveWait, 200));
    assert.equal(readFileSync(heartbeat, 'utf8'), receipt, 'Verified job teardown must end the preflight descendant heartbeat.');
  } finally { await fixture.cleanup(); }
});

test('target startup failure before admission restores actual old backend', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const old = await fixture.start();
    const artifact = fixture.artifact('2.0.3', root => {
      const path = join(root, 'bin', 'mcp-bridge.mjs');
      const code = readFileSync(path, 'utf8');
      writeFileSync(path, code.replace("const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));",
        "if (!CONFIG.includes('preflight')) throw new Error('owned target-start failure');\nconst servers = JSON.parse(readFileSync(CONFIG, 'utf8'));"));
    });
    const hooks = [];
    await assert.rejects(fixture.upgrader(artifact, {
      beforeInterruption: async () => { hooks.push('interruption'); },
      beforeStop: async (instance, journal) => { hooks.push(`stop:${journal.phase}`); },
      beforeAdmission: async (instance, journal) => {
        assert.equal(journal.rollback, true);
        assert.equal((await inspectInstance(instance)).held, true);
        hooks.push('rollback-admission');
      },
    }).execute(await fixture.plan()), /startup/);
    assert.deepEqual(hooks, ['interruption', 'stop:quiescing', 'stop:launching', 'rollback-admission']);
    const status = await backendStatus(old.instance.port);
    assert.equal(status.version, '2.0.2');
    assert.notEqual(status.instanceId, old.ready.instanceId);
    assert.deepEqual(readFileSync(fixture.config), fixture.original);
    assert.equal(readManagedJson(join(old.instance.directory, 'journal.json')).phase, 'rolled-back');
    assert.equal(await fixture.cli('--version'), '2.0.2');
  } finally { await fixture.cleanup(); }
});

test('SxS autoport keeps old backend and persists independent config and actual port', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    fixture.original = Buffer.from(JSON.stringify({ alpha: {
      command: process.execPath, args: [fileURLToPath(new URL('./fixtures/echo-mcp-server.mjs', import.meta.url))],
    } }) + '\n');
    writeFileSync(fixture.config, fixture.original);
    const old = await fixture.start();
    const plan = await fixture.plan({ sxs: true });
    assert.match(describeUpgrade(plan), /OS-assigned/);
    const artifact = fixture.artifact('2.0.3', root => {
      const path = join(root, 'bin', 'cli-main.mjs');
      const code = readFileSync(path, 'utf8');
      const boundary = "const { runPrewarm } = await import('./prewarm.mjs');";
      assert.equal(code.includes(boundary), true);
      writeFileSync(path, code.replace(boundary, boundary +
        "\n    const observed = join(HOME, 'executed-cli-versions.json');\n" +
        "    writeJson(observed, [...(existsSync(observed) ? readJson(observed) : []), pkgVersion]);"));
    });
    const result = await fixture.upgrader(artifact).execute(plan);
    fixture.instances.push(result.directory);
    assert.equal(await fixture.cli('--version'), '2.0.2');
    assert.equal(await fixture.cli('--instance', result.directory, '--version'), '2.0.3');
    assert.notEqual(result.port, old.instance.port);
    const sxs = loadInstance(result.directory);
    assert.notEqual(sxs.config, old.instance.config);
    assert.ok(sxs.active.root.startsWith(join(sxs.directory, 'versions')));
    assert.equal(sxs.port, result.port);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    const cancel = await fixture.cli('--instance', sxs.directory, 'prewarm', '--enable', 'alpha', '--count', '1');
    assert.match(await fixture.executeGeneratedPrewarm(cancel), /pending batch cancelled/);
    assert.deepEqual(readFileSync(sxs.config), fixture.original);
    const undo = await fixture.cli('prewarm', `--instance=${sxs.directory}`, '--enable', 'alpha', '--count', '1');
    await fixture.cli('--instance', sxs.directory, 'reload');
    assert.equal(JSON.parse(readFileSync(sxs.config, 'utf8')).alpha.minWarm, 1);
    assert.match(await fixture.executeGeneratedPrewarm(undo), /previous batch configuration staged/);
    await fixture.cli('--instance', sxs.directory, 'reload');
    assert.deepEqual(readFileSync(sxs.config), fixture.original);
    assert.deepEqual(readFileSync(old.instance.config), fixture.original);
    assert.deepEqual(readManagedJson(join(dirname(sxs.config), 'executed-cli-versions.json')),
      ['2.0.3', '2.0.3', '2.0.3', '2.0.3']);
    assert.equal(existsSync(join(fixture.home, 'executed-cli-versions.json')), false);
    assert.equal(await fixture.cli('--version'), '2.0.2');
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    await stopInstance(sxs);
    const operation = basename(result.directory).slice('sxs-'.length);
    const staged = readManagedJson(join(old.instance.directory, 'staging', operation, 'verified-package.json'));
    assert.notEqual(sxs.active.root, staged.root);
    rmSync(staged.root, { recursive: true });
    const restarted = await startInstance(sxs.directory);
    assert.equal(restarted.instance.port, result.port);
  } finally { await fixture.cleanup(); }
});

test('SxS explicit free port starts at exactly that port without changing old backend', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  const reservation = createServer();
  try {
    const old = await fixture.start();
    await new Promise(resolveListen => reservation.listen(0, '127.0.0.1', resolveListen));
    const port = reservation.address().port;
    await new Promise(resolveClose => reservation.close(resolveClose));
    const result = await fixture.upgrader().execute(await fixture.plan({ sxs: true, port: String(port) }));
    fixture.instances.push(result.directory);
    assert.equal(result.port, port);
    assert.equal(loadInstance(result.directory).port, port);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
  } finally { await fixture.cleanup(); }
});

test('an active tool request refuses bounded drain without interruption or replay', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  let releaseRequest;
  let seen;
  let calls = 0;
  const entered = new Promise(resolveEntered => { seen = resolveEntered; });
  const upstream = createHttpServer((request, response) => {
    calls++;
    request.resume();
    releaseRequest = () => response.end('{"ok":true}');
    seen();
  });
  let request;
  try {
    await new Promise(resolveListen => upstream.listen(0, '127.0.0.1', resolveListen));
    fixture.original = Buffer.from(JSON.stringify({
      alpha: { type: 'http', url: `http://127.0.0.1:${upstream.address().port}/`, auth: { type: 'none' } },
    }) + '\n');
    writeFileSync(fixture.config, fixture.original);
    const old = await fixture.start();
    request = fetch(`http://127.0.0.1:${old.instance.port}/alpha`, {
      method: 'POST', body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"owned"}}',
      headers: { 'content-type': 'application/json' },
    });
    await entered;
    await assert.rejects(fixture.upgrader().execute(await fixture.plan()), /Active work/);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    assert.equal((await inspectInstance(old.instance)).held, true, 'A failed drain must keep admission held.');
    assert.equal((await fetch(`http://127.0.0.1:${old.instance.port}/ui`)).status, 503);
    assert.equal(calls, 1);
    assert.deepEqual(readFileSync(fixture.config), fixture.original);
    releaseRequest();
    assert.equal((await request).status, 200);
    assert.equal((await new ManagedUpgrader().recover(old.instance.directory)).status, 'aborted');
    assert.equal((await inspectInstance(old.instance)).held, false, 'Only explicit recovery resumes admission.');
  } finally {
    releaseRequest?.();
    if (request) await request.catch(() => {});
    await new Promise(resolveClose => upstream.close(resolveClose));
    await fixture.cleanup();
  }
});

test('explicit busy SxS port and changed supervisor identity refuse without touching old service', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  const server = createServer();
  try {
    const old = await fixture.start();
    await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
    await assert.rejects(fixture.plan({ sxs: true, port: String(server.address().port) }), /busy/);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    const recordPath = join(fixture.home, `service-${old.instance.port}.json`);
    const record = readFileSync(recordPath);
    writeFileSync(recordPath, JSON.stringify({ ...JSON.parse(record), root: fixture.directory }));
    try { await assert.rejects(fixture.plan(), /identity/); }
    finally { writeFileSync(recordPath, record); }
  } finally {
    await new Promise(resolveClose => server.close(resolveClose));
    await fixture.cleanup();
  }
});

test('unresolved transaction and multiple-instance discovery refuse without acquisition', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const old = await fixture.start();
    const transaction = `${fixture.config}.pooling-transaction`;
    mkdirSync(transaction);
    try { await assert.rejects(fixture.plan(), /transaction/); }
    finally { rmSync(transaction, { recursive: true }); }
    const second = createInstance({
      directory: join(fixture.home, 'managed', 'second'), root: fixture.instance.active.root,
      config: fixture.config, port: 0,
    });
    await assert.rejects(planUpgrade({ to: '2.0.3' }, { home: fixture.home }), /Multiple/);
    assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    assert.equal(loadInstance(second.directory).port, 0);
  } finally { await fixture.cleanup(); }
});

test('held admission refuses new traffic and resumes without replay', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const held = await inspectInstance(fixture.instance, 'quiesce');
    assert.equal(held.held, true);
    const blocked = await fetch(`http://127.0.0.1:${fixture.instance.port}/admin/reload`, { method: 'POST' });
    assert.equal(blocked.status, 503);
    assert.deepEqual(readFileSync(fixture.config), fixture.original);
    await inspectInstance(fixture.instance, 'resume');
    const resumed = await fetch(`http://127.0.0.1:${fixture.instance.port}/ui`);
    assert.equal(resumed.status, 200);
  } finally { await fixture.cleanup(); }
});

test('activation binds config and session state before admission opens', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const held = await inspectInstance(fixture.instance, 'quiesce');
    const expected = { authority: held.authority, sessionState: null };
    writeFileSync(fixture.config, '{}\n ');
    await assert.rejects(inspectInstance(fixture.instance, 'activate', expected), /changed before admission/);
    assert.equal((await inspectInstance(fixture.instance)).held, true);
    writeFileSync(fixture.config, fixture.original);
    const sessions = join(fixture.home, 'sessions.json');
    writeFileSync(sessions, '{}\n');
    await assert.rejects(inspectInstance(fixture.instance, 'activate', expected), /changed before admission/);
    assert.equal((await inspectInstance(fixture.instance)).held, true);
    unlinkSync(sessions);
    assert.equal((await inspectInstance(fixture.instance, 'activate', expected)).held, false);
  } finally { await fixture.cleanup(); }
});

test('matching root/config/port cannot authorize another managed-instance directory', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const running = await fixture.start();
    const recordPath = join(fixture.home, `service-${fixture.instance.port}.json`);
    const original = readFileSync(recordPath);
    writeFileSync(recordPath, JSON.stringify({ ...JSON.parse(original), managedInstance: join(fixture.home, 'unrelated') }));
    try {
      await assert.rejects(inspectInstance(fixture.instance, 'quiesce'), /different managed instance/);
      await assert.rejects(stopInstance(fixture.instance), /different managed instance/);
      assert.equal((await backendStatus(fixture.instance.port)).instanceId, running.ready.instanceId);
    } finally { writeFileSync(recordPath, original); }
  } finally { await fixture.cleanup(); }
});

test('an old confirmed plan cannot overwrite a newer unfinished journal', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const running = await fixture.start();
    const plan = await fixture.plan();
    const instance = fixture.instance;
    const journalPath = join(instance.directory, 'journal.json');
    durableJson(journalPath, {
      protocol: 1, instanceId: instance.id, previous: instance.active, target: instance.active,
      binding: { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port },
      phase: 'quiescing',
    });
    const before = readFileSync(journalPath);
    let acquisitions = 0;
    const upgrader = new ManagedUpgrader({ acquire: async () => { acquisitions++; throw new Error('must not acquire'); } });
    await assert.rejects(upgrader.execute(plan), /unfinished upgrade/);
    assert.equal(acquisitions, 0);
    assert.deepEqual(readFileSync(journalPath), before);
    assert.equal((await backendStatus(instance.port)).instanceId, running.ready.instanceId);
  } finally { await fixture.cleanup(); }
});

for (const phase of ['prepared', 'quiescing', 'stopping', 'stopped', 'selecting', 'selected', 'launching', 'admitting']) {
  test(`real upgrader process crash at ${phase} leaves a durable, recoverable or explicit-refusal journal`, { timeout: 300000 }, async () => {
    const fixture = new UpgradeFixture();
    try {
      await fixture.start();
      const artifact = fixture.artifact('2.0.3');
      const archive = join(fixture.directory, 'candidate.tgz');
      writeFileSync(archive, artifact.bytes);
      const input = join(fixture.directory, 'crash.json');
      writeFileSync(input, JSON.stringify({ archive, integrity: artifact.integrity, phase, plan: await fixture.plan() }));
      assert.throws(() => execFileSync(process.execPath, [
        fileURLToPath(new URL('./fixtures/managed-upgrade-crash.mjs', import.meta.url)), input,
      ], { timeout: 180000, windowsHide: true, stdio: 'pipe' }), error => error.status === 86);
      assert.equal(readManagedJson(join(fixture.instance.directory, 'journal.json')).phase, phase);
      const upgrader = fixture.upgrader(artifact);
      await assert.rejects(upgrader.recover(fixture.instance.directory), /lock remains/);
      // execFileSync observed exit of our exact owned process; no reusable PID check.
      unlinkSync(join(fixture.instance.directory, 'upgrade.lock'));
      if (phase === 'selected') {
        const pkg = fixture.package('2.0.2', root => {
          const path = join(root, 'bin', 'managed-upgrade.mjs');
          const code = readFileSync(path, 'utf8');
          const boundary = "['stopped', 'selecting', 'selected'].includes(journal.phase)";
          assert.equal(code.includes(boundary), true);
          writeFileSync(path, code.replace(boundary, "['stopped'].includes(journal.phase)"));
        });
        cpSync(join(source, 'node_modules', 'semver'), join(pkg.root, 'node_modules', 'semver'), { recursive: true });
        const mutant = await import(pathToFileURL(join(pkg.root, 'bin', 'managed-upgrade.mjs')).href);
        await assert.rejects(new mutant.ManagedUpgrader().recover(fixture.instance.directory), /identity|Launch intent/,
          'RED: treating selection as launch demands a target record that cannot exist before launch.');
        const target = readManagedJson(join(fixture.instance.directory, 'journal.json')).target;
        unlinkSync(join(target.root, 'bin', 'cli-main.mjs'));
        await assert.rejects(async () => loadInstance(fixture.instance.directory), /ENOENT/);
        const shim = join(fixture.directory, 'old validating shim', 'bin');
        mkdirSync(shim, { recursive: true });
        for (const file of ['cli.mjs', 'cli-dispatch.mjs', 'managed-state.mjs',
          'task-scope.mjs', 'task-transaction-protocol.mjs']) {
          copyFileSync(join(source, 'bin', file), join(shim, file));
        }
        const dispatcher = join(shim, 'cli-dispatch.mjs');
        const code = readFileSync(dispatcher, 'utf8');
        const boundary = 'const instance = readInstanceState(directory);';
        assert.equal(code.includes(boundary), true);
        writeFileSync(dispatcher, code.replace(boundary, 'const instance = loadInstance(directory);'));
        assert.throws(() => execFileSync(process.execPath, [
          join(shim, 'cli.mjs'), 'upgrade', '--recover', '--instance', fixture.instance.directory, '--yes',
        ], { encoding: 'utf8', windowsHide: true, stdio: 'pipe' }), /ENOENT/,
        'RED: validating selected target bytes prevents the retained recovery CLI from running.');
        assert.match(await fixture.cli('upgrade', '--recover', `--instance=${fixture.instance.directory}`, '--yes'), /rolled-back/);
        assert.equal(await fixture.cli('--version'), '2.0.2');
      }
      if (phase === 'admitting' ||
          phase === 'launching') {
        await assert.rejects(upgrader.recover(fixture.instance.directory),
          phase === 'admitting' ? /Admission may have occurred/ : /Launch intent|identity/);
        if (phase === 'admitting') assert.equal((await inspectInstance(loadInstance(fixture.instance.directory))).held, true);
      } else if (phase !== 'selected') {
        const result = await upgrader.recover(fixture.instance.directory);
        assert.ok(['aborted', 'rolled-back'].includes(result.status));
        assert.equal((await backendStatus(fixture.instance.port)).version, '2.0.2');
      }

      assert.deepEqual(readFileSync(fixture.config), fixture.original);
    } finally { await fixture.cleanup(); }
  });
}

for (const phase of ['starting', 'launching', 'admitting']) {
  test(`SxS process crash at ${phase} does not convert an unknown launch into a safe abort`, { timeout: 300000 }, async () => {
    const fixture = new UpgradeFixture();
    try {
      const old = await fixture.start();
      const artifact = fixture.artifact('2.0.3');
      const archive = join(fixture.directory, 'candidate.tgz');
      writeFileSync(archive, artifact.bytes);
      const input = join(fixture.directory, 'crash.json');
      writeFileSync(input, JSON.stringify({ archive, integrity: artifact.integrity, phase, plan: await fixture.plan({ sxs: true }) }));
      assert.throws(() => execFileSync(process.execPath, [
        fileURLToPath(new URL('./fixtures/managed-upgrade-crash.mjs', import.meta.url)), input,
      ], { timeout: 180000, windowsHide: true, stdio: 'pipe' }), error => error.status === 86);
      const name = readdirSync(join(fixture.home, 'managed')).find(entry => entry.startsWith('sxs-'));
      assert.ok(name);
      const directory = join(fixture.home, 'managed', name);
      fixture.instances.push(directory);
      assert.equal(readManagedJson(join(directory, 'journal.json')).phase, phase);
      unlinkSync(join(directory, 'upgrade.lock'));
      const upgrader = fixture.upgrader(artifact);
      if (phase === 'starting') assert.equal((await upgrader.recover(directory)).status, 'aborted');
      else {
        await assert.rejects(upgrader.recover(directory), /unknown|may have occurred/);
        assert.equal(readManagedJson(join(directory, 'journal.json')).phase, phase);
      }
      assert.equal((await backendStatus(old.instance.port)).instanceId, old.ready.instanceId);
    } finally { await fixture.cleanup(); }
  });
}

test('RED controls reject historical CLI behavior and a probe-close allocator', () => {
  const oldCli = execFileSync('git', ['show', `${previousRelease}:bin/cli.mjs`], { cwd: source, encoding: 'utf8', windowsHide: true });
  const assertManagedCli = code => {
    assert.match(code, /option\('--to <version>'/);
    assert.match(code, /planUpgrade/);
    assert.match(code, /upgrader\.execute/);
  };
  assert.throws(() => assertManagedCli(oldCli), { code: 'ERR_ASSERTION' });
  assertManagedCli(readFileSync(join(source, 'bin', 'cli-main.mjs'), 'utf8'));
  const assertRetainedAllocator = code => {
    assert.match(code, /PORT = server\.address\(\)\.port/);
    assert.match(code, /type: 'upgrade-ready'/);
  };
  const oldBridge = execFileSync('git', ['show', `${previousRelease}:bin/mcp-bridge.mjs`], { cwd: source, encoding: 'utf8', windowsHide: true });
  assert.throws(() => assertRetainedAllocator(oldBridge), { code: 'ERR_ASSERTION' });
  assertRetainedAllocator(readFileSync(join(source, 'bin', 'mcp-bridge.mjs'), 'utf8'));
});

test('RED retained-listener oracle fails when actual bound port publication is removed', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const pkg = fixture.package('2.0.2', root => {
      const path = join(root, 'bin', 'mcp-bridge.mjs');
      const code = readFileSync(path, 'utf8');
      assert.equal(code.includes('PORT = server.address().port;'), true);
      writeFileSync(path, code.replace('PORT = server.address().port;', ''));
    });
    await retainedCliDependencies(pkg.root);
    const instance = createInstance({
      directory: join(fixture.home, 'managed', 'mutant'), root: pkg.root, config: fixture.config, port: 0,
    });
    fixture.instances.push(instance.directory);
    await assert.rejects(startInstance(instance.directory), error => {
      assert.equal(error.startupStopped, true, 'The actual owned mutant and descendants must stop.');
      return /startup/.test(error.message);
    });
    assert.equal(loadInstance(instance.directory).port, 0);
  } finally { await fixture.cleanup(); }
});

async function recoveryLockOracle(Upgrader, rejectRollback) {
      const fixture = new UpgradeFixture();
      let settle;
      const operation = new Promise((resolveOperation, rejectOperation) => {
        settle = rejectRollback ? rejectOperation : resolveOperation;
      });
      try {
        const pkg = fixture.package('2.0.2');
        const instance = createInstance({
          directory: join(fixture.home, 'managed', 'lock'), root: pkg.root,
          config: fixture.config, port: 12345, selection: ownedPackageSelection(pkg.root),
        });
        durableJson(join(instance.directory, 'journal.json'), {
          protocol: 1, instanceId: instance.id, previous: instance.active, target: instance.active,
          binding: { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port },
          phase: 'selected',
        });
        const upgrader = new Upgrader();
        upgrader.rollback = async () => operation;
        const recovering = upgrader.recover(instance.directory);
        recovering.catch(() => {});
        await new Promise(resolveTurn => setImmediate(resolveTurn));
        assert.equal(existsSync(join(instance.directory, 'upgrade.lock')), true, 'Recovery must hold its lock across async rollback.');
        await assert.rejects(upgrader.recover(instance.directory), /lock remains/);
        if (rejectRollback) {
          settle(new Error('owned rollback failure'));
          await assert.rejects(recovering, /owned rollback failure/);
        } else {
          settle({ status: 'owned rollback completed' });
          assert.equal((await recovering).status, 'owned rollback completed');
        }
        assert.equal(existsSync(join(instance.directory, 'upgrade.lock')), false);
      } finally {
        settle({ status: 'cleanup' });
        await fixture.cleanup();
      }
}

test('recovery lock is retained throughout async rollback resolution and rejection', async () => {
      await recoveryLockOracle(ManagedUpgrader, false);
      await recoveryLockOracle(ManagedUpgrader, true);
});

test('RED recovery lock oracle rejects the unawaited rollback implementation', async () => {
      const fixture = new UpgradeFixture();
      try {
        const pkg = fixture.package('2.0.2', root => {
          const path = join(root, 'bin', 'managed-upgrade.mjs');
          const code = readFileSync(path, 'utf8');
          const fixed = "return await this.rollback(instance.directory, journal, 'Recovered interrupted activation.');";
          assert.equal(code.includes(fixed), true);
          writeFileSync(path, code.replace(fixed, fixed.replace('return await', 'return')));
        });
        cpSync(join(source, 'node_modules', 'semver'), join(pkg.root, 'node_modules', 'semver'), { recursive: true });
        const mutant = await import(pathToFileURL(join(pkg.root, 'bin', 'managed-upgrade.mjs')).href);
        await assert.rejects(recoveryLockOracle(mutant.ManagedUpgrader, false), { code: 'ERR_ASSERTION' });
      } finally { await fixture.cleanup(); }
});

for (const [lostResponse, mutant] of [[false, false], [true, false], [false, true]]) {
      test(`${mutant ? 'RED quiesce hold mutation' : 'quiesce'} ${lostResponse ? 'lost response' : 'acknowledged'} across an actual bridge crash`, { timeout: 180000 }, async () => {
        const fixture = new UpgradeFixture();
        try {
          const old = await fixture.start(root => {
            const path = join(root, 'bin', 'mcp-bridge.mjs');
            const code = readFileSync(path, 'utf8');
            writeFileSync(path, code + "\nsetInterval(() => { if (existsSync(CONFIG + '.crash')) process.exit(42); }, 20).unref();\n");
            if (mutant) {
              const supervisor = join(root, 'supervisor', 'supervise.mjs');
              const original = readFileSync(supervisor, 'utf8');
              assert.equal(original.includes('pendingStart = true;'), true);
              writeFileSync(supervisor, original.replace('pendingStart = true;', ''));
            }
          });
          let drained;
          if (lostResponse) {
            const record = readManagedJson(join(fixture.home, `service-${old.instance.port}.json`));
            await new Promise((resolveSent, reject) => {
              const socket = connect(record.socket, () => socket.end(JSON.stringify({
                id: record.id, token: record.token, action: 'quiesce',
              }) + '\n', resolveSent));
              socket.on('error', reject);
            });
          } else {
            drained = await inspectInstance(old.instance, 'quiesce');
          }
          const untilHeld = Date.now() + 10000;
          while (!(await inspectInstance(old.instance)).held) {
            assert.ok(Date.now() < untilHeld);
            await new Promise(resolveWait => setTimeout(resolveWait, 20));
          }
          writeFileSync(fixture.config + '.crash', 'owned crash');
          const deadline = Date.now() + 15000;
          let next;
          while (Date.now() < deadline) {
            try {
              next = await backendStatus(old.instance.port);
              if (next.instanceId !== old.ready.instanceId) break;
            } catch (error) { if (error.code !== 'ECONNREFUSED' && error.code !== 'ECONNRESET') throw error; }
            // Remove the marker after root exit; the replacement must not crash again.
            const record = readManagedJson(join(fixture.home, `service-${old.instance.port}.json`));
            if (next === undefined || record.instanceId !== old.ready.instanceId) {
              if (existsSync(fixture.config + '.crash')) unlinkSync(fixture.config + '.crash');
            }
            next = undefined;
            await new Promise(resolveWait => setTimeout(resolveWait, 30));
          }
          assert.notEqual(next?.instanceId, old.ready.instanceId);
          assert.ok(next);
          const held = (await inspectInstance(old.instance)).held;
          const status = (await fetch(`http://127.0.0.1:${old.instance.port}/ui`)).status;
          if (mutant) {
            assert.throws(() => assert.equal(held, true), { code: 'ERR_ASSERTION' });
            assert.equal(status, 200, 'The actual mutant reopened admission after the quiesced generation crashed.');
          } else {
            assert.equal(held, true);
            assert.equal(status, 503);
            if (drained) await stopInstance(old.instance, drained.instanceId);
          }
        } finally { await fixture.cleanup(); }
      });
}

test('RED rollback oracle fails when the real recovery call is removed from an owned module copy', { timeout: 300000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    await fixture.start();
    const artifact = fixture.artifact('2.0.3', root => {
      const path = join(root, 'bin', 'mcp-bridge.mjs');
      const code = readFileSync(path, 'utf8');
      writeFileSync(path, code.replace("const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));",
        "if (!CONFIG.includes('preflight')) throw new Error('owned failed target');\nconst servers = JSON.parse(readFileSync(CONFIG, 'utf8'));"));
    });
    const pkg = fixture.package('2.0.2', root => {
      const path = join(root, 'bin', 'managed-upgrade.mjs');
      const code = readFileSync(path, 'utf8');
      const recovery = 'await this.rollback(destination, journal, error.message, { startupProof: error.startupProof });';
      assert.equal(code.includes(recovery), true);
      writeFileSync(path, code.replace(recovery, ''));
    });
    cpSync(join(source, 'node_modules', 'semver'), join(pkg.root, 'node_modules', 'semver'), { recursive: true });
    const mutant = await import(pathToFileURL(join(pkg.root, 'bin', 'managed-upgrade.mjs')).href);
    const upgrader = new mutant.ManagedUpgrader({ acquire: async () => artifact, dependencies: retainedCliDependencies });
    await assert.rejects(upgrader.execute(await fixture.plan()), /startup/);
    await assert.rejects(backendStatus(fixture.instance.port), { code: 'ECONNREFUSED' },
      'The same old-restored oracle from the positive test fails against the actual mutant.');
    assert.equal(readManagedJson(join(fixture.instance.directory, 'journal.json')).phase, 'launching');
  } finally { await fixture.cleanup(); }
});

test('native npm acquires target CLI dependencies only from an owned registry and verifies its lock', { timeout: 90000 }, async () => {
  const fixture = new UpgradeFixture();
  let requests = 0;
  let tarball;
  let registry;
  const name = 'managed-owned-dependency';
  const server = createHttpServer((request, response) => {
    requests++;
    if (request.url === '/dependency.tgz') {
      response.end(tarball.bytes);
      return;
    }
    if (request.url !== `/${name}`) { response.writeHead(404).end(); return; }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({
      name, 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': '2020-01-01T00:00:00.000Z' },
      versions: { '1.0.0': { name, version: '1.0.0', main: 'index.cjs',
        dist: { tarball: `${registry}dependency.tgz`, integrity: tarball.integrity } } },
    }));
  });
  try {
    const lifecycle = join(fixture.directory, 'lifecycle-ran');
    tarball = fixture.artifact('1.0.0', root => {
      writeFileSync(join(root, 'package.json'), JSON.stringify({
        name, version: '1.0.0', main: 'index.cjs',
        scripts: { postinstall: `node -e "require('fs').writeFileSync(${JSON.stringify(lifecycle).replaceAll('"', '\\"')},'unexpected')"` },
      }));
      writeFileSync(join(root, 'index.cjs'), 'module.exports = 73;\n');
    });
    await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
    registry = `http://127.0.0.1:${server.address().port}/`;
    const root = join(fixture.directory, 'dependency-target');
    mkdirSync(root);
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      name: 'mcp-pacemaker', version: '2.0.3', dependencies: { [name]: '1.0.0' },
    }));
    const userconfig = join(fixture.directory, 'user.npmrc');
    const globalconfig = join(fixture.directory, 'global.npmrc');
    writeFileSync(userconfig, `registry=${registry}\nstrict-ssl=true\nallow-git=false\nallow-file=false\nallow-directory=false\nmin-release-age=7\nfetch-retries=0\n`);
    writeFileSync(globalconfig, '');
    const npm = process.env.MCP_UPGRADE_TEST_NPM_CLI || npmCliPath();
    const run = async (node, args, options) => {
      const env = Object.fromEntries(Object.entries(options.env ?? process.env)
        .filter(([key]) => !key.toLowerCase().startsWith('npm_config_')));
      Object.assign(env, {
        npm_config_userconfig: userconfig, npm_config_globalconfig: globalconfig,
        npm_config_registry: registry, npm_config_cache: join(fixture.directory, 'cache'),
      });
      return promisify(execFile)(node, [npm, ...args.slice(1)], {
        ...options, cwd: options.cwd ?? fixture.directory, env,
      });
    };
    const inventory = await stageCliDependencies(root, { registry, cache: join(fixture.directory, 'cache'), run });
    assert.ok(requests >= 2);
    assert.ok(inventory.some(file => file.path === `node_modules/${name}/index.cjs`));
    assert.equal(execFileSync(process.execPath, ['-e', `console.log(require(${JSON.stringify(join(root, 'node_modules', name))}))`],
      { encoding: 'utf8', windowsHide: true }).trim(), '73');
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.packages[`node_modules/${name}`].integrity, tarball.integrity);
    assert.equal(lock.packages[`node_modules/${name}`].resolved, `${registry}dependency.tgz`);
    assert.equal(existsSync(join(root, '.npmrc')), false);
    assert.equal(existsSync(lifecycle), false, 'Dependency lifecycle scripts must not run during staging.');
    const denied = join(fixture.directory, 'corrupt-dependency-target');
    mkdirSync(denied);
    copyFileSync(join(root, 'package.json'), join(denied, 'package.json'));
    tarball = { ...tarball, bytes: Buffer.from('corrupt owned archive') };
    await assert.rejects(stageCliDependencies(denied, {
      registry, cache: join(fixture.directory, 'corrupt-cache'), run,
    }), /refused or unavailable/);
  } finally {
    await new Promise(resolveClose => server.close(resolveClose));
    await fixture.cleanup();
  }
});

for (const phase of ['rollback-selecting', 'rollback-active-written', 'rollback-selected', 'rollback-launching', 'rollback-launched']) {
  test(`actual rollback interruption at ${phase} preserves its stop proof and recovery boundary`, { timeout: 300000 }, async () => {
    const fixture = new UpgradeFixture();
    try {
      await fixture.start();
      const artifact = fixture.artifact('2.0.3', root => {
        const path = join(root, 'bin', 'mcp-bridge.mjs');
        const code = readFileSync(path, 'utf8');
        writeFileSync(path, code.replace("const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));",
          "if (!CONFIG.includes('preflight')) throw new Error('owned startup failure');\nconst servers = JSON.parse(readFileSync(CONFIG, 'utf8'));"));
      });
      const archive = join(fixture.directory, 'rollback-target.tgz');
      writeFileSync(archive, artifact.bytes);
      const input = join(fixture.directory, 'rollback-crash.json');
      writeFileSync(input, JSON.stringify({ archive, integrity: artifact.integrity, phase, plan: await fixture.plan() }));
      assert.throws(() => execFileSync(process.execPath, [
        fileURLToPath(new URL('./fixtures/managed-upgrade-crash.mjs', import.meta.url)), input,
      ], { timeout: 180000, windowsHide: true, stdio: 'pipe' }), error => error.status === 86);
      unlinkSync(join(fixture.instance.directory, 'upgrade.lock'));
      const journal = readManagedJson(join(fixture.instance.directory, 'journal.json'));
      assert.ok(journal.rollbackStopProof);
      if (phase === 'rollback-selected') {
        const pkg = fixture.package('2.0.2', root => {
          const path = join(root, 'bin', 'managed-upgrade.mjs');
          const code = readFileSync(path, 'utf8');
          const fixed = "'rollback-selecting', 'rollback-selected', 'rollback-launching'].includes(journal.phase)";
          assert.equal(code.includes(fixed), true);
          writeFileSync(path, code.replace(fixed, "'unknown-rollback'].includes(journal.phase)"));
        });
        cpSync(join(source, 'node_modules', 'semver'), join(pkg.root, 'node_modules', 'semver'), { recursive: true });
        const mutant = await import(pathToFileURL(join(pkg.root, 'bin', 'managed-upgrade.mjs')).href);
        await assert.rejects(new mutant.ManagedUpgrader().recover(fixture.instance.directory), /Admission may have occurred/,
          'RED: the former forward-only transition table rejects a safely stopped rollback selection.');
      }
      if (phase === 'rollback-launching') {
        await assert.rejects(new ManagedUpgrader().recover(fixture.instance.directory), /Launch intent/);
      } else {
        assert.match(await fixture.cli('upgrade', '--recover', '--instance', fixture.instance.directory, '--yes'), /rolled-back/);
        assert.equal((await backendStatus(fixture.instance.port)).version, '2.0.2');
        assert.equal(await fixture.cli('--version'), '2.0.2');
      }
    } finally { await fixture.cleanup(); }
  });
}

test('one selector normalization covers equals/separate placement, Windows spelling, conflicts and --', async () => {
  const fixture = new UpgradeFixture();
  try {
    const first = join(fixture.directory, 'instance with spaces');
    const second = join(fixture.directory, 'second instance');
    mkdirSync(first);
    mkdirSync(second);
    const variants = [
      ['--instance', first, 'status'], [`--instance=${first}`, 'status'],
      ['status', '--instance', first], ['status', `--instance=${first}`],
    ];
    for (const args of variants) {
      const selected = normalizeInstanceSelection(args);
      assert.equal(selected.directory, realpathSync(first));
      assert.equal(selected.explicit, true);
      assert.deepEqual(selected.args, ['status']);
    }
    if (process.platform === 'win32') {
      assert.equal(normalizeInstanceSelection(['--instance', first.replaceAll('\\', '/')]).directory, realpathSync(first));
      assert.equal(normalizeInstanceSelection([`--instance=${first.toUpperCase()}`]).directory, realpathSync(first));
    }
    assert.deepEqual(normalizeInstanceSelection(['logs', '--', `--instance=${first}`]),
      { directory: undefined, explicit: false, args: ['logs', '--', `--instance=${first}`] });
    assert.deepEqual(normalizeInstanceSelection(['prewarm', '--server', `--instance=${second}`, '--instance', first]),
      { directory: realpathSync(first), explicit: true, args: ['prewarm', '--server', `--instance=${second}`] });
    for (const args of [
      ['--instance='], ['--instance'], ['--instance', '--'], ['--instance', 'missing-owned-instance'],
      ['--instance', first, 'stop', `--instance=${second}`],
    ]) assert.throws(() => normalizeInstanceSelection(args));
    const instance = { config: fixture.config, port: 12345 };
    for (const command of ['init', 'import', 'install', 'uninstall']) {
      assert.throws(() => validateSelectedCommand(instance, command, {}), /not supported/);
    }
    for (const command of ['stop', 'start', 'reload', 'prewarm', 'top']) {
      assert.throws(() => validateSelectedCommand(instance, command, { port: '12346' }), /conflicts/);
      assert.doesNotThrow(() => validateSelectedCommand(instance, command, { port: '12345' }));
    }
    assert.throws(() => validateSelectedCommand(instance, 'logs', { config: join(second, 'unknown') }));
  } finally { await fixture.cleanup(); }
});

test('recovery parsing tolerates damaged target bytes but rejects stale identity, corrupt previous and unknown journal', async () => {
  const fixture = new UpgradeFixture();
  try {
    const old = fixture.package('2.0.2');
    const candidate = fixture.package('2.0.3');
    const previous = ownedPackageSelection(old.root);
    const target = ownedPackageSelection(candidate.root);
    const instance = createInstance({
      directory: join(fixture.home, 'managed', 'recovery with spaces'),
      root: old.root, config: fixture.config, port: 12345, selection: previous,
    });
    const journalPath = join(instance.directory, 'journal.json');
    const journal = {
      protocol: 1, instanceId: instance.id, previous, target, phase: 'selected',
      binding: { config: instance.config, cwd: instance.cwd, node: instance.node, port: instance.port },
    };
    durableJson(join(instance.directory, 'active.json'), target);
    durableJson(journalPath, journal);
    writeFileSync(join(candidate.root, 'package.json'), '{corrupt');
    assert.throws(() => loadInstance(instance.directory));
    assert.equal(readRecoveryContext(instance.directory).journal.previous.root, previous.root);
    assert.doesNotThrow(() => verifySelection(previous));
    rmSync(candidate.root, { recursive: true });
    assert.equal(readRecoveryContext(instance.directory).journal.target.root, target.root);
    writeFileSync(join(old.root, 'bin', 'cli-main.mjs'), 'corrupt previous');
    assert.throws(() => verifySelection(previous), /Immutable package bytes changed/);
    const beforeFailure = readFileSync(journalPath);
    await assert.rejects(fixture.cli('upgrade', '--recover', '--instance', instance.directory, '--yes'), error => {
      assert.match(error.stderr, /Immutable package bytes changed/);
      return error.code === 1;
    });
    assert.deepEqual(readFileSync(journalPath), beforeFailure);
    assert.equal(existsSync(join(instance.directory, 'upgrade.lock')), false);
    for (const change of [{ instanceId: randomUUID() }, { phase: 'unrecognized' }, { binding: { ...journal.binding, port: 12346 } }]) {
      durableJson(journalPath, { ...journal, ...change });
      assert.throws(() => readRecoveryContext(instance.directory), /identity or phase/);
    }
  } finally { await fixture.cleanup(); }
});

for (const mode of ['fixed', 'legacy-selector', 'legacy-top']) {
test(`${mode}: explicit instance commands and actual TUI recycle target only the selected owned backend`, { timeout: 600000 }, async () => {
  const fixture = new UpgradeFixture();
  try {
    const script = join(fixture.home, 'owned-stdio.mjs');
    writeFileSync(script, [
      "import { createInterface } from 'node:readline';",
      "createInterface({input:process.stdin}).on('line', line => {",
      " const message=JSON.parse(line); if(message.id===undefined)return;",
      " const result=message.method==='initialize'?{protocolVersion:'2024-11-05',capabilities:{tools:{}}}:{tools:[]};",
      " console.log(JSON.stringify({jsonrpc:'2.0',id:message.id,result}));",
      '});',
    ].join('\n'));
    fixture.original = Buffer.from(JSON.stringify({ alpha: { command: process.execPath, args: [script] } }));
    writeFileSync(fixture.config, fixture.original);
    const main = (await fixture.start(root => {
      const bridgePath = join(root, 'bin', 'mcp-bridge.mjs');
      const bridge = readFileSync(bridgePath, 'utf8');
      writeFileSync(bridgePath, bridge.replace('server.listen(PORT, HOST, () => {',
        "server.on('request', (req) => { if (req.method === 'POST' && req.url.startsWith('/admin/')) appendFileSync(CONFIG + '.api-requests', JSON.stringify({path:req.url, nonceValid:req.headers['x-mcp-nonce'] === ADMIN_NONCE}) + '\\n'); });\nserver.listen(PORT, HOST, () => {"));
      if (mode === 'legacy-selector') {
        const path = join(root, 'bin', 'cli-dispatch.mjs');
        const code = readFileSync(path, 'utf8').replaceAll('\r\n', '\n');
        const supported = "argument !== '--instance' &&\n        !argument.startsWith('--instance=')";
        assert.equal(code.includes(supported), true);
        writeFileSync(path, code.replace(supported, "argument !== '--instance'"));
      }
      if (mode === 'legacy-top') {
        const path = join(root, 'bin', 'cli-main.mjs');
        const code = readFileSync(path, 'utf8');
        const selected = "runTop(explicitInstance ? selectedInstance.port : opts.port ? parseInt(opts.port, 10) : undefined,\n      explicitInstance ? CONFIG : undefined);";
        assert.equal(code.includes(selected), true);
        writeFileSync(path, code.replace(selected, 'runTop(undefined, undefined);'));
      }
    })).instance;
    const profile = join(fixture.directory, 'isolated profile with spaces');
    mkdirSync(profile);
    const config = join(profile, 'servers.json');
    writeFileSync(config, fixture.original);
    const second = createInstance({
      directory: join(fixture.home, 'managed', 'second with spaces'), root: main.active.root,
      selection: main.active, config, port: 0,
    });
    fixture.instances.push(second.directory);
    let sxs = (await startInstance(second.directory)).instance;
    writeFileSync(join(fixture.home, 'state.json'), JSON.stringify({
      hosts: [{ id: 'vscode', port: main.port, servers: [] }, { id: 'cursor', port: sxs.port, servers: [] }],
    }));
    const mainBefore = await backendStatus(main.port);
    const mainConfig = readFileSync(main.config);
    const mainLog = readFileSync(join(fixture.home, 'bridge.log'));
    const selectors = [
      command => ['--instance', sxs.directory.replaceAll('\\', '/'), command],
      command => [`--instance=${sxs.directory}`, command],
      command => [command, '--instance', sxs.directory],
      command => [command, `--instance=${sxs.directory}`],
    ];
    if (mode === 'legacy-selector') {
      await promisify(execFile)(process.execPath, [
        join(fixture.initialRoot, 'bin', 'cli.mjs'), `--instance=${sxs.directory}`, 'reload',
      ], { encoding: 'utf8', windowsHide: true, timeout: 30000,
        env: { ...process.env, HOME: fixture.directory, USERPROFILE: fixture.directory } });
      const wrong = JSON.parse(readFileSync(main.config + '.api-requests', 'utf8').trim());
      assert.deepEqual(wrong, { path: '/admin/reload', nonceValid: true });
      assert.throws(() => assert.equal(existsSync(main.config + '.api-requests'), false), { code: 'ERR_ASSERTION' },
        'RED: equals syntax falling through dispatcher really sends a mutation to the default backend.');
      return;
    }
    const tui = await promisify(execFile)(process.execPath, [
      '--import', new URL('./fixtures/managed-top-input.mjs', import.meta.url).href,
      join(fixture.initialRoot, 'bin', 'cli.mjs'), `--instance=${sxs.directory}`, 'top',
    ], { encoding: 'utf8', timeout: 30000, windowsHide: true,
      env: { ...process.env, HOME: fixture.directory, USERPROFILE: fixture.directory, CI: '1' } });
    assert.match(tui.stdout, /recycled alpha/);
    if (mode === 'legacy-top') {
      const wrong = JSON.parse(readFileSync(main.config + '.api-requests', 'utf8').trim());
      assert.deepEqual(wrong, { path: '/admin/recycle/alpha', nonceValid: true });
      assert.throws(() => assert.equal(existsSync(main.config + '.api-requests'), false), { code: 'ERR_ASSERTION' },
        'RED: unbound top really recycles the default backend with its nonce.');
      return;
    }
    const tuiRequest = JSON.parse(readFileSync(config + '.api-requests', 'utf8').trim());
    assert.deepEqual(tuiRequest, { path: '/admin/recycle/alpha', nonceValid: true });
    assert.equal(existsSync(main.config + '.api-requests'), false);
    assert.deepEqual(readFileSync(join(fixture.home, 'bridge.log')), mainLog, 'TUI must not send recycle to the default backend.');
    assert.match(readFileSync(join(profile, 'bridge.log'), 'utf8'), /admin: recycled/);
    writeFileSync(join(profile, 'bridge.log'), '2026-10-07T00:00:00.000Z selected-log-marker\n');
    const logs = await fixture.cli(`--instance=${sxs.directory}`, 'logs');
    assert.match(logs, /selected-log-marker/);
    assert.doesNotMatch(logs, new RegExp(String(main.port)));
    assert.deepEqual(readFileSync(join(fixture.home, 'bridge.log')), mainLog);
    const bareBefore = readFileSync(config);
    const bare = await fixture.cli('--instance', sxs.directory);
    assert.match(bare, /bridge UP/);
    assert.equal(existsSync(join(profile, 'state.json')), false);
    assert.deepEqual(readFileSync(config), bareBefore);
    assert.equal(await fixture.cli(`--instance=${sxs.directory}`, '--version'), '2.0.2');
    assert.match(await fixture.cli('status', '--instance', sxs.directory, '--help'), /Usage:/);
    const plan = await fixture.cli('upgrade', `--instance=${sxs.directory}`, '--to', '2.0.3', '--plan',
      '--registry', `http://127.0.0.1:${main.port}/`);
    assert.ok(plan.includes(sxs.directory));
    await assert.rejects(fixture.cli('--instance', main.directory, 'reload', `--instance=${sxs.directory}`),
      error => /Conflicting/.test(error.stderr));
    await assert.rejects(fixture.cli('--instance', sxs.directory, 'reload', '--port', String(main.port)),
      error => /conflicts/.test(error.stdout));
    await assert.rejects(fixture.cli('--instance', sxs.directory, 'logs', '--config', main.config),
      error => /conflicts/.test(error.stdout));
    assert.equal(existsSync(main.config + '.api-requests'), false);
    for (const select of selectors) {
      await fixture.cli(...select('prewarm'), '--enable', 'alpha', '--count', '1');
      await fixture.cli(...select('reload'));
      assert.equal(JSON.parse(readFileSync(config, 'utf8')).alpha.minWarm, 1);
      assert.deepEqual(readFileSync(main.config), mainConfig);
      assert.equal((await backendStatus(main.port)).instanceId, mainBefore.instanceId);
      assert.equal(existsSync(main.config + '.api-requests'), false);
      await fixture.cli(...select('stop'));
      assert.equal(await listenerOpen(sxs.port), false);
      assert.equal((await backendStatus(main.port)).instanceId, mainBefore.instanceId);
      sxs = (await startInstance(sxs.directory)).instance;
      await fixture.cli(...select('prewarm'), '--disable', 'alpha');
      await fixture.cli(...select('reload'));
    }
    const other = await backendStatus(sxs.port);
    await fixture.cli('--instance', main.directory, 'stop');
    assert.equal(await listenerOpen(main.port), false);
    assert.equal((await backendStatus(sxs.port)).instanceId, other.instanceId);
    for (const command of ['init', 'import', 'install', 'uninstall']) {
      await assert.rejects(fixture.cli('--instance', sxs.directory, command), error => {
        assert.match(error.stdout, /not supported with --instance/);
        return error.code === 1;
      });
    }
  } finally { await fixture.cleanup(); }
});
}

test('RED bare-instance action control rejects the former state-file-only setup decision', () => {
  const source = readFileSync(new URL('../bin/cli-main.mjs', import.meta.url), 'utf8');
  const line = source.split('\n').find(value => value.startsWith('program.action(() =>'));
  assert.ok(line);
  const invoke = text => {
    let action;
    runInNewContext(text, {
      program: { action: callback => { action = callback; } },
      selectedInstance: { id: 'owned' }, STATE: 'owned/no-state.json',
      existsSync: () => false, cmdStatus: () => 'status', cmdInit: () => 'setup',
    });
    return action();
  };
  assert.equal(invoke(line), 'status');
  assert.throws(() => assert.equal(invoke(line.replace('selectedInstance || ', '')), 'status'), { code: 'ERR_ASSERTION' });
});

test('selected commands reject noncanonical ports before execution, including exact 8.791e3', () => {
  const instance = { port: 8791, config: 'owned-config' };
  const invalid = ['8.791e3', '0x2257', '+8791', ' 8791', '8791 ', '08791', '8791.0', '8791x'];
  for (const command of ['reload', 'prewarm', 'top', 'start', 'stop', 'emit', 'plan']) {
    for (const port of invalid) {
      assert.throws(() => validateSelectedCommand(instance, command, { port }), /canonical/,
        `${command} must reject ${JSON.stringify(port)} before parsing or executing it differently`);
    }
  }
});

test('invalid scientific port sends no request or selected nonce to an actual foreign owned endpoint', { timeout: 180000 }, async () => {
  const fixture = new UpgradeFixture();
  const requests = [];
  let foreign;
  try {
    foreign = createHttpServer((request, response) => {
      requests.push({ path: request.url, nonce: request.headers['x-mcp-nonce'] });
      response.setHeader('content-type', 'application/json');
      response.end('{"ok":true,"unchanged":true}');
    });
    for (let attempt = 0; attempt < 32; attempt++) {
      const listening = once(foreign, 'listening');
      foreign.listen(randomInt(1000, 6554) * 10, '127.0.0.1');
      try {
        await listening;
        break;
      } catch (error) {
        if (error.code !== 'EADDRINUSE') throw error;
      }
    }
    assert.equal(foreign.listening, true, 'Own a retained listener whose port can demonstrate the parser split.');
    const port = foreign.address().port;
    assert.equal(port % 10, 0);
    const selectedPort = port / 10;
    const pkg = fixture.package('2.0.2');
    await retainedCliDependencies(pkg.root);
    const instance = createInstance({
      directory: join(fixture.home, 'managed', 'no-running-backend'), root: pkg.root,
      config: fixture.config, port: selectedPort, selection: ownedPackageSelection(pkg.root),
    });
    writeFileSync(join(fixture.home, 'admin.nonce'), 'owned-selected-nonce');
    const before = readFileSync(join(instance.directory, 'instance.json'));
    await assert.rejects(fixture.cli('reload', '--instance', instance.directory, '--port', `${port}e-1`),
      error => /canonical/.test(error.stdout));
    assert.deepEqual(requests, [], 'No HTTP request may carry the selected nonce to the parseInt destination.');
    assert.deepEqual(readFileSync(join(instance.directory, 'instance.json')), before);
  } finally {
    if (foreign?.listening) await new Promise(resolveClose => foreign.close(resolveClose));
    await fixture.cleanup();
  }
});
