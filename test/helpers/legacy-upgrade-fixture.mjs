import assert from 'node:assert/strict';
import { execFile, execFileSync, fork } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { promisify } from 'node:util';
import { backendStatus, listenerOpen, stopInstance, waitForInstanceExit } from '../../bin/managed-runtime.mjs';
import { loadInstance, readManagedJson } from '../../bin/managed-state.mjs';
import { ManagedUpgrader, planUpgrade } from '../../bin/managed-upgrade.mjs';
import { confirmLegacyUpgrade } from '../../bin/legacy-installation.mjs';
import { legacyDormant } from '../../bin/legacy-upgrade.mjs';
import { observeWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';
import { retainedCliDependencies } from './managed-package.mjs';

export const legacyCommit = '2d525f4ced01b978a5aeb83aef69145e96cced05';
const source = fileURLToPath(new URL('../../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');

export class OwnedLegacyTask {
  constructor(path, launch) { this.path = path; this.launch = launch; }
  read() { return JSON.parse(readFileSync(this.path, 'utf8')); }
  inspect() { return [this.read().current]; }
  save(record, operation) {
    const state = this.read();
    const semantic = { ...record };
    delete semantic.xml;
    delete semantic.xmlSha256;
    delete semantic.security;
    record.xml = JSON.stringify(semantic);
    record.xmlSha256 = hash(record.xml);
    state.current = record;
    state.actions.push(operation);
    writeFileSync(this.path, JSON.stringify(state));
    return record;
  }
  check(expected) {
    assert.deepEqual(this.read().current, expected, 'Owned registration changed before operation.');
    return structuredClone(expected);
  }
  hold(port, expected) {
    const record = this.check(expected);
    record.enabled = false;
    return this.save(record, 'hold');
  }
  repoint(port, expected, launcher) {
    const record = this.check(expected);
    assert.equal(record.enabled, false);
    record.actions[0].arguments = `"${launcher}"`;
    return this.save(record, 'repoint');
  }
  enable(port, expected) {
    const record = this.check(expected);
    record.enabled = true;
    return this.save(record, 'enable');
  }
  restore(port, expected, original) {
    this.check(expected);
    assert.equal(expected.enabled, false);
    return this.save(structuredClone(original), 'restore');
  }
  start(port, expected) {
    this.check(expected);
    this.save(structuredClone(expected), 'start');
    if (!this.launch) throw new Error('Owned crash actor cannot launch rollback; recover from its fixture parent.');
    this.launch();
    return expected;
  }
  stableRecords() { return []; }
}

export class LegacyUpgradeFixture {
  constructor({ cacheBacked = false, taskOwner = 'current-user' } = {}) {
    assert.ok(['current-user', 'builtin-administrators'].includes(taskOwner));
    this.taskOwner = taskOwner;
    this.directory = realpathSync.native(mkdtempSync(join(tmpdir(), 'legacy upgrade ')));
    this.root = join(this.directory, ...(cacheBacked ? ['_npx', 'retained old package'] : ['retained old package']));
    this.home = join(this.directory, '.mcp-pacemaker');
    this.config = join(this.home, 'servers.json');
    this.taskPath = join(this.directory, 'owned-task.json');
    this.instances = [];
    this.pending = new Map();
    this.log = '';
    mkdirSync(this.root, { recursive: true });
    mkdirSync(this.home);
    const archive = execFileSync('git', ['archive', '--format=tar', legacyCommit, 'bin', 'supervisor', 'autostart', 'package.json'], {
      cwd: source, windowsHide: true, maxBuffer: 16 * 1024 * 1024,
    });
    execFileSync('tar', ['-xf', '-', '-C', this.root], { input: archive, windowsHide: true });
    this.originalConfig = Buffer.from('{}\n');
    writeFileSync(this.config, this.originalConfig, { mode: 0o600 });
    this.task = new OwnedLegacyTask(this.taskPath, () => {
      this.launchLegacy().catch(error => { this.launchFailure = error; });
    });
  }

  async start(config = {}) {
    this.originalConfig = Buffer.from(JSON.stringify(config) + '\n');
    writeFileSync(this.config, this.originalConfig);
    await retainedCliDependencies(this.root);
    const server = createServer();
    await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
    this.port = server.address().port;
    await new Promise(resolveClose => server.close(resolveClose));
    this.originalState = Buffer.from(JSON.stringify({ hosts: [{ id: 'vscode', port: this.port }] }) + '\n');
    writeFileSync(join(this.home, 'state.json'), this.originalState);
    this.owner = fork(fileURLToPath(new URL('../fixtures/legacy-supervisor-owner.mjs', import.meta.url)), [], {
      execArgv: [], windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    this.ownerExit = new Promise(resolveExit => this.owner.once('exit', resolveExit));
    this.owner.stdout.on('data', bytes => { this.log = (this.log + bytes).slice(-32768); });
    this.owner.stderr.on('data', bytes => { this.log = (this.log + bytes).slice(-32768); });
    const lifetime = await new Promise((resolveReady, reject) => {
      const deadline = setTimeout(() => reject(new Error('Owned cleanup capsule did not become ready.')), 10000);
      this.owner.once('error', reject);
      this.owner.on('message', message => {
        if (message.type === 'ready') {
          clearTimeout(deadline);
          resolveReady(message.lifetime);
        } else {
          const pending = this.pending.get(message.id);
          if (!pending) return;
          this.pending.delete(message.id);
          if (message.error) pending.reject(new Error(message.error));
          else pending.resolve(message);
        }
      });
    });
    this.observer = await observeWindowsProcessLifetime(lifetime);
    await this.launchLegacy();
    this.old = await this.waitVersion('1.3.0');
    const api = await import('../../bin/windows-legacy-process.mjs');
    const held = await api.prepareLegacyProcesses({ port: this.port, root: this.root });
    this.initialProcesses = held.plan;
    await held.close();
    const userSid = this.initialProcesses.ownerSid;
    const ownerSid = this.taskOwner === 'builtin-administrators' ? 'S-1-5-32-544' : userSid;
    const sddl = `O:${ownerSid}G:${userSid}D:P(A;;FA;;;${userSid})S:(ML;;NW;;;ME)`;
    const record = {
      name: `McpPacemaker-${this.port}`, path: `\\McpPacemaker-${this.port}`, enabled: true,
      userSid, currentUserSid: userSid, logonType: 3, runLevel: 0,
      security: {
        protocol: 1, information: 31, complete: true, ownerSid, groupSid: userSid,
        controlFlags: 36884, sddl, sha256: hash(sddl),
      },
      actions: [{ type: 0, path: 'wscript.exe', arguments: `"${join(this.root, 'autostart', 'windows', 'launcher.vbs')}" ${this.port}`, workingDirectory: '' }],
      triggers: [{ type: 9, userSid, enabled: true, stateChange: 0 }, { type: 11, userSid, enabled: true, stateChange: 8 }],
      settings: {
        multipleInstances: 2, restartCount: 3, restartInterval: 'PT1M', executionTimeLimit: 'PT0S',
        startWhenAvailable: true, disallowStartIfOnBatteries: false, stopIfGoingOnBatteries: false,
      },
    };
    writeFileSync(this.taskPath, JSON.stringify({ current: record, actions: [] }));
    this.originalTask = this.task.save(record, 'fixture-registered');
    this.shim = join(this.directory, 'mcp-pacemaker.cmd');
    writeFileSync(this.shim, `@echo off\r\n"${process.execPath}" "${join(this.root, 'bin', 'cli.mjs')}" %*\r\n`);
    return this.old;
  }

  env() {
    return {
      ...process.env, HOME: this.directory, USERPROFILE: this.directory,
      PATH: `${dirname(process.execPath)};${process.env.PATH}`,
      MCP_CONFIG_WATCH: '0', MCP_HEALTH_INTERVAL_MS: '0', MCP_TOKEN_REFRESH_LEAD_MS: '0',
    };
  }

  launchLegacy() {
    const id = randomUUID();
    return new Promise((resolveLaunch, reject) => {
      this.pending.set(id, { resolve: resolveLaunch, reject });
      this.owner.send({
        action: 'launch', id, script: join(this.root, 'supervisor', 'supervise.ps1'),
        port: this.port, cwd: this.directory, env: this.env(),
      });
    });
  }

  launchWorker(args, env) {
    const id = randomUUID();
    return new Promise((resolveExit, reject) => {
      this.pending.set(id, { resolve: result => resolveExit(result.code), reject });
      this.owner.send({ action: 'launch-worker', id, args, cwd: this.directory, env });
    });
  }

  async waitVersion(version) {
    const deadline = Date.now() + 15000;
    let lastError;
    while (Date.now() < deadline) {
      try {
        const status = await backendStatus(this.port);
        if (status.version === version) return status;
      } catch (error) { lastError = error; }
      await new Promise(resolveWait => setTimeout(resolveWait, 50));
    }
    throw new Error(`Owned ${version} backend did not become ready: ${this.log}`, { cause: lastError });
  }

  async plan(options = {}) {
    const plan = await planUpgrade({ to: '2.0.3', ...options }, { home: this.home, legacy: { task: this.task } });
    this.instances.push(plan.instance.directory);
    return plan;
  }

  async approve(plan) {
    assert.equal(await confirmLegacyUpgrade(plan, { interactive: true, confirm: async () => true }), true);
  }

  artifact(modify, version = '2.0.3') {
    const root = join(this.directory, `target-${randomUUID()}`);
    mkdirSync(root);
    for (const relative of ['bin', 'supervisor', 'autostart', 'ui/dist']) {
      cpSync(join(source, relative), join(root, relative), { recursive: true });
    }
    const pkg = readManagedJson(join(source, 'package.json'));
    writeFileSync(join(root, 'package.json'), JSON.stringify({ ...pkg, version }));
    modify?.(root);
    const entries = [];
    const walk = (directory, prefix = '') => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const relative = prefix + entry.name;
        if (entry.isDirectory()) { walk(join(directory, entry.name), `${relative}/`); continue; }
        const bytes = readFileSync(join(directory, entry.name));
        const name = `package/${relative}`;
        assert.ok(Buffer.byteLength(name) <= 100, name);
        const header = Buffer.alloc(512);
        header.write(name);
        header.write('0000644\0', 100);
        header.write('0000000\0', 108);
        header.write('0000000\0', 116);
        header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124);
        header.write('00000000000\0', 136);
        header.fill(32, 148, 156);
        header.write('0', 156);
        header.write('ustar\0', 257);
        header.write('00', 263);
        header.write([...header].reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148);
        entries.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
      }
    };
    walk(root);
    entries.push(Buffer.alloc(1024));
    const bytes = gzipSync(Buffer.concat(entries));
    return { bytes, integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` };
  }

  upgrader(artifact = this.artifact(), options = {}) {
    return new ManagedUpgrader({
      acquire: async () => artifact, dependencies: retainedCliDependencies,
      legacy: { task: this.task }, ...options,
    });
  }

  async cliVersion() {
    const result = await promisify(execFile)(process.env.ComSpec, ['/d', '/s', '/c', `""${this.shim}" --version"`], {
      env: this.env(), encoding: 'utf8', timeout: 30000, windowsHide: true, windowsVerbatimArguments: true,
    });
    return result.stdout.trim();
  }

  async cleanup() {
    const errors = [];
    const modern = [];
    let capsule;
    try {
      for (const directory of new Set(this.instances)) {
        if (!existsSync(join(directory, 'instance.json'))) continue;
        try {
          const instance = loadInstance(directory, { verifyFiles: false });
          if (legacyDormant(instance)) continue;
          if (await listenerOpen(instance.port)) {
            const status = await backendStatus(instance.port).catch(() => null);
            if (status?.version !== '1.3.0') modern.push(await stopInstance(instance));
          }
          await waitForInstanceExit(directory);
        } catch (error) { errors.push(error); }
      }
      if (this.owner?.connected) this.owner.send({ action: 'close' });
      await this.ownerExit;
      if (this.observer) {
        capsule = await this.observer.done;
        assert.deepEqual(capsule, { verified: true, ownerExited: true, activeProcesses: 0 });
      }
      const api = await import('../../bin/windows-legacy-process.mjs');
      const old = this.initialProcesses ? await api.verifyLegacyProcessesGone(this.initialProcesses) : null;
      if (old) {
        assert.equal(old.legacyRootStopVerified, true);
        assert.equal(old.observedDescendantsStopped, true);
      }
      if (!errors.length) {
        try { rmSync(this.directory, { recursive: true }); }
        catch (error) { errors.push(error); }
      }
      if (process.env.MCP_LEGACY_TEST_EVIDENCE) {
        mkdirSync(process.env.MCP_LEGACY_TEST_EVIDENCE, { recursive: true });
        writeFileSync(join(process.env.MCP_LEGACY_TEST_EVIDENCE, `${basename(this.directory)}.json`), JSON.stringify({
          at: new Date().toISOString(), directory: this.directory, node: process.version,
          initialProcesses: this.initialProcesses, old, modern, capsule,
          capsuleScope: 'Test-only birth-contained cleanup capsule; not a production legacy completeness certificate.',
          errors: errors.map(error => error.message), removed: !existsSync(this.directory),
        }, null, 2), { flag: 'wx', mode: 0o600 });
      }
    } catch (error) { errors.push(error); }
    if (errors.length) {
      throw new AggregateError(errors, `Owned legacy fixture retained at ${this.directory}\n${this.log}`);
    }
  }
}
