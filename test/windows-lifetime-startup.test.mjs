import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { observeWindowsProcessLifetime } from '../bin/windows-process-lifetime.mjs';

class StartupFixture {
  constructor(t, mode) {
    this.directory = mkdtempSync(join(process.env.MCP_LIFETIME_TEST_EVIDENCE || tmpdir(), 'mcp-lifetime-startup-'));
    this.mode = mode;
    this.records = [];
    this.messages = [];
    this.stdout = '';
    this.stderr = '';
    this.cleanup = [];
    t.diagnostic(`Owned startup evidence: ${this.directory}`);
    t.after(() => this.finish());
  }

  powershell(name, args) {
    const script = fileURLToPath(new URL(`./fixtures/windows-process-lifetime/${name}.ps1`, import.meta.url));
    const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script, ...args], {
      windowsHide: true, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    return result.stdout.trim();
  }

  capture(pid, parentPid) {
    const record = JSON.parse(this.powershell('identity', ['-ProcessId', String(pid), '-ParentId', String(parentPid)]));
    assert.equal(record.gone, false, 'Capture identity while the owned process is held at readiness');
    this.records.push(record);
    return record;
  }

  async wait(check) {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      const value = check();
      if (value) return value;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.fail(`Owned startup readiness timed out: ${this.stderr}`);
  }

  async run() {
    const config = join(this.directory, 'servers.json');
    writeFileSync(config, JSON.stringify({
      warm: { command: process.execPath, args: ['-e', 'setTimeout(() => process.exit(0), 45000)'],
        sharing: 'pool', minWarm: 1 },
    }));
    let failureHelper;
    if (this.mode === 'assignment-failure') {
      failureHelper = this.powershell('build-failure', ['-OutputDirectory', this.directory]);
    }
    if (this.mode === 'observer-zero-exit') {
      this.zeroExit = this.powershell('build-failure', ['-OutputDirectory', this.directory, '-Variant', 'zero-exit']);
    }
    this.child = fork(fileURLToPath(new URL('../bin/mcp-bridge.mjs', import.meta.url)),
      ['--port', '0', '--host', '127.0.0.1', '--config', config], {
        execPath: process.execPath,
        execArgv: ['--import', new URL('./fixtures/windows-process-lifetime/startup-preload.mjs', import.meta.url).href],
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true,
        env: {
          SystemRoot: process.env.SystemRoot, ComSpec: process.env.ComSpec, PATH: process.env.PATH,
          HOME: this.directory, USERPROFILE: this.directory, TEMP: this.directory, TMP: this.directory,
          PROBE_STARTUP_MODE: this.mode, ...(failureHelper ? { PROBE_FAILURE_HELPER: failureHelper } : {}),
          MCP_CONFIG_WATCH: '0', MCP_RESUME: '0', MCP_HEALTH_INTERVAL_MS: '0',
          MCP_PACEMAKER_MANAGED_INSTANCE: this.directory,
        },
      });
    this.child.on('message', (message) => {
      this.messages.push(message);
      if (message.type === 'upgrade-lifetime') {
        this.observerPromise = observeWindowsProcessLifetime(message.lifetime).then((observer) => {
          this.observer = observer;
          this.capture(observer.pid, process.pid);
          observer.done.then((value) => { this.observed = { value }; },
            (error) => { this.observed = { error: error.message }; });
          this.child.send('upgrade-lifetime-observed');
          return observer;
        });
        this.observerPromise.catch((error) => { this.armingError = error.message; });
      }
    });
    this.child.stdout.on('data', (data) => { this.stdout += data; });
    this.child.stderr.on('data', (data) => { this.stderr += data; });
    this.child.on('error', (error) => { this.stderr += error.message; });
    const barrier = await this.wait(() => this.messages.find((message) => message.event === 'before-assignment'));
    this.rootIdentity = this.capture(this.child.pid, process.pid);
    assert.deepEqual(barrier, { event: 'before-assignment', released: false, assigned: false });
    assert.equal(existsSync(join(this.directory, 'admin.nonce')), false);
    assert.equal(this.messages.some((message) => message.event === 'workload'), false);
    this.child.send('release');
    const successfulStart = ['gated-success', 'observer-owner-loss', 'observer-stale',
      'observer-wrong-image', 'observer-parent-loss', 'observer-zero-exit'].includes(this.mode);
    if (!successfulStart) {
      await this.wait(() => this.child.exitCode != null || this.child.signalCode != null);
      assert.equal(this.messages.some((message) => message.event === 'workload'), false);
      assert.equal(existsSync(join(this.directory, 'admin.nonce')), false);
      assert.match(this.stderr, /Windows process containment failed/);
      if (this.mode === 'assignment-failure') assert.match(this.stderr, /stage=assign.*nativeError=6/);
      return;
    }
    const listening = await this.wait(() => this.messages.find((message) => message.event === 'listening'));
    const workload = await this.wait(() => this.messages.find((message) => message.event === 'workload'));
    const owner = this.messages.find((message) => message.event === 'owner');
    const ownerIdentity = this.capture(owner.pid, this.child.pid);
    const workerIdentity = this.capture(workload.pid, this.child.pid);
    const lifetime = (await this.wait(() => this.messages.find((message) => message.event === 'lifetime'))).identity;
    assert.equal(lifetime.ownerPid, owner.pid);
    if (this.mode === 'observer-stale') {
      await assert.rejects(observeWindowsProcessLifetime({
        ...lifetime, ownerCreationTime: String(BigInt(lifetime.ownerCreationTime) + 1n),
      }), /Windows lifetime verification failed/);
    }
    if (this.mode === 'observer-wrong-image') {
      await assert.rejects(observeWindowsProcessLifetime({
        protocol: 1, ownerPid: workerIdentity.pid, ownerCreationTime: workerIdentity.creationFileTime,
      }), /Windows lifetime verification failed/);
    }
    assert.equal(this.armingError, undefined);
    assert.ok(await this.observerPromise);
    if (this.mode === 'observer-parent-loss') await this.checkObserverParentLoss(lifetime);
    assert.equal(listening.assigned, true);
    assert.equal(listening.released, true);
    const status = await new Promise((resolve, reject) => {
      const request = http.get({ host: '127.0.0.1', port: listening.port, path: '/api/status', agent: false }, (response) => {
        let body = '';
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve(JSON.parse(body)));
      });
      request.on('error', reject);
      request.setTimeout(2000, () => request.destroy(new Error('Owned control plane timeout')));
    });
    assert.equal(status.sessions, 0);
    assert.equal(status.servers[0].warm, 1);
    if (this.mode === 'observer-zero-exit') {
      const result = spawnSync(this.zeroExit, [String(ownerIdentity.pid), lifetime.ownerCreationTime],
        { encoding: 'utf8', timeout: 5000, windowsHide: true });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr);
    } else {
      this.stop(this.mode === 'observer-owner-loss' ? ownerIdentity : this.rootIdentity);
    }
    await this.wait(() => this.child.exitCode != null || this.child.signalCode != null);
    await this.wait(() => this.observed);
    if (this.mode === 'observer-owner-loss' ||
        this.mode === 'observer-zero-exit') {
      assert.equal(this.observed.value, undefined, 'Forced owner death is not a measured job-drain receipt');
      assert.match(this.observed.error, /Windows lifetime verification failed/);
    } else {
      assert.deepEqual(this.observed.value, { verified: true, ownerExited: true, activeProcesses: 0 });
    }
    for (const record of this.records.slice(1)) {
      const result = JSON.parse(this.powershell('identity',
        ['-ProcessId', String(record.pid), '-CreationTicks', record.creationTicks]));
      assert.equal(result.gone, true, 'Job owner and warm child must exit on root loss');
    }
  }

  stop(record) {
    const result = JSON.parse(this.powershell('identity',
      ['-ProcessId', String(record.pid), '-CreationTicks', record.creationTicks, '-StopOwned']));
    this.cleanup.push({ ...record, ...result });
    assert.equal(result.gone, true);
  }

  async checkObserverParentLoss(identity) {
    const host = fork(fileURLToPath(new URL('./fixtures/windows-process-lifetime/observer-host.mjs', import.meta.url)),
      [], { execPath: process.execPath, execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true });
    host.stderr.on('data', (data) => { this.stderr += data; });
    const hostIdentity = this.capture(host.pid, process.pid);
    let observerPid;
    host.on('message', (message) => { observerPid = message.pid; });
    host.send(identity);
    await this.wait(() => observerPid);
    const observerIdentity = this.capture(observerPid, host.pid);
    this.stop(hostIdentity);
    await this.wait(() => host.exitCode != null || host.signalCode != null);
    const result = JSON.parse(this.powershell('identity', ['-ProcessId', String(observerIdentity.pid),
      '-CreationTicks', observerIdentity.creationTicks]));
    assert.equal(result.gone, true, 'Read-only observer must exit when its own parent dies');
    assert.equal(this.child.exitCode, null, 'Observer parent loss must not stop the bridge');
  }

  finish() {
    const errors = [];
    for (const record of this.records.toReversed()) {
      try { this.stop(record); } catch (error) { errors.push(error.message); }
    }
    writeFileSync(join(this.directory, 'stdout.txt'), this.stdout);
    writeFileSync(join(this.directory, 'stderr.txt'), this.stderr);
    writeFileSync(join(this.directory, 'receipt.json'), JSON.stringify({
      node: process.version, mode: this.mode, records: this.records, messages: this.messages,
      observation: this.observed, cleanup: this.cleanup, errors,
    }, null, 2));
    const nonce = join(this.directory, 'admin.nonce');
    if (existsSync(nonce)) unlinkSync(nonce);
    if (errors.length) throw new Error(errors.join('\n'));
  }
}

for (const mode of ['gated-success', 'missing', 'invalid', 'assignment-failure',
  'observer-owner-loss', 'observer-stale', 'observer-wrong-image', 'observer-parent-loss', 'observer-zero-exit']) {
  test(`Windows lifetime startup: ${mode}`,
    { skip: process.platform !== 'win32', timeout: 60000 }, async (t) => {
      await new StartupFixture(t, mode).run();
    });
}

test('lifetime helper bare or unrelated-parent invocation cannot assign the caller',
  { skip: process.platform !== 'win32' }, () => {
    const helper = fileURLToPath(new URL('../bin/windows-lifetime/ProcessLifetimeHelper.exe', import.meta.url));
    for (const args of [[], ['watch-parent', '0']]) {
      const result = spawnSync(helper, args, { encoding: 'utf8', timeout: 5000, windowsHide: true });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /ArgumentException/);
    }
  });
