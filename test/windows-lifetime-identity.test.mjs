import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

class IdentityFixture {
  constructor(t, kind, action) {
    this.directory = mkdtempSync(join(tmpdir(), 'mcp-native-id-'));
    this.kind = kind;
    this.action = action;
    this.messages = [];
    this.identities = [];
    this.output = '';
    t.diagnostic(`Owned packaged-identity evidence: ${this.directory}`);
    t.after(() => this.cleanup());
  }

  powershell(name, args) {
    const file = fileURLToPath(new URL(`./fixtures/windows-process-lifetime/${name}.ps1`, import.meta.url));
    const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', file, ...args],
      { encoding: 'utf8', timeout: 15000, windowsHide: true });
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    return result.stdout.trim();
  }

  capture(pid) {
    const value = JSON.parse(this.powershell('identity', ['-ProcessId', String(pid)]));
    if (!value.gone) this.identities.push(value);
    return value;
  }

  async wait(check) {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      const value = check();
      if (value) return value;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.fail(`Owned identity fixture timed out: ${this.output}`);
  }

  async run() {
    const bin = join(this.directory, 'windows-lifetime');
    mkdirSync(bin);
    const module = join(this.directory, 'windows-process-lifetime.mjs');
    copyFileSync(new URL('../bin/windows-process-lifetime.mjs', import.meta.url), module);
    const metadata = JSON.parse(readFileSync(new URL('../bin/windows-lifetime/ProcessLifetimeHelper.build.json', import.meta.url)));
    const binary = join(bin, 'ProcessLifetimeHelper.exe');
    if (this.kind === 'protocol') {
      const fake = this.powershell('build-failure', ['-OutputDirectory', this.directory, '-Variant', 'protocol']);
      copyFileSync(fake, binary);
    } else if (this.kind !== 'missing') {
      const bytes = readFileSync(new URL('../bin/windows-lifetime/ProcessLifetimeHelper.exe', import.meta.url));
      writeFileSync(binary, this.kind === 'altered' ? Buffer.concat([bytes, Buffer.from('changed')]) : bytes);
    }
    if (this.kind === 'stale') metadata.binarySha256 = '0'.repeat(64);
    writeFileSync(join(bin, 'ProcessLifetimeHelper.build.json'), JSON.stringify(metadata));
    this.child = fork(fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity-host.mjs', import.meta.url)),
      [module, this.action], { execPath: process.execPath, execArgv: [],
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true });
    this.child.on('message', (message) => this.messages.push(message));
    this.child.stdout.on('data', (chunk) => { this.output += chunk; });
    this.child.stderr.on('data', (chunk) => { this.output += chunk; });
    await this.wait(() => this.messages.some((message) => message.type === 'ready'));
    this.root = this.capture(this.child.pid);
    assert.equal(this.root.gone, false);
    this.child.send('start');
    const result = await this.wait(() => this.messages.find((message) => message.type === 'result'));
    // Record any deliberately wrong helper that the RED implementation accepted.
    for (const message of this.messages.filter((item) => item.type === 'child')) this.capture(message.pid);
    this.result = result;
    assert.equal(result.accepted, false, `Wrong packaged helper accepted: ${JSON.stringify(result)}`);
    assert.match(result.message, /packaged helper identity/i);
    assert.equal(this.messages.some((message) => message.type === 'child'), false,
      'Identity failure must occur before native spawn');
  }

  async cleanup() {
    const receipts = [];
    if (this.root) {
      receipts.push(JSON.parse(this.powershell('identity',
        ['-ProcessId', String(this.root.pid), '-CreationTicks', this.root.creationTicks, '-StopOwned'])));
      await this.wait(() => this.child.exitCode != null || this.child.signalCode != null);
    }
    for (const identity of this.identities) {
      const value = JSON.parse(this.powershell('identity',
        ['-ProcessId', String(identity.pid), '-CreationTicks', identity.creationTicks, '-StopOwned']));
      receipts.push(value);
      assert.equal(value.gone, true);
    }
    writeFileSync(join(this.directory, 'receipt.json'), JSON.stringify({
      node: process.version, kind: this.kind, action: this.action,
      result: this.result, messages: this.messages, identities: this.identities, cleanup: receipts,
    }, null, 2));
    writeFileSync(join(this.directory, 'output.txt'), this.output);
    if (process.env.MCP_LIFETIME_TEST_EVIDENCE) {
      const retained = join(process.env.MCP_LIFETIME_TEST_EVIDENCE, basename(this.directory));
      cpSync(this.directory, retained, { recursive: true });
      rmSync(this.directory, { recursive: true });
    }
  }
}

for (const kind of ['missing', 'altered', 'stale', 'protocol']) {
  for (const action of ['owner', 'observer']) {
    test(`packaged helper identity rejects ${kind} before ${action} spawn`,
      { skip: process.platform !== 'win32', timeout: 60000 }, async (t) => {
        await new IdentityFixture(t, kind, action).run();
      });
  }
}
