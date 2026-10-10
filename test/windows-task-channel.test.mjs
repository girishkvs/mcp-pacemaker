import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork, spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, copyFileSync, rmSync, writeFileSync, existsSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, basename, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TASK_CHANNEL_FILES, verifyTaskChannelAssets } from '../tools/windows-task-channel/inventory.mjs';
import './fixtures/windows-task-channel/auth-state-cases.mjs';

const modulePath = process.env.MCP_TASK_CHANNEL_TEST_MODULE ||
  fileURLToPath(new URL('../bin/windows-task-channel.mjs', import.meta.url));
const api = await import(pathToFileURL(modulePath).href);
const windows = { skip: process.platform !== 'win32', timeout: 60000 };
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');

class Fixture {
  constructor(t) {
    this.directory = mkdtempSync(join(tmpdir(), 'mcp-task-channel-owned-'));
    this.records = [];
    this.children = [];
    this.channels = [];
    this.messages = [];
    this.receipts = [];
    this.script = join(this.directory, 'owned worker ü.mjs');
    copyFileSync(new URL('./fixtures/windows-task-channel/worker.mjs', import.meta.url), this.script);
    t.after(() => this.cleanup());
    t.diagnostic(`Owned task-channel fixture ${this.directory}`);
    this.evidence('start', { directory: this.directory, node: process.version });
  }

  evidence(kind, value) {
    const parent = process.env.MCP_TASK_CHANNEL_TEST_EVIDENCE;
    if (parent) writeFileSync(join(parent, `${basename(this.directory)}-${kind}.json`),
      JSON.stringify(value, null, 2) + '\n');
  }

  record(identity) {
    if (!identity) return;
    this.records.push(identity);
    this.evidence('identities', this.records);
  }

  identity(pid, creationTime, stop = false) {
    const script = fileURLToPath(new URL('./fixtures/windows-process-lifetime/identity.ps1', import.meta.url));
    const args = ['-NoProfile', '-NonInteractive', '-File', script, '-ProcessId', String(pid)];
    if (creationTime) args.push('-CreationTicks', String(BigInt(creationTime) + 504911232000000000n));
    if (stop) args.push('-StopOwned');
    const result = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  }

  async create(extra = {}, channelApi = api) {
    const caller = await this.callerQuery(channelApi);
    this.record(caller.guardIdentity);
    this.caller = caller;
    const options = {
      operationId: randomUUID(), targetSid: caller.identity.ownerSid, sessionId: caller.identity.sessionId,
      bootstrap: { nodePath: process.execPath, nodeSha256: digest(process.execPath),
        scriptPath: this.script, scriptSha256: digest(this.script) },
      manifestParent: this.directory, manifest: { operationDigest: 'a'.repeat(64), publicKey: 'owned-public-only' },
      handshakeTimeoutMs: 15000, lifetimeMs: 45000, ...extra,
    };
    this.options = options;
    try {
      const channel = await channelApi.createTaskChannel(options);
      this.channels.push(channel);
      this.record(channel.guardIdentity);
      this.channel = channel;
      return channel;
    } catch (error) {
      this.record(error.guardIdentity);
      throw error;
    }
  }

  async callerQuery(channelApi = api) {
    try {
      const result = await channelApi.queryTaskChannelCaller();
      this.record(result.guardIdentity);
      return result;
    } catch (error) {
      this.record(error.guardIdentity);
      throw error;
    }
  }

  blockedQuery(disableMonitor = false) {
    const pack = join(this.directory, 'blocked-package');
    const script = fileURLToPath(new URL('./fixtures/windows-task-channel/build-blocked-query.ps1', import.meta.url));
    const args = ['-NoProfile', '-NonInteractive', '-File', script,
      '-SourceRoot', dirname(dirname(modulePath)), '-Destination', pack];
    if (disableMonitor) args.push('-DisableMonitor');
    const built = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 120000 });
    this.evidence('blocked-build', { code: built.status, stdout: built.stdout, stderr: built.stderr });
    assert.equal(built.status, 0, built.stderr);
    const target = join(this.directory, 'scan-target');
    mkdirSync(target);
    return { pack, target, helper: join(pack, 'bin/windows-task-channel/TaskChannelGuard.exe'),
      module: join(pack, 'bin/windows-task-channel.mjs') };
  }

  async entered(target) {
    const marker = join(target, 'owned-query-entered.json');
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline) {
      if (existsSync(marker)) {
        const identity = JSON.parse(readFileSync(marker, 'utf8'));
        this.record(identity);
        return identity;
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error('Owned blocked query did not reach its deterministic marker');
  }

  async worker({ protectedRead = false, extra = [], channelModule = modulePath } = {}) {
    const args = ['--manifest', this.channel.manifestPath, '--operation', this.options.operationId,
      '--controller-root', this.directory, ...extra];
    const child = fork(this.script, args, {
      execPath: process.execPath, execArgv: [], windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      env: { ...process.env, OWNED_CHANNEL_MODULE: channelModule, OWNED_CHANNEL_PROTECTED_READ: protectedRead ? '1' : '0' },
    });
    this.children.push(child);
    child.on('message', message => {
      this.messages.push(message);
      this.record(message.caller?.guardIdentity ?? message.result?.guardIdentity ?? message.guardIdentity);
    });
    child.stdout.resume();
    child.stderr.on('data', data => { this.stderr = (this.stderr ?? '') + data; });
    this.record({ pid: child.pid, creationTime: this.identity(child.pid).creationFileTime });
    return child;
  }

  async raw(request) {
    const helper = join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.exe');
    const child = spawn(helper, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.children.push(child);
    this.record({ pid: child.pid, creationTime: this.identity(child.pid).creationFileTime });
    let output = '', stderr = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', text => { output += text; });
    child.stderr.on('data', text => { stderr += text; });
    const exit = new Promise(resolve => child.once('close', code => resolve(code)));
    child.stdin.write(JSON.stringify(request) + '\n');
    const code = await exit;
    const frames = output.trim().split('\n').map(line => JSON.parse(line));
    for (const frame of frames) this.record(frame.guardIdentity);
    return { code, frames: frames.filter(frame => frame.type !== 'started'), stderr };
  }

  async message(type) {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      const index = this.messages.findIndex(message => (Array.isArray(type) ? type : [type]).includes(message.type));
      if (index >= 0) return this.messages.splice(index, 1)[0];
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    throw new Error(`Owned message missing: ${type}; ${this.stderr ?? ''}; ${JSON.stringify(this.messages)}`);
  }

  async cleanup() {
    const errors = [];
    for (const channel of this.channels) {
      try { this.receipts.push(await channel.close()); } catch (error) { errors.push(error.message); }
    }
    for (const child of this.children) {
      if (child.connected) child.send({ action: 'exit' });
    }
    await new Promise(resolve => setTimeout(resolve, 200));
    const seen = new Set();
    const cleanup = [];
    for (const identity of this.records) {
      const key = `${identity.pid}:${identity.creationTime}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try {
        const state = this.identity(identity.pid, identity.creationTime);
        const final = state.gone ? state : this.identity(identity.pid, identity.creationTime, true);
        assert.equal(final.gone, true);
        cleanup.push({ identity, final });
      } catch (error) { errors.push(`${key}: ${error.message}`); }
    }
    this.evidence('cleanup', { cleanup, errors, exits: this.receipts });
    if (!errors.length) rmSync(this.directory, { recursive: true, force: true });
    this.evidence('removed', { removed: !existsSync(this.directory) });
    assert.deepEqual(errors, []);
  }
}

test('task channel observes its actual caller token and held parent identity', windows, async t => {
  const fixture = new Fixture(t);
  const result = await fixture.callerQuery();
  fixture.record(result.guardIdentity);
  assert.equal(result.identity.pid, process.pid);
  assert.equal(result.identity.creationTime, fixture.identity(process.pid).creationFileTime);
  assert.equal(result.actorFacts.ownerSid, result.identity.ownerSid);
  assert.equal(result.actorFacts.parentThreadImpersonation, 'observed-none');
  assert.equal(result.actorFacts.parentThreadQueryError, null);
  assert.equal(result.actorFacts.guardThreadImpersonating, false);
  for (const field of ['elevated', 'enabledAdministrator', 'restricted', 'appContainer']) {
    assert.equal(typeof result.actorFacts[field], 'boolean');
  }
  assert.equal(result.helperExit.code, 0);
});

test('task channel binds direct Node peer and preserves identity across bidirectional frames', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create();
  assert.equal(channel.targetSession.ownerSid, fixture.caller.identity.ownerSid);
  assert.equal(channel.targetSession.sessionId, fixture.caller.identity.sessionId);
  assert.ok(['active', 'disconnected'].includes(channel.targetSession.state));
  assert.equal(channel.targetSession.atomicRunExBinding, false);
  assert.throws(() => writeFileSync(channel.manifestPath, 'owned attempted mutation'),
    error => ['EBUSY', 'EACCES', 'EPERM'].includes(error.code));
  assert.equal((await channel.authorize()).controllerIdentity.pid, process.pid);
  const worker = await fixture.worker({ protectedRead: true });
  const peer = await channel.awaitWorker();
  assert.equal(channel.workerSession.logonTime, channel.targetSession.logonTime);
  assert.equal(channel.workerSession.ownerSid, peer.ownerSid);
  assert.equal(peer.pid, worker.pid);
  assert.equal(peer.ownerSid, fixture.caller.identity.ownerSid);
  assert.equal(peer.creationTime, fixture.records.find(record => record.pid === worker.pid).creationTime);
  const read = await fixture.message('manifest');
  assert.equal(read.result.targetSession.logonTime, channel.targetSession.logonTime);
  assert.equal(read.result.readerIdentity.pid, worker.pid);
  assert.equal(read.result.document.document.operationDigest, 'a'.repeat(64));
  assert.equal(read.result.protection.loadedCodeAttestation, false);
  const hello = await channel.receive();
  assert.equal(hello.frame.claimedPid, 1);
  assert.equal(hello.peer.pid, worker.pid);
  await channel.send({ kind: 'reply', text: 'unicode ü 🦊' });
  assert.equal((await fixture.message('received')).frame.text, 'unicode ü 🦊');
  const authorization = await channel.authorize();
  assert.equal(authorization.targetSession.logonTime, channel.targetSession.logonTime);
  assert.notEqual(authorization.targetSession.observedAt, channel.targetSession.observedAt);
  assert.equal(authorization.controllerIdentity.pid, process.pid);
  assert.equal(authorization.actorFacts.parentThreadImpersonation, 'observed-none');
  const receipt = await channel.close();
  assert.equal(receipt.code, 0);
  assert.equal(fixture.identity(worker.pid, peer.creationTime).gone, false, 'Read-only close must not stop worker');
});

test('task channel refuses another SID without actual elevated token despite supplied admin flags', windows, async t => {
  const fixture = new Fixture(t);
  const caller = await fixture.callerQuery();
  fixture.record(caller.guardIdentity);
  assert.equal(caller.actorFacts.elevated, false, 'Owned suite requires its deliberately unelevated runner');
  await assert.rejects(fixture.create({ targetSid: 'S-1-5-21-1-2-3-500', admin: true, elevated: true }),
    error => error.code === 'ACTUAL_ADMIN_TOKEN_REQUIRED');
  assert.equal(existsSync(join(fixture.directory, fixture.options.operationId)), false);
});

for (const [label, options, pattern] of [
  ['generation', { expectedCreationTime: '1' }, /PEER_IDENTITY_MISMATCH/],
]) {
  test(`task channel refuses wrong peer ${label} without stopping the worker`, windows, async t => {
    const fixture = new Fixture(t);
    const channel = await fixture.create(options);
    const worker = await fixture.worker();
    await assert.rejects(channel.awaitWorker(), pattern);
    assert.equal((await channel.closed).code, 3);
    const identity = fixture.records.find(record => record.pid === worker.pid);
    assert.equal(fixture.identity(worker.pid, identity.creationTime).gone, false);
  });
}

test('task channel refuses an unavailable bound session before creating bootstrap resources', windows, async t => {
  const fixture = new Fixture(t);
  await assert.rejects(fixture.create({ sessionId: 999999 }), /SESSION_QUERY_FAILED/);
  assert.equal(existsSync(join(fixture.directory, fixture.options.operationId)), false);
});

test('task channel refuses extra worker argv without stopping the worker', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create();
  const worker = await fixture.worker({ extra: ['--spoof'] });
  await assert.rejects(channel.awaitWorker(), /PEER_ARGV_MISMATCH/);
  assert.equal((await channel.closed).code, 3);
  assert.equal(fixture.identity(worker.pid).gone, false);
});

test('task channel rejects changed bootstrap bytes before creating operation resources', windows, async t => {
  const fixture = new Fixture(t);
  await assert.rejects(fixture.create({ bootstrap: { nodePath: process.execPath, nodeSha256: digest(process.execPath),
    scriptPath: fixture.script, scriptSha256: '0'.repeat(64) } }), /BOOTSTRAP_HASH_MISMATCH/);
  assert.equal(existsSync(join(fixture.directory, fixture.options.operationId)), false);
});

test('task channel accepts only its first connection and cannot reconnect after close', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create();
  const worker = await fixture.worker();
  await channel.awaitWorker();
  await channel.receive();
  worker.send({ action: 'reconnect' });
  const blocked = await fixture.message(['second-pending-not-connected', 'second-error']);
  if (blocked.type === 'second-error') assert.ok(['EBUSY', 'EACCES'].includes(blocked.code));
  assert.equal(fixture.messages.some(message => message.type === 'second-connected'), false);
  await channel.send({ still: 'first-peer' });
  assert.equal((await fixture.message('received')).frame.still, 'first-peer');
  await channel.close();
  worker.send({ action: 'reconnect' });
  assert.equal((await fixture.message('second-error')).code, 'ENOENT');
  await assert.rejects(channel.send({ stale: true }), /closed/);
});

for (const action of ['disconnect', 'exit']) {
  test(`task channel invalidates held connection on worker ${action}`, windows, async t => {
    const fixture = new Fixture(t);
    const channel = await fixture.create();
    const worker = await fixture.worker();
    await channel.awaitWorker();
    await channel.receive();
    worker.send({ action });
    const receipt = await channel.closed;
    assert.equal(receipt.code, 3);
    await assert.rejects(channel.receive(), /CHANNEL_DISCONNECTED|PEER_EXITED/);
    if (action === 'disconnect') assert.equal(fixture.identity(worker.pid).gone, false);
  });
}

for (const [name, bytes, pattern] of [
  ['nonobject', Buffer.from('[]\n'), /OBJECT_FRAME_REQUIRED/],
  ['invalid json', Buffer.from('bad\n'), /QUERY_OR_PROTOCOL_REFUSED/],
  ['invalid UTF8', Buffer.from([255, 10]), /QUERY_OR_PROTOCOL_REFUSED/],
  ['oversize', Buffer.from('x'.repeat(16385)), /FRAME_BOUNDS_OR_FRAMING/],
  ['CR framing', Buffer.from('{}\r\n'), /FRAME_BOUNDS_OR_FRAMING/],
  ['incomplete frame timeout', Buffer.from('{'), /FRAME_TIMEOUT/],
]) {
  test(`task channel refuses ${name} without terminating its peer`, windows, async t => {
    const fixture = new Fixture(t);
    const channel = await fixture.create();
    const worker = await fixture.worker();
    await channel.awaitWorker();
    await channel.receive();
    worker.send({ action: 'raw', base64: bytes.toString('base64') });
    await assert.rejects(channel.receive(), pattern);
    assert.equal((await channel.closed).code, 3);
    assert.equal(fixture.identity(worker.pid).gone, false);
  });
}

test('task channel processes fragmented UTF8 and multiple complete frames on the same peer', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create();
  const worker = await fixture.worker();
  await channel.awaitWorker();
  await channel.receive();
  const bytes = Buffer.from('{"value":"🦊"}\n{"value":"second"}\n');
  const offset = bytes.indexOf(Buffer.from('🦊')) + 1;
  worker.send({ action: 'raw', base64: bytes.subarray(0, offset).toString('base64') });
  await new Promise(resolve => setTimeout(resolve, 50));
  worker.send({ action: 'raw', base64: bytes.subarray(offset).toString('base64') });
  assert.equal((await channel.receive()).frame.value, '🦊');
  assert.equal((await channel.receive()).frame.value, 'second');
  await assert.rejects(async () => channel.send({ value: 'x'.repeat(16384) }), /bounds/);
});

test('task channel handshake deadline releases its resources without adopting a peer', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create({ handshakeTimeoutMs: 2000 });
  await assert.rejects(channel.awaitWorker(), /HANDSHAKE_TIMEOUT/);
  assert.equal((await channel.closed).code, 3);
});

test('task channel rejects unsupported role and never uses claimed parent or admin identity', windows, async t => {
  const fixture = new Fixture(t);
  const caller = await fixture.raw({ action: 'caller', pid: 1, admin: true, elevated: true });
  assert.equal(caller.code, 0);
  assert.equal(caller.frames[0].identity.pid, process.pid);
  assert.equal(caller.frames[0].actorFacts.elevated, false);
  const invalid = await fixture.raw({ action: 'kill', pid: 1 });
  assert.equal(invalid.code, 3);
  assert.equal(invalid.frames[0].reason, 'UNKNOWN_ROLE');
});

test('task channel admin policy requires all actual token and parent-thread facts', windows, t => {
  const fixture = new Fixture(t);
  const script = fileURLToPath(new URL('./fixtures/windows-task-channel/policy-model.ps1', import.meta.url));
  const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-Helper', join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.exe')],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  const model = JSON.parse(result.stdout);
  assert.equal(model.qualification, 'pure-policy-model-not-OS-authorization');
  for (const entry of model.results) assert.equal(entry.accepted, entry.case === 'valid');
  for (const entry of model.peerResults) assert.equal(entry.accepted, entry.case === 'valid');
  fixture.evidence('policy-model', model);
});

test('task channel session policy refuses unavailable owner state and logon-generation ambiguity', windows, t => {
  const fixture = new Fixture(t);
  const script = fileURLToPath(new URL('./fixtures/windows-task-channel/session-model.ps1', import.meta.url));
  const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-Helper', join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.exe')],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  const model = JSON.parse(result.stdout);
  assert.equal(model.qualification, 'pure-session-policy-model-no-session-mutations');
  for (const entry of model.results) assert.equal(entry.accepted, ['active', 'disconnected'].includes(entry.case), entry.case);
  fixture.evidence('session-model', model);
});

test('task channel trusted-root inspection refuses a reparse path and does not import files', windows, async t => {
  const fixture = new Fixture(t);
  writeFileSync(join(fixture.directory, 'must-not-run.mjs'), 'throw new Error("NOT IMPORTED");\n');
  const valid = await api.inspectTrustedCodeRoot(fixture.directory);
  fixture.record(valid.guardIdentity);
  assert.equal(valid.proof.loadedCodeAttestation, false);
  assert.equal(valid.actorFacts.parentThreadImpersonation, 'unverified');
  assert.equal(valid.actorFacts.parentThreadQueryError, 'NOT_OBSERVED_READ_ONLY_ROLE');
  const target = join(fixture.directory, 'target');
  mkdirSync(target);
  symlinkSync(target, join(fixture.directory, 'link'), 'junction');
  await assert.rejects(api.inspectTrustedCodeRoot(fixture.directory).catch(error => {
    fixture.record(error.guardIdentity);
    throw error;
  }), /REPARSE_PATH_REFUSED/);
});

test('task channel parent exit releases native proof without stopping the direct worker', windows, async t => {
  const fixture = new Fixture(t);
  const initial = await fixture.create();
  await initial.close();
  const options = { ...fixture.options, operationId: randomUUID() };
  const host = fork(new URL('./fixtures/windows-task-channel/controller-host.mjs', import.meta.url), [], {
    execPath: process.execPath, execArgv: [], windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: { ...process.env, OWNED_CHANNEL_MODULE: modulePath },
  });
  fixture.children.push(host);
  fixture.record({ pid: host.pid, creationTime: fixture.identity(host.pid).creationFileTime });
  host.stdout.resume();
  host.stderr.resume();
  host.on('message', message => {
    fixture.messages.push(message);
    fixture.record(message.channel?.guardIdentity ?? message.guardIdentity);
  });
  host.send(options);
  const ready = await fixture.message('host-ready');
  fixture.options = options;
  fixture.channel = ready.channel;
  const worker = await fixture.worker();
  const observed = await fixture.message('host-peer');
  assert.equal(observed.peer.pid, worker.pid);
  const exit = new Promise(resolve => host.once('close', resolve));
  host.send({ action: 'exit' });
  await exit;
  await new Promise(resolve => setTimeout(resolve, 300));
  const guard = ready.channel.guardIdentity;
  assert.equal(fixture.identity(guard.pid, guard.creationTime).gone, true);
  assert.equal(fixture.identity(worker.pid, observed.peer.creationTime).gone, false);
});

test('task channel manifest reader rejects wrong operation and a caller that is not its bootstrap', windows, async t => {
  const fixture = new Fixture(t);
  const channel = await fixture.create();
  for (const [operationId, expected] of [
    [randomUUID(), /MANIFEST_PATH_MISMATCH/], [fixture.options.operationId, /PEER_ARGV_MISMATCH/],
  ]) {
    await assert.rejects(api.readProtectedManifest(channel.manifestPath, {
      operationId, manifestParent: fixture.directory,
    }).catch(error => { fixture.record(error.guardIdentity); throw error; }), expected);
  }
});

test('task channel refuses a newly created untrusted-writer code file without repairing its ACL', windows, async t => {
  const fixture = new Fixture(t);
  const script = fileURLToPath(new URL('./fixtures/windows-task-channel/untrusted-file.ps1', import.meta.url));
  const path = join(fixture.directory, 'owned-insecure-file.txt');
  const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script, '-Path', path],
    { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).existingAclModified, false);
  await assert.rejects(api.inspectTrustedCodeRoot(fixture.directory).catch(error => {
    fixture.record(error.guardIdentity);
    throw error;
  }), /UNTRUSTED_PATH_WRITER/);
  assert.equal(readFileSync(path, 'utf8'), ' ');
});

test('task channel inventories exact packaged native bytes and rejects source metadata or binary drift', windows, t => {
  const fixture = new Fixture(t);
  const root = dirname(dirname(modulePath));
  assert.equal(verifyTaskChannelAssets(root).status, 'source-and-binary-hashes-verified');
  const copy = join(fixture.directory, 'package');
  for (const relative of TASK_CHANNEL_FILES) {
    mkdirSync(dirname(join(copy, relative)), { recursive: true });
    copyFileSync(join(root, relative), join(copy, relative));
  }
  for (const relative of ['bin/windows-task-channel/TaskChannelGuard.exe',
    'bin/windows-task-channel/src/ChannelNative.cs', 'bin/windows-task-channel/TaskChannelGuard.build.json']) {
    const file = join(copy, relative);
    const original = readFileSync(file);
    writeFileSync(file, Buffer.concat([original, Buffer.from('changed')]));
    assert.throws(() => verifyTaskChannelAssets(copy));
    writeFileSync(file, original);
  }
});

test('task channel checks helper hashes before every native role and refuses missing helpers', windows, async t => {
  const fixture = new Fixture(t);
  const copy = join(fixture.directory, 'module');
  mkdirSync(join(copy, 'windows-task-channel'), { recursive: true });
  copyFileSync(modulePath, join(copy, 'windows-task-channel.mjs'));
  copyFileSync(join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.build.json'),
    join(copy, 'windows-task-channel/TaskChannelGuard.build.json'));
  const helper = join(copy, 'windows-task-channel/TaskChannelGuard.exe');
  const copied = await import(pathToFileURL(join(copy, 'windows-task-channel.mjs')).href);
  const roles = [
    () => copied.queryCliCallerContext(),
    () => copied.queryTaskChannelCaller(),
    () => copied.inspectTrustedCodeRoot(fixture.directory),
    () => copied.readProtectedManifest('not-opened', { operationId: randomUUID(), manifestParent: fixture.directory }),
    () => copied.createTaskChannel({}),
  ];
  for (const role of roles) await assert.rejects(role, /ENOENT/);
  writeFileSync(helper, 'owned-nonexecutable-wrong-hash');
  for (const role of roles) await assert.rejects(role, /helper identity mismatch/);
});

test('task channel stdin cancellation ends a blocked query with its early owned identity', windows, async t => {
  const fixture = new Fixture(t);
  const variant = fixture.blockedQuery();
  const child = spawn(variant.helper, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  fixture.children.push(child);
  let output = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', text => { output += text; });
  child.stderr.resume();
  const exited = new Promise(resolve => child.once('close', code => resolve(code)));
  child.stdin.write(JSON.stringify({ action: 'inspect-root', root: variant.target }) + '\n');
  const identity = await fixture.entered(variant.target);
  const first = JSON.parse(output.split('\n')[0]);
  assert.equal(first.type, 'started');
  assert.equal(first.guardIdentity.pid, identity.pid);
  assert.equal(first.guardIdentity.creationTime, identity.creationTime);
  child.stdin.end();
  const code = await exited;
  assert.notEqual(code, 0);
  assert.equal(fixture.identity(identity.pid, identity.creationTime).gone, true);
});

test('task channel parent loss ends a blocked query without waiting for its root walk', windows, async t => {
  const fixture = new Fixture(t);
  const variant = fixture.blockedQuery();
  const host = fork(new URL('./fixtures/windows-task-channel/query-host.mjs', import.meta.url), [], {
    execPath: process.execPath, execArgv: [], windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: { ...process.env, OWNED_QUERY_MODULE: variant.module, OWNED_QUERY_ROOT: variant.target },
  });
  fixture.children.push(host);
  fixture.record({ pid: host.pid, creationTime: fixture.identity(host.pid).creationFileTime });
  host.stdout.resume();
  host.stderr.resume();
  const identity = await fixture.entered(variant.target);
  const exited = new Promise(resolve => host.once('close', resolve));
  host.send({ action: 'exit' });
  await exited;
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal(fixture.identity(identity.pid, identity.creationTime).gone, true);
});

test('task channel blocked query deadline reports verified native exit without a surviving helper', windows, async t => {
  const fixture = new Fixture(t);
  const variant = fixture.blockedQuery();
  const api = await import(pathToFileURL(variant.module).href);
  const outcome = api.inspectTrustedCodeRoot(variant.target).then(() => null, error => error);
  const identity = await fixture.entered(variant.target);
  const error = await outcome;
  assert.ok(error);
  assert.equal(error.guardIdentity.creationTime, identity.creationTime);
  assert.equal(error.cleanupUnverified, false);
  assert.notEqual(error.helperExit.code, 0);
  assert.equal(fixture.identity(identity.pid, identity.creationTime).gone, true);
});

test('task channel preserves exit-unverified evidence when a test-only native watchdog is blocked', windows, async t => {
  const fixture = new Fixture(t);
  const variant = fixture.blockedQuery(true);
  const api = await import(pathToFileURL(variant.module).href);
  const outcome = api.inspectTrustedCodeRoot(variant.target).then(() => null, error => error);
  const identity = await fixture.entered(variant.target);
  const error = await outcome;
  assert.ok(error);
  assert.equal(error.cleanupUnverified, true);
  assert.match(error.cleanupError, /exit unverified/);
  assert.equal(error.guardIdentity.creationTime, identity.creationTime);
  assert.equal(fixture.identity(identity.pid, identity.creationTime).gone, false);
  fixture.evidence('expected-exit-unverified', { message: error.message, guardIdentity: error.guardIdentity,
    cleanupUnverified: error.cleanupUnverified, cleanupError: error.cleanupError });
});

test('task channel ordinary context proves the actual owned caller through complete held PSS threads', windows, async t => {
  const fixture = new Fixture(t);
  const started = performance.now();
  const result = await api.queryCliCallerContext().catch(error => { fixture.record(error.guardIdentity); throw error; });
  const elapsedMs = performance.now() - started;
  fixture.record(result.guardIdentity);
  assert.equal(result.identity.pid, process.pid);
  assert.equal(result.identity.creationTime, fixture.identity(process.pid).creationFileTime);
  assert.equal(result.identity.ownerSid, result.actorFacts.ownerSid);
  assert.equal(result.identity.sessionId, result.actorFacts.sessionId);
  assert.equal(result.proofScope, 'cli-effective-context-snapshot');
  assert.equal(result.ordinaryEligible, true, result.reason);
  assert.equal(result.actorFacts.elevated, false);
  assert.equal(result.actorFacts.enabledAdministrator, false);
  assert.equal(result.actorFacts.guardThreadImpersonating, false);
  assert.equal(result.actorFacts.parentThreadImpersonation, 'observed-none');
  assert.equal(result.observation.processAccess, '0x101400');
  assert.equal(result.observation.captureFlags, '0x80');
  assert.equal(result.observation.threadContextFlags, 0);
  assert.equal(result.observation.completeStableThreadSet, true);
  assert.equal(result.observation.primaryStable, true);
  assert.equal(result.observation.atomicFutureProtection, false);
  assert.ok(result.observation.threadCount > 0);
  assert.equal(result.helperExit.code, 0);
  assert.equal(result.helperExit.signal, null);
  fixture.evidence('ordinary-context', { elapsedMs, result, timingScope: 'native role roundtrip, not CLI end-to-end' });
});

test('task channel ordinary eligibility refuses incomplete ambiguous or privileged policy facts', windows, t => {
  const fixture = new Fixture(t);
  const script = fileURLToPath(new URL('./fixtures/windows-task-channel/context-policy.ps1', import.meta.url));
  const result = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-Helper', join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.exe')],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  const model = JSON.parse(result.stdout);
  for (const entry of model.results) assert.equal(entry.eligible, entry.case === 'complete', entry.case);
  fixture.evidence('context-policy', model);
});

for (const [variant, reason] of [
  ['denied', 'THREAD_SNAPSHOT_FAILED_5'], ['token', 'THREAD_TOKEN_OBSERVED'],
  ['churn', 'THREAD_SET_CHANGED'], ['layout', 'THREAD_SNAPSHOT_LAYOUT_UNSUPPORTED'],
  ['binding', 'CLI_PARENT_LAYOUT_OR_BINDING_UNVERIFIED'],
]) {
  test(`task channel ordinary context refuses owned ${variant} fault without relaxing authority`, windows, async t => {
    const fixture = new Fixture(t);
    const pack = join(fixture.directory, 'context-variant');
    const script = fileURLToPath(new URL('./fixtures/windows-task-channel/build-context-variant.ps1', import.meta.url));
    const built = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
      '-SourceRoot', dirname(dirname(modulePath)), '-Destination', pack, '-Variant', variant],
    { encoding: 'utf8', windowsHide: true, timeout: 120000 });
    fixture.evidence('context-variant-build', { variant, code: built.status, stdout: built.stdout, stderr: built.stderr });
    assert.equal(built.status, 0, built.stderr);
    const variantApi = await import(pathToFileURL(join(pack, 'bin/windows-task-channel.mjs')).href);
    if (variant === 'binding') {
      await assert.rejects(variantApi.queryCliCallerContext().catch(error => {
        fixture.record(error.guardIdentity);
        assert.equal(error.cleanupUnverified, false);
        throw error;
      }), new RegExp(reason));
    } else {
      const result = await variantApi.queryCliCallerContext();
      fixture.record(result.guardIdentity);
      assert.equal(result.ordinaryEligible, false);
      assert.equal(result.reason, reason);
      assert.equal(result.helperExit.code, 0);
      assert.notEqual(result.actorFacts?.parentThreadImpersonation, 'observed-none');
      fixture.evidence('context-variant-result', result);
    }
  });
}

for (const [variant, reason] of [
  ['query-denied', 'CLI_PARENT_QUERY_ACCESS_DENIED'], ['denied', 'THREAD_SNAPSHOT_FAILED_5'],
  ['token', 'PARENT_THREAD_IMPERSONATING'], ['churn', 'THREAD_SET_CHANGED'],
  ['reuse', 'HELD_THREAD_CHANGED_OR_EXITED'], ['layout', 'THREAD_SNAPSHOT_LAYOUT_UNSUPPORTED'],
  ['no-info', 'THREAD_SNAPSHOT_FAILED_5'], ['walk', 'THREAD_SNAPSHOT_FAILED_5'],
  ['marker-free', 'THREAD_SNAPSHOT_FAILED_5'], ['snapshot-free', 'THREAD_SNAPSHOT_FAILED_5'],
  ['duplicate', 'THREAD_SNAPSHOT_INCOMPLETE'], ['empty', 'THREAD_SNAPSHOT_BOUNDS'],
  ['count', 'THREAD_SNAPSHOT_COUNT_CHANGED'],
  ['owner', 'THREAD_IDENTITY_CHANGED'], ['birth', 'HELD_THREAD_CHANGED_OR_EXITED'],
  ['exit-zero', 'THREAD_SNAPSHOT_METADATA_INVALID'], ['exit-future', 'THREAD_SNAPSHOT_METADATA_INVALID'],
  ['missing-flag', 'THREAD_SNAPSHOT_METADATA_INVALID'], ['unknown-flags', 'THREAD_SNAPSHOT_METADATA_INVALID'],
  ['changed-exit', 'HELD_THREAD_CHANGED_OR_EXITED'], ['classification', 'HELD_THREAD_CHANGED_OR_EXITED'],
  ['thread-denied', 'QUERY_OR_PROTOCOL_REFUSED'], ['no-live', 'LIVE_THREAD_SET_EMPTY'],
]) {
  test(`task channel full facts refuses owned ${variant} fault without fallback`, windows, async t => {
    const fixture = new Fixture(t);
    const pack = join(fixture.directory, 'facts-variant');
    const script = fileURLToPath(new URL('./fixtures/windows-task-channel/build-context-variant.ps1', import.meta.url));
    const built = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
      '-SourceRoot', dirname(dirname(modulePath)), '-Destination', pack, '-Variant', variant, '-Scope', 'facts'],
    { encoding: 'utf8', windowsHide: true, timeout: 120000 });
    fixture.evidence('facts-variant-build', {
      qualification: 'private-fault-injection-not-real-token-or-permission-change',
      variant, code: built.status, stdout: built.stdout, stderr: built.stderr,
    });
    assert.equal(built.status, 0, built.stderr);
    const variantApi = await import(pathToFileURL(join(pack, 'bin/windows-task-channel.mjs')).href);
    await assert.rejects(fixture.callerQuery(variantApi), error => {
      assert.equal(error.code, reason);
      assert.equal(error.cleanupUnverified, false);
      assert.equal(error.helperExit.code, 3);
      fixture.evidence('facts-variant-refusal', {
        reason: error.code, guardIdentity: error.guardIdentity, exit: error.helperExit,
      });
      return true;
    });
  });
}

test('task channel full facts repeats PSS per authorization and keeps peer and reader limited', windows, async t => {
  const fixture = new Fixture(t);
  const pack = join(fixture.directory, 'access-variant');
  const ledger = join(fixture.directory, 'access');
  const script = fileURLToPath(new URL('./fixtures/windows-task-channel/build-context-variant.ps1', import.meta.url));
  const built = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
    '-SourceRoot', dirname(dirname(modulePath)), '-Destination', pack, '-Variant', 'access-ledger', '-LedgerPath', ledger],
  { encoding: 'utf8', windowsHide: true, timeout: 120000 });
  assert.equal(built.status, 0, built.stderr);
  const channelModule = join(pack, 'bin/windows-task-channel.mjs');
  const variantApi = await import(pathToFileURL(channelModule).href);
  const channel = await fixture.create({}, variantApi);
  const observations = [];
  for (let index = 0; index < 2; index++) observations.push(await channel.authorize());
  const worker = await fixture.worker({ protectedRead: true, channelModule });
  const peer = await channel.awaitWorker();
  const reader = (await fixture.message('manifest')).result;
  for (let index = 0; index < 2; index++) observations.push(await channel.authorize());
  const inspected = await variantApi.inspectTrustedCodeRoot(fixture.directory);
  fixture.record(inspected.guardIdentity);
  const ordinary = await variantApi.queryCliCallerContext();
  fixture.record(ordinary.guardIdentity);
  assert.equal(ordinary.ordinaryEligible, true);
  for (const observation of observations) {
    assert.equal(observation.actorFacts.parentThreadImpersonation, 'observed-none');
    assert.equal(observation.targetSession.logonTime, channel.targetSession.logonTime);
  }
  const entries = identity => readFileSync(`${ledger}.${identity.pid}`, 'utf8').trim().split('\n')
    .map(line => { const [kind, pid, mask] = line.split('|'); return { kind, pid: Number(pid), mask }; });
  const serve = entries(channel.guardIdentity);
  const caller = entries(fixture.caller.guardIdentity);
  const read = entries(reader.guardIdentity);
  const inspect = entries(inspected.guardIdentity);
  const cli = entries(ordinary.guardIdentity);
  assert.equal(caller.filter(entry => entry.kind === 'snapshot').length, 2);
  assert.equal(serve.filter(entry => entry.kind === 'snapshot').length, 10);
  assert.deepEqual(serve.filter(entry => entry.kind === 'capture'), [{ kind: 'capture', pid: process.pid, mask: '0x101400' }]);
  assert.ok(serve.some(entry => entry.kind === 'limited' && entry.pid === worker.pid && entry.mask === '0x101000'));
  assert.deepEqual(read.filter(entry => entry.pid === worker.pid), [{ kind: 'limited', pid: worker.pid, mask: '0x101000' }]);
  assert.ok(read.every(entry => entry.kind === 'limited'));
  assert.ok(inspect.every(entry => entry.kind === 'limited'));
  assert.equal(cli.filter(entry => entry.kind === 'snapshot').length, 2);
  assert.equal(peer.pid, worker.pid);
  fixture.evidence('access-ledger', {
    qualification: 'actual-query-calls-in-private-ledger-variant-no-OS-rights-mutation',
    caller, serve, read, inspect, cli, observations,
  });
});

for (const role of ['caller', 'cli-context']) {
    for (const mode of ['ended', 'live']) {
      test(`task channel ${role} ${mode === 'ended' ? 'accepts proven already-ended held thread' : 'refuses live thread ending after first snapshot'}`, windows, async t => {
        const fixture = new Fixture(t);
        const host = join(fixture.directory, 'ThreadLifecycleHost.exe');
        const buildHost = fileURLToPath(new URL('./fixtures/windows-task-channel/build-thread-lifecycle.ps1', import.meta.url));
        const built = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', buildHost, '-Destination', host],
          { encoding: 'utf8', windowsHide: true, timeout: 120000 });
        assert.equal(built.status, 0, built.stderr);
        let helper = join(dirname(modulePath), 'windows-task-channel/TaskChannelGuard.exe');
        const barrier = join(fixture.directory, 'lifecycle');
        if (mode === 'live') {
          const pack = join(fixture.directory, 'lifecycle-variant');
          const script = fileURLToPath(new URL('./fixtures/windows-task-channel/build-context-variant.ps1', import.meta.url));
          const variant = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-File', script,
            '-SourceRoot', dirname(dirname(modulePath)), '-Destination', pack,
            '-Variant', 'end-after-snapshot', '-LedgerPath', barrier],
          { encoding: 'utf8', windowsHide: true, timeout: 120000 });
          assert.equal(variant.status, 0, variant.stderr);
          helper = join(pack, 'bin/windows-task-channel/TaskChannelGuard.exe');
        }
        const run = spawnSync(host, [helper, role, mode, barrier],
          { encoding: 'utf8', windowsHide: true, timeout: 45000 });
        assert.equal(run.status, 0, run.stderr);
        const receipt = JSON.parse(run.stdout);
        fixture.record(receipt.host);
        const frames = receipt.output.trim().split('\n').map(line => JSON.parse(line));
        for (const frame of frames) fixture.record(frame.guardIdentity);
        fixture.evidence('thread-lifecycle', { ...receipt, frames });
        assert.equal(receipt.heldThroughGuardExit, true);
        assert.equal(receipt.beforeWait, mode === 'ended' ? 0 : 258);
        assert.equal(BigInt(receipt.exit) > 0n, mode === 'ended');
        assert.equal(frames.some(frame => frame.type === 'authorized'), false);
        const result = frames.find(frame => frame.type === 'result');
        if (mode === 'ended') {
          assert.equal(receipt.guardExit, 0, receipt.output);
          assert.equal(result.actorFacts.parentThreadImpersonation, 'observed-none');
          if (role === 'cli-context') {
            assert.equal(result.ordinaryEligible, true, result.reason);
            assert.equal(result.observation.completeStableThreadSet, true);
            assert.equal(result.observation.primaryStable, true);
          }
        } else {
          assert.equal(existsSync(`${barrier}.ended`), true, receipt.output);
          if (role === 'caller') {
            assert.equal(receipt.guardExit, 3);
            assert.equal(result, undefined);
            assert.match(frames.find(frame => frame.type === 'failed').reason, /HELD_THREAD_CHANGED_OR_EXITED|THREAD_LIVENESS_CHANGED/);
          } else {
            assert.equal(receipt.guardExit, 0);
            assert.equal(result.ordinaryEligible, false);
            assert.match(result.reason, /HELD_THREAD_CHANGED_OR_EXITED|THREAD_LIVENESS_CHANGED/);
          }
        }
      });
    }
}
