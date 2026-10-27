import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, readFileSync, readdirSync, statfsSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { POLICY, digest } from './policy.mjs';
import { InputSnapshot, outside, physical, safeName, sha256, writeManifest } from './local-inputs.mjs';
import { LocalGitConfig } from './local-git.mjs';
import { LocalSourceReader, captureSourceIdentity } from './local-source.mjs';
import {
  LOCAL_CONTRACT, LOCAL_NATIVE_PACKAGES, LOCAL_NODES, localCaseUser, releaseRole, releaseVersions,
} from './local-regression.mjs';
import { controllerBinding, evidenceInventory, readLocalJson, writeEvidenceInventory } from './local-evidence.mjs';
import { LOCAL_FROZEN_CONTROLLER, LocalRunLock, LocalRunState } from './local-run-state.mjs';
import { SOURCE_SUITE_TIMEOUT_MS, testTotals } from './local-gate.mjs';
import { SESSION_REQUIRED_TESTS } from '../ci/test-contracts.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const IMAGE = 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9';
const LIMIT = 4 * 1024 ** 3;
// Separate from LIMIT, which also caps container memory. The growth check samples
// machine-wide free space, so it charges writes this run does not control, and it
// must leave room above the container's own 4 GB StorageOpt scratch.
const DISK_LIMIT = 8 * 1024 ** 3;
const RESERVE = 3 * 1024 ** 3;
const IO_BYTES_PER_SECOND = 32 * 1024 ** 2;
const MAX_EXPORT = 128 * 1024 ** 2;
const SESSION_LANE_TIMEOUT_MS = 40 * 60_000;
// The ordinary launcher forwards its own fixed allowlist to the task worker. This is the parent's
// equivalent: a real profile and temporary tree, because an interactive logon owns them.
const SESSION_LANE_ENVIRONMENT = Object.freeze(['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec',
  'PATHEXT', 'OS', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData', 'SystemDrive', 'USERPROFILE',
  'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'USERNAME', 'USERDOMAIN']);

export function evidenceEntryFilter() {
  const names = new Set();
  let total = 0;
  return (name, entry) => {
    const normalized = name.endsWith('/') ? name.slice(0, -1) : name;
    safeName(normalized);
    assert.ok(normalized === 'output' ||
      normalized.startsWith('output/'), 'Unexpected export prefix');
    assert.ok(entry.type === 'Directory' ||
      entry.type === 'File', 'Linked or special exported evidence');
    assert.equal(names.has(normalized.toLowerCase()), false, 'Duplicate evidence path');
    names.add(normalized.toLowerCase());
    assert.ok(Number.isSafeInteger(entry.size) &&
      entry.size >= 0);
    total += entry.size;
    assert.ok(names.size <= 10_000 &&
      total <= MAX_EXPORT &&
      entry.size <= 32 * 1024 ** 2, 'Evidence inventory exceeds its bounds');
    return true;
  };
}

export function validateContainer(value, { id, owner, image, user = '' }) {
  assert.equal(value.Id, id);
  assert.equal(value.Config.Labels['pacemaker.local-gate'], owner);
  assert.equal(value.Image, image);
  assert.equal(value.Config.User ?? '', user, 'Container execution account differs from its case');
  assert.equal(value.HostConfig.Isolation, 'hyperv');
  assert.equal(value.HostConfig.NetworkMode, 'none');
  assert.equal(value.HostConfig.CpuCount, 4);
  assert.equal(value.HostConfig.Memory, LIMIT);
  assert.deepEqual(value.Mounts, []);
  assert.ok(!value.HostConfig.Binds?.length);
  assert.deepEqual(value.HostConfig.PortBindings ?? {}, {});
  assert.ok(!value.HostConfig.Privileged);
  assert.equal(value.HostConfig.Devices?.length ?? 0, 0);
  assert.equal(value.HostConfig.DeviceRequests?.length ?? 0, 0);
  assert.equal(value.HostConfig.VolumesFrom?.length ?? 0, 0);
  assert.equal(value.HostConfig.PublishAllPorts ?? false, false);
  assert.equal(value.HostConfig.RestartPolicy.Name, 'no');
  assert.equal(value.HostConfig.StorageOpt?.size, '4GB');
  assert.equal(value.HostConfig.IOMaximumBandwidth, IO_BYTES_PER_SECOND);
  for (const item of value.Config.Env ?? []) {
    assert.doesNotMatch(item.split('=', 1)[0], /proxy|token|password|secret|credential/i);
  }
}

export function launcherArguments(argv) {
  const args = [...argv];
  const usage = 'Usage: local-windows.mjs --npm-cli PATH --peer-root PATH (--output NEW_DIRECTORY | --resume RUN_DIRECTORY) --node-root PATH --pwsh-root PATH [--native-packages PATH] [--controls-only]';
  const controlsOnly = args.at(-1) === '--controls-only';
  if (controlsOnly) args.pop();
  assert.ok([10, 12].includes(args.length), usage);
  const resume = args[4] === '--resume';
  assert.deepEqual([args[0], args[2], args[4], args[6], args[8]],
    ['--npm-cli', '--peer-root', resume ? '--resume' : '--output', '--node-root', '--pwsh-root'], usage);
  if (args.length === 12) assert.equal(args[10], '--native-packages', usage);
  if (resume) assert.equal(controlsOnly, false, 'Only a full qualification run can be resumed');
  assert.ok(isAbsolute(args[5]), 'Absolute paths required');
  // Resolved once, so the lock, the binding and the sibling attempts directory all name the same run.
  return { controlsOnly, options: { npmCli: args[1], peerRoot: args[3], output: resolve(args[5]), nodeRoot: args[7],
    pwshRoot: args[9], nativePackages: args[11], resume } };
}

export class WindowsLocalGate {
  constructor({ output, npmCli, peerRoot, nodeRoot, pwshRoot, nativePackages, image = IMAGE, resume = false }) {
    assert.equal(process.platform, 'win32', 'The local Hyper-V launcher requires Windows');
    for (const path of [output, npmCli, peerRoot, nodeRoot, pwshRoot]) assert.ok(isAbsolute(path), 'Absolute paths required');
    // The run path names the lock, the binding and the sibling attempts directory, so it must be one spelling.
    assert.equal(output, resolve(output), 'The run directory path must be normalized');
    for (const root of [ROOT, peerRoot]) {
      outside(root, output);
    }
    assert.match(image, /^sha256:[a-f0-9]{64}$/);
    if (resume) assert.equal(existsSync(output), true, 'Resume requires the original run directory');
    else assert.equal(existsSync(output), false, 'Use a new output directory; no overwrite');
    assert.notEqual(resolve(peerRoot), resolve(ROOT), 'Both release lines are required');
    const current = JSON.parse(readFileSync(join(ROOT, 'package.json')));
    const peer = JSON.parse(readFileSync(join(peerRoot, 'package.json')));
    releaseVersions([current.version, peer.version]);
    const npm = JSON.parse(readFileSync(resolve(dirname(npmCli), '../package.json')));
    assert.equal(npm.name, 'npm');
    assert.equal(npm.version, POLICY.npm);
    this.output = output;
    this.npmRoot = resolve(dirname(npmCli), '..');
    this.nodeRoot = physical(nodeRoot);
    this.pwshRoot = physical(pwshRoot);
    if (nativePackages !== undefined) {
      assert.ok(isAbsolute(nativePackages), 'Absolute native-package directory required');
      this.nativeRoot = physical(nativePackages);
      this.nativeSnapshot = this.nativeInputs(this.nativeRoot);
    }
    this.nodes = LOCAL_NODES.map(version => physical(join(nodeRoot, `node-v${version}-win-x64/node.exe`)));
    this.publisherNode = this.nodes[2];
    this.roots = [ROOT, peerRoot];
    this.image = image;
    this.owner = randomUUID();
    this.results = [];
    this.started = performance.now();
    this.startedAt = new Date().toISOString();
    this.deadline = this.started + 2 * 60 * 60_000;
    this.cleaning = false;
    this.snapshots = this.nativeSnapshot ? [this.nativeSnapshot] : [];
    this.sourceBindings = [];
    this.commandIndex = 0;
    this.openRun(resume);
  }

  // A resume is checked and accepted here, before this invocation writes its first receipt.
  openRun(resume) {
    this.resumed = resume;
    this.config = join(this.output, 'docker-config');
    if (!resume) {
      mkdirSync(this.output);
      mkdirSync(this.config);
      mkdirSync(join(this.output, 'commands'));
    }
    this.env = this.hostEnvironment();
    if (resume) this.resumeRun(this.gitRootOf(this.probe('git', ['--exec-path'])));
    const gitRoot = this.gitRootOf(this.command('git', ['--exec-path']).stdout);
    if (resume) assert.equal(gitRoot, this.gitRoot, 'Git for Windows changed while the run was resuming');
    this.gitRoot = gitRoot;
    for (const [index, node] of this.nodes.entries()) {
      assert.equal(this.command(node, ['--version']).stdout.trim(), `v${LOCAL_NODES[index]}`);
    }
    const runtime = new InputSnapshot(this.nodeRoot);
    for (const version of LOCAL_NODES) runtime.add(`node-v${version}-win-x64/node.exe`);
    const frozenRuntime = join(this.output, 'runtime');
    if (!resume) runtime.copy(frozenRuntime);
    this.snapshots.push(runtime);
    this.runtimeSnapshot = new InputSnapshot(frozenRuntime);
    this.runtimeSnapshot.addAll();
    this.snapshots.push(this.runtimeSnapshot);
    this.nodes = LOCAL_NODES.map(version => join(frozenRuntime, `node-v${version}-win-x64/node.exe`));
    this.publisherNode = this.nodes[2];
    this.freezeController(ROOT);
  }

  hostEnvironment() {
    const env = {};
    for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
      if (process.env[key]) env[key] = process.env[key];
    }
    return Object.assign(env, {
      HOME: this.config, USERPROFILE: this.config, APPDATA: this.config, LOCALAPPDATA: this.config,
      GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: 'NUL',
      GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never',
    });
  }

  nativeInputs(root) {
    assert.deepEqual(readdirSync(root).sort(), Object.keys(LOCAL_NATIVE_PACKAGES).sort(),
      'Native input directory must contain exactly the two pinned archives');
    const snapshot = new InputSnapshot(root, { maxBytes: 128 * 1024 ** 2, maxFiles: 2 });
    snapshot.addAll();
    assert.deepEqual(snapshot.directories, [], 'Native archives must be regular files');
    assert.equal(snapshot.files.length, 2);
    for (const file of snapshot.files) {
      assert.equal(file.sha256, LOCAL_NATIVE_PACKAGES[file.path], 'Native archive hash differs');
    }
    return snapshot;
  }

  freezeController(root) {
    const controller = new InputSnapshot(root);
    for (const path of LOCAL_FROZEN_CONTROLLER) controller.add(path);
    this.controller = join(this.output, 'controller');
    if (!this.resumed) controller.copy(this.controller);
    this.snapshots.push(controller);
    const frozen = new InputSnapshot(this.controller);
    frozen.addAll();
    this.snapshots.push(frozen);
  }

  // Read without a receipt: a refused resume must leave the run directory exactly as it was.
  probe(file, args) {
    const value = spawnSync(file, args, {
      env: this.env, encoding: 'utf8', windowsHide: true, shell: false, timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(value.error, undefined, `${file} could not be run: ${value.error?.message}`);
    assert.equal(value.status, 0, `${file} failed: ${(value.stderr ?? '').trim().slice(0, 400)}`);
    return value.stdout;
  }

  gitRootOf(execPath) {
    const root = resolve(execPath.trim(), '../../..');
    assert.ok(existsSync(join(root, 'cmd', 'git.exe')), 'A retained Git for Windows distribution is required');
    return root;
  }

  // The controls prove containment on one engine and host build, so later cases may not run on another.
  platform() {
    const server = JSON.parse(this.probe('docker', ['--host', 'npipe:////./pipe/docker_engine', '--config', this.config,
      'version', '--format', '{{json .Server}}']));
    const docker = { version: server.Version, apiVersion: server.ApiVersion, os: server.Os,
      kernelVersion: server.KernelVersion };
    for (const value of Object.values(docker)) {
      assert.ok(typeof value === 'string' &&
        value.length > 0, 'Unreadable Docker engine version');
    }
    const registry = this.probe('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']);
    const build = /^\s+CurrentBuild\s+REG_SZ\s+(\d+)\s*$/m.exec(registry)?.[1];
    const ubr = /^\s+UBR\s+REG_DWORD\s+0x([0-9a-f]+)\s*$/im.exec(registry)?.[1];
    assert.ok(build &&
      ubr, 'Unreadable Windows build');
    return { docker, windows: { build, ubr: Number.parseInt(ubr, 16) } };
  }

  resumeRun(gitRoot) {
    assert.ok(this.nativeRoot, 'Full qualification requires --native-packages with the pinned CI archives');
    this.state = new LocalRunState(this.output);
    const state = this.state.load();
    this.owner = state.runId;
    this.startedAt = state.startedAt;
    this.gitRoot = gitRoot;
    const { binding, live } = this.binding(state.binding.scope);
    this.commandIndex = this.state.accept(this.state.preflight(binding));
    // Reused inputs are not frozen again, so the final input check re-reads the live trees
    // the binding hashed.
    this.snapshots.push(...live.snapshots);
    this.sourceBindings.push(...live.sources);
  }

  createState(scope) {
    this.state = new LocalRunState(this.output);
    this.state.create(this.binding(scope).binding, this.startedAt);
  }

  // Everything a resumed invocation must find unchanged. It is hashed directly, not through the
  // command journal, so the same computation serves a fresh run and a read-only resume check.
  binding(scope) {
    const live = { snapshots: [], sources: [] };
    const binding = { runId: this.owner, scope, image: this.image, platform: this.platform(),
      arguments: { output: this.output, npmRoot: this.npmRoot, peerRoot: this.roots[1], nodeRoot: this.nodeRoot,
        pwshRoot: this.pwshRoot, nativeRoot: this.nativeRoot ?? null, gitRoot: this.gitRoot, controllerRoot: ROOT },
      controller: controllerBinding(ROOT),
      nodes: LOCAL_NODES.map(version => ({ version,
        sha256: sha256(readFileSync(physical(join(this.nodeRoot, `node-v${version}-win-x64/node.exe`)))) })),
      tools: {}, sources: [] };
    if (scope === 'containment-controls-only') return { binding, live };
    for (const [name, root, selections] of [['npm', this.npmRoot, null], ['pwsh', this.pwshRoot, null],
      ['git', this.gitRoot, this.state.gitSelection(this.gitRoot)], ['native', this.nativeRoot, null]]) {
      const { snapshot, fingerprint } = this.state.digest(root, selections);
      live.snapshots.push(snapshot);
      binding.tools[name] = fingerprint;
    }
    for (const root of this.roots) {
      const source = this.readSource(root);
      const { snapshot, fingerprint } = this.state.digest(root, [...source.names, 'node_modules', 'ui/node_modules']);
      live.snapshots.push(snapshot);
      live.sources.push({ root, head: source.head, names: source.names });
      binding.sources.push({ version: source.version, head: source.head, tree: source.tree, files: fingerprint });
    }
    return { binding, live };
  }

  readSource(root) {
    const reader = new LocalSourceReader(root, join(this.gitRoot, 'cmd', 'git.exe'));
    const names = reader.git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'])
      .split('\0').filter(name => name.length > 0 &&
        existsSync(join(root, name))).sort();
    return { version: JSON.parse(readFileSync(join(root, 'package.json'))).version,
      head: reader.git(['rev-parse', 'HEAD']).trim(), tree: reader.git(['rev-parse', 'HEAD^{tree}']).trim(), names };
  }

  command(file, args, timeout = 180_000, allowFailure = false) {
    if (!this.cleaning) {
      const remaining = this.deadline - performance.now();
      assert.ok(remaining > 0, 'Whole local gate deadline expired');
      timeout = Math.max(1, Math.floor(Math.min(timeout, remaining)));
    }
    timeout = Math.max(1, Math.floor(timeout));
    const value = spawnSync(file, args, {
      env: this.env, encoding: 'utf8', windowsHide: true, shell: false,
      timeout, maxBuffer: 4 * 1024 * 1024,
    });
    const result = { status: value.status, signal: value.signal, error: value.error?.code ?? null,
      stdout: value.stdout ?? '', stderr: value.stderr ?? '' };
    writeFileSync(join(this.output, 'commands', `${++this.commandIndex}.json`),
      `${JSON.stringify({ file, args, timeout, ...result })}\n`, { flag: 'wx' });
    if (!allowFailure) {
      assert.equal(result.error, null, `${file} failed or timed out: ${result.error}`);
      assert.equal(result.signal, null, `${file} terminated`);
      assert.equal(result.status, 0, `${file} failed: ${result.stderr}`);
    }
    return result;
  }

  docker(args, timeout, allowFailure) {
    return this.command('docker', ['--host', 'npipe:////./pipe/docker_engine', '--config', this.config, ...args],
      timeout, allowFailure);
  }

  inspect(id) {
    return JSON.parse(this.docker(['inspect', id]).stdout)[0];
  }

  git(root, args) {
    const config = new LocalGitConfig(root, this.config,
      options => this.command('git', options).stdout);
    try {
      return this.command('git', [...config.options(), '-c', 'core.hooksPath=', '-c', 'credential.helper=',
        '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=', '-C', root, ...args]).stdout;
    } finally {
      config.verify();
    }
  }

  sourceNames(root) {
    return this.git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate'])
      .split('\0').filter(name => name.length > 0 &&
        existsSync(join(root, name))).sort();
  }

  verifyInputs() {
    for (const binding of this.sourceBindings) {
      assert.equal(this.git(binding.root, ['rev-parse', 'HEAD']).trim(), binding.head, 'Source HEAD changed');
      assert.deepEqual(this.sourceNames(binding.root), binding.names, 'Source inventory changed during the run');
    }
    for (const snapshot of this.snapshots) snapshot.verify();
  }

  inputs(root) {
    const version = JSON.parse(readFileSync(join(root, 'package.json'))).version;
    const destination = join(this.output, `inputs-${version}`);
    mkdirSync(destination);
    const source = new InputSnapshot(root, { maxBytes: 512 * 1024 ** 2 });
    const names = this.sourceNames(root);
    for (const name of names) {
      assert.doesNotMatch(name, /(?:^|\/)(?:\.git|\.npmrc|servers\.json)(?:\/|$)/i, 'Private source input');
      source.add(name);
    }
    source.add('node_modules');
    source.add('ui/node_modules');
    source.copy(join(destination, 'source'));
    const head = this.git(root, ['rev-parse', 'HEAD']).trim();
    this.git(root, ['bundle', 'create', join(destination, 'history.bundle'), 'HEAD']);
    assert.equal(this.git(root, ['rev-parse', 'HEAD']).trim(), head, 'Source HEAD changed');
    for (const [name, toolRoot, entries] of [
      ['npm', this.npmRoot, null],
      ['git', this.gitRoot, this.state.gitSelection(this.gitRoot)],
      ['pwsh', this.pwshRoot, null],
      ...(this.nativeRoot ? [['native', this.nativeRoot, null]] : []),
    ]) {
      const tool = new InputSnapshot(toolRoot);
      if (entries === null) tool.addAll();
      else for (const entry of entries) tool.add(entry);
      tool.copy(join(destination, name));
      this.snapshots.push(tool);
    }
    source.verify();
    assert.deepEqual(this.sourceNames(root), names, 'Source file set changed');
    this.snapshots.push(source);
    this.sourceBindings.push({ root, head, names });
    const sourceIdentity = captureSourceIdentity(root, args => this.git(root, args));
    assert.equal(sourceIdentity.head, head);
    const manifest = writeManifest(destination, { version, head, sourcePaths: names, sourceIdentity });
    return { path: destination, ...manifest };
  }

  wait(id, storage, timeout, initialFree) {
    const deadline = performance.now() + timeout;
    for (;;) {
      const space = statfsSync(storage, { bigint: true });
      const free = space.bavail * space.bsize;
      assert.ok(free >= BigInt(RESERVE), 'Daemon disk reserve reached');
      assert.ok(initialFree - free < BigInt(DISK_LIMIT), 'Per-case daemon disk-growth budget reached');
      const remaining = deadline - performance.now();
      if (remaining <= 0) return { error: 'ETIMEDOUT', status: null };
      const value = this.docker(['wait', id], Math.min(3000, remaining), true);
      if (value.error === 'ETIMEDOUT') continue;
      assert.equal(value.error, null);
      assert.equal(value.signal, null);
      assert.equal(value.status, 0, 'Container wait failed');
      return value;
    }
  }

  descendants(id) {
      const script = `const fs=require('node:fs');
        const tree=JSON.parse(fs.readFileSync('C:\\\\output\\\\tree.json'));
        const heartbeat=JSON.parse(fs.readFileSync('C:\\\\output\\\\heartbeat.json'));
        const alive=[tree.root,tree.child,tree.grandchild].map(pid=>{
          try{process.kill(pid,0);return true}catch(e){if(e.code==='ESRCH')return false;throw e}
        });
        console.log(JSON.stringify({tree,heartbeat,alive}));`;
      const before = JSON.parse(this.docker(['exec', id, 'C:\\node.exe', '-e', script], 10_000).stdout);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
      const after = JSON.parse(this.docker(['exec', id, 'C:\\node.exe', '-e', script], 10_000).stdout);
      for (const value of [before, after]) {
        assert.equal(value.tree.owner, this.owner);
        assert.equal(new Set([value.tree.root, value.tree.child, value.tree.grandchild]).size, 3);
        assert.equal(value.heartbeat.pid, value.tree.grandchild);
        assert.ok(value.heartbeat.count >= 2);
      }
      assert.deepEqual(before.tree, after.tree);
      return { before, after, progressing: after.heartbeat.count > before.heartbeat.count &&
        before.alive.every(Boolean) &&
        after.alive.every(Boolean) };
  }

  exportEvidence(id, output) {
      const space = statfsSync(output, { bigint: true });
      assert.ok(space.bavail * space.bsize >= BigInt(RESERVE + 2 * MAX_EXPORT), 'Evidence volume reserve reached');
      const args = ['--host', 'npipe:////./pipe/docker_engine', '--config', this.config, 'cp', `${id}:C:\\output`, '-'];
      const value = spawnSync('docker', args, {
        env: this.env, shell: false, windowsHide: true, timeout: 180_000, maxBuffer: MAX_EXPORT,
      });
      const record = { args, status: value.status, error: value.error?.code ?? null, signal: value.signal,
        bytes: value.stdout?.length ?? 0, stderr: value.stderr?.toString() ?? '' };
      writeFileSync(join(output, 'export.json'), JSON.stringify(record), { flag: 'wx', flush: true });
      assert.equal(value.error, undefined, 'Evidence export failed or exceeded its byte/time limit');
      assert.equal(value.signal, null);
      assert.equal(value.status, 0);
      assert.ok(record.bytes > 0 &&
        record.bytes <= MAX_EXPORT);
      const archive = join(output, 'evidence.tar');
      writeFileSync(archive, value.stdout, { flag: 'wx', flush: true });
      const tar = createRequire(join(this.npmRoot, 'package.json'))('tar');
      tar.t({ file: archive, sync: true, strict: true, filter: evidenceEntryFilter() });
      const destination = join(output, 'guest');
      assert.equal(existsSync(destination), false);
      mkdirSync(destination);
      tar.x({ file: archive, cwd: destination, strip: 1, sync: true, strict: true,
        preservePaths: false, preserveOwner: false, noChmod: true, filter: evidenceEntryFilter() });
      assert.equal(sha256(readFileSync(archive)), sha256(value.stdout), 'Evidence archive changed during extraction');
      return { status: 0, error: null, archiveSha256: sha256(value.stdout), bytes: record.bytes };
  }

  caseTimeout(mode) {
    // A gate case runs the complete source suite once, so it must outlast that suite plus its
    // checkout, native restore, UI, pack and capture work.
    if (mode === 'gate') return SOURCE_SUITE_TIMEOUT_MS + 30 * 60_000;
    if (mode === 'audit') return 5 * 60_000;
    if (mode === 'fail') return 20 * 60_000;
    assert.ok(mode === 'timeout' ||
      mode === 'timeout-early-exit', 'Unsupported local case mode');
    return 15_000;
  }

  stopContainer(id) {
    let inspected = this.inspect(id);
    assert.equal(inspected.Id, id);
    assert.equal(inspected.Config.Labels['pacemaker.local-gate'], this.owner);
    if (inspected.State.Running) this.docker(['kill', id], 60_000);
    inspected = this.inspect(id);
    assert.equal(inspected.State.Running, false);
    assert.equal(inspected.State.Pid, 0, 'The owned container still has a process after kill');
    return inspected;
  }

  removeContainer(id) {
    this.docker(['rm', id], 60_000);
    const absent = this.docker(['inspect', id], 30_000, true);
    assert.equal(absent.error, null);
    assert.notEqual(absent.status, 0);
    assert.match(absent.stderr, /No such (?:object|container)/i);
  }

  runCase(name, mode, input, node = this.publisherNode) {
    const sourceMode = mode === 'gate' || mode === 'audit';
    const user = localCaseUser(mode, input?.manifest.version);
    const storage = JSON.parse(this.docker(['info', '--format', '{{json .DockerRootDir}}']).stdout);
    let space = statfsSync(storage, { bigint: true });
    const admissionDeadline = Math.min(this.deadline, performance.now() + 60_000);
    const samples = [];
    while (space.bavail * space.bsize < BigInt(DISK_LIMIT + RESERVE) &&
      performance.now() < admissionDeadline) {
      samples.push({ elapsedMs: performance.now() - this.started,
        freeBytes: Number(space.bavail * space.bsize) });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
      space = statfsSync(storage, { bigint: true });
    }
    samples.push({ elapsedMs: performance.now() - this.started, freeBytes: Number(space.bavail * space.bsize) });
    writeFileSync(join(this.output, `${name}-storage-admission.json`), JSON.stringify(samples), { flag: 'wx' });
    assert.ok(space.bavail * space.bsize >= BigInt(DISK_LIMIT + RESERVE), 'Insufficient free daemon storage; no pull or cleanup attempted');
    const image = JSON.parse(this.docker(['image', 'inspect', this.image]).stdout)[0];
    assert.equal(image.Id, this.image);
    assert.equal(image.Os, 'windows');
    const output = join(this.output, name);
    mkdirSync(output);
    const containerName = `pacemaker-local-${this.owner}-${name}`;
    let id;
    let originalError;
    const result = { name, mode, image: this.image, status: 'failed', guest: null, removed: false };
    const timeoutControl = mode === 'timeout' ||
      mode === 'timeout-early-exit';
    try {
      const created = this.docker([
        'create', '--pull', 'never', '--name', containerName, '--label', `pacemaker.local-gate=${this.owner}`,
        '--isolation', 'hyperv', '--network', 'none', '--cpu-count', '4', '--memory', '4g',
        '--storage-opt', 'size=4GB',
        '--io-maxbandwidth', String(IO_BYTES_PER_SECOND),
        '--restart', 'no', '--log-opt', 'max-size=4m', '--log-opt', 'max-file=1',
        ...(user ? ['--user', user] : []),
        '--entrypoint', 'C:\\node.exe', this.image, 'C:\\entry.mjs', mode, this.owner, input?.sha256 ?? '-',
        sha256(readFileSync(node)), sourceMode ? sha256(readFileSync(this.publisherNode)) : '-',
      ]);
      id = created.stdout.trim();
      assert.match(id, /^[a-f0-9]{64}$/);
      validateContainer(this.inspect(id), { id, owner: this.owner, image: this.image, user });
      this.docker(['cp', node, `${id}:C:\\node.exe`]);
      this.docker(['cp', join(this.controller, 'tools/npm-publication/local-windows-entry.mjs'), `${id}:C:\\entry.mjs`]);
      this.docker(['cp', join(this.controller, 'tools/npm-publication/local-inputs.mjs'), `${id}:C:\\local-inputs.mjs`]);
      this.docker(['cp', join(this.controller, 'tools/npm-publication/local-environment.mjs'), `${id}:C:\\local-environment.mjs`]);
      if (sourceMode) {
        this.docker(['cp', input.path, `${id}:C:\\input`], 300_000);
        this.docker(['cp', this.publisherNode, `${id}:C:\\publisher-node.exe`]);
      }
      this.docker(['start', id]);
      const waited = this.wait(id, storage, this.caseTimeout(mode), space.bavail * space.bsize);
      result.wait = waited;
      if (timeoutControl) {
        assert.equal(waited.error, 'ETIMEDOUT', 'The outer timeout control did not expire');
        result.descendants = this.descendants(id);
        assert.equal(result.descendants.progressing, mode === 'timeout',
          'Timeout descendant liveness did not match the positive/negative control');
      }
      else {
        assert.equal(waited.error, null, 'Guest wait failed or expired; no retry');
        assert.equal(waited.status, 0);
      }
    } catch (error) {
      originalError = error;
      result.error = error.message;
    } finally {
      this.cleaning = true;
      try {
      // Reconcile an uncertain create by its unique name and ownership label before any cleanup.
      if (!id) {
        const probe = this.docker(['inspect', containerName], 30_000, true);
        if (probe.status === 0) {
          const value = JSON.parse(probe.stdout)[0];
          assert.equal(value.Config.Labels['pacemaker.local-gate'], this.owner);
          id = value.Id;
        } else {
          assert.equal(probe.error, null);
          assert.match(probe.stderr, /No such (?:object|container)/i, 'Container creation outcome is unknown');
        }
      }
      if (id) {
        const inspected = this.stopContainer(id);
        result.container = { id, state: inspected.State, hostConfig: inspected.HostConfig };
        let copied;
        try {
          writeFileSync(join(output, 'container-log.json'), JSON.stringify(this.docker(['logs', id])), { flag: 'wx' });
          copied = this.exportEvidence(id, output);
          result.copy = copied;
        } finally {
          this.removeContainer(id);
          result.removed = true;
        }
        if (!originalError) {
          assert.equal(copied.error, null);
          assert.equal(copied.status, 0, 'Missing guest evidence');
          result.guest = JSON.parse(readFileSync(join(output, 'guest/runtime.json')));
          assert.equal(result.guest.owner, this.owner);
          assert.equal(result.guest.manifestSha256, input?.sha256 ?? '-');
          assert.equal(result.guest.node, this.command(node, ['--version']).stdout.trim());
          assert.equal(result.guest.nodeSha256, sha256(readFileSync(node)));
          assert.equal(result.guest.publisherSha256, sourceMode ? sha256(readFileSync(this.publisherNode)) : '-');
          assert.deepEqual(result.guest.directories, Object.fromEntries(
            ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR']
              .map(key => [key, 'C:\\bootstrap'])));
          assert.equal(result.guest.cpu, 4);
          assert.ok(result.guest.disk.totalBytes > 0);
          result.diskGuard = { kind: 'host-free-space-observer', reserveBytes: RESERVE,
            maxGrowthBytes: DISK_LIMIT, sampleTimeoutMs: 3000, requestedIoBytesPerSecond: IO_BYTES_PER_SECOND,
            virtualCapacityIsNotQuotaProof: true };
          assert.equal(inspected.State.OOMKilled, false);
          for (const addresses of Object.values(result.guest.network)) {
            assert.ok(addresses.every(address => address.internal), 'Non-loopback guest adapter');
          }
          if (sourceMode) {
            const entryFailure = join(output, 'guest/entry-failure.json');
            if (existsSync(entryFailure)) {
              const failure = JSON.parse(readFileSync(entryFailure));
              assert.equal(failure.owner, this.owner);
              assert.fail(`Original guest entry failed (${inspected.State.ExitCode}): ${failure.error.message}`);
            }
            const gate = JSON.parse(readFileSync(join(output, 'guest/gate/result.json')));
            assert.equal(inspected.State.ExitCode, 0, `Original gate failed: ${gate.error ?? 'see guest logs'}`);
            assert.equal(gate.status, 'passed');
            assert.equal(gate.kind, mode === 'audit' ? 'local-privileged-audit' : 'local-publication-regression');
            assert.equal(gate.releaseReady, false);
          } else if (mode === 'fail') {
            assert.equal(inspected.State.ExitCode, 1);
            const control = JSON.parse(readFileSync(join(output, 'guest/control.json')));
            assert.equal(control.owner, this.owner);
            assert.equal(control.error.code, 'ERR_ASSERTION');
            assert.equal(control.error.actual, 1);
            assert.equal(control.error.expected, 2);
            assert.match(control.error.message, /Deliberate isolated assertion failure/);
          }
          else {
            const tree = JSON.parse(readFileSync(join(output, 'guest/tree.json')));
            assert.equal(tree.owner, this.owner);
            assert.ok(tree.root > 0 &&
              tree.child > 0 &&
              tree.grandchild > 0, 'Timeout control did not start its descendant tree');
            const heartbeat = JSON.parse(readFileSync(join(output, 'guest/heartbeat.json')));
            assert.equal(heartbeat.pid, tree.grandchild);
            assert.ok(heartbeat.count > 1, 'Grandchild did not remain alive until cancellation');
          }
          result.status = 'passed';
        }
      }
      } catch (error) {
        result.error = [originalError?.message, error.message].filter(Boolean).join('; ');
        originalError = originalError ? new AggregateError([originalError, error], result.error) : error;
      } finally {
        this.cleaning = false;
        this.results.push(result);
        writeFileSync(join(output, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
      }
    }
    if (originalError) throw originalError;
    assert.equal(result.status, 'passed');
  }

  // A Windows container has no interactive logon session, so the registered files that bind one
  // cannot run inside a case. They run here, in the launcher's own ordinary interactive session,
  // against the same working tree the cases qualify, and the receipt binds them to that commit.
  sessionLane(input) {
    const root = this.roots[0];
    assert.equal(releaseRole(input.manifest.version), 'current', 'The session lane belongs to the current release line');
    // The pinned runtime node has no co-located npm, so the launcher is given the same pinned CLI
    // the contained cases use rather than resolving one beside the executable.
    const environment = { CI: 'true', MCP_CI_NPM_CLI: join(this.npmRoot, 'bin/npm-cli.js') };
    for (const key of SESSION_LANE_ENVIRONMENT) {
      if (process.env[key]) environment[key] = process.env[key];
    }
    const startedAt = new Date().toISOString();
    const result = spawnSync(this.publisherNode,
      [join(root, 'tools/windows-ci/ordinary-run.mjs'), 'session-required'],
      { cwd: root, env: environment, shell: false, windowsHide: true,
        timeout: SESSION_LANE_TIMEOUT_MS, maxBuffer: MAX_EXPORT, encoding: 'utf8' });
    const evidence = /^Ordinary CI evidence: (.+)$/m.exec(result.stdout ?? '')?.[1]?.trim();
    assert.equal(result.error, undefined, `Host session lane did not run: ${result.error?.message}`);
    assert.ok(evidence &&
      isAbsolute(evidence),
    `Host session lane did not record its evidence directory: ${(result.stderr ?? '').trim().slice(0, 400)}`);
    assert.equal(result.status, 0, 'Host session lane did not pass');
    const output = readFileSync(join(evidence, 'stdout.log'), 'utf8');
    const context = JSON.parse(output.slice(0, output.indexOf('\n')));
    assert.deepEqual(context, { contract: 'session-required', platform: 'win32', role: 'user-runtime',
      verified: true, sessionVerified: true }, 'Host session lane ran without a verified user session');
    const totals = testTotals(output);
    assert.equal(totals.fail, 0, 'Host session lane reported failing tests');
    assert.ok(totals.pass > 0, 'Host session lane executed no tests');
    const receipt = { schemaVersion: 1, kind: 'host-session-lane', runId: this.owner,
      version: input.manifest.version, head: input.manifest.head, node: `v${LOCAL_NODES[2]}`,
      files: [...SESSION_REQUIRED_TESTS], startedAt, completedAt: new Date().toISOString(),
      context, totals, contained: false };
    writeFileSync(join(this.output, 'session-lane.json'), `${JSON.stringify(receipt, null, 2)}\n`,
      { flag: 'wx', flush: true });
    return receipt;
  }

  // A killed invocation can leave its container behind. It carries this run's unique ownership
  // label, so it is reconciled the same way an uncertain create is, before any case runs again.
  reconcileContainers() {
    const listed = this.docker(['ps', '--all', '--quiet', '--no-trunc', '--filter',
      `label=pacemaker.local-gate=${this.owner}`]).stdout.split(/\r?\n/).filter(id => id.length > 0);
    for (const id of listed) {
      assert.match(id, /^[a-f0-9]{64}$/);
      this.stopContainer(id);
      this.removeContainer(id);
      this.state.removed(id);
    }
  }

  caseStep(name, mode, input, node) {
    if (this.state.passed(name)) {
      this.state.reuse(name);
      this.results.push(readLocalJson(join(this.output, name, 'result.json')));
      return;
    }
    this.state.begin(name);
    this.runCase(name, mode, input, node);
    this.state.pass(name, this.commandIndex);
  }

  inputStep(root) {
    const name = `inputs-${JSON.parse(readFileSync(join(root, 'package.json'))).version}`;
    if (this.state.passed(name)) {
      this.state.reuse(name);
      const bytes = readFileSync(join(this.output, name, 'manifest.json'));
      return { path: join(this.output, name), manifest: JSON.parse(bytes), sha256: sha256(bytes) };
    }
    this.state.begin(name);
    const input = this.inputs(root);
    this.state.confirmInputs(input.manifest);
    this.state.pass(name, this.commandIndex);
    return input;
  }

  sessionLaneStep(input) {
    if (this.state.passed('session-lane')) {
      this.state.reuse('session-lane');
      return readLocalJson(join(this.output, 'session-lane.json'));
    }
    this.state.begin('session-lane');
    const receipt = this.sessionLane(input);
    // The lane runs the live working tree. Its receipt is only reusable if that tree still
    // matched every frozen input when it finished, which the end of the run would otherwise prove.
    this.verifyInputs();
    this.state.pass('session-lane', this.commandIndex);
    return receipt;
  }

  run({ controlsOnly = false } = {}) {
    if (!controlsOnly) assert.ok(this.nativeRoot, 'Full qualification requires --native-packages with the pinned CI archives');
    if (this.resumed) assert.equal(controlsOnly, false, 'Only a full qualification run can be resumed');
    // Every docker call is clamped to the remaining whole-run budget, so that budget has to be
    // derived from the cases actually planned. A fixed ceiling silently starves the later cases.
    const planned = this.roots.length * this.nodes.length;
    this.deadline = performance.now() + 15 * 60_000 +
      3 * this.caseTimeout('fail') +
      (controlsOnly ? 0 : SESSION_LANE_TIMEOUT_MS + planned * (this.caseTimeout('gate') + this.caseTimeout('audit')));
    const report = { schemaVersion: 3, kind: 'private-local-publication-run', contract: LOCAL_CONTRACT,
      runId: this.owner, startedAt: this.startedAt, completedAt: null, controller: controllerBinding(ROOT),
      status: 'failed', scope: controlsOnly ? 'containment-controls-only' : 'both-release-lines-local-only',
      releaseReady: false, sessionLane: null, nodes: this.nodes.map((node, index) => ({
        version: LOCAL_NODES[index], sha256: digest(readFileSync(node)).sha256,
      })), image: this.image, ciImageEquivalent: false, cases: this.results, invocations: null };
    try {
      if (this.resumed) this.reconcileContainers();
      else this.createState(report.scope);
      this.caseStep('failure-control', 'fail');
      this.caseStep('timeout-control', 'timeout');
      this.caseStep('early-descendant-exit-control', 'timeout-early-exit');
      if (!controlsOnly) {
        const inputs = this.roots.map(root => this.inputStep(root));
        report.sessionLane = this.sessionLaneStep(inputs[0]);
        for (const input of inputs) {
          for (const [index, node] of this.nodes.entries()) {
            if (releaseRole(input.manifest.version) === 'current') {
              this.caseStep(`audit-v${input.manifest.version}-node${LOCAL_NODES[index]}`, 'audit', input, node);
            }
            this.caseStep(`v${input.manifest.version}-node${LOCAL_NODES[index]}`, 'gate', input, node);
          }
        }
      }
      this.verifyInputs();
      // The state records a pass before the inventory is written, so the inventory must already
      // be buildable from these members; otherwise the run could be neither verified nor resumed.
      if (!controlsOnly) evidenceInventory(this.output, report);
      report.status = 'passed';
      return report;
    } catch (error) {
      report.error = error.message;
      throw error;
    } finally {
      const passed = report.status === 'passed';
      report.completedAt = new Date().toISOString();
      let unrecorded;
      try {
        report.invocations = this.state?.finish(report) ?? null;
      } catch (error) {
        unrecorded = error;
        report.status = 'failed';
        report.error = [report.error, `The run state was not recorded: ${error.message}`].filter(Boolean).join('; ');
      }
      writeFileSync(join(this.output, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
      if (report.status === 'passed' &&
          !controlsOnly) writeEvidenceInventory(this.output);
      // A run that otherwise passed must not report success. A failed run keeps its original error.
      if (unrecorded &&
          passed) throw unrecorded;
    }
  }
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { options, controlsOnly } = launcherArguments(process.argv.slice(2));
    const lock = new LocalRunLock(options.output);
    await lock.acquire();
    try {
      const report = new WindowsLocalGate(options).run({ controlsOnly });
      console.log(JSON.stringify({ status: report.status, releaseReady: false }));
    } finally {
      await lock.release();
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
