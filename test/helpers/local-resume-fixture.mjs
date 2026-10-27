import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WindowsLocalGate } from '../../tools/npm-publication/local-windows.mjs';
import { InputSnapshot } from '../../tools/npm-publication/local-inputs.mjs';
import { LOCAL_NODES } from '../../tools/npm-publication/local-regression.mjs';
import { SESSION_REQUIRED_TESTS } from '../../tools/ci/test-contracts.mjs';

export const RESUME_IMAGE = 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9';
export const LEFTOVER_CONTAINER = 'e'.repeat(64);

// SYNTHETIC: drives the real launcher steps, checkpoints, resume and history checks over owned
// miniature inputs. Docker, Git, the registry and every guest case are replaced; nothing here is
// qualification evidence.
export class ResumeFixture {
  constructor(t, { gitLayout = 'mingw64' } = {}) {
    this.home = realpathSync.native(mkdtempSync(join(tmpdir(), 'local-resume-')));
    t.after(() => rmSync(this.home, { recursive: true, force: true }));
    this.output = join(this.home, 'run');
    this.attempts = `${this.output}.attempts`;
    this.roots = [this.source('current', '2.1.0'), this.source('legacy', '1.3.1')];
    this.heads = new Map([[this.roots[0], 'a'.repeat(40)], [this.roots[1], 'b'.repeat(40)]]);
    this.tools = {};
    for (const name of ['npm', 'pwsh', 'native']) {
      this.tools[name] = join(this.home, name);
      mkdirSync(this.tools[name]);
      writeFileSync(join(this.tools[name], 'tool.bin'), `SYNTHETIC ${name}`);
    }
    this.tools.git = join(this.home, 'git');
    for (const path of ['cmd', `${gitLayout}/bin`, `${gitLayout}/libexec/git-core`, 'usr/bin', 'usr/share']) {
      mkdirSync(join(this.tools.git, path), { recursive: true });
    }
    writeFileSync(join(this.tools.git, 'cmd', 'git.exe'), 'SYNTHETIC git');
    this.execPath = join(this.tools.git, gitLayout, 'libexec', 'git-core');
    this.tools.node = join(this.home, 'node');
    for (const version of LOCAL_NODES) {
      mkdirSync(join(this.tools.node, `node-v${version}-win-x64`), { recursive: true });
      writeFileSync(join(this.tools.node, `node-v${version}-win-x64`, 'node.exe'), `SYNTHETIC node ${version}`);
    }
    this.server = { Version: '20.10.15+azure', ApiVersion: '1.41', Os: 'windows',
      KernelVersion: '10.0 26300 (26100.1.amd64fre.ge_release.240331-1435)' };
    this.windows = { build: '26300', ubr: 9457 };
    this.failures = new Set();
    this.hooks = new Map();
    this.containers = new Map();
    this.ran = [];
  }

  source(name, version) {
    const root = join(this.home, name);
    mkdirSync(join(root, 'node_modules'), { recursive: true });
    mkdirSync(join(root, 'ui', 'node_modules'), { recursive: true });
    writeFileSync(join(root, 'package.json'), `{"version":"${version}"}`);
    writeFileSync(join(root, 'node_modules', 'retained.js'), 'SYNTHETIC retained dependency');
    return root;
  }

  // The launcher constructor validates real paths and then calls openRun. This supplies the same
  // fields and replaces only the probes that need Windows, Docker, the registry or real repositories.
  gate(resume = false, { image = RESUME_IMAGE, output = this.output } = {}) {
    const gate = Object.create(WindowsLocalGate.prototype);
    Object.assign(gate, {
      output, npmRoot: this.tools.npm, nodeRoot: this.tools.node, pwshRoot: this.tools.pwsh,
      nativeRoot: this.tools.native, roots: this.roots, image, owner: randomUUID(), results: [],
      started: performance.now(), startedAt: new Date().toISOString(), deadline: performance.now() + 60_000,
      cleaning: false, snapshots: [], sourceBindings: [], commandIndex: 0,
      nodes: LOCAL_NODES.map(version => join(this.tools.node, `node-v${version}-win-x64`, 'node.exe')),
    });
    gate.publisherNode = gate.nodes[2];
    gate.probe = (file, args) => this.probe(file, args);
    gate.command = (file, args, timeout, allowFailure) => this.command(gate, file, args, allowFailure);
    gate.git = (cwd, args) => this.git(cwd, args);
    gate.readSource = root => ({ version: JSON.parse(readFileSync(join(root, 'package.json'))).version,
      head: this.heads.get(root), tree: 'c'.repeat(40), names: ['package.json'] });
    gate.runCase = (name, mode) => this.runCase(gate, name, mode);
    gate.sessionLane = input => this.sessionLane(gate, input);
    gate.openRun(resume);
    return gate;
  }

  probe(file, args) {
    if (file === 'git') return `${this.execPath}\n`;
    if (file === 'docker') return `${JSON.stringify(this.server)}\n`;
    assert.deepEqual([file, ...args], ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']);
    return ['', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
      `    CurrentBuildNumber    REG_SZ    ${this.windows.build}`, `    CurrentBuild    REG_SZ    ${this.windows.build}`,
      `    UBR    REG_DWORD    0x${this.windows.ubr.toString(16)}`, ''].join('\r\n');
  }

  command(gate, file, args, allowFailure = false) {
    let result = { status: 0, signal: null, error: null, stdout: '', stderr: '' };
    if (file === 'docker') result = this.docker(args.slice(4));
    else if (file === 'git') result.stdout = `${this.execPath}\n`;
    else result.stdout = `v${/node-v([\d.]+)-win-x64/.exec(file)[1]}\n`;
    writeFileSync(join(gate.output, 'commands', `${++gate.commandIndex}.json`),
      `${JSON.stringify({ file, args, ...result })}\n`, { flag: 'wx' });
    if (!allowFailure) assert.equal(result.status, 0, `${file} failed: ${result.stderr}`);
    return result;
  }

  docker([verb, id]) {
    const done = stdout => ({ status: 0, signal: null, error: null, stdout, stderr: '' });
    if (verb === 'ps') return done([...this.containers.keys()].join('\n'));
    if (verb === 'inspect') {
      const container = this.containers.get(id);
      if (!container) return { status: 1, signal: null, error: null, stdout: '[]', stderr: `Error: No such object: ${id}` };
      return done(JSON.stringify([{ Id: id, Config: { Labels: { 'pacemaker.local-gate': container.owner } },
        State: { Running: container.running, Pid: container.pid } }]));
    }
    if (verb === 'kill') {
      const container = this.containers.get(id);
      container.running = false;
      if (!container.stuck) container.pid = 0;
    }
    if (verb === 'rm') this.containers.delete(id);
    return done('');
  }

  git(cwd, args) {
    if (args[0] === 'bundle') {
      const step = `inputs-${JSON.parse(readFileSync(join(cwd, 'package.json'))).version}`;
      if (this.failures.delete(step)) throw new Error(`SYNTHETIC failure: ${step}`);
      writeFileSync(args[2], 'SYNTHETIC: not a Git bundle');
      return '';
    }
    if (args[0] === 'rev-parse') return `${args[1] === 'HEAD' ? this.heads.get(cwd) : 'c'.repeat(40)}\n`;
    if (args[0] === 'status') return '?? package.json\n';
    if (args[0] === 'ls-tree') return `100644 blob ${'d'.repeat(40)}\tpackage.json\0`;
    assert.deepEqual(args, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate']);
    return 'package.json\0';
  }

  runCase(gate, name, mode) {
    this.ran.push(name);
    writeFileSync(join(gate.output, `${name}-storage-admission.json`), '[]', { flag: 'wx' });
    const directory = join(gate.output, name);
    mkdirSync(join(directory, 'guest'), { recursive: true });
    gate.docker(['create', '--name', `pacemaker-local-${gate.owner}-${name}`]);
    writeFileSync(join(directory, 'guest', 'runtime.json'), JSON.stringify({ owner: gate.owner, name }));
    const failed = this.failures.delete(name);
    const result = { name, mode, image: gate.image, status: failed ? 'failed' : 'passed', removed: true,
      ...(failed ? { error: 'SYNTHETIC case failure' } : {}) };
    gate.results.push(result);
    writeFileSync(join(directory, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
    this.hooks.get(name)?.(gate);
    if (failed) throw new Error(`SYNTHETIC failure: ${name}`);
  }

  sessionLane(gate, input) {
    this.ran.push('session-lane');
    if (this.failures.delete('session-lane')) throw new Error('SYNTHETIC failure: session-lane');
    const receipt = { schemaVersion: 1, kind: 'host-session-lane', runId: gate.owner, version: input.manifest.version,
      head: input.manifest.head, node: 'v24.21.0', files: [...SESSION_REQUIRED_TESTS],
      startedAt: new Date().toISOString(), completedAt: new Date().toISOString(),
      context: { contract: 'session-required', platform: 'win32', role: 'user-runtime', verified: true,
        sessionVerified: true },
      totals: { tests: 4, pass: 4, fail: 0, cancelled: 0, skipped: 0, todo: 0 }, contained: false };
    writeFileSync(join(gate.output, 'session-lane.json'), `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx' });
    this.hooks.get('session-lane')?.(gate);
    return receipt;
  }

  // What a killed launcher leaves: a started step, its partial evidence, a still-running owned
  // container, a receipt cut off mid-write and a state write cut off before its rename. There is
  // no report and no completion record.
  interrupt(gate, step) {
    gate.state.begin(step);
    writeFileSync(join(gate.output, `${step}-storage-admission.json`), '[]', { flag: 'wx' });
    mkdirSync(join(gate.output, step));
    this.containers.set(LEFTOVER_CONTAINER, { owner: gate.owner, running: true, pid: 4321 });
    gate.docker(['create', '--name', `pacemaker-local-${gate.owner}-${step}`]);
    writeFileSync(join(gate.output, 'commands', `${gate.commandIndex + 1}.json`), '', { flag: 'wx' });
    writeFileSync(join(gate.output, 'run-state.json.tmp'), '{"schemaVersion":1,"checkpoints":[');
  }

  failRun(step) {
    this.failures.add(step);
    assert.throws(() => this.gate().run(), { message: `SYNTHETIC failure: ${step}` });
    assert.equal(this.json('result.json').status, 'failed');
    this.ran.length = 0;
  }

  // Returns the undo, so a test can restore the exact original bytes.
  replace(path, bytes) {
    const original = readFileSync(path);
    writeFileSync(path, bytes);
    return () => writeFileSync(path, original);
  }

  json(path) {
    return JSON.parse(readFileSync(join(this.output, path)));
  }

  inputs() {
    return new Map(['1.3.1', '2.1.0'].map(version => [version, { manifest: this.json(`inputs-${version}/manifest.json`) }]));
  }

  tree() {
    const snapshot = new InputSnapshot(this.output, { maxFiles: 100_000 });
    snapshot.addAll();
    return { files: snapshot.files, directories: snapshot.directories, attempts: existsSync(this.attempts) };
  }
}
