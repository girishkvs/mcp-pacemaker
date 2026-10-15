import assert from 'node:assert/strict';
import { existsSync, lstatSync, mkdirSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { basename, join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { InputSnapshot, physical, safeName, verifyManifest } from './local-inputs.mjs';
import { evidenceInventory, readLocalBytes, readLocalJson } from './local-evidence.mjs';
import {
  LOCAL_CONTRACT, LOCAL_CONTROLS, LOCAL_NODES, exactLocalKeys, localCommitment, localHash, localSha, releaseRole,
  releaseVersions,
} from './local-regression.mjs';

export const LOCAL_RUN_STATE = 'run-state.json';
export const LOCAL_GIT_SELECTION = Object.freeze(['cmd', 'mingw64/bin', 'mingw64/libexec/git-core', 'usr/bin', 'usr/share']);
export const LOCAL_FROZEN_CONTROLLER = Object.freeze(['local-windows-entry.mjs', 'local-inputs.mjs', 'local-environment.mjs']
  .map(name => `tools/npm-publication/${name}`));
const FULL_SCOPE = 'both-release-lines-local-only';
const RUN_MEMBERS = Object.freeze([LOCAL_RUN_STATE, 'commands', 'controller', 'runtime', 'docker-config']);
const LEFTOVERS = Object.freeze(['result.json', 'evidence-manifest.json']);
const INVOCATION_KEYS = Object.freeze(['index', 'startedAt', 'completedAt', 'status', 'bindingSha256', 'reused', 'ran',
  'setAside', 'removedContainers']);
const RUN_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

// The order the controller executes. A resumed run continues it from the first step that has not passed.
export function localRunPlan(scope, versions) {
  const controls = LOCAL_CONTROLS.map(([name]) => name);
  if (scope === 'containment-controls-only') return controls;
  assert.equal(scope, FULL_SCOPE, 'Unknown local run scope');
  const [legacy, current] = releaseVersions(versions);
  return [...controls, `inputs-${current}`, `inputs-${legacy}`, 'session-lane',
    ...[current, legacy].flatMap(version => LOCAL_NODES.flatMap(node => [
      ...(releaseRole(version) === 'current' ? [`audit-v${version}-node${node}`] : []),
      `v${version}-node${node}`,
    ]))];
}

// A named pipe is released by the OS when its owner exits, however it exits, so a killed
// invocation never leaves a stale lock and a live one can never be resumed underneath.
export class LocalRunLock {
  constructor(output) {
    this.name = `\\\\.\\pipe\\mcp-pacemaker-local-gate-${localHash(resolve(output).toLowerCase())}`;
    this.server = null;
  }

  acquire() {
    return new Promise((accept, reject) => {
      const server = createServer();
      server.once('error', error => reject(error.code === 'EADDRINUSE'
        ? new Error('Another invocation is already using this run directory') : error));
      server.listen(this.name, () => {
        this.server = server;
        accept();
      });
    });
  }

  release() {
    const server = this.server;
    this.server = null;
    return new Promise(done => {
      if (server) server.close(() => done());
      else done();
    });
  }
}

export class LocalRunState {
  constructor(output) {
    this.output = output;
    this.path = join(output, LOCAL_RUN_STATE);
    this.hashes = [];
    this.value = null;
  }

  digest(root, selections) {
    const snapshot = new InputSnapshot(root, { maxBytes: 3 * 1024 ** 3, maxFiles: 100_000 });
    if (selections) for (const name of selections) snapshot.add(name);
    else snapshot.addAll();
    return { snapshot, fingerprint: this.commitment(snapshot.files, snapshot.directories) };
  }

  manifestDigest(manifest, prefix) {
    const strip = path => path.slice(prefix.length + 1);
    const files = manifest.files.filter(file => file.path.startsWith(`${prefix}/`))
      .map(file => ({ ...file, path: strip(file.path) }));
    return this.commitment(files, manifest.directories.filter(name => name.startsWith(`${prefix}/`)).map(strip));
  }

  // Canonical form, so a live selection and the frozen copy of the same bytes commit identically.
  commitment(files, directories) {
    const closure = new Set(directories);
    for (const path of [...directories, ...files.map(file => file.path)]) {
      const parts = path.split('/');
      while (parts.length > 1) {
        parts.pop();
        closure.add(parts.join('/'));
      }
    }
    const ordered = this.byPath(files.map(({ path, size, sha256 }) => ({ path, size, sha256 })));
    return { files: ordered.length, sha256: localCommitment({ files: ordered, directories: [...closure].sort() }) };
  }

  byPath(items) {
    return [...items].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  }

  members(step) {
    if (step === 'session-lane') return ['session-lane.json'];
    if (step.startsWith('inputs-')) return [`${step}/manifest.json`];
    return [step, `${step}-storage-admission.json`];
  }

  owned(step) {
    return step.startsWith('inputs-') ? [step] : this.members(step);
  }

  isCase(step) {
    return step !== 'session-lane' &&
      !step.startsWith('inputs-');
  }

  receipts() {
    const names = readdirSync(physical(join(this.output, 'commands')));
    const expected = Array.from({ length: names.length }, (_, index) => `${index + 1}.json`);
    assert.deepEqual([...names].sort(), expected.sort(), 'The command journal is not contiguous');
    return names.length;
  }

  journal(count) {
    for (let index = this.hashes.length; index < count; index++) {
      this.hashes.push(localHash(readLocalBytes(join(this.output, 'commands', `${index + 1}.json`), 8 * 1024 ** 2)));
    }
    return localCommitment(this.hashes.slice(0, count));
  }

  read() {
    assert.ok(existsSync(this.path), 'Missing local run state');
    return readLocalJson(this.path, 8 * 1024 ** 2);
  }

  // The temporary file only exists if a write was cut off before its rename. It never holds a
  // committed state, so the next write replaces it rather than treating it as evidence.
  write() {
    const temporary = `${this.path}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(this.value, null, 2)}\n`, { flush: true });
    renameSync(temporary, this.path);
  }

  invocation(index, startedAt, reused, setAside) {
    return { index, startedAt, completedAt: null, status: 'running', bindingSha256: this.value.bindingSha256, reused,
      ran: [], setAside, removedContainers: [] };
  }

  create(binding, startedAt) {
    assert.equal(existsSync(this.path), false, 'Run state already exists');
    this.value = { schemaVersion: 1, kind: 'private-local-publication-run-state', contract: LOCAL_CONTRACT,
      runId: binding.runId, startedAt, plan: localRunPlan(binding.scope, binding.sources.map(item => item.version)),
      binding, bindingSha256: localCommitment(binding), checkpoints: [], invocations: [] };
    this.value.invocations.push(this.invocation(1, startedAt, [], null));
    this.write();
  }

  load() {
    assert.ok(existsSync(this.path), 'This run has no run-state.json; only runs started by this controller can be resumed');
    this.value = this.history(this.read(), false);
    assert.equal(this.value.binding.scope, FULL_SCOPE, 'Only a full qualification run can be resumed');
    const last = this.value.invocations.at(-1);
    if (last.status === 'passed') {
      const recorded = this.recordedInventory();
      // Only a finish cut off after the pass was recorded leaves the inventory absent or partly
      // written. That run resumes and reruns nothing; any other passed run refuses.
      if (recorded !== null) {
        assert.ok(isDeepStrictEqual(recorded, evidenceInventory(this.output)), 'The evidence changed after the run passed');
        assert.fail('This run already passed; there is nothing to resume');
      }
      last.status = 'failed';
      last.error = 'The run passed but its evidence inventory was not written';
    }
    return this.value;
  }

  // Null only for an absent or unparseable inventory. Any other read failure refuses the resume.
  recordedInventory() {
    const path = join(this.output, 'evidence-manifest.json');
    let stat;
    try {
      stat = lstatSync(path);
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    const empty = stat.isFile() &&
      stat.size === 0;
    if (empty) return null;
    const bytes = readLocalBytes(path);
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch {
      return null;
    }
  }

  // Read-only: a refused resume leaves every member of the run directory exactly as it was.
  preflight(binding) {
    const state = this.value;
    for (const key of Object.keys(state.binding)) {
      assert.deepEqual(binding[key], state.binding[key], `Resume refused: the ${key} binding differs from the original run`);
    }
    assert.equal(localCommitment(binding), state.bindingSha256, 'Resume refused: the run binding differs');
    for (const name of RUN_MEMBERS) assert.ok(existsSync(join(this.output, name)), `Missing run member: ${name}`);
    const kept = new Set([...RUN_MEMBERS, `${LOCAL_RUN_STATE}.tmp`,
      ...state.checkpoints.flatMap(item => this.owned(item.step))]);
    const movable = new Set([...LEFTOVERS,
      ...state.plan.slice(state.checkpoints.length).flatMap(step => this.owned(step))]);
    const members = readdirSync(physical(this.output)).filter(name => !kept.has(name)).sort();
    for (const name of members) assert.ok(movable.has(name), `Unexpected run member; refusing to resume: ${name}`);
    const index = state.invocations.length + 1;
    const attempts = join(`${this.output}.attempts`, `before-invocation-${index}`);
    assert.equal(existsSync(attempts), false, 'The set-aside directory for this invocation already exists');
    this.frozen(state.binding);
    const last = state.checkpoints.at(-1);
    const bound = last?.commands ?? 0;
    const receipts = this.receipts();
    assert.ok(receipts >= bound, 'The command journal is shorter than its last checkpoint');
    if (last) assert.equal(this.journal(bound), last.commandsSha256, 'Command receipts changed after they were checkpointed');
    for (const checkpoint of state.checkpoints) this.reuse(checkpoint.step, true);
    return { index, bound, members, receipts: receipts > bound ? [bound + 1, receipts] : null, attempts };
  }

  frozen(binding) {
    const runtime = new InputSnapshot(join(this.output, 'runtime'));
    runtime.addAll();
    assert.deepEqual(runtime.files.map(({ path, sha256 }) => ({ path, sha256 })),
      binding.nodes.map(node => ({ path: `node-v${node.version}-win-x64/node.exe`, sha256: node.sha256 })),
      'The frozen runtime differs from the run binding');
    assert.deepEqual(runtime.directories, binding.nodes.map(node => `node-v${node.version}-win-x64`),
      'The frozen runtime differs from the run binding');
    const controller = new InputSnapshot(join(this.output, 'controller'));
    controller.addAll();
    assert.deepEqual(this.byPath(controller.files.map(({ path, sha256 }) => ({ path, sha256 }))),
      this.byPath(binding.controller.files.filter(item => LOCAL_FROZEN_CONTROLLER.includes(item.path))),
      'The frozen controller differs from the run binding');
    assert.deepEqual(controller.directories, ['tools', 'tools/npm-publication'],
      'The frozen controller differs from the run binding');
    assert.deepEqual(readdirSync(physical(join(this.output, 'docker-config'))), [], 'Unexpected private Docker configuration');
  }

  reuse(step, deep = false) {
    const checkpoint = this.value.checkpoints.find(item => item.step === step);
    assert.ok(checkpoint, `No checkpoint for ${step}`);
    const members = this.members(step);
    assert.ok(members.every(name => existsSync(join(this.output, name))), `Reused evidence is missing: ${step}`);
    assert.deepEqual(this.digest(this.output, members).fingerprint, checkpoint.evidence,
      `Reused evidence changed after it passed: ${step}`);
    if (step === 'session-lane') {
      const lane = readLocalJson(join(this.output, 'session-lane.json'));
      assert.equal(lane.runId, this.value.runId, 'The session-lane receipt belongs to another run');
      assert.equal(lane.totals?.fail, 0, 'The session-lane receipt did not pass');
    } else if (this.isCase(step)) {
      const result = readLocalJson(join(this.output, step, 'result.json'));
      assert.equal(result.name, step, 'A reused result names another case');
      assert.equal(result.status, 'passed', `The recorded result did not pass: ${step}`);
    } else if (deep) {
      const manifest = readLocalJson(join(this.output, step, 'manifest.json'));
      assert.equal(`inputs-${manifest.version}`, step, 'A frozen input names another version');
      try {
        verifyManifest(join(this.output, step), manifest);
      } catch (error) {
        throw new Error(`Reused evidence changed after it passed: ${step}`, { cause: error });
      }
      this.confirmInputs(manifest);
    }
  }

  confirmInputs(manifest) {
    const binding = this.value.binding;
    const source = binding.sources.find(item => item.version === manifest.version);
    assert.ok(source, 'The frozen input belongs to no bound source');
    assert.deepEqual({ version: manifest.version, head: manifest.head, tree: manifest.sourceIdentity?.tree,
      files: this.manifestDigest(manifest, 'source') }, source, 'Frozen source input differs from the run binding');
    for (const [name, fingerprint] of Object.entries(binding.tools)) {
      assert.deepEqual(this.manifestDigest(manifest, name), fingerprint, `Frozen ${name} input differs from the run binding`);
    }
  }

  accept({ index, bound, members, receipts, attempts }) {
    const state = this.value;
    const previous = state.invocations.at(-1);
    if (previous.status === 'running') previous.status = 'interrupted';
    const leftovers = members.length > 0 ||
      receipts !== null;
    const setAside = leftovers ? { directory: basename(attempts), members, commands: receipts } : null;
    state.invocations.push(this.invocation(index, new Date().toISOString(),
      state.checkpoints.map(item => item.step), setAside));
    // A clock that stepped back would otherwise only fail verification after the whole run.
    this.history(state, false);
    this.write();
    if (leftovers) {
      mkdirSync(attempts, { recursive: true });
      physical(attempts);
      for (const name of members) this.move(join(this.output, name), join(attempts, name));
      if (receipts) {
        mkdirSync(join(attempts, 'commands'));
        // Highest first, so a kill part way still leaves a contiguous journal for the next resume.
        for (let number = receipts[1]; number >= receipts[0]; number--) {
          this.move(join(this.output, 'commands', `${number}.json`), join(attempts, 'commands', `${number}.json`));
        }
      }
    }
    this.hashes.length = bound;
    return bound;
  }

  move(source, target) {
    renameSync(source, target);
  }

  begin(step) {
    const state = this.value;
    assert.equal(step, state.plan[state.checkpoints.length], 'Run steps must follow the recorded plan');
    state.invocations.at(-1).ran.push(step);
    this.write();
  }

  pass(step, commands) {
    const state = this.value;
    const invocation = state.invocations.at(-1);
    assert.equal(invocation.ran.at(-1), step, 'Only the step in progress can pass');
    assert.equal(step, state.plan[state.checkpoints.length], 'Run steps must follow the recorded plan');
    state.checkpoints.push({ step, invocation: invocation.index, completedAt: new Date().toISOString(),
      evidence: this.digest(this.output, this.members(step)).fingerprint, commands,
      commandsSha256: this.journal(commands) });
    this.write();
  }

  passed(step) {
    const position = this.value.plan.indexOf(step);
    assert.ok(position >= 0, `Step is not in the run plan: ${step}`);
    return position < this.value.checkpoints.length;
  }

  removed(id) {
    this.value.invocations.at(-1).removedContainers.push(id);
    this.write();
  }

  finish(report) {
    if (this.value === null) return null;
    const invocation = this.value.invocations.at(-1);
    invocation.completedAt = report.completedAt;
    invocation.status = report.status;
    if (report.status === 'failed') invocation.error = report.error || 'The run failed without a recorded error';
    this.write();
    return structuredClone(this.value.invocations);
  }

  history(state, complete) {
    exactLocalKeys(state, ['schemaVersion', 'kind', 'contract', 'runId', 'startedAt', 'plan', 'binding', 'bindingSha256',
      'checkpoints', 'invocations']);
    assert.equal(state.schemaVersion, 1);
    assert.equal(state.kind, 'private-local-publication-run-state');
    assert.equal(state.contract, LOCAL_CONTRACT);
    assert.match(state.runId, RUN_ID);
    assert.ok(Number.isFinite(Date.parse(state.startedAt)), 'Invalid run start');
    exactLocalKeys(state.binding, ['runId', 'scope', 'image', 'platform', 'arguments', 'controller', 'nodes', 'tools',
      'sources']);
    assert.equal(state.binding.runId, state.runId);
    assert.equal(state.bindingSha256, localCommitment(state.binding), 'The run binding does not match its commitment');
    assert.ok(Array.isArray(state.binding.sources), 'Invalid bound sources');
    assert.deepEqual(state.plan, localRunPlan(state.binding.scope, state.binding.sources.map(item => item.version)),
      'The recorded plan differs from the controller plan');
    assert.ok(Array.isArray(state.checkpoints) &&
      state.checkpoints.length <= state.plan.length, 'Invalid checkpoint list');
    assert.ok(Array.isArray(state.invocations) &&
      state.invocations.length > 0 &&
      state.invocations.length <= 1000, 'Invalid invocation list');
    let commands = 0;
    for (const [position, checkpoint] of state.checkpoints.entries()) {
      exactLocalKeys(checkpoint, ['step', 'invocation', 'completedAt', 'evidence', 'commands', 'commandsSha256']);
      assert.equal(checkpoint.step, state.plan[position], 'Checkpoints do not follow the run plan');
      exactLocalKeys(checkpoint.evidence, ['files', 'sha256']);
      assert.ok(Number.isSafeInteger(checkpoint.evidence.files) &&
        checkpoint.evidence.files > 0, 'Invalid checkpoint evidence');
      localSha(checkpoint.evidence.sha256);
      assert.ok(Number.isSafeInteger(checkpoint.commands) &&
        checkpoint.commands >= commands, 'The checkpointed command journal shrank');
      localSha(checkpoint.commandsSha256);
      commands = checkpoint.commands;
    }
    let passed = 0;
    for (const position of state.invocations.keys()) passed += this.invocationHistory(state, position, passed, complete);
    assert.equal(passed, state.checkpoints.length, 'A checkpoint belongs to no recorded invocation');
    if (complete) assert.equal(passed, state.plan.length, 'Not every planned step passed');
    return state;
  }

  invocationHistory(state, position, passed, complete) {
    const invocation = state.invocations[position];
    const previous = state.invocations[position - 1];
    const recorded = Object.hasOwn(invocation ?? {}, 'error');
    exactLocalKeys(invocation, [...INVOCATION_KEYS, ...(recorded ? ['error'] : [])]);
    assert.equal(invocation.index, position + 1, 'The invocation history has a gap or duplicate');
    assert.equal(invocation.bindingSha256, state.bindingSha256, 'An invocation was bound to different inputs or controller');
    let statuses = ['failed', 'interrupted'];
    if (position === state.invocations.length - 1) statuses = complete ? ['passed'] : ['running', 'failed', 'passed'];
    assert.ok(statuses.includes(invocation.status), `Invalid status for invocation ${invocation.index}`);
    assert.equal(recorded, invocation.status === 'failed', 'A failed invocation, and only a failed one, records its error');
    if (recorded) {
      assert.ok(typeof invocation.error === 'string' &&
        invocation.error.length > 0, 'A failed invocation must record its error');
    }
    const started = Date.parse(invocation.startedAt);
    assert.ok(Number.isFinite(started), 'Invalid invocation start');
    if (previous) {
      const earlier = state.checkpoints.slice(0, passed).map(item => Date.parse(item.completedAt));
      const floor = Math.max(Date.parse(previous.completedAt ?? previous.startedAt), ...earlier);
      assert.ok(started >= floor, 'Invocations overlap or are out of order');
    } else assert.equal(invocation.startedAt, state.startedAt, 'The first invocation must start the run');
    const open = invocation.status === 'running' ||
      invocation.status === 'interrupted';
    if (open) assert.equal(invocation.completedAt, null, 'An unfinished invocation cannot record a completion time');
    else assert.ok(Date.parse(invocation.completedAt) >= started, 'Invalid invocation completion time');
    assert.deepEqual(invocation.reused, state.plan.slice(0, passed), 'Reused steps are not the passed plan prefix');
    const own = state.checkpoints.filter(item => item.invocation === invocation.index);
    const steps = state.plan.slice(passed, passed + own.length);
    assert.deepEqual(own.map(item => item.step), steps, 'Steps passed out of plan order');
    assert.ok(Array.isArray(invocation.ran), 'Invalid ran steps');
    assert.deepEqual(invocation.ran.slice(0, own.length), steps, 'Ran steps are out of plan order');
    if (invocation.status === 'passed') {
      assert.equal(passed + own.length, state.plan.length, 'A passed invocation did not complete the plan');
    }
    const unfinished = invocation.ran.length - own.length;
    const stopped = unfinished === 1 &&
      invocation.status !== 'passed' &&
      invocation.ran.at(-1) === state.plan[passed + own.length];
    assert.ok(unfinished === 0 ||
      stopped, 'Ran steps are out of plan order');
    for (const checkpoint of own) {
      const at = Date.parse(checkpoint.completedAt);
      const inside = at >= started &&
        (open ||
          at <= Date.parse(invocation.completedAt));
      assert.ok(inside, 'A checkpoint lies outside its invocation');
    }
    this.leftoverHistory(invocation, position, state.checkpoints[passed - 1]?.commands ?? 0);
    return own.length;
  }

  leftoverHistory(invocation, position, bound) {
    assert.ok(Array.isArray(invocation.removedContainers) &&
      invocation.removedContainers.every(id => /^[a-f0-9]{64}$/.test(id)), 'Invalid removed container record');
    if (position === 0) {
      assert.equal(invocation.setAside, null, 'The first invocation cannot set evidence aside');
      assert.deepEqual(invocation.removedContainers, [], 'The first invocation cannot inherit containers');
      return;
    }
    if (invocation.setAside === null) return;
    exactLocalKeys(invocation.setAside, ['directory', 'members', 'commands']);
    assert.equal(invocation.setAside.directory, `before-invocation-${invocation.index}`, 'Invalid set-aside directory');
    assert.ok(Array.isArray(invocation.setAside.members), 'Invalid set-aside members');
    for (const name of invocation.setAside.members) safeName(name);
    const range = invocation.setAside.commands;
    const validRange = range === null ||
      (Array.isArray(range) &&
        range.length === 2 &&
        range.every(Number.isSafeInteger) &&
        range[0] === bound + 1 &&
        range[1] >= range[0]);
    assert.ok(validRange, 'Invalid set-aside receipt range');
    assert.ok(invocation.setAside.members.length > 0 ||
      range !== null, 'An empty set-aside must be recorded as null');
  }

  verify(report, inputs) {
    const state = this.history(this.read(), true);
    this.value = state;
    assert.equal(report.runId, state.runId, 'The run state belongs to another run');
    assert.equal(report.startedAt, state.startedAt, 'The report and run state record different starts');
    assert.deepEqual(report.invocations, state.invocations, 'The report and run state record different histories');
    assert.equal(report.completedAt, state.invocations.at(-1).completedAt, 'The report did not end with its final invocation');
    const binding = state.binding;
    assert.equal(binding.scope, report.scope);
    assert.equal(binding.image, report.image);
    assert.deepEqual(binding.controller, report.controller, 'The run was bound to a different controller');
    assert.deepEqual(binding.nodes, report.nodes, 'The run was bound to different Node runtimes');
    assert.deepEqual(report.cases.map(item => item.name), state.plan.filter(step => this.isCase(step)),
      'Cases are missing, repeated or out of plan order');
    assert.equal(report.sessionLane.runId, report.runId, 'The session lane belongs to another run');
    assert.deepEqual(readLocalJson(join(this.output, 'session-lane.json')), report.sessionLane,
      'The reported session lane differs from its receipt');
    assert.deepEqual(binding.sources.map(item => item.version).sort(), [...inputs.keys()].sort());
    for (const input of inputs.values()) this.confirmInputs(input.manifest);
    this.frozen(binding);
    for (const checkpoint of state.checkpoints) {
      assert.deepEqual(this.digest(this.output, this.members(checkpoint.step)).fingerprint, checkpoint.evidence,
        `Evidence changed after it passed: ${checkpoint.step}`);
      assert.equal(this.journal(checkpoint.commands), checkpoint.commandsSha256, 'A checkpointed command receipt changed');
    }
    return state;
  }
}
