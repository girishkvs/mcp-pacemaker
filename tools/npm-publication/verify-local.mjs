import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InputSnapshot, verifyManifest, physical } from './local-inputs.mjs';
import { LocalSourceReader } from './local-source.mjs';
import { LocalCaseReplay } from './local-case-evidence.mjs';
import { digest, sameDigests, npm12Contents } from './policy.mjs';
import { inspectTarball } from './tarball.mjs';
import {
  LOCAL_CONTRACT, LOCAL_CASES, LOCAL_NODES, LOCAL_VERSIONS, localHash, localCommitment,
  validateLocalRegression,
} from './local-regression.mjs';
import { readLocalBytes, readLocalJson, controllerBinding, evidenceInventory, evidenceTar } from './local-evidence.mjs';
import { validateContainer } from './local-windows.mjs';
import { bindStageProofCheckout, requireStageProofCheckout } from './stage-proof-contract.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const IMAGE = 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9';
const sameFiles = (a, b) => assert.deepEqual([...a].sort((x, y) => x.path.localeCompare(y.path)),
  [...b].sort((x, y) => x.path.localeCompare(y.path)));

export function verifyLocalHeader(report) {
  assert.equal(report?.schemaVersion, 2, 'A fresh schema 2 outer local report is required');
  assert.equal(report.kind, 'private-local-publication-run');
  assert.equal(report.contract, LOCAL_CONTRACT);
  assert.equal(report.status, 'passed', 'Original complete local run did not pass');
  assert.equal(report.scope, 'both-release-lines-local-only', 'Controls-only/diagnostics are not a complete gate');
  assert.equal(report.releaseReady, false);
  assert.equal(report.ciImageEquivalent, false);
  assert.equal(report.image, IMAGE);
  assert.match(report.runId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.ok(Number.isFinite(Date.parse(report.startedAt)) &&
    Date.parse(report.startedAt) <= Date.parse(report.completedAt) &&
    Date.parse(report.completedAt) <= Date.now());
  assert.equal(report.error, undefined);
  assert.deepEqual(report.nodes.map(item => item.version), LOCAL_NODES);
  assert.deepEqual(report.cases.map(item => item.name).sort(), LOCAL_CASES.map(item => item.name).sort());
  assert.equal(report.cases.length, 9);
  return report;
}

export function verifyCommandTimeout(command) {
  assert.equal(typeof command.label, 'string');
  assert.ok(Number.isSafeInteger(command.timeoutMs), 'Missing or invalid recorded local command timeoutMs');
  const expected = command.label === 'Complete source suite' ? 25 * 60_000 : 15 * 60_000;
  assert.equal(command.timeoutMs, expected, 'Recorded local command timeoutMs differs from the reviewed harness budget');
  assert.ok(Number.isSafeInteger(command.elapsedMs) &&
    command.elapsedMs >= 0, 'Missing or invalid original command duration');
}

// Component replay also supports retained schema-1/2/3 diagnostics. It does not qualify a case or report.
export async function verifyRecordedSteps(directory, gate, sourceRoot, version, options = {}) {
  assert.equal(gate.kind, 'local-publication-regression');
  assert.ok([1, 2, 3, 4].includes(gate.schemaVersion));
  assert.equal(gate.status, 'passed');
  assert.equal(gate.releaseReady, false);
  assert.equal(gate.publicationCandidate, false);
  assert.equal(gate.originalPreserved, true);
  assert.equal(gate.error, undefined);
  assert.equal(gate.originalError, undefined);
  assert.ok(gate.steps.length > 0 &&
    gate.steps.length <= 10_000);
  const commands = gate.steps.map((step, index) => {
    assert.equal(step.file, `command-${index + 1}.json`);
    const bytes = readLocalBytes(join(directory, step.file));
    assert.equal(localHash(bytes), step.sha256);
    const command = JSON.parse(bytes.toString('utf8'));
    verifyCommandTimeout(command);
    for (const value of [command, step]) {
      assert.equal(value.exitCode, 0, 'Original local command failed');
      assert.equal(value.signal, null);
      assert.equal(value.error, null);
    }
    assert.equal(command.label, step.label);
    assert.ok(Array.isArray(command.args) &&
      command.args.every(arg => typeof arg === 'string'));
    assert.ok(['base64', 'utf8'].includes(command.encoding));
    assert.equal(typeof command.stdout, 'string');
    assert.equal(typeof command.stderr, 'string');
    return command;
  });
  assert.deepEqual(readdirSync(directory).filter(name => /^command-/.test(name)).sort(),
    gate.steps.map(step => step.file).sort(), 'Missing or extra raw command receipts');
  return new LocalCaseReplay(commands, gate, sourceRoot, version, options).verify(directory);
}

export async function verifyRawSteps(directory, gate, sourceRoot, version, options = {}) {
  assert.equal(gate.schemaVersion, 4, 'Fresh inner schema 4 with an explicit checkout policy is required');
  const packOutput = await verifyRecordedSteps(directory, gate, sourceRoot, version, options);
  requireStageProofCheckout(options.checkout, sourceRoot, gate.source.head, version);
  const artifact = gate.checks['checkout-false'].artifact;
  assert.equal(artifact.evidenceFile, 'fixture.tgz');
  const bytes = readLocalBytes(join(directory, 'fixture.tgz'), 32 * 1024 ** 2);
  sameDigests(digest(bytes), artifact);
  const approval = { version, commit: artifact.fixtureCommit };
  npm12Contents(packOutput, approval, bytes);
  assert.deepEqual(inspectTarball(bytes, approval).files, artifact.files);
}

export async function verifyLocalCase(root, result, expected, report, input, commands) {
  const directory = join(root, expected.name);
  assert.deepEqual(readLocalJson(join(directory, 'result.json')), result);
  assert.equal(result.name, expected.name);
  assert.equal(result.mode, expected.mode);
  assert.equal(result.status, 'passed');
  assert.equal(result.error, undefined);
  assert.equal(result.removed, true);
  assert.equal(result.image, report.image);
  assert.equal(result.container.state.Running, false);
  assert.equal(result.container.state.Pid, 0);
  assert.equal(result.container.state.OOMKilled, false);
  const id = result.container.id;
  assert.match(id, /^[a-f0-9]{64}$/);
  const inspections = commands.filter(item => item.file === 'docker' &&
    item.args[4] === 'inspect' &&
    item.args[5] === id);
  const lastPresent = inspections.filter(item => item.status === 0).at(-1);
  assert.ok(lastPresent, 'Missing original stopped-container inspection');
  const container = JSON.parse(lastPresent.stdout)[0];
  validateContainer(container, { id, owner: report.runId, image: report.image });
  assert.deepEqual(container.State, result.container.state);
  assert.deepEqual(container.HostConfig, result.container.hostConfig);
  const absent = inspections.at(-1);
  assert.equal(absent.error, null);
  assert.notEqual(absent.status, 0);
  assert.match(absent.stderr, /No such (?:object|container)/i);
  assert.ok(commands.some(item => item.file === 'docker' &&
    item.args[4] === 'rm' &&
    item.args[5] === id &&
    item.status === 0 &&
    item.error === null), 'Missing original container-removal receipt');
  const archive = readLocalBytes(join(directory, 'evidence.tar'), 128 * 1024 ** 2);
  assert.equal(result.copy.status, 0);
  assert.equal(result.copy.error, null);
  assert.equal(result.copy.bytes, archive.length);
  assert.equal(result.copy.archiveSha256, localHash(archive));
  const fromTar = evidenceTar(archive);
  const extracted = new InputSnapshot(join(directory, 'guest'), { maxBytes: 128 * 1024 ** 2, maxFiles: 10_000 });
  extracted.addAll();
  sameFiles(fromTar.files, extracted.files);
  assert.deepEqual(fromTar.directories, [...extracted.directories].sort());
  const guest = readLocalJson(join(directory, 'guest/runtime.json'));
  assert.deepEqual(result.guest, guest);
  assert.equal(guest.owner, report.runId);
  assert.equal(guest.platform, 'win32');
  assert.equal(guest.cpu, 4);
  const version = expected.node ?? LOCAL_NODES[2];
  const node = report.nodes.find(item => item.version === version);
  assert.equal(guest.node, `v${version}`);
  assert.equal(guest.nodeSha256, node.sha256);
  assert.equal(guest.publisherSha256, expected.mode === 'gate' ? report.nodes[2].sha256 : '-');
  assert.equal(guest.manifestSha256, input?.sha256 ?? '-');
  if (expected.mode === 'gate') {
    assert.equal(result.wait.error, null);
    assert.equal(result.wait.status, 0);
    assert.equal(result.container.state.ExitCode, 0);
    const gate = readLocalJson(join(directory, 'guest/gate/result.json'));
    assert.equal(gate.version, expected.version);
    assert.equal(gate.node, guest.node);
    assert.equal(gate.publisherNode, 'v24.21.0');
    assert.equal(gate.npm, '12.0.2');
    assert.equal(gate.source.head, input.manifest.head);
    assert.equal(gate.containment.manifestSha256, input.sha256);
    assert.deepEqual(gate.source.files, input.manifest.sourceIdentity.files.map(({ path, sha256 }) => ({ path, sha256 })));
    await verifyRawSteps(join(directory, 'guest/gate'), gate, join(input.directory, 'source'), expected.version,
      { checkout: input.checkout });
  } else if (expected.mode === 'fail') {
    assert.equal(result.wait.error, null);
    assert.equal(result.wait.status, 0);
    assert.equal(result.container.state.ExitCode, 1);
    const control = readLocalJson(join(directory, 'guest/control.json'));
    assert.equal(control.owner, report.runId);
    assert.equal(control.error.code, 'ERR_ASSERTION');
    assert.equal(control.error.actual, 1);
    assert.equal(control.error.expected, 2);
    assert.match(control.error.message, /Deliberate isolated assertion failure/);
  } else {
    assert.equal(result.wait.error, 'ETIMEDOUT');
    assert.equal(result.descendants.progressing, expected.mode === 'timeout');
    const { before, after } = result.descendants;
    assert.deepEqual(before.tree, after.tree);
    assert.equal(after.tree.owner, report.runId);
    assert.equal(new Set([after.tree.root, after.tree.child, after.tree.grandchild]).size, 3);
    assert.equal(after.heartbeat.pid, after.tree.grandchild);
    assert.deepEqual(readLocalJson(join(directory, 'guest/tree.json')), after.tree);
    const progressing = after.heartbeat.count > before.heartbeat.count &&
      before.alive.every(Boolean) &&
      after.alive.every(Boolean);
    assert.equal(progressing, expected.mode === 'timeout');
    assert.ok(after.heartbeat.count >= 2);
  }
}

export function compareInputSelection(root, prefix, manifest, selections) {
  const snapshot = new InputSnapshot(root, { maxFiles: 100_000, maxBytes: 3 * 1024 ** 3 });
  if (selections) for (const name of selections) snapshot.add(name);
  else snapshot.addAll();
  sameFiles(snapshot.files.map(file => ({ ...file, path: `${prefix}/${file.path}` })),
    manifest.files.filter(file => file.path.startsWith(`${prefix}/`)));
  const directories = new Set(snapshot.directories);
  for (const path of [...snapshot.directories, ...snapshot.files.map(file => file.path)]) {
    const parts = path.split('/');
    while (parts.length > 1) {
      parts.pop();
      directories.add(parts.join('/'));
    }
  }
  assert.deepEqual([...directories].map(name => `${prefix}/${name}`).sort(),
    manifest.directories.filter(name => name.startsWith(`${prefix}/`)).sort());
}

export async function verifyLocalEvidence({ directory, sourceRoots, toolRoots, controllerRoot = ROOT }) {
  physical(directory);
  const reportBytes = readLocalBytes(join(directory, 'result.json'));
  const report = verifyLocalHeader(JSON.parse(reportBytes.toString('utf8')));
  const evidenceBytes = readLocalBytes(join(directory, 'evidence-manifest.json'));
  const inventory = evidenceInventory(directory);
  assert.deepEqual(JSON.parse(evidenceBytes.toString('utf8')), inventory);
  assert.deepEqual(report.controller, controllerBinding(controllerRoot));
  const commandNames = readdirSync(join(directory, 'commands'));
  assert.deepEqual(commandNames.sort(),
    Array.from({ length: commandNames.length }, (_, index) => `${index + 1}.json`).sort());
  assert.ok(commandNames.length > 0);
  const commands = Array.from({ length: commandNames.length }, (_, index) =>
    readLocalJson(join(directory, 'commands', `${index + 1}.json`), 8 * 1024 ** 2));
  for (const name of ['local-windows-entry.mjs', 'local-inputs.mjs', 'local-environment.mjs']) {
    const path = `tools/npm-publication/${name}`;
    assert.equal(localHash(readLocalBytes(join(directory, 'controller', path))),
      report.controller.files.find(item => item.path === path).sha256);
  }
  assert.deepEqual(Object.keys(sourceRoots).sort(), LOCAL_VERSIONS);
  assert.deepEqual(Object.keys(toolRoots).sort(), ['git', 'node', 'npm', 'pwsh']);
  assert.equal(process.platform, 'win32', 'Verify the private Windows receipt on Windows');
  assert.equal(process.arch, 'x64');
  assert.equal(process.versions.node, '24.21.0', 'Use the retained publisher Node for final verification');
  assert.equal(localHash(readLocalBytes(process.execPath, 128 * 1024 ** 2)), report.nodes[2].sha256);
  const gitExecutable = join(toolRoots.git, 'cmd/git.exe');
  for (const node of report.nodes) {
    const name = `node-v${node.version}-win-x64/node.exe`;
    assert.equal(localHash(readLocalBytes(join(directory, 'runtime', name), 128 * 1024 ** 2)), node.sha256);
    assert.equal(localHash(readLocalBytes(join(toolRoots.node, name), 128 * 1024 ** 2)), node.sha256);
  }
  const inputs = new Map();
  const subjects = LOCAL_VERSIONS.map(version => {
    const input = join(directory, `inputs-${version}`);
    const bytes = readLocalBytes(join(input, 'manifest.json'));
    const manifest = JSON.parse(bytes.toString('utf8'));
    assert.equal(manifest.version, version);
    verifyManifest(input, manifest);
    const reader = new LocalSourceReader(sourceRoots[version], gitExecutable);
    const identity = reader.capture();
    assert.equal(identity.version, version);
    assert.deepEqual(manifest.sourceIdentity, identity, 'Local evidence is stale or not from clean final HEADs');
    assert.equal(manifest.head, identity.head);
    assert.deepEqual(manifest.sourcePaths, identity.files.map(item => item.path));
    compareInputSelection(sourceRoots[version], 'source', manifest,
      [...manifest.sourcePaths, 'node_modules', 'ui/node_modules']);
    compareInputSelection(toolRoots.npm, 'npm', manifest);
    compareInputSelection(toolRoots.pwsh, 'pwsh', manifest);
    compareInputSelection(toolRoots.git, 'git', manifest,
      ['cmd', 'mingw64/bin', 'mingw64/libexec/git-core', 'usr/bin', 'usr/share']);
    const checkout = bindStageProofCheckout({ root: join(input, 'source'), identity,
      readGit: args => reader.git(args, true) });
    const value = { directory: input, manifest, sha256: localHash(bytes), checkout };
    inputs.set(version, value);
    return { version, commit: identity.head, tree: identity.tree,
      treeEntriesSha256: localCommitment(identity.entries), checkoutFilesSha256: localCommitment(identity.files),
      inputManifestSha256: value.sha256 };
  });
  for (const expected of LOCAL_CASES) {
    await verifyLocalCase(directory, report.cases.find(item => item.name === expected.name), expected,
      report, inputs.get(expected.version), commands);
  }
  // This final re-enumeration catches changed receipts as well as changed live source/tool inputs.
  assert.deepEqual(evidenceInventory(directory), inventory);
  for (const version of LOCAL_VERSIONS) {
    const input = inputs.get(version);
    assert.deepEqual(new LocalSourceReader(sourceRoots[version], gitExecutable).capture(), input.manifest.sourceIdentity);
    verifyManifest(input.directory, input.manifest);
    compareInputSelection(sourceRoots[version], 'source', input.manifest,
      [...input.manifest.sourcePaths, 'node_modules', 'ui/node_modules']);
    compareInputSelection(toolRoots.npm, 'npm', input.manifest);
    compareInputSelection(toolRoots.pwsh, 'pwsh', input.manifest);
    compareInputSelection(toolRoots.git, 'git', input.manifest,
      ['cmd', 'mingw64/bin', 'mingw64/libexec/git-core', 'usr/bin', 'usr/share']);
  }
  assert.deepEqual(report.controller, controllerBinding(controllerRoot));
  for (const node of report.nodes) {
    assert.equal(localHash(readLocalBytes(join(toolRoots.node, `node-v${node.version}-win-x64/node.exe`),
      128 * 1024 ** 2)), node.sha256);
  }
  const statement = { schemaVersion: 1, kind: 'local-regression-integrity-checked', contract: LOCAL_CONTRACT,
    scope: report.scope, runId: report.runId, completedAt: report.completedAt,
    reportSha256: localHash(reportBytes), evidenceSha256: localHash(evidenceBytes),
    controllerSha256: report.controller.sha256, image: report.image, runtimes: report.nodes,
    subjects, coverage: { controls: 3, sourceCases: 6 }, releaseReady: false, executionProof: 'not-authenticated' };
  return validateLocalRegression(statement);
}

export async function main(args) {
  const names = ['--report', '--legacy-root', '--current-root', '--npm-root', '--git-root', '--pwsh-root', '--node-root'];
  assert.equal(args.length, names.length * 2);
  assert.deepEqual(args.filter((_, index) => index % 2 === 0), names);
  for (let index = 1; index < args.length; index += 2) assert.ok(isAbsolute(args[index]));
  const result = await verifyLocalEvidence({ directory: args[1],
    sourceRoots: { '1.3.1': args[3], '2.0.1': args[5] },
    toolRoots: { npm: args[7], git: args[9], pwsh: args[11], node: args[13] } });
  // No owner acceptance is generated. Full evidence and paths remain private.
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(process.argv.slice(2)); }
  catch {
    console.error('Local publication evidence rejected; no owner acceptance or publication authorization was created.');
    process.exitCode = 1;
  }
}
