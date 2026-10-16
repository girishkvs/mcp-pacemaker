import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  LOCAL_CONTRACT, LOCAL_NODES, localCases, localHash, localCommitment, releaseRole, releaseVersions,
  validateLocalRegression, validateLocalApproval, validatePreparedLocal, validateLocalManifest,
} from '../tools/npm-publication/local-regression.mjs';
import { treeEntries, captureSourceIdentity, validateSourceSubject } from '../tools/npm-publication/local-source.mjs';
import { readOwnerLocalAcceptance, publicationHelperEnvironment } from '../tools/npm-publication/local-regression-hosted.mjs';
import { verifyLocalHeader, verifyRawSteps, verifyRecordedSteps, verifyLocalEvidence, verifyAuditSteps, compareInputSelection,
  verifyCommandTimeout } from '../tools/npm-publication/verify-local.mjs';
import { evidenceTar, evidenceInventory } from '../tools/npm-publication/local-evidence.mjs';
import { submitOnce, validateCi } from '../tools/npm-publication/policy.mjs';
import { main as publicationMain } from '../tools/npm-publication/run.mjs';
import { LocalCaseFixture } from './helpers/local-case-fixture.mjs';
import { syntheticCleanProducerEvidence } from './helpers/local-regression-fixture.mjs';
import { physical } from '../tools/npm-publication/local-inputs.mjs';
import './helpers/npm-publication-local-audit.mjs';
import { syntheticAuditReport } from './helpers/npm-publication-local-audit.mjs';
import { auditArguments, AUDIT_COMMAND_TIMEOUT_MS } from '../tools/npm-publication/local-audit-report.mjs';
import { nativeRestoreArguments, LOCAL_NATIVE_PATHS, sourceSuiteLabel, SOURCE_SUITE_TIMEOUT_MS } from '../tools/npm-publication/local-gate.mjs';
import { SESSION_REQUIRED_TESTS } from '../tools/ci/test-contracts.mjs';
import { CheckoutProofFixture } from './helpers/npm-publication-checkout-proof.mjs';
import { LocalRunState, localRunPlan } from '../tools/npm-publication/local-run-state.mjs';
import { ResumeFixture } from './helpers/local-resume-fixture.mjs';
import {
  PUBLISHED_LEGACY_STAGE_CONTRACT, STAGE_PROOF_FILES, sourceStageContract, validateStageProof,
} from '../tools/npm-publication/stage-proof-contract.mjs';

test('Historical proof selection requires exact source, tree, role and every independently pinned Git member', () => {
  const pin = PUBLISHED_LEGACY_STAGE_CONTRACT;
  const source = { version: pin.version, head: pin.head, tree: pin.tree };
  const selected = sourceStageContract(source, pin.members);
  assert.equal(selected.paths.length, 20);
  assert.equal(selected.id, `git:${pin.head}`);
  for (const change of [
    value => { value.version = '2.0.1'; }, value => { value.version = '1.3.2'; },
    value => { value.tree = '0'.repeat(40); },
  ]) {
    const changed = structuredClone(source);
    change(changed);
    assert.throws(() => sourceStageContract(changed, pin.members));
  }
  for (const change of [
    entries => entries.pop(),
    entries => { entries.find(item => item.path.endsWith('stage-sdk-loader.json')).blob = '0'.repeat(40); },
    entries => { entries.find(item => item.path.endsWith('stage-proof-contract.mjs')).blob = '0'.repeat(40); },
    entries => { entries[0].mode = '100755'; },
  ]) {
    const entries = structuredClone(pin.members);
    change(entries);
    assert.throws(() => sourceStageContract(source, entries));
  }
  for (const version of ['1.3.1', '1.3.2', '2.0.2', '2.7.13']) {
    assert.deepEqual(sourceStageContract({ ...source, head: 'a'.repeat(40), version }, pin.members),
      { id: 'current-v4', paths: STAGE_PROOF_FILES });
  }
});

test('Current checkout binding rejects a historical-sized, swapped or extended report inventory', t => {
  const f = new CheckoutProofFixture(t).create();
  const options = { root: f.root, version: f.version, sourceHead: f.identity.head, checkout: f.binding(),
    invocation: f.invocation };
  validateStageProof(f.report, options);
  for (const files of [
    f.report.files.slice(0, 20),
    [...f.report.files, { path: 'extra.mjs', sha256: '0'.repeat(64) }],
    PUBLISHED_LEGACY_STAGE_CONTRACT.members.map(item => ({ path: item.path, sha256: '0'.repeat(64) })),
  ]) {
    assert.throws(() => validateStageProof({ ...f.report, files }, options));
  }
});

// All positive objects below are SYNTHETIC UNIT FIXTURES. None are report evidence or owner acceptance.
class Fixtures {
  statement(version = '2.0.1') {
    const peerVersion = releaseRole(version) === 'legacy' ? '2.0.1' : '1.3.1';
    return { schemaVersion: 1, kind: 'local-regression-integrity-checked', contract: LOCAL_CONTRACT,
      scope: 'both-release-lines-local-only', runId: '11111111-1111-4111-8111-111111111111',
      completedAt: new Date(Date.now() - 60_000).toISOString(), reportSha256: 'a'.repeat(64),
      evidenceSha256: 'b'.repeat(64), controllerSha256: 'c'.repeat(64),
      image: 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9',
      runtimes: LOCAL_NODES.map(version => ({ version, sha256: 'd'.repeat(64) })),
      subjects: releaseVersions([version, peerVersion]).map((version, index) => ({ version,
        commit: String(index + 1).repeat(40), tree: String(index + 3).repeat(40),
        treeEntriesSha256: 'e'.repeat(64), checkoutFilesSha256: 'f'.repeat(64),
        inputManifestSha256: 'a'.repeat(64) })),
      coverage: { controls: 3, sourceCases: 6 }, releaseReady: false, executionProof: 'not-authenticated' };
  }

  review(statement) {
    return { reviewer: 'girishkvs', scope: 'private-local-regression-evidence', disposition: 'accepted',
      statementSha256: localCommitment(statement), reviewedAt: new Date(Date.now() - 1000).toISOString() };
  }

  approval(scope = 'prepare') {
    const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
    const localRegression = this.statement(version);
    const source = localRegression.subjects.find(item => item.version === version);
    return { schemaVersion: 1, scope, name: 'mcp-pacemaker', version, commit: source.commit, tree: source.tree,
      ref: `refs/tags/npm-r5/v${version}`, tagObject: '5'.repeat(40), approver: 'girishkvs',
      approvedAt: new Date().toISOString(), ciRunId: '100', ciAttempt: 1,
      publicPackages: ['mcp-pacemaker'], localRegression,
      ...(scope === 'prepare' ? { localRegressionReview: this.review(localRegression) } :
        { ownerPreflight: { privateContentReview: { localRegression: this.review(localRegression) } } }) };
  }

  hosted() {
    const approval = this.approval();
    const owner = { login: 'girishkvs', id: 17 };
    const repository = { id: 23, full_name: 'girishkvs/mcp-pacemaker', private: false, fork: false, owner };
    const event = { sender: owner, repository, inputs: { action: 'prepare', approval: JSON.stringify(approval) } };
    const env = {
      GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
      RUNNER_ENVIRONMENT: 'github-hosted', ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: repository.full_name,
      GITHUB_SHA: approval.commit, GITHUB_REF: approval.ref, GITHUB_WORKFLOW_SHA: approval.commit,
      GITHUB_WORKFLOW_REF: `${repository.full_name}/.github/workflows/npm-publish.yml@${approval.ref}`,
      GITHUB_RUN_ID: '71', GITHUB_RUN_ATTEMPT: '1', GITHUB_REPOSITORY_ID: '23',
      GITHUB_REPOSITORY_OWNER_ID: '17', GITHUB_ACTOR: 'girishkvs', GITHUB_TRIGGERING_ACTOR: 'girishkvs',
    };
    const run = { id: 71, run_attempt: 1, head_sha: approval.commit, path: '.github/workflows/npm-publish.yml',
      event: 'workflow_dispatch', status: 'in_progress', conclusion: null, repository,
      head_repository: repository, actor: owner, triggering_actor: owner };
    return { approval, env, event, run };
  }

  prepared(approval) {
    const source = { version: approval.version, commit: approval.commit,
      rootLockSha256: '1'.repeat(64), uiLockSha256: '2'.repeat(64) };
    return { version: approval.version,
      source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]])),
      producerLocks: { root: source.rootLockSha256, ui: source.uiLockSha256 },
      producerAdvisories: syntheticCleanProducerEvidence(source),
      preparationApproval: { scope: 'prepare', approver: 'girishkvs', approvedAt: approval.approvedAt },
      localRegression: approval.localRegression, localRegressionReview: this.review(approval.localRegression) };
  }

  directory(t) {
    const path = realpathSync.native(mkdtempSync(join(tmpdir(), 'pacemaker-enforcement-unit-')));
    t.after(() => rmSync(path, { recursive: true, force: true }));
    return path;
  }

  tar(path, data = Buffer.from('fixture'), type = '0') {
    const header = Buffer.alloc(512);
    header.write(path);
    header.write('0000644\0', 100);
    header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
    header.fill(32, 148, 156);
    header.write(type, 156);
    const checksum = [...header].reduce((a, b) => a + b, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
    return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512), Buffer.alloc(1024)]);
  }
}
const fixture = new Fixtures();

test('owned publication fixtures resolve aliased temporary parents without accepting linked inputs', async t => {
  const parent = fixture.directory(t);
  const target = join(parent, 'physical-temp');
  const alias = join(parent, 'temp-alias');
  mkdirSync(target);
  symlinkSync(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const previous = Object.fromEntries(['TEMP', 'TMP', 'TMPDIR'].map(key => [key, process.env[key]]));
  try {
    for (const key of Object.keys(previous)) process.env[key] = alias;
    assert.equal(tmpdir(), alias);
    assert.notEqual(realpathSync.native(alias), alias);
    const directory = fixture.directory(t);
    assert.equal(directory, realpathSync.native(directory));
    assert.doesNotThrow(() => physical(directory));
    for (const version of ['1.3.1', '2.0.1']) {
      const checkout = new CheckoutProofFixture(t, version).create();
      const complete = await new LocalCaseFixture(t, version).create();
      for (const root of [checkout.base, checkout.root, complete.base, complete.root, complete.directory]) {
        assert.equal(root, realpathSync.native(root));
        assert.doesNotThrow(() => physical(root));
      }
      assert.doesNotThrow(() => checkout.verify());
      await verifyRawSteps(complete.directory, complete.gate, complete.root, version, { checkout: complete.checkoutBinding });
    }
    assert.throws(() => physical(alias), /Linked input/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('SYNTHETIC statement schema is integrity-only and rejects success/authentication shortcuts', () => {
  const statement = fixture.statement();
  assert.equal(validateLocalRegression(statement).releaseReady, false);
  for (const mutate of [
    value => { value.authenticated = true; },
    value => { value.executionProof = 'verified'; },
    value => { value.releaseReady = true; },
    value => { value.schemaVersion = 0; },
    value => { value.coverage.sourceCases = 5; },
    value => { value.subjects.pop(); },
    value => { value.subjects[0] = value.subjects[1]; },
    value => { value.runtimes[0].version = '24.11.0'; },
    value => { value.subjects[0].commit = 'HEAD'; },
    value => { value.reportSha256 = 'passed'; },
    value => { value.path = 'Q:\\private\\anything'; },
  ]) {
    const copy = structuredClone(statement);
    mutate(copy);
    assert.throws(() => validateLocalRegression(copy));
  }
  assert.throws(() => validateLocalRegression({ status: 'passed', sha256: 'a'.repeat(64) }));
});

test('SYNTHETIC owner review must cover exact source/evidence; no automatic acceptance', () => {
  const approval = fixture.approval();
  validateLocalApproval(approval);
  for (const mutate of [
    value => { delete value.localRegressionReview; },
    value => { value.localRegressionReview.reviewer = 'someone-else'; },
    value => { value.localRegression.reportSha256 = '0'.repeat(64); },
    value => { value.commit = '0'.repeat(40); },
    value => { value.tree = '0'.repeat(40); },
    value => { value.localRegressionReview.reviewedAt = new Date(0).toISOString(); },
    value => { value.localRegressionReview.authenticated = true; },
    value => { value.localRegressionReview.disposition = 'pending'; },
  ]) {
    const copy = structuredClone(approval);
    mutate(copy);
    assert.throws(() => validateLocalApproval(copy));
  }
  const stage = fixture.approval('stage');
  validateLocalApproval(stage);
  delete stage.ownerPreflight.privateContentReview.localRegression;
  stage.localRegressionReview = fixture.review(stage.localRegression);
  assert.throws(() => validateLocalApproval(stage), 'Prepare review cannot replace fresh content review');
});

test('continuation retains original preparation time; a fresh action cannot reuse an expired review', () => {
  const approval = fixture.approval();
  const then = Date.now() - 2 * 3_600_000;
  approval.approvedAt = new Date(then).toISOString();
  approval.localRegression.completedAt = new Date(then - 60_000).toISOString();
  approval.localRegressionReview = fixture.review(approval.localRegression);
  approval.localRegressionReview.reviewedAt = new Date(then - 1000).toISOString();
  validateLocalApproval(approval, { continuing: true });
  assert.throws(() => validateLocalApproval(approval));
});

test('SYNTHETIC hosted reader requires actual run API data, exact actor IDs and exact dispatch input', async () => {
  const context = fixture.hosted();
  let reads = 0;
  const readers = { readJson: async path => {
    reads++;
    assert.equal(path, 'actions/runs/71');
    return context.run;
  } };
  const result = await readOwnerLocalAcceptance({ ...context, readers });
  assert.equal(result.kind, 'owner-dispatch-acceptance-not-execution-proof');
  assert.equal(reads, 1);
  await assert.rejects(readOwnerLocalAcceptance({ ...context, readers: {}, authenticated: true }));
  for (const mutate of [
    value => { value.run.actor = { login: 'girishkvs', id: 99 }; },
    value => { value.run.status = 'completed'; },
    value => { value.run.run_attempt = 2; },
    value => { value.run.path = '.github/workflows/ci.yml'; },
    value => { value.run.repository = { ...value.run.repository, id: 99 }; },
    value => { value.run.head_sha = '9'.repeat(40); },
    value => { value.event.inputs.approval = '{}'; },
    value => { value.env.RUNNER_ENVIRONMENT = 'self-hosted'; },
  ]) {
    const copy = structuredClone(context);
    mutate(copy);
    await assert.rejects(readOwnerLocalAcceptance({ ...copy, readers: { readJson: async () => copy.run } }));
  }
});

test('SYNTHETIC prepared and candidate bindings reject old artifacts and mismatched peer subjects', () => {
  const approval = fixture.approval();
  const prepared = fixture.prepared(approval);
  validatePreparedLocal(prepared, approval);
  assert.throws(() => validatePreparedLocal({}, approval));
  assert.throws(() => validatePreparedLocal(prepared, approval, { version: '1.3.1', commit: '9'.repeat(40), tree: '3'.repeat(40) }));
  const stage = fixture.approval('stage');
  stage.localRegression = approval.localRegression;
  stage.ownerPreflight.privateContentReview.localRegression = fixture.review(approval.localRegression);
  const bytes = Buffer.from(JSON.stringify(prepared));
  stage.artifact = { manifestSha256: localHash(bytes) };
  validateLocalManifest(bytes, stage, { localRegression: approval.localRegression,
    source: prepared.producerAdvisories.source, sourceChecks: prepared.producerAdvisories.checks,
    gates: { 'producer-advisories': prepared.producerAdvisories.gate } });
  assert.throws(() => validateLocalManifest(Buffer.from('{}'), stage));
  assert.throws(() => validateLocalManifest(bytes, stage, {}));
  const changed = structuredClone(prepared);
  delete changed.localRegression;
  const old = Buffer.from(JSON.stringify(changed));
  stage.artifact.manifestSha256 = localHash(old);
  assert.throws(() => validateLocalManifest(old, stage), 'Even hash-approved old artifacts must fail');
});

test('Git tree binding includes every path/blob/mode and rejects symlinks, duplicates and dirty source', t => {
  const blob = 'a'.repeat(40);
  assert.deepEqual(treeEntries(`100755 blob ${blob}\ttool.sh\0`), [{ path: 'tool.sh', mode: '100755', blob }]);
  for (const input of [
    `120000 blob ${blob}\tlink\0`, `160000 commit ${blob}\tsubmodule\0`,
    `100644 blob ${blob}\ta\0` + `100644 blob ${blob}\tA\0`, `100644 blob ${blob}\t../escape\0`,
  ]) assert.throws(() => treeEntries(input));
  const root = fixture.directory(t);
  writeFileSync(join(root, 'package.json'), '{"version":"2.0.1"}');
  let dirty = false;
  let conversion = false;
  const git = args => {
    if (args[0] === 'rev-parse') return args[1] === 'HEAD' ? '2'.repeat(40) : '4'.repeat(40);
    if (args[0] === 'status') return dirty ? ' M package.json' : '';
    if (args[0] === 'ls-tree') return `100644 blob ${blob}\tpackage.json\0`;
    if (args[0] === 'ls-files') return 'package.json\0';
    if (args[0] === 'check-attr') return `package.json\0filter\0${conversion ? 'driver' : 'unspecified'}\0package.json\0working-tree-encoding\0unspecified\0`;
    if (args[0] === 'hash-object') return blob;
    throw new Error('Unexpected synthetic Git operation');
  };
  const identity = captureSourceIdentity(root, git, { requireClean: true });
  const statement = fixture.statement();
  statement.subjects[1].treeEntriesSha256 = localCommitment(identity.entries);
  validateSourceSubject(identity, statement);
  const changed = structuredClone(identity);
  changed.entries[0].mode = '100755';
  assert.throws(() => validateSourceSubject(changed, statement));
  dirty = true;
  assert.throws(() => captureSourceIdentity(root, git, { requireClean: true }));
  dirty = false;
  conversion = true;
  assert.throws(() => captureSourceIdentity(root, git, { requireClean: true }), /conversion/);
  conversion = false;
  mkdirSync(join(root, '.git/info'), { recursive: true });
  writeFileSync(join(root, '.git/info/attributes'), '*.json -text');
  assert.throws(() => captureSourceIdentity(root, git, { requireClean: true }), /attribute overrides/);
});

test('selected input binding includes implied parents, additions and empty-directory membership', t => {
  const root = fixture.directory(t);
  mkdirSync(join(root, 'nested/deep'), { recursive: true });
  mkdirSync(join(root, 'tools/empty'), { recursive: true });
  writeFileSync(join(root, 'nested/deep/source.mjs'), 'unit fixture');
  const manifest = {
    files: [{ path: 'source/nested/deep/source.mjs', size: 12, sha256: localHash('unit fixture') }],
    directories: ['source', 'source/nested', 'source/nested/deep', 'source/tools', 'source/tools/empty'],
  };
  compareInputSelection(root, 'source', manifest, ['nested/deep/source.mjs', 'tools']);
  mkdirSync(join(root, 'tools/new-empty'));
  assert.throws(() => compareInputSelection(root, 'source', manifest, ['nested/deep/source.mjs', 'tools']));
  writeFileSync(join(root, 'nested/deep/source.mjs'), 'changed');
  assert.throws(() => compareInputSelection(root, 'source', manifest, ['nested/deep/source.mjs', 'tools']));
});

const sessionLaneFixture = (version, head = 'a'.repeat(40)) => ({
  schemaVersion: 1, kind: 'host-session-lane', runId: fixture.statement().runId, version, head,
  node: 'v24.21.0', files: [...SESSION_REQUIRED_TESTS],
  startedAt: new Date(Date.now() - 1000).toISOString(), completedAt: new Date().toISOString(),
  context: { contract: 'session-required', platform: 'win32', role: 'user-runtime',
    verified: true, sessionVerified: true },
  totals: { tests: 165, pass: 165, fail: 0, cancelled: 0, skipped: 0, todo: 0 }, contained: false,
});

test('outer schema rejects actual failure shapes, controls-only, old, partial and duplicate cases', () => {
  const report = { schemaVersion: 3, kind: 'private-local-publication-run', contract: LOCAL_CONTRACT,
    status: 'passed', scope: 'both-release-lines-local-only', releaseReady: false, ciImageEquivalent: false,
    image: fixture.statement().image, runId: fixture.statement().runId,
    startedAt: new Date(Date.now() - 1000).toISOString(), completedAt: new Date().toISOString(),
    sessionLane: sessionLaneFixture('2.0.1'),
    nodes: fixture.statement().runtimes, cases: localCases(['1.3.1', '2.0.1']).map(item => ({ name: item.name })) };
  // Header-only fixture, not execution evidence.
  verifyLocalHeader(report);
  for (const mutate of [
    value => { delete value.schemaVersion; }, value => { value.status = 'failed'; },
    value => { value.scope = 'containment-controls-only'; }, value => { value.cases.pop(); },
    value => { value.cases[1] = value.cases[0]; }, value => { value.error = 'original timeout'; },
    value => { value.schemaVersion = 2; },
    value => { value.cases = value.cases.filter(item => !item.name.startsWith('audit-')); },
    value => { value.cases.find(item => item.name.startsWith('audit-')).name = 'audit-v2.0.2-node20.20.2'; },
    value => { delete value.sessionLane; },
    value => { value.sessionLane.context.sessionVerified = false; },
    value => { value.sessionLane.context.role = 'privileged-fixture'; },
    value => { value.sessionLane.totals.fail = 1; },
    value => { value.sessionLane.totals.pass = 0; },
    value => { value.sessionLane.files = value.sessionLane.files.slice(1); },
    value => { value.sessionLane.version = '1.3.1'; },
    value => { value.sessionLane.contained = true; },
  ]) {
    const copy = structuredClone(report);
    mutate(copy);
    assert.throws(() => verifyLocalHeader(copy));
  }
});

test('evidence inventory binds the host session-lane receipt and still rejects stray members', t => {
  const versions = ['1.3.1', '2.0.1'];
  const cases = localCases(versions);
  const build = ({ receipt, declared, state = true }) => {
    const root = realpathSync.native(mkdtempSync(join(tmpdir(), 'local-inventory-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    for (const name of ['commands', 'controller', 'runtime', 'docker-config',
      ...versions.map(version => `inputs-${version}`)]) mkdirSync(join(root, name));
    for (const version of versions) writeFileSync(join(root, `inputs-${version}`, 'manifest.json'), '{}');
    for (const name of ['commands', 'controller', 'runtime']) writeFileSync(join(root, name, 'member.json'), '{}');
    for (const item of cases) {
      mkdirSync(join(root, item.name));
      writeFileSync(join(root, item.name, 'member.json'), '{}');
      writeFileSync(join(root, `${item.name}-storage-admission.json`), '{}');
    }
    const report = { cases: cases.map(item => ({ name: item.name })) };
    if (declared) report.sessionLane = { kind: 'host-session-lane' };
    if (receipt) writeFileSync(join(root, 'session-lane.json'), '{"kind":"host-session-lane"}');
    if (state) writeFileSync(join(root, 'run-state.json'), '{"kind":"private-local-publication-run-state"}');
    writeFileSync(join(root, 'result.json'), JSON.stringify(report));
    return root;
  };
  const manifest = evidenceInventory(build({ receipt: true, declared: true }));
  assert.ok(manifest.files.some(file => file.path === 'session-lane.json'),
    'The session-lane receipt must be hashed with every other run member');
  assert.ok(manifest.files.some(file => file.path === 'run-state.json'),
    'The run state and its invocation history must be hashed with every other run member');
  assert.throws(() => evidenceInventory(build({ receipt: true, declared: false })),
    /Missing or unexpected local run members/);
  assert.throws(() => evidenceInventory(build({ receipt: false, declared: true })),
    /Missing or unexpected local run members/);
  assert.throws(() => evidenceInventory(build({ receipt: true, declared: true, state: false })),
    /Missing or unexpected local run members/);
  const pending = build({ receipt: true, declared: true });
  const report = JSON.parse(readFileSync(join(pending, 'result.json')));
  rmSync(join(pending, 'result.json'));
  assert.ok(!evidenceInventory(pending, report).files.some(file => file.path === 'result.json'),
    'Before the report is written, every other member is checked and hashed');
  writeFileSync(join(pending, 'notes.txt'), 'stray');
  assert.throws(() => evidenceInventory(pending, report), /Missing or unexpected local run members/);
});

test('the run plan covers every registered case once, in the order the launcher executes it', () => {
  const versions = ['1.3.1', '2.1.0'];
  const plan = localRunPlan('both-release-lines-local-only', versions);
  const state = new LocalRunState('unused');
  assert.equal(new Set(plan).size, plan.length);
  assert.deepEqual(plan.filter(step => state.isCase(step)).sort(), localCases(versions).map(item => item.name).sort());
  assert.deepEqual(plan.slice(0, 6), ['failure-control', 'timeout-control', 'early-descendant-exit-control',
    'inputs-2.1.0', 'inputs-1.3.1', 'session-lane']);
  assert.deepEqual(plan.slice(6), [
    ...LOCAL_NODES.flatMap(node => [`audit-v2.1.0-node${node}`, `v2.1.0-node${node}`]),
    ...LOCAL_NODES.map(node => `v1.3.1-node${node}`)]);
  assert.deepEqual(localRunPlan('containment-controls-only'), plan.slice(0, 3));
  assert.throws(() => localRunPlan('unknown-scope', versions), /Unknown local run scope/);
});

test('verify-local accepts a resumed history and rejects malformed or inconsistent history', t => {
  const f = new ResumeFixture(t);
  f.failRun('v2.1.0-node22.23.2');
  const report = f.gate(true).run();
  verifyLocalHeader(report);
  assert.deepEqual(f.json('evidence-manifest.json'), evidenceInventory(f.output));
  new LocalRunState(f.output).verify(report, f.inputs());
  const state = f.json('run-state.json');
  const runState = new LocalRunState(f.output);
  runState.history(structuredClone(state), true);
  const failed = state.plan.indexOf('v2.1.0-node22.23.2');
  const earlier = time => new Date(Date.parse(time) - 60_000).toISOString();
  for (const [name, mutate, pattern] of [
    ['gap', value => { value.invocations[1].index = 3; }, /The invocation history has a gap or duplicate/],
    ['duplicate', value => { value.invocations.splice(1, 0, structuredClone(value.invocations[0])); },
      /The invocation history has a gap or duplicate/],
    ['non-final pass', value => {
      value.invocations[0].status = 'passed';
      delete value.invocations[0].error;
    }, /Invalid status for invocation 1/],
    ['unfinished final', value => {
      value.invocations[1].status = 'interrupted';
      value.invocations[1].completedAt = null;
    }, /Invalid status for invocation 2/],
    ['interrupted with an end', value => {
      value.invocations[0].status = 'interrupted';
      delete value.invocations[0].error;
    }, /An unfinished invocation cannot record a completion time/],
    ['failed without an end', value => { value.invocations[0].completedAt = null; }, /Invalid invocation completion time/],
    ['failed without an error', value => { delete value.invocations[0].error; }, /records its error/],
    ['error on a pass', value => { value.invocations[1].error = 'not a failure'; }, /records its error/],
    ['other binding', value => { value.invocations[1].bindingSha256 = '0'.repeat(64); },
      /An invocation was bound to different inputs or controller/],
    ['reuse gap', value => { value.invocations[1].reused.pop(); }, /Reused steps are not the passed plan prefix/],
    ['passed twice', value => {
      value.checkpoints[failed].invocation = 1;
      value.checkpoints[failed].completedAt = value.invocations[0].completedAt;
    }, /Reused steps are not the passed plan prefix/],
    ['reordered steps', value => {
      const ran = value.invocations[1].ran;
      [ran[0], ran[1]] = [ran[1], ran[0]];
    }, /Ran steps are out of plan order/],
    ['skipped step', value => { value.invocations[1].ran.splice(1, 1); }, /Ran steps are out of plan order/],
    ['step after completion', value => { value.invocations[1].ran.push('failure-control'); },
      /Ran steps are out of plan order/],
    ['invocations out of order', value => { value.invocations[1].startedAt = earlier(value.invocations[0].startedAt); },
      /Invocations overlap or are out of order/],
    ['checkpoint outside its invocation', value => { value.checkpoints[0].completedAt = new Date(0).toISOString(); },
      /A checkpoint lies outside its invocation/],
    ['checkpoint order', value => {
      [value.checkpoints[0], value.checkpoints[1]] = [value.checkpoints[1], value.checkpoints[0]];
    }, /Checkpoints do not follow the run plan/],
    ['missing checkpoint', value => { value.checkpoints.pop(); }, /A passed invocation did not complete the plan/],
    ['set-aside elsewhere', value => { value.invocations[1].setAside.directory = 'before-invocation-1'; },
      /Invalid set-aside directory/],
    ['set-aside range', value => { value.invocations[1].setAside.commands[0] += 1; }, /Invalid set-aside receipt range/],
    ['first invocation set aside', value => { value.invocations[0].setAside = value.invocations[1].setAside; },
      /The first invocation cannot set evidence aside/],
    ['first invocation inherited a container', value => { value.invocations[0].removedContainers = ['f'.repeat(64)]; },
      /The first invocation cannot inherit containers/],
    ['unknown field', value => { value.invocations[1].note = 'unreviewed'; }, /Unexpected local regression fields/],
    ['plan order', value => { value.plan.reverse(); }, /The recorded plan differs from the controller plan/],
    ['binding edit', value => { value.binding.image = `sha256:${'0'.repeat(64)}`; },
      /The run binding does not match its commitment/],
  ]) {
    const copy = structuredClone(state);
    mutate(copy);
    assert.throws(() => runState.history(copy, true), pattern, name);
  }
  for (const [name, mutate, pattern] of [
    ['history differs', value => { value.invocations[0].ran.pop(); }, /The report and run state record different histories/],
    ['history truncated', value => { value.invocations.pop(); }, /The report and run state record different histories/],
    ['case order', value => { value.cases.reverse(); }, /Cases are missing, repeated or out of plan order/],
    ['repeated case', value => { value.cases.push(value.cases[0]); }, /Cases are missing, repeated or out of plan order/],
    ['start', value => { value.startedAt = earlier(value.startedAt); }, /The report and run state record different starts/],
    ['completion', value => { value.completedAt = earlier(value.completedAt); },
      /The report did not end with its final invocation/],
    ['run', value => { value.runId = '11111111-1111-4111-8111-111111111111'; }, /The run state belongs to another run/],
    ['session lane run', value => { value.sessionLane.runId = '11111111-1111-4111-8111-111111111111'; },
      /The session lane belongs to another run/],
    ['session receipt', value => { value.sessionLane.totals.pass++; }, /The reported session lane differs from its receipt/],
    ['runtime', value => { value.nodes[0].sha256 = '0'.repeat(64); }, /The run was bound to different Node runtimes/],
    ['controller', value => { value.controller.sha256 = '0'.repeat(64); }, /The run was bound to a different controller/],
  ]) {
    const copy = structuredClone(report);
    mutate(copy);
    assert.throws(() => new LocalRunState(f.output).verify(copy, f.inputs()), pattern, name);
  }
  const inputs = f.inputs();
  inputs.get('1.3.1').manifest.files.find(file => file.path === 'source/package.json').sha256 = '0'.repeat(64);
  assert.throws(() => new LocalRunState(f.output).verify(report, inputs), /Frozen source input differs/);
  for (const [pattern, member] of [
    [/Evidence changed after it passed: failure-control/, join('failure-control', 'guest', 'runtime.json')],
    [/A checkpointed command receipt changed/, join('commands', '1.json')],
  ]) {
    const path = join(f.output, member);
    const original = readFileSync(path);
    writeFileSync(path, Buffer.concat([original, Buffer.from(' ')]));
    assert.throws(() => new LocalRunState(f.output).verify(report, f.inputs()), pattern);
    writeFileSync(path, original);
  }
  new LocalRunState(f.output).verify(report, f.inputs());
});

test('raw timeout metadata requires the dedicated source budget without extending other commands', () => {
  const source = { label: 'Complete source suite', timeoutMs: 25 * 60_000, elapsedMs: 1000 };
  const other = { label: 'Local Git', timeoutMs: 15 * 60_000, elapsedMs: 10 };
  verifyCommandTimeout(source);
  verifyCommandTimeout(other);
  verifyCommandTimeout({ label: 'Contained source suite', timeoutMs: SOURCE_SUITE_TIMEOUT_MS, elapsedMs: 1000 });
  assert.throws(() => verifyCommandTimeout({ label: 'Contained source suite',
    timeoutMs: 25 * 60_000, elapsedMs: 1000 }), /timeoutMs/);
  verifyCommandTimeout({ label: 'Required privileged audit', timeoutMs: AUDIT_COMMAND_TIMEOUT_MS, elapsedMs: 1000 });
  assert.throws(() => verifyCommandTimeout({ label: 'Required privileged audit', timeoutMs: 15 * 60_000, elapsedMs: 1000 }));
  for (const timeoutMs of [undefined, null, '1500000', NaN, Infinity, -1, 0, 15 * 60_000, 26 * 60_000]) {
    assert.throws(() => verifyCommandTimeout({ ...source, timeoutMs }), /timeoutMs/);
  }
  assert.throws(() => verifyCommandTimeout({ ...other, timeoutMs: 25 * 60_000 }), /timeoutMs/);
  assert.throws(() => verifyCommandTimeout({ ...source, elapsedMs: -1 }), /duration/);
});

test('audit companion replay rejects altered selection, runtime, source, skipped evidence and raw failures', async t => {
  const f = await new LocalCaseFixture(t).create();
  const directory = join(f.base, 'audit-receipts');
  mkdirSync(directory);
  const command = {
    label: 'Required privileged audit', executable: 'C:\\node.exe', args: auditArguments(), cwd: 'C:\\source',
    timeoutMs: AUDIT_COMMAND_TIMEOUT_MS, elapsedMs: 40000, exitCode: 0, signal: null,
    error: null, encoding: 'utf8', stdout: f.sourceTap, stderr: '',
  };
  const preflight = { ...command, label: 'Verify privileged fixture execution contract',
    args: ['tools/ci/run-tests.mjs', 'audit', '--check'], timeoutMs: 15 * 60_000,
    stdout: JSON.stringify({ contract: 'audit', platform: 'win32', role: 'privileged-fixture', verified: true }) };
  const original = [...f.commands.slice(0, 5), preflight, command, ...f.commands.slice(-4)];
  const report = {
    schemaVersion: 1, kind: 'local-privileged-audit', version: f.version, node: f.gate.node,
    publisherNode: f.gate.publisherNode, npm: f.gate.npm, platform: 'win32',
    source: f.gate.source, status: 'passed', releaseReady: false, publicationCandidate: false,
    originalPreserved: true, tests: f.totals, audit: syntheticAuditReport(f.gate.node),
  };
  const save = commands => {
    report.steps = commands.map((value, index) => {
      const file = `command-${index + 1}.json`;
      const bytes = JSON.stringify(value);
      writeFileSync(join(directory, file), bytes);
      return { label: value.label, file, sha256: localHash(bytes),
        exitCode: value.exitCode, signal: value.signal, error: value.error };
    });

  };
  save(original);
  verifyAuditSteps(directory, report, f.root, f.version);
  for (const mutate of [
    value => { value.args = ['--test', '--test-name-pattern', 'missing']; },
    value => { value.executable = 'C:\\other-node.exe'; },
    value => { value.cwd = 'C:\\other-source'; },
    value => { value.stdout = value.stdout.replace('ok 1 - ', 'ok 1 - skipped # SKIP '); },
    value => { value.stdout = value.stdout.replace('"cases":19', '"cases":18'); },
    value => { value.stdout = value.stdout.replace('v24.21.0', 'v20.20.2'); },
    value => { value.stdout = value.stdout.replace('# fail 0', '# fail 1'); },
    value => { value.stdout = value.stdout.replace('# cancelled 0', '# cancelled 1'); },
    value => { value.stdout = value.stdout.split('\n').filter(line =>
      !/^# (tests|pass|fail|cancelled|skipped|todo) /.test(line)).join('\n'); },
    value => { value.exitCode = 1; },
    value => { value.signal = 'SIGTERM'; },
  ]) {
    const commands = structuredClone(original);
    mutate(commands[6]);
    save(commands);
    assert.throws(() => verifyAuditSteps(directory, report, f.root, f.version));
  }
  for (const mutate of [
    value => { value.args = ['tools/ci/run-tests.mjs', 'source', '--check']; },
    value => { value.stdout = value.stdout.replace('"verified":true', '"verified":false'); },
    value => { value.stdout = value.stdout.replace('privileged-fixture', 'user-runtime'); },
    value => { value.executable = 'C:\\other-node.exe'; },
  ]) {
    const commands = structuredClone(original);
    mutate(commands[5]);
    save(commands);
    assert.throws(() => verifyAuditSteps(directory, report, f.root, f.version));
  }
  save(original.filter(value => value.label !== preflight.label));
  assert.throws(() => verifyAuditSteps(directory, report, f.root, f.version));
  save(original);
  assert.throws(() => verifyAuditSteps(directory, { ...report, version: '2.1.0' }, f.root, f.version));
  const source = structuredClone(report.source);
  source.head = '0'.repeat(40);
  assert.throws(() => verifyAuditSteps(directory, { ...report, source }, f.root, f.version));
});

test('current schema-5 source replay requires ordinary session preflight and exact offline native restore', async t => {
  const f = await new LocalCaseFixture(t).create();
  f.gate.schemaVersion = 5;
  f.gate.checks['checkout-false'].auditExecution = 'required-privileged-companion';
  const index = f.commands.findIndex(command => command.label === sourceSuiteLabel(f.version));
  const restore = { label: 'Restore pinned native fixture toolchain', executable: 'C:\\input\\pwsh\\pwsh.exe',
    args: nativeRestoreArguments(), cwd: 'C:\\work\\checkout-false', timeoutMs: 15 * 60_000,
    elapsedMs: 1000, exitCode: 0, signal: null, error: null, encoding: 'utf8',
    stdout: JSON.stringify(LOCAL_NATIVE_PATHS), stderr: '' };
  const context = { ...restore, label: 'Verify user-runtime execution contract', executable: 'C:\\node.exe',
    args: ['tools/ci/run-tests.mjs', 'source-ordinary', '--check'],
    stdout: JSON.stringify({ contract: 'source-ordinary', platform: 'win32', role: 'user-runtime',
      verified: true }) };
  f.commands.splice(index, 0, context, restore);
  f.save();
  const verify = () => verifyRawSteps(f.directory, f.gate, f.root, f.version, { checkout: f.checkoutBinding });
  await verify();
  const originalContext = structuredClone(context);
  for (const mutate of [
    value => { value.stdout = JSON.stringify({ ...JSON.parse(value.stdout), sessionVerified: true }); },
    value => { value.stdout = value.stdout.replace('"contract":"source-ordinary"', '"contract":"source"'); },
    value => { value.stdout = value.stdout.replace('"verified":true', '"verified":false'); },
    value => { value.args = ['tools/ci/run-tests.mjs', 'service-context', '--check']; },
    value => { value.executable = 'C:\\other-node.exe'; },
  ]) {
    mutate(context);
    f.save();
    await assert.rejects(verify);
    Object.assign(context, structuredClone(originalContext));
  }
  f.commands.splice(index, 1);
  f.save();
  await assert.rejects(verify);
  f.commands.splice(index, 0, context);
  const original = structuredClone(restore);
  restore.stdout = JSON.stringify({ ...LOCAL_NATIVE_PATHS, CompilerPath: 'C:\\unowned\\csc.exe' });
  f.save();
  await assert.rejects(verify);
  Object.assign(restore, original);
  restore.args = ['-Command', 'download-an-unpinned-compiler'];
  f.save();
  await assert.rejects(verify);
});

test('missing root and failed/changed raw command receipts reject without executing anything', async t => {
  const directory = fixture.directory(t);
  await assert.rejects(() => verifyLocalEvidence({ directory, sourceRoots: {}, toolRoots: {} }));
  const record = { label: 'Complete source suite', exitCode: 1, signal: null, error: null,
    timeoutMs: 25 * 60_000, elapsedMs: 1000,
    executable: 'C:\\node.exe', args: [], stdout: '# fail 1', stderr: '', encoding: 'utf8' };
  const bytes = Buffer.from(JSON.stringify(record));
  writeFileSync(join(directory, 'command-1.json'), bytes);
  const gate = { kind: 'local-publication-regression', schemaVersion: 4, status: 'passed',
    releaseReady: false, publicationCandidate: false, originalPreserved: true,
    steps: [{ file: 'command-1.json', sha256: localHash(bytes), label: record.label, exitCode: 0, signal: null, error: null }] };
  await assert.rejects(() => verifyRawSteps(directory, gate, directory, '2.0.1'), /command failed/);
  const old = { ...record, exitCode: 0 };
  delete old.timeoutMs;
  const oldBytes = Buffer.from(JSON.stringify(old));
  writeFileSync(join(directory, 'command-1.json'), oldBytes);
  gate.steps[0].sha256 = localHash(oldBytes);
  await assert.rejects(() => verifyRawSteps(directory, gate, directory, '2.0.1'), /timeoutMs/);
  writeFileSync(join(directory, 'command-1.json'), '{}');
  await assert.rejects(() => verifyRawSteps(directory, gate, directory, '2.0.1'));
});

for (const version of ['1.3.2', '2.0.2', '2.7.13']) {
  test(`SYNTHETIC selected-version local replay: ${version}`, async t => {
    const f = await new LocalCaseFixture(t, version).create();
    await verifyRawSteps(f.directory, f.gate, f.root, version, { checkout: f.checkoutBinding });
  });
}

for (const version of ['1.3.1', '2.0.1']) {
  test(`SYNTHETIC producer-complete case and independent record corruptions: ${version}`, async t => {
    const f = await new LocalCaseFixture(t, version).create();
    const verify = () => verifyRawSteps(f.directory, f.gate, f.root, version, { checkout: f.checkoutBinding });
    await verify();
    if (version === '2.0.1') {
      await t.test('rehashing cannot admit skipped, missing or changed mandatory Windows audit evidence', async () => {
        for (const mutate of [
          stdout => stdout.split('\n').filter(line => !line.startsWith('# MCP_WINDOWS_AUDIT_V1 ')).join('\n'),
          stdout => stdout.replace('ordinary-token staging and retained original policy',
            'ordinary-token staging and retained original policy # SKIP'),
          stdout => stdout.replace('"cases":19', '"cases":18'),
          stdout => stdout.replace('"cleanupVerified":true', '"cleanupVerified":false'),
        ]) {
          f.reset();
          const command = f.commands.find(item => item.label === sourceSuiteLabel(f.version));
          command.stdout = mutate(command.stdout);
          f.save();
          await assert.rejects(verify);
        }
      });
      for (const schema of [1, 2]) {
        await t.test(`schema-${schema} diagnostic replay remains component-only without new audit evidence`, async () => {
          f.reset();
          f.gate.schemaVersion = schema;
          for (const command of f.commands) {
            const index = command.args.indexOf('core.eol=crlf');
            if (index !== -1) command.args.splice(index - 1, 2);
          }
          if (schema === 1) delete f.gate.checks['checkout-false'].artifact.evidenceFile;
          delete f.gate.checks['checkout-false'].stageCapture;
          f.commands = f.commands.filter(item => item.label !== 'Actual pinned npm stage capture, offline fixtures');
          f.commands.find(item => item.label === sourceSuiteLabel(f.version)).stdout = f.tap;
          f.save();
          assert.equal(typeof await verifyRecordedSteps(f.directory, f.gate, f.root, version), 'string');
          await assert.rejects(verify, /schema 4/);
        });
      }
      f.reset();
      f.save();
      await t.test('schema-3 checkout diagnostic cannot qualify as a fresh inner report', async () => {
        f.reset();
        f.gate.schemaVersion = 3;
        for (const command of f.commands) {
          const index = command.args.indexOf('core.eol=crlf');
          if (index !== -1) command.args.splice(index - 1, 2);
        }
        f.save();
        assert.equal(typeof await verifyRecordedSteps(f.directory, f.gate, f.root, version,
          { checkout: f.checkoutBinding }), 'string');
        await assert.rejects(verify, /schema 4/);
      });
      f.reset();
      f.save();
    }
    await t.test('every supporting raw record is mandatory even after renumbering and rehashing', async () => {
      for (let index = 0; index < f.original.commands.length; index++) {
        f.reset();
        f.commands.splice(index, 1);
        f.save();
        await assert.rejects(verify, `Missing command ${index + 1} was accepted`);
      }
    });
    await t.test('every supporting command cwd is bound, including SDK cwd', async () => {
      for (let index = 0; index < f.original.commands.length; index++) {
        f.reset();
        f.commands[index].cwd = 'C:\\wrong-sdk-cwd';
        f.save();
        await assert.rejects(verify, `Wrong cwd for command ${index + 1} was accepted`);
      }
    });
    const fields = [
      ['native empty object', value => { value.gate.checks['checkout-false'].nativeIdentity.files = [{}]; }],
      ['true-checkout native absent', value => { delete value.gate.checks['checkout-true'].nativeIdentity; }],
      ['native digest changed', value => { value.gate.checks['checkout-false'].nativeIdentity.files[0].sha256 = '0'.repeat(64); }],
      ['native build-script evidence missing', value => { delete value.gate.checks['checkout-false'].nativeIdentity.buildScript.sourceBlobSha256; }],
      ['artifact SHA256 missing', value => { delete value.gate.checks['checkout-false'].artifact.sha256; }],
      ['artifact SHA256 well-formed but wrong', value => { value.gate.checks['checkout-false'].artifact.sha256 = '0'.repeat(64); }],
      ['artifact SHA512 missing', value => { delete value.gate.checks['checkout-false'].artifact.sha512; }],
      ['artifact SHA512 changed', value => { value.gate.checks['checkout-false'].artifact.sha512 = '0'.repeat(128); }],
      ['artifact SRI missing', value => { delete value.gate.checks['checkout-false'].artifact.integrity; }],
      ['artifact SRI changed', value => { value.gate.checks['checkout-false'].artifact.integrity = 'sha512-invalid'; }],
      ['artifact inventory empty', value => { value.gate.checks['checkout-false'].artifact.files = []; }],
      ['artifact record missing', value => { value.gate.checks['checkout-false'].artifact.files.pop(); }],
      ['artifact empty record', value => { value.gate.checks['checkout-false'].artifact.files[0] = {}; }],
      ['artifact file digest missing', value => { delete value.gate.checks['checkout-false'].artifact.files[0].sha256; }],
      ['artifact size missing', value => { delete value.gate.checks['checkout-false'].artifact.files[0].size; }],
      ['artifact mode missing', value => { delete value.gate.checks['checkout-false'].artifact.files[0].mode; }],
      ['artifact noncanonical order', value => { value.gate.checks['checkout-false'].artifact.files.reverse(); }],
      ['extracted empty record', value => { value.gate.checks['checkout-false'].extractedFiles = [{}]; }],
      ['extracted digest missing', value => { delete value.gate.checks['checkout-false'].extractedFiles[0].sha256; }],
      ['extracted missing file', value => { value.gate.checks['checkout-false'].extractedFiles.pop(); }],
      ['notices empty', value => { value.gate.checks['checkout-false'].notices = {}; }],
      ['notices artifact digest changed', value => { value.gate.checks['checkout-false'].notices.artifacts[0].sha256 = '0'.repeat(64); }],
      ['old schema', value => { value.gate.schemaVersion = 1; }],
      ['old schema without stage proof', value => { value.gate.schemaVersion = 2; }],
      ['missing stage capture proof', value => { delete value.gate.checks['checkout-false'].stageCapture; }],
      ['partial stage capture proof', value => {
        const command = value.commands.find(item => item.label === 'Actual pinned npm stage capture, offline fixtures');
        const proof = JSON.parse(command.stdout);
        proof.cases.pop();
        command.stdout = JSON.stringify(proof);
        value.gate.checks['checkout-false'].stageCapture = proof;
      }],
      ['fixture name missing', value => { delete value.gate.checks['checkout-false'].artifact.evidenceFile; }],
      ['fixture name traversal', value => { value.gate.checks['checkout-false'].artifact.evidenceFile = '../candidate.tgz'; }],
      ['source-head preservation missing', value => { delete value.gate.source.head; }],
      ['source snapshot record missing', value => { value.gate.source.files.pop(); }],
      ['license JSON empty', value => { value.licenses = {}; }],
      ['license dependency missing', value => { value.licenses.dependencies.pop(); }],
      ['license evidence record missing', value => { value.licenses.licenseEvidence.packages.pop(); }],
      ['license dependency integrity changed', value => { value.licenses.dependencies[0].integrity = 'sha512-invalid'; }],
      ['license package JSON digest changed', value => { value.licenses.licenseEvidence.packages[0].packageJson.sha256 = '0'.repeat(64); }],
      ['license text changed', value => { value.licenses.licenseEvidence.packages[0].files[0].text = 'changed'; }],
      ['license candidate record missing', value => { value.licenses.packages = value.licenses.packages.filter(item => item.name !== 'mcp-pacemaker'); }],
      ['license package coverage missing', value => { value.licenses.packages = []; }],
      ['license notice hash changed', value => { value.licenses.notices[0].sha256 = '0'.repeat(64); }],
      ['license summary count changed', value => { value.gate.checks['checkout-false'].retainedGraphLicenseContract.packages++; }],
      ['SDK missing kind', value => {
        const command = value.commands.find(item => item.label === 'Actual lane SDK/signature load, no transport');
        const sdk = JSON.parse(command.stdout);
        delete sdk.kind;
        command.stdout = JSON.stringify(sdk);
        value.gate.checks['checkout-false'].sdk = sdk;
      }],
      ['pack empty inventory with report rehashed', value => {
        const command = value.commands.find(item => item.label === 'Real offline npm pack');
        const packed = JSON.parse(command.stdout);
        packed['mcp-pacemaker'].files = [];
        value.gate.checks['checkout-false'].artifact.files = [];
        command.stdout = JSON.stringify(packed);
      }],
      ['pack SRI omitted from both reports', value => {
        const command = value.commands.find(item => item.label === 'Real offline npm pack');
        const packed = JSON.parse(command.stdout);
        delete packed['mcp-pacemaker'].integrity;
        delete value.gate.checks['checkout-false'].artifact.integrity;
        command.stdout = JSON.stringify(packed);
      }],
    ];
    for (const [name, mutate] of fields) {
      await t.test(name, async () => {
        f.reset();
        mutate(f);
        f.save();
        await assert.rejects(verify);
      });
    }
    await t.test('each native binary stdout is independently required and hash bound to its Git object', async () => {
      const indices = f.original.commands.flatMap((command, index) =>
        command.args.includes('blob') ? [index] : []);
      assert.ok(indices.length >= 14);
      for (const index of indices) {
        f.reset();
        f.commands[index].stdout = Buffer.from('different native blob').toString('base64');
        f.save();
        await assert.rejects(verify);
      }
    });
    await t.test('missing or changed retained compressed fixture bytes fail', async () => {
      f.reset();
      f.save();
      rmSync(join(f.directory, 'fixture.tgz'));
      await assert.rejects(verify);
      writeFileSync(join(f.directory, 'fixture.tgz'), 'not the tested archive');
      await assert.rejects(verify);
    });
    await t.test('license receipt digest is checked independently of its fields', async () => {
      f.reset();
      f.save();
      f.gate.checks['checkout-false'].retainedGraphLicenseContract.sha256 = '0'.repeat(64);
      await assert.rejects(verify);
    });
    f.reset();
    f.save();
    await verify();
  });
}

test('bounded read-only evidence TAR parsing rejects tampering, traversal, duplicates and links', () => {
  const bytes = fixture.tar('output/runtime.json', Buffer.from('{}'));
  assert.equal(evidenceTar(bytes).files[0].sha256, localHash('{}'));
  assert.throws(() => evidenceTar(fixture.tar('output/../escape')));
  assert.throws(() => evidenceTar(fixture.tar('output/link', Buffer.alloc(0), '2')));
  const bad = Buffer.from(bytes);
  bad[0] ^= 1;
  assert.throws(() => evidenceTar(bad), /checksum/);
  assert.throws(() => evidenceTar(Buffer.concat([bytes.subarray(0, -1024), bytes])));
  assert.throws(() => evidenceTar(bytes.subarray(0, 700)));
});

test('all dispatcher commands and the stage sink fail before effects when local acceptance is missing', async t => {
  let calls = 0;
  await assert.rejects(submitOnce({ approval: {}, execute: () => { calls++; }, readRegistry: () => { calls++; } }));
  assert.equal(calls, 0);
  const directory = fixture.directory(t);
  const event = join(directory, 'event.json');
  writeFileSync(event, JSON.stringify({ inputs: { action: 'prepare', approval: '{}' } }));
  const previous = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_EVENT_PATH = event;
  try {
    for (const command of ['prepare', 'finalize', 'transfer', 'stage']) {
      await assert.rejects(publicationMain(command));
    }
  } finally {
    if (previous === undefined) delete process.env.GITHUB_EVENT_PATH;
    else process.env.GITHUB_EVENT_PATH = previous;
  }
});

test('local evidence cannot replace hosted CI or forward credentials to ordinary test children', () => {
  const approval = fixture.approval();
  validateLocalApproval(approval);
  assert.throws(() => validateCi({ id: approval.ciRunId, run_attempt: 1, head_sha: approval.commit }, [], approval));
  const { env } = fixture.hosted();
  const helper = publicationHelperEnvironment({ PATH: 'fixture-path' }, {
    ...env, GITHUB_EVENT_PATH: '/fixture/event.json', GITHUB_TOKEN: 'SYNTHETIC-READ-TOKEN',
    NPM_TOKEN: 'must-not-forward', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'must-not-forward',
  });
  assert.equal(helper.NPM_TOKEN, undefined);
  assert.equal(helper.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
  assert.equal(helper.GITHUB_TOKEN, 'SYNTHETIC-READ-TOKEN');
});

if (existsSync(new URL('../tools/npm-publication/owner-sdk.mjs', import.meta.url))) {
  test('current-only SDK and owner orchestration reject missing local evidence before loading/calling SDK', async () => {
    const { createOwnerSdk } = await import('../tools/npm-publication/owner-sdk.mjs');
    const { publishOwnerOnce } = await import('../tools/npm-publication/owner-bootstrap.mjs');
    assert.throws(() => createOwnerSdk({ approval: {} }));
    await assert.rejects(publishOwnerOnce({ approval: {} }));
  });
}
