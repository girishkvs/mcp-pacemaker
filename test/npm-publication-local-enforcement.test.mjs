import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  LOCAL_CONTRACT, LOCAL_NODES, LOCAL_CASES, localHash, localCommitment,
  validateLocalRegression, validateLocalApproval, validatePreparedLocal, validateLocalManifest,
} from '../tools/npm-publication/local-regression.mjs';
import { treeEntries, captureSourceIdentity, validateSourceSubject } from '../tools/npm-publication/local-source.mjs';
import { readOwnerLocalAcceptance, publicationHelperEnvironment } from '../tools/npm-publication/local-regression-hosted.mjs';
import { verifyLocalHeader, verifyRawSteps, verifyRecordedSteps, verifyLocalEvidence, compareInputSelection,
  verifyCommandTimeout } from '../tools/npm-publication/verify-local.mjs';
import { evidenceTar } from '../tools/npm-publication/local-evidence.mjs';
import { submitOnce, validateCi } from '../tools/npm-publication/policy.mjs';
import { main as publicationMain } from '../tools/npm-publication/run.mjs';
import { LocalCaseFixture } from './helpers/local-case-fixture.mjs';
import { physical } from '../tools/npm-publication/local-inputs.mjs';
import './helpers/npm-publication-local-audit.mjs';
import { CheckoutProofFixture } from './helpers/npm-publication-checkout-proof.mjs';

// All positive objects below are SYNTHETIC UNIT FIXTURES. None are report evidence or owner acceptance.
class Fixtures {
  statement() {
    return { schemaVersion: 1, kind: 'local-regression-integrity-checked', contract: LOCAL_CONTRACT,
      scope: 'both-release-lines-local-only', runId: '11111111-1111-4111-8111-111111111111',
      completedAt: new Date(Date.now() - 60_000).toISOString(), reportSha256: 'a'.repeat(64),
      evidenceSha256: 'b'.repeat(64), controllerSha256: 'c'.repeat(64),
      image: 'sha256:e7fb7bcc43051b57c111aab28761e35ec2880c523075b06db81c63160d02f7e9',
      runtimes: LOCAL_NODES.map(version => ({ version, sha256: 'd'.repeat(64) })),
      subjects: ['1.3.1', '2.0.1'].map((version, index) => ({ version,
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
    const localRegression = this.statement();
    const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version;
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
    return { source: Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]])),
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
  validateLocalManifest(bytes, stage, { localRegression: approval.localRegression });
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

test('outer schema rejects actual failure shapes, controls-only, old, partial and duplicate cases', () => {
  const report = { schemaVersion: 2, kind: 'private-local-publication-run', contract: LOCAL_CONTRACT,
    status: 'passed', scope: 'both-release-lines-local-only', releaseReady: false, ciImageEquivalent: false,
    image: fixture.statement().image, runId: fixture.statement().runId,
    startedAt: new Date(Date.now() - 1000).toISOString(), completedAt: new Date().toISOString(),
    nodes: fixture.statement().runtimes, cases: LOCAL_CASES.map(item => ({ name: item.name })) };
  // Header-only fixture, not a nine-green execution report.
  verifyLocalHeader(report);
  for (const mutate of [
    value => { delete value.schemaVersion; }, value => { value.status = 'failed'; },
    value => { value.scope = 'containment-controls-only'; }, value => { value.cases.pop(); },
    value => { value.cases[1] = value.cases[0]; }, value => { value.error = 'original timeout'; },
  ]) {
    const copy = structuredClone(report);
    mutate(copy);
    assert.throws(() => verifyLocalHeader(copy));
  }
});

test('raw timeout metadata requires the dedicated source budget without extending other commands', () => {
  const source = { label: 'Complete source suite', timeoutMs: 25 * 60_000, elapsedMs: 1000 };
  const other = { label: 'Local Git', timeoutMs: 15 * 60_000, elapsedMs: 10 };
  verifyCommandTimeout(source);
  verifyCommandTimeout(other);
  for (const timeoutMs of [undefined, null, '1500000', NaN, Infinity, -1, 0, 15 * 60_000, 26 * 60_000]) {
    assert.throws(() => verifyCommandTimeout({ ...source, timeoutMs }), /timeoutMs/);
  }
  assert.throws(() => verifyCommandTimeout({ ...other, timeoutMs: 25 * 60_000 }), /timeoutMs/);
  assert.throws(() => verifyCommandTimeout({ ...source, elapsedMs: -1 }), /duration/);
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
          const command = f.commands.find(item => item.label === 'Complete source suite');
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
          f.commands.find(item => item.label === 'Complete source suite').stdout = f.tap;
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
