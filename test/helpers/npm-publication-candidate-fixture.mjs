import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { syntheticPreparedLocal, syntheticLocalReview } from './local-regression-fixture.mjs';
import { fixtureIntegrity, fixtureLicenseEvidence, fixtureMit } from '../fixtures/consumer-license-evidence.mjs';
import {
  POLICY, channelFor, digest, sameDigests, validateApproval, validateCi,
  validateContext, validateEnvironment, validateGates, validatePackage, validateSource, validateTransfer,
} from '../../tools/npm-publication/policy.mjs';
import { releaseRole, validateLocalApproval, validateLocalManifest } from '../../tools/npm-publication/local-regression.mjs';
import { readOwnerLocalAcceptance } from '../../tools/npm-publication/local-regression-hosted.mjs';
import { MATRIX, runMatrix, verifyMatrixReports, verifyPreparedBundle, zipFiles } from '../../tools/npm-publication/matrix.mjs';
import { extractTarball, inspectTarball } from '../../tools/npm-publication/tarball.mjs';
import { finalizeInputs } from '../../tools/npm-publication/run.mjs';
import { downloadPeer } from '../../tools/npm-publication/peer.mjs';
import { ARTIFACT_EXTERNAL, SOURCE_EXTERNAL, GateRunner, evidenceFor, externalGates } from '../../tools/npm-publication/gates.mjs';
import { runSourceChecks } from '../../tools/npm-publication/source-gates.mjs';
import { runArtifactChecks } from '../../tools/npm-publication/artifact-gates.mjs';
import { CURRENT_REF, LEGACY_REF, fixturePlan } from '../../tools/compatibility/fixtures.mjs';
import { renderNotices } from '../../tools/third-party-notices/inventory.mjs';
import { aggregateExternalGates, verifyNativeIdentity } from '../../tools/npm-publication/external-gates.mjs';
import { replacementOptions } from '../../tools/service-replacement/check.mjs';
import { scanPublicationRequest } from '../../tools/publication-scanners/publication.mjs';

const hash = bytes => digest(bytes).sha256;
const save = (path, bytes) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
};
const json = value => `${JSON.stringify(value, null, 2)}\n`;
const sourceTuple = approval => Object.fromEntries(['ref', 'tagObject', 'commit', 'tree'].map(key => [key, approval[key]]));
const evidence = evidenceFor('SYNTHETIC external command/reader response; not execution evidence', 'fixture');

export function syntheticRegistrySourceProof(peer, env) {
  const proof = peer.sourceProof;
  const statement = {
    _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: `pkg:npm/${POLICY.name}@${peer.version}`, digest: { sha512: peer.sha512 } }],
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: {
          ref: proof.ref, repository: `https://github.com/${POLICY.repository}`, path: POLICY.workflow,
        } },
        resolvedDependencies: [{ uri: `git+https://github.com/${POLICY.repository}@${proof.ref}`,
          digest: { gitCommit: peer.commit } }],
        internalParameters: { github: { event_name: 'workflow_dispatch',
          repository_id: env.GITHUB_REPOSITORY_ID, repository_owner_id: env.GITHUB_REPOSITORY_OWNER_ID } },
      },
      runDetails: {
        builder: { id: 'https://github.com/actions/runner/github-hosted' },
        metadata: { invocationId: `https://github.com/${POLICY.repository}/actions/runs/${proof.runId}/attempts/1` },
      },
    },
  };
  return { attestations: [{ predicateType: statement.predicateType, bundle: { dsseEnvelope: {
    payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
    signatures: [{ sig: 'SYNTHETIC-NOT-A-SIGNATURE', keyid: '' }],
  } } }] };
}

// Ported shared legacy fixture. Commands, API responses and tarballs are synthetic; validators are real.
export class CandidateFixture {
  constructor(t, approval, env, ownerReaders, controls = {}) {
    this.approval = approval;
    this.controls = controls;
    this.home = realpathSync.native(mkdtempSync(join(tmpdir(), 'candidate-flow-unit-')));
    t.after(() => rmSync(this.home, { recursive: true, force: true }));
    this.env = { ...env, RUNNER_NAME: 'synthetic-source', RUNNER_TEMP: this.home };
    this.ownerReaders = ownerReaders;
    this.package = this.pack(approval.version, controls.package);
    this.root = join(this.home, 'source-checkout');
    for (const [name, bytes] of Object.entries(this.package.files)) save(join(this.root, name), bytes);
    const lock = { lockfileVersion: 3, packages: {
      '': { name: POLICY.name, version: approval.version },
      'node_modules/smol-toml': { name: 'smol-toml', version: '1.8.0',
        resolved: `${POLICY.registry}smol-toml/-/smol-toml-1.8.0.tgz` },
    } };
    save(join(this.root, 'package-lock.json'), json(lock));
    save(join(this.root, 'ui/package-lock.json'), json(lock));
    this.calls = [];
    this.metadata = [];
    this.archives = new Map();
    this.jobs = [];
    this.reports = join(this.home, 'npm-consumer-reports');
    mkdirSync(this.reports);
    this.readers = {
      readArtifactMetadata: async id => structuredClone(this.metadata.find(item => String(item.id) === String(id))),
      readArtifactArchive: async id => this.archives.get(String(id)),
      readArtifacts: async () => structuredClone(this.metadata),
      readJobs: async () => structuredClone(this.jobs),
    };
    this.ciRun = { id: approval.ciRunId, run_attempt: approval.ciAttempt, head_sha: approval.commit,
      repository: { full_name: POLICY.repository }, head_repository: { full_name: POLICY.repository },
      path: '.github/workflows/ci.yml', event: 'push', status: 'completed', conclusion: 'success' };
    this.ciJobs = ['Lockfiles resolve to the public registry', 'ui',
      ...['ubuntu-latest', 'windows-latest', 'macos-latest'].flatMap(os =>
        [20, 22, 24].map(node => `test (${os}, ${node})`))]
      .map(name => ({ name, head_sha: approval.commit, status: 'completed', conclusion: 'success' }));
    this.sourceResponse = { tagType: 'tag', tagObject: approval.tagObject, tagCommit: approval.commit,
      tagTree: approval.tree, head: approval.commit, tree: approval.tree, status: '', workflowMatches: true };
  }

  pack(version, change = () => {}) {
    const pkg = { name: POLICY.name, version, repository: { url: `git+https://github.com/${POLICY.repository}.git` },
      license: 'MIT', dependencies: { 'smol-toml': '^1.8.0' },
      files: ['bin/', 'ui/dist/', 'supervisor/', 'tools/windows-security-helper/', 'THIRD_PARTY_NOTICES.txt'],
      scripts: Object.fromEntries(['test', 'consumer:check', 'compat:prepare', 'compat:clean',
        'test:compat', 'test:compat:browser'].map(name => [name, 'synthetic-command-output-only'])) };
    const files = {
      'package.json': JSON.stringify(pkg), 'README.md': 'SYNTHETIC', LICENSE: fixtureMit,
      'bin/cli.mjs': 'never executed', 'bin/mcp-bridge.mjs': 'never executed', 'ui/dist/index.html': 'synthetic',
      'ui/dist/assets/app.js': 'SYNTHETIC UI; never executed',
      'bin/windows/PoolingSecurityHelper.exe': `SYNTHETIC ${releaseRole(version)} helper; never executed`,
      'bin/windows/PoolingSecurityHelper.build.json': '{}',
      'tools/windows-security-helper/build.ps1': '# SYNTHETIC build script; never executed\r\n',
      ...Object.fromEntries(['service-control', 'pooling-writer', 'pooling-config', 'pooling-editor', 'pooling-files',
        ...(releaseRole(version) === 'current' ? ['pooling-execution', 'pooling-batches', 'pooling-batch-scheduler'] : [])]
        .map(name => [`bin/${name}.mjs`, `SYNTHETIC ${releaseRole(version)} runtime; never executed`])),
      ...Object.fromEntries(['supervise.mjs', 'bridge-child.mjs', 'supervise.sh', 'supervise.ps1']
        .map(name => [`supervisor/${name}`, 'SYNTHETIC supervisor; never executed'])),
      ...Object.fromEntries(['AssemblyInfo', 'PoolingSecurityHelper', 'PoolingSecurityReader',
        ...(releaseRole(version) === 'current' ? ['PoolingNativeFiles'] : [])]
        .map(name => [`bin/windows/src/${name}.cs`, 'synthetic source'])),
    };
    const license = { file: 'LICENSE', text: fixtureMit, sha256: hash(fixtureMit) };
    const packages = [{ name: 'synthetic-ui', version: '1.0.0', license: 'MIT', licenses: [license], comments: [] }];
    const runtimeNotices = [{ name: 'synthetic-runtime', version: '1.0.0', license: 'MIT',
      distribution: 'separately-installed', licenses: [license], comments: [] }];
    const notices = renderNotices(packages, runtimeNotices);
    files['THIRD_PARTY_NOTICES.txt'] = files['ui/dist/THIRD_PARTY_NOTICES.txt'] = notices;
    files['ui/dist/third-party-manifest.json'] = JSON.stringify({
      schemaVersion: 1, chunks: [{ modules: [] }], packages, runtimeNotices,
      sources: [{ path: 'src/main.js', sha256: hash('SYNTHETIC UI source') }],
      projectLicenseSha256: hash(fixtureMit), noticesSha256: hash(notices),
      artifacts: ['index.html', 'assets/app.js'].map(file => ({ file, sha256: hash(files[`ui/dist/${file}`]) })),
    });
    const nativeBaseline = Object.fromEntries(Object.entries(files)
      .filter(([path]) => path.startsWith('bin/windows/') || path === 'tools/windows-security-helper/build.ps1')
      .map(([path, bytes]) => [path, path.endsWith('.ps1') ? bytes.replaceAll('\r\n', '\n') : bytes]));
    change(files);
    const chunks = [];
    for (const [path, content] of Object.entries(files)) {
      const bytes = Buffer.from(content);
      const header = Buffer.alloc(512);
      header.write(`package/${path}`);
      header.write('0000644\0', 100);
      header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124);
      header.fill(32, 148, 156);
      header.write('0', 156);
      header.write(`${[...header].reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0')}\0 `, 148);
      chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
    }
    return { pkg, files, nativeBaseline, bytes: gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)])) };
  }

  zip(files) {
    const chunks = [];
    const directory = [];
    let offset = 0;
    for (const [name, content] of Object.entries(files)) {
      const bytes = Buffer.from(content);
      const encoded = Buffer.from(name);
      const header = Buffer.alloc(30);
      header.writeUInt32LE(0x04034b50);
      header.writeUInt32LE(bytes.length, 18);
      header.writeUInt32LE(bytes.length, 22);
      header.writeUInt16LE(encoded.length, 26);
      const entry = Buffer.alloc(46);
      entry.writeUInt32LE(0x02014b50);
      entry.writeUInt32LE(bytes.length, 20);
      entry.writeUInt32LE(bytes.length, 24);
      entry.writeUInt16LE(encoded.length, 28);
      entry.writeUInt32LE(offset, 42);
      chunks.push(header, encoded, bytes);
      directory.push(entry, encoded);
      offset += header.length + encoded.length + bytes.length;
    }
    const index = Buffer.concat(directory);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50);
    end.writeUInt16LE(directory.length / 2, 8);
    end.writeUInt16LE(directory.length / 2, 10);
    end.writeUInt32LE(index.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...chunks, index, end]);
  }

  async preflight(approval, { collectionProof = false, continuing = false } = {}, env = this.env) {
    validateApproval(approval, approval.scope);
    validateLocalApproval(approval, { continuing });
    validateContext(env, { sender: { login: POLICY.owner },
      repository: { full_name: POLICY.repository, private: false, fork: false } }, approval);
    validateSource(this.sourceResponse, approval);
    validatePackage(this.package.pkg, approval);
    validateCi(this.ciRun, this.ciJobs, approval);
    const run = await this.ownerReaders.readJson(`actions/runs/${env.GITHUB_RUN_ID}`);
    await readOwnerLocalAcceptance({ approval, env, continuing,
      event: { sender: run.actor, repository: run.repository,
        inputs: { action: approval.scope, approval: JSON.stringify(approval) } },
      readers: { readJson: async () => ({ ...run, status: 'in_progress', conclusion: null }) } });
    return collectionProof
      ? { runId: String(this.ciRun.id), attempt: this.ciRun.run_attempt, commit: this.ciRun.head_sha,
        completedAt: this.ciCompletedAt }
      : { runId: String(this.ciRun.id), attempt: this.ciRun.run_attempt,
        headSha: this.ciRun.head_sha, conclusion: this.ciRun.conclusion };
  }

  addArtifact(id, name, files) {
    const archive = this.zip(files);
    this.archives.set(String(id), archive);
    const metadata = { id, name, expired: false, digest: `sha256:${hash(archive)}`,
      workflow_run: { id: Number(this.env.GITHUB_RUN_ID), head_sha: this.approval.commit,
        repository_id: Number(this.env.GITHUB_REPOSITORY_ID), head_repository_id: Number(this.env.GITHUB_REPOSITORY_ID) } };
    this.metadata.push(metadata);
    return metadata;
  }

  async prepare(admitted) {
    const ci = await this.preflight(this.approval);
    this.nativeIdentity = await verifyNativeIdentity({
      sourceRoot: this.root, version: this.approval.version, commit: this.approval.commit,
    }, { run: (...args) => this.nativeResponse(...args) });
    const runner = new GateReaderFixture(this, admitted);
    this.source = runner.snapshot();
    if (this.approval.version === '2.0.2') {
      this.producerScan = await scanPublicationRequest({
        request: { schemaVersion: 1, phase: 'source', sourceRoot: this.root, root: this.root,
          name: POLICY.name, version: this.approval.version, commit: this.approval.commit,
          requiredGates: ['producer-advisories'] },
        publicPackages: this.approval.publicPackages,
        bindingReader: async () => ({ syntheticFixtureIdentityOnly: true }),
        fetchImpl: async (_url, options) => new Response(JSON.stringify({
          results: JSON.parse(options.body).queries.map(() => ({})),
        }), { headers: { 'Content-Type': 'application/json' } }),
      });
    }
    this.sourceReport = runSourceChecks(runner);
    this.prepared = syntheticPreparedLocal({
      schemaVersion: 1, status: 'prepared-awaiting-platform-gates', name: POLICY.name,
      version: this.approval.version, channel: channelFor(this.approval.version), source: sourceTuple(this.approval),
      toolchain: { node: POLICY.node, npm: POLICY.npm }, ci, publicPackages: this.approval.publicPackages,
      producerLocks: { root: this.source.rootLockSha256, ui: this.source.uiLockSha256 },
      workflow: { ref: this.env.GITHUB_WORKFLOW_REF, commit: this.approval.commit, runId: this.env.GITHUB_RUN_ID, attempt: 1 },
      artifact: { filename: 'candidate.tgz', ...digest(this.package.bytes),
        files: inspectTarball(this.package.bytes, this.approval).files },
      sourceReportSha256: hash(json(this.sourceReport)),
      ...(this.approval.version === '2.0.2' ? { producerAdvisories: {
        source: this.sourceReport.source, checks: this.sourceReport.checks,
        gate: this.sourceReport.gates['producer-advisories'],
      } } : {}),
    }, this.approval);
    this.sourceFiles = { 'prepared.json': json(this.prepared), 'candidate.tgz': this.package.bytes,
      'source-gates.json': json(this.sourceReport) };
    const metadata = this.addArtifact(300, `npm-prepared-${this.env.GITHUB_RUN_ID}-1`, this.sourceFiles);
    Object.assign(this.env, { PREPARED_MANIFEST_SHA256: hash(this.sourceFiles['prepared.json']), PREPARED_ARTIFACT_ID: '300',
      PREPARED_ARTIFACT_DIGEST: metadata.digest, PREPARED_TARBALL_SHA256: this.prepared.artifact.sha256,
      PREPARED_TARBALL_SHA512: this.prepared.artifact.sha512, PREPARED_TARBALL_INTEGRITY: this.prepared.artifact.integrity });
    this.writeSource(this.home);
    return verifyPreparedBundle({ directory: join(this.home, 'npm-prepared'), approval: this.approval,
      env: this.env, ...this.readers });
  }

  writeSource(temp) {
    for (const [name, bytes] of Object.entries(this.sourceFiles)) save(join(temp, 'npm-prepared', name), bytes);
  }

  async consumers() {
    for (const [index, lane] of MATRIX.entries()) {
      const temp = join(this.home, `lane-${index}`);
      this.writeSource(temp);
      const root = join(temp, 'checkout');
      for (const [name, bytes] of Object.entries(this.package.files)) save(join(root, name), bytes);
      save(join(root, 'package-lock.json'), '{}');
      const cli = join(temp, 'npm-consumer-toolchain-fixture/prefix/node_modules/npm/bin/npm-cli.js');
      save(cli, 'never executed');
      save(join(dirname(cli), '../package.json'), json({ name: 'npm', version: lane.npm }));
      const env = { ...this.env, RUNNER_TEMP: temp, RUNNER_NAME: `synthetic-${index}`, RUNNER_OS: lane.os,
        GITHUB_JOB: 'consumers', MATRIX_PLATFORM: lane.platform, MATRIX_NODE: lane.node, MATRIX_NPM: lane.npm, NPM_CONSUMER_CLI: cli };
      await runMatrix({ approval: this.approval, env, root, ...this.readers,
        event: { inputs: { action: 'prepare', approval: JSON.stringify(this.approval) },
          sender: { login: POLICY.owner }, repository: { full_name: POLICY.repository, private: false, fork: false } },
        runtime: { platform: lane.platform, versions: { node: lane.node }, arch: 'x64', execPath: join(temp, 'node.exe') },
        executor: (file, args) => this.consumerResponse(file, args, lane) });
      const bytes = readFileSync(join(temp, 'npm-consumer-report/report.json'));
      const name = `npm-consumer-${this.env.GITHUB_RUN_ID}-1-${lane.platform}-${lane.npm}`;
      this.addArtifact(400 + index, name, { 'report.json': bytes });
      save(join(this.reports, name, 'report.json'), bytes);
      this.jobs.push({ id: 500 + index, name: lane.jobName, run_id: Number(this.env.GITHUB_RUN_ID), run_attempt: 1,
        head_sha: this.approval.commit, status: 'completed', conclusion: 'success', runner_id: 600 + index,
        runner_name: env.RUNNER_NAME, labels: [lane.image],
        steps: ['Require supported hosted runner', 'Verify source transfer and run real consumers', 'Upload one consumer report']
          .map(name => ({ name, status: 'completed', conclusion: 'success' })) });
    }
    return verifyMatrixReports({ directory: this.reports, approval: this.approval,
      prepared: this.prepared, env: this.env, ...this.readers });
  }

  consumerResponse(file, args, lane) {
    this.calls.push({ file, args, syntheticExternalResponse: true });
    if (file === 'git') {
      const query = args.slice(2);
      const value = query[0] === 'cat-file' ? 'tag' : query[0] === 'status' ? ''
        : query[0] === 'hash-object' || query.at(-1).includes(POLICY.workflow) ? 'd'.repeat(40)
          : query[1] === this.approval.ref ? this.approval.tagObject
            : query[1].includes('^{tree}') ? this.approval.tree : this.approval.commit;
      return { stdout: value, stderr: '' };
    }
    if (args.at(-1) === '--version') return { stdout: lane.npm, stderr: '' };
    if (args.includes('ci')) return { stdout: 'synthetic restore response', stderr: '' };
    if (args.includes('--test')) {
      const names = ['real helper inspection emits only one fingerprint and does not change file contents',
        'real helper prepares both files with matching security without writing config data',
        'real helper refuses a stale fingerprint without writing config data',
        ...Array.from({ length: 6 }, (_, index) => `synthetic ${index}`)];
      return { stdout: `TAP version 13\n${names.map((name, index) => `ok ${index + 1} - ${name}\n`).join('')}` +
        '1..9\n# tests 9\n# pass 9\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n', stderr: '' };
    }
    assert.ok(args.includes('consumer:check'));
    const dependencies = [{ path: `node_modules/${POLICY.name}`, name: POLICY.name,
      version: this.approval.version, integrity: this.prepared.artifact.integrity },
    { path: 'node_modules/smol-toml', name: 'smol-toml', version: '1.8.0', integrity: fixtureIntegrity }];
    const licenseEvidence = fixtureLicenseEvidence(dependencies);
    const candidate = licenseEvidence.packages.find(item => item.name === POLICY.name);
    const text = this.package.files['package.json'];
    candidate.packageJson = { path: 'package.json', text, sha256: hash(text) };
    candidate.files = [{ path: 'LICENSE', text: this.package.files.LICENSE, sha256: hash(this.package.files.LICENSE) }];
    return { stdout: json({ schemaVersion: 2, name: POLICY.name, version: this.approval.version,
      sha256: this.prepared.artifact.sha256, node: `v${lane.node}`, npm: lane.npm, platform: lane.platform,
      installScripts: args.includes('--ignore-scripts') ? 'disabled' : 'npm-default',
      producerLockCopied: false, installedBin: true, bridgeAndUi: true, dependencies,
      licenseEvidence, registrySignature: 'pending-publication',
      provenance: 'not-verified-by-consumer-smoke' }), stderr: '' };
  }

  async nativeResponse(file, args) {
    assert.equal(file, 'git');
    const at = args.indexOf('-C');
    assert.equal(args[at + 1], this.root);
    const command = args.slice(at + 2);
    const build = 'tools/windows-security-helper/build.ps1';
    const entries = Object.entries(this.package.nativeBaseline).map(([path, value]) => ({
      path, bytes: Buffer.from(value),
      blob: createHash('sha1').update(`blob ${Buffer.byteLength(value)}\0`).update(value).digest('hex'),
    }));
    let stdout;
    if (command[0] === 'cat-file' &&
        command[1] === '-e') stdout = '';
    else if (command[0] === 'ls-tree') {
      assert.ok(command.includes(releaseRole(this.approval.version) === 'legacy' ? LEGACY_REF : CURRENT_REF));
      stdout = entries.map(item => `100644 blob ${item.blob}\t${item.path}\0`).join('');
    } else if (command[0] === 'cat-file') {
      const entry = command[2] === `${this.approval.commit}:${build}`
        ? entries.find(item => item.path === build) : entries.find(item => item.blob === command[2]);
      assert.ok(entry, 'Unexpected synthetic native blob query');
      stdout = entry.bytes;
    } else if (command[0] === 'rev-parse') {
      assert.equal(command.at(-1), 'info/attributes');
      stdout = join(this.root, '.git/info/attributes');
    } else if (command[0] === 'check-attr') {
      assert.ok(command.includes(`--source=${this.approval.commit}`));
      stdout = Object.entries({ text: 'set', eol: 'crlf', filter: 'unspecified',
        'working-tree-encoding': 'unspecified', ident: 'unspecified' })
        .flatMap(([name, value]) => [build, name, value]).join('\0') + '\0';
    } else assert.fail('Unexpected synthetic native Git operation');
    return { code: 0, stdout, stderr: '' };
  }

  replacementResponse(args) {
    const selected = replacementOptions(args);
    const artifacts = Object.fromEntries(Object.entries(selected).map(([role, spec]) => {
      const bytes = readFileSync(spec.tarball);
      assert.equal(digest(bytes).sha256, spec.sha256);
      return [role, { ...spec, files: inspectTarball(bytes, { version: spec.version }).files }];
    }));
    const result = {
      gate: 'T32-service-replacement', node: `v${POLICY.node}`, platform: 'linux',
      artifacts: Object.fromEntries(Object.entries(artifacts).map(([role, value]) =>
        [role, { version: value.version, sha256: value.sha256 }])),
      steps: [0, 1, 2, 3].map(index => {
        const from = artifacts[index % 2 ? 'current' : 'legacy'];
        const to = artifacts[index % 2 ? 'legacy' : 'current'];
        return { from: from.version, to: to.version,
          timing: index < 2 ? 'before-first-write' : 'after-worker-loaded',
          fromInstanceId: `synthetic-instance-${index}`, instanceId: `synthetic-instance-${index + 1}`,
          heldBeforeAndAfterReplacement: true, ui: { version: to.version,
            files: to.files.filter(item => item.path.startsWith('ui/dist/')).map(({ path, sha256 }) => ({ path, sha256 })) } };
      }),
      currentWrite: { applyBatch: 'synthetic-apply', undoBatch: 'synthetic-undo', workerObserved: true },
      legacyBefore: { scope: 'posix', status: 200, writeSupported: true },
      legacyAfter: { scope: 'posix', status: 200, writeSupported: true },
      secondInstanceUnchanged: 'synthetic-second-instance',
      nativeHelper: { executed: false, sha256: Object.fromEntries(Object.entries(artifacts).map(([role, value]) =>
        [role, value.files.find(item => item.path === 'bin/windows/PoolingSecurityHelper.exe').sha256])) },
    };
    this.controls.replacement?.(result);
    return result;
  }

  async finalize(peerFetcher, verifyBundle) {
    return finalizeInputs({ approval: this.approval, env: this.env,
      preflight: (...args) => this.preflight(...args),
      verifySource: options => verifyPreparedBundle({ ...options, ...this.readers }),
      verifyConsumers: options => verifyMatrixReports({ ...options, ...this.readers }),
      resolvePeer: options => downloadPeer({ ...options, fetcher: peerFetcher, verifyBundle }) });
  }

  async stageInputs(finalized, admitted) {
    const extractedRoot = mkdtempSync(join(this.home, 'extracted-'));
    extractTarball(this.package.bytes, this.approval, extractedRoot);
    const binding = { source: this.source, commit: this.approval.commit, version: this.approval.version,
      artifact: digest(this.package.bytes), tarball: join(this.home, 'npm-prepared/candidate.tgz'),
      extractedRoot, files: finalized.inspection.files, sourceReportSha256: this.prepared.sourceReportSha256 };
    const gates = await runArtifactChecks(new GateReaderFixture(this, admitted, finalized), binding, this.sourceReport, evidence);
    const { status, ...prepared } = finalized.prepared;
    const manifest = { ...prepared, phase: 'prepared-not-staged', gateReportSha256: hash(json(gates)),
      sourceArtifact: finalized.sourceArtifact, matrixArtifacts: finalized.matrix.artifactEvidence, peerArtifact: finalized.peer.evidence };
    return new StageFixture(this.approval, this.package.bytes, manifest, gates, files => this.zip(files), this.jobs);
  }
}

class GateReaderFixture {
  constructor(candidate, admitted, finalized = {}) {
    this.candidate = candidate;
    this.admitted = admitted;
    this.root = candidate.root;
    this.package = candidate.package.pkg;
    this.uiPackage = { scripts: { typecheck: 'synthetic', build: 'synthetic' } };
    this.context = { approval: candidate.approval, publicPackages: candidate.approval.publicPackages,
      matrix: finalized.matrix, peer: finalized.peer };
  }
  snapshot() { return GateRunner.prototype.snapshot.call(this); }
  requireScripts(...args) { return GateRunner.prototype.requireScripts.call(this, ...args); }
  publicCoordinates() { return GateRunner.prototype.publicCoordinates.call(this); }
  verifyArtifact(...args) { return GateRunner.prototype.verifyArtifact.call(this, ...args); }
  run(_label, executable, args) {
    assert.equal(executable, 'git');
    return this.candidate.consumerResponse(executable, args);
  }
  npm(args) {
    const audit = { auditReportVersion: 2, vulnerabilities: {},
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } };
    return { stdout: args.includes('audit') ? json(audit) : POLICY.npm, evidence };
  }
  script() { return { stdout: '', evidence }; }
  node(file, args) {
    this.candidate.calls.push({ file, args, syntheticExternalResponse: true });
    const response = file === 'tools/npm-publication/compatibility-report.mjs'
      ? { npmVersion: POLICY.npm, runtimeMajor: POLICY.node.split('.')[0], plan: fixturePlan(this.package.version),
        sources: { [releaseRole(this.package.version) === 'legacy' ? 'legacy' : 'candidate']:
          { archiveSha256: this.candidate.prepared.artifact.sha256 } } }
      : file === 'tools/service-replacement/check.mjs'
        ? this.candidate.replacementResponse(args) : { syntheticExternalCommand: true };
    const stdout = json(response);
    const command = { file: process.execPath, args: [join(this.root, file), ...args], cwd: this.root };
    return { stdout, rawStdout: stdout, evidence: {
      ...evidenceFor('SYNTHETIC external command response; not OS execution', json({ exitCode: 0, stdout, stderr: '' })),
      exitCode: 0, command,
      commandSha256: hash(JSON.stringify(command)), stdoutSha256: hash(stdout), stderrSha256: hash('') } };
  }
  compatibility(...args) { return GateRunner.prototype.compatibility.call(this, ...args); }
  external(phase, binding, additional) {
    if (phase === 'artifact') {
      const request = { schemaVersion: 1, phase, name: POLICY.name, version: binding.version,
        commit: binding.commit, sourceRoot: this.root, root: binding.extractedRoot,
        extractedRoot: binding.extractedRoot, tarball: binding.tarball, artifact: binding.artifact,
        approval: this.context.approval, publicPackages: this.context.publicPackages,
        requiredGates: ARTIFACT_EXTERNAL, ...additional };
      this.candidate.calls.push({ phase, request, actualExternalValidation: true });
      return aggregateExternalGates(request, {
        scanPublication: async ({ request: scan }) => ({
          schemaVersion: 1, phase, commit: scan.commit, artifact: scan.artifact,
          status: 'passed', scannerDetails: { syntheticExternalResponse: true },
          gates: Object.fromEntries(scan.requiredGates.map(name => [name, {
            status: 'passed', ...(name.endsWith('private-identifiers') ? { ownerReview: 'pending' } : {}),
            evidence: [evidence],
          }])),
        }),
        advisories: async () => ({ status: 'passed', syntheticExternalResponse: true }),
      }).then(report => {
        this.candidate.externalReport = report;
        return { ...report, gates: externalGates(report, phase, binding) };
      });
    }
    assert.ok(this.candidate.nativeIdentity, 'Actual native identity validator must complete first');
    const names = phase === 'source' ? SOURCE_EXTERNAL : ARTIFACT_EXTERNAL;
    const report = { schemaVersion: 1, phase, commit: this.candidate.approval.commit,
      artifact: binding.artifact, gates: Object.fromEntries(names.map(name => [name, { status: 'passed', evidence: [evidence] }])) };
    if (phase === 'source') Object.assign(report.gates, this.admitted.gates);
    if (phase === 'source' &&
        this.candidate.producerScan) Object.assign(report.gates, this.candidate.producerScan.gates);
    return { ...report, nativeIdentity: this.candidate.nativeIdentity, gates: externalGates(report, phase, binding),
      ...(phase === 'source' ? { scannerDetails: this.admitted.scannerDetails } : {}) };
  }
}

export class StageFixture {
  constructor(prepareApproval, tarball, manifest, gates, zip, consumerJobs = []) {
    this.manifest = manifest;
    this.gates = gates;
    this.files = { 'candidate.tgz': tarball, 'manifest.json': json(manifest), 'gates.json': json(gates) };
    this.archive = zip(this.files);
    const now = new Date().toISOString();
    this.approval = { ...structuredClone(prepareApproval), scope: 'stage', approvedAt: now,
      artifact: { ...digest(tarball), manifestSha256: hash(this.files['manifest.json']),
        artifactDigest: `sha256:${hash(this.archive)}`, artifactId: '800', runId: manifest.workflow.runId, runAttempt: 1 },
      ownerPreflight: {
        owner: POLICY.owner, checkedAt: now, packageName: POLICY.name, expectedDistTags: prepareApproval.expectedDistTags,
        unresolvedSubmission: false, pending: { status: 'none' },
        trust: { repository: POLICY.repository, workflow: 'npm-publish.yml', environment: POLICY.environment,
          allowPublish: false, allowStagePublish: true },
        privateContentReview: { reviewer: POLICY.owner, reviewedAt: now, scope: 'source-and-tarball', disposition: 'approved',
          historyAndAuthorsReviewed: true, historicalEvidenceAccepted: true, commit: prepareApproval.commit,
          artifact: digest(tarball), localRegression: syntheticLocalReview(prepareApproval.localRegression, now) },
      } };
    delete this.approval.secretReview;
    this.run = { id: manifest.workflow.runId, head_sha: prepareApproval.commit,
      repository: { full_name: POLICY.repository }, head_repository: { full_name: POLICY.repository },
      path: POLICY.workflow, event: 'workflow_dispatch', run_attempt: 1, status: 'completed', conclusion: 'success' };
    this.jobs = [...consumerJobs, ...['source', 'prepare'].map(name =>
      ({ name, head_sha: prepareApproval.commit, status: 'completed', conclusion: 'success' })),
    { name: 'stage', status: 'completed', conclusion: 'skipped' }];
    this.metadata = { id: 800, name: `npm-candidate-${manifest.workflow.runId}-1`, expired: false,
      digest: this.approval.artifact.artifactDigest, workflow_run: { id: manifest.workflow.runId, head_sha: prepareApproval.commit } };
    this.environment = { id: 9, name: POLICY.environment,
      protection_rules: [{ type: 'required_reviewers', prevent_self_review: false,
        reviewers: [{ reviewer: { login: POLICY.owner } }] }],
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } };
    this.environmentPolicies = [{ type: 'tag', name: prepareApproval.ref.slice('refs/tags/'.length) }];
    this.environmentReviews = [{ state: 'approved', user: { login: POLICY.owner },
      environments: [{ id: this.environment.id, name: POLICY.environment }] }];
  }
  validate() {
    validateApproval(this.approval, 'stage');
    validateEnvironment(this.environment, this.environmentPolicies, this.environmentReviews, this.approval);
    validateTransfer(this.run, this.jobs, this.metadata, this.approval);
    assert.equal(`sha256:${hash(this.archive)}`, this.approval.artifact.artifactDigest);
    const files = zipFiles(this.archive);
    assert.deepEqual([...files.keys()].sort(), ['candidate.tgz', 'gates.json', 'manifest.json']);
    const gates = JSON.parse(files.get('gates.json'));
    const manifest = validateLocalManifest(files.get('manifest.json'), this.approval, gates);
    sameDigests(digest(files.get('candidate.tgz')), this.approval.artifact);
    assert.equal(manifest.phase, 'prepared-not-staged');
    assert.equal(manifest.name, this.approval.name);
    assert.equal(manifest.version, this.approval.version);
    assert.equal(manifest.channel, channelFor(this.approval.version));
    assert.equal(manifest.gateReportSha256, hash(files.get('gates.json')));
    assert.equal(manifest.ci.runId, this.approval.ciRunId);
    assert.equal(manifest.ci.attempt, this.approval.ciAttempt);
    assert.deepEqual(inspectTarball(files.get('candidate.tgz'), this.approval).files, manifest.artifact.files);
    validateGates(gates, this.approval, this.approval.artifact);
    return manifest;
  }
}
