import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, lstatSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  POLICY, digest, sameDigests, channelFor, validateApproval, validateContext, validateSource, validatePackage,
  validateCi, validateEnvironment, validateGates, validateTransfer, npm12Contents, submitOnce,
} from './policy.mjs';
import { inspectTarball } from './tarball.mjs';
import { scannerEnvironment, temporaryEnvironment } from './gate-environment.mjs';
import { githubReaders, zipFiles, validateMatrixContext, verifyPreparedBundle, verifyMatrixReports } from './matrix.mjs';
import { downloadPeer } from './peer.mjs';
import { bootstrapWorkflow, validateBootstrapContext, signBootstrapOnce } from './bootstrap.mjs';
import { readCandidateEvidence, readRemoteSource, readProtectedEnvironment, readSigningRun,
  readAbsentRegistry } from './bootstrap-readers.mjs';
import { npmProvenance } from './provenance.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const save = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });

function run(executable, args, options = {}) {
  const { showOutput = false, ...spawnOptions } = options;
  const result = spawnSync(executable, args, {
    cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, shell: false, ...spawnOptions,
  });
  if (showOutput) {
    process.stdout.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
  }
  assert.equal(result.error, undefined, 'Executable failed to start');
  // Do not echo npm output on failure: authentication responses can contain credentials.
  assert.equal(result.status, 0, `${executable === process.execPath ? 'Node command' : executable} failed (${result.status}); no retry`);
  return result.stdout.trim();
}

function git(...args) {
  return run('git', ['-c', 'core.autocrlf=false', ...args]);
}

function source(approval) {
  return {
    tagType: git('cat-file', '-t', approval.ref),
    tagObject: git('rev-parse', approval.ref),
    tagCommit: git('rev-parse', `${approval.ref}^{commit}`),
    tagTree: git('rev-parse', `${approval.ref}^{tree}`),
    head: git('rev-parse', 'HEAD'),
    tree: git('rev-parse', 'HEAD^{tree}'),
    status: git('status', '--porcelain', '--untracked-files=all'),
    workflowMatches: git('hash-object', POLICY.workflow) === git('rev-parse', `${approval.commit}:${POLICY.workflow}`),
  };
}

export function cleanNpmEnvironment(env, home, stage = false) {
  for (const key of Object.keys(env)) {
    assert.ok(!/^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_ID_TOKEN|SIGSTORE_ID_TOKEN|NODE_OPTIONS)$/i.test(key) ||
      !env[key], 'Preexisting token/Node injection is forbidden');
    assert.ok(!/^npm_config_/i.test(key) ||
      !env[key], 'Inherited npm configuration is forbidden in publication jobs');
  }
  const result = {
    PATH: env.PATH, HOME: home, USERPROFILE: home,
    ...temporaryEnvironment(stage ? home : env.RUNNER_TEMP ?? tmpdir()),
    CI: 'true', NO_COLOR: '1',
    ...(!stage ? scannerEnvironment(env) : {}),
  };
  if (stage) {
    for (const key of ['GITHUB_ACTIONS', 'GITHUB_SERVER_URL', 'GITHUB_REPOSITORY',
      'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_REF', 'GITHUB_SHA',
      'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
      'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT', 'ACTIONS_ID_TOKEN_REQUEST_URL',
      'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) {
      assert.ok(env[key], `Missing hosted identity: ${key}`);
      result[key] = env[key];
    }
  }
  return result;
}

export function bootstrapEnvironment(env, home) {
  const child = cleanNpmEnvironment(env, home, true);
  for (const key of ['GITHUB_API_URL', 'GITHUB_REPOSITORY_OWNER', 'GITHUB_ACTOR',
    'GITHUB_TRIGGERING_ACTOR', 'GITHUB_JOB', 'GITHUB_EVENT_PATH', 'RUNNER_OS', 'RUNNER_ARCH',
    'ACTUAL_RUNNER_ENVIRONMENT', 'NPM_PUBLICATION_CLI']) {
    assert.ok(env[key], `Missing bootstrap context: ${key}`);
    child[key] = env[key];
  }
  return child;
}

async function github(path) {
  assert.ok(process.env.GITHUB_TOKEN, 'Read-only GitHub job token required');
  const response = await fetch(`https://api.github.com/repos/${POLICY.repository}/${path}`, {
    headers: {
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
    },
    redirect: 'error', signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 200, `GitHub read failed (${response.status}); no fallback`);
  return response.json();
}

async function jobs(runId, attempt) {
  const all = [];
  for (let page = 1; page <= 20; page++) {
    const result = await github(`actions/runs/${runId}/attempts/${attempt}/jobs?per_page=100&page=${page}`);
    all.push(...result.jobs);
    if (all.length === result.total_count) return all;
    assert.ok(result.jobs.length > 0, 'Incomplete CI job pagination');
  }
  throw new Error('Unexpected CI job count');
}

export async function sourceAndCi(approval) {
  validateSource(source(approval), approval);
  validatePackage(json(join(root, 'package.json')), approval);
  for (const name of ['.npmrc', 'ui/.npmrc']) {
    assert.ok(!existsSync(join(root, name)), 'Project npm configuration is forbidden in publication preparation');
  }
  const tag = await github(`git/ref/tags/${approval.ref.slice('refs/tags/'.length)}`);
  assert.equal(tag.object?.type, 'tag');
  assert.equal(tag.object?.sha, approval.tagObject, 'Remote release tag moved');
  const ci = await github(`actions/runs/${approval.ciRunId}/attempts/${approval.ciAttempt}`);
  validateCi(ci, await jobs(approval.ciRunId, approval.ciAttempt), approval);
  return { runId: ci.id, attempt: ci.run_attempt, headSha: ci.head_sha, conclusion: ci.conclusion };
}

export function sourceLocks() {
  return {
    root: digest(readFileSync(join(root, 'package-lock.json'))).sha256,
    ui: digest(readFileSync(join(root, 'ui/package-lock.json'))).sha256,
  };
}

function toolchain() {
  assert.equal(process.versions.node, POLICY.node, 'Use the reviewed publishing Node patch');
  const cli = resolve(process.env.NPM_PUBLICATION_CLI ?? '');
  const pkg = json(resolve(dirname(cli), '../package.json'));
  assert.equal(pkg.name, 'npm');
  assert.equal(pkg.version, POLICY.npm);
  assert.equal(run(process.execPath, [cli, '--version']), POLICY.npm);
  return cli;
}

function workspace(name = 'npm-publication') {
  const temp = resolve(process.env.RUNNER_TEMP);
  const output = join(temp, name);
  assert.ok(!existsSync(output), 'Publication output already exists; no resume/retry');
  mkdirSync(output);
  const home = join(temp, 'npm-publication-home');
  mkdirSync(home, { mode: 0o700 });
  const config = { user: join(home, 'user.npmrc'), global: join(home, 'global.npmrc') };
  for (const path of Object.values(config)) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
  return { output, home, config };
}

async function prepare(approval) {
  const ci = await sourceAndCi(approval);
  const cli = toolchain();
  const { output, home, config } = workspace('npm-publication-prepared');
  const env = cleanNpmEnvironment(process.env, home);
  env.NPM_PUBLICATION_CLI = cli;
  const npm = args => run(process.execPath, [cli,
    `--userconfig=${config.user}`, `--globalconfig=${config.global}`, ...args], {
    env, showOutput: args[0] === 'run',
  });
  const context = join(home, 'context.json');
  save(context, { publicPackages: approval.publicPackages });
  const sourceReport = join(output, 'source-gates.json');
  run(process.execPath, [join(root, 'tools/npm-publication/source-gates.mjs'),
    '--context', context, '--output', sourceReport], { env, showOutput: true });
  validateSource(source(approval), approval);
  const locks = {
    root: digest(readFileSync(join(root, 'package-lock.json'))).sha256,
    ui: digest(readFileSync(join(root, 'ui/package-lock.json'))).sha256,
  };
  const packedOutput = npm(['pack', '--ignore-scripts', '--json', '--offline', '--pack-destination', output]);
  const generated = join(output, `${POLICY.name}-${approval.version}.tgz`);
  const bytes = readFileSync(generated);
  const packed = npm12Contents(packedOutput, approval, bytes);
  const inspection = inspectTarball(bytes, approval);
  assert.deepEqual(packed.files.map(({ path, size, mode }) => ({ path, size, mode }))
    .sort((a, b) => a.path.localeCompare(b.path)),
  inspection.files.map(({ path, size, mode }) => ({ path, size, mode })));
  const tarball = join(output, 'candidate.tgz');
  // Rename is not a repack. Validation and stage receive these same bytes.
  const { renameSync } = await import('node:fs');
  renameSync(generated, tarball);
  sameDigests(digest(readFileSync(tarball)), digest(bytes));
  validateSource(source(approval), approval);
  assert.equal(digest(readFileSync(join(root, 'package-lock.json'))).sha256, locks.root);
  assert.equal(digest(readFileSync(join(root, 'ui/package-lock.json'))).sha256, locks.ui);
  const prepared = {
    schemaVersion: 1, status: 'prepared-awaiting-platform-gates', name: POLICY.name, version: approval.version,
    major: Number(approval.version[0]), channel: channelFor(approval.version),
    source: { ref: approval.ref, tagObject: approval.tagObject, commit: approval.commit, tree: approval.tree },
    workflow: { ref: process.env.GITHUB_WORKFLOW_REF, commit: process.env.GITHUB_WORKFLOW_SHA,
      runId: process.env.GITHUB_RUN_ID, attempt: 1 },
    ci, toolchain: { node: POLICY.node, npm: POLICY.npm }, producerLocks: locks,
    artifact: { filename: 'candidate.tgz', ...digest(bytes), files: inspection.files },
    sourceReportSha256: digest(readFileSync(sourceReport)).sha256,
    publicPackages: approval.publicPackages,
    preparationApproval: { approver: approval.approver, approvedAt: approval.approvedAt, scope: 'prepare' },
    stage: { status: 'not-submitted', stageId: null },
    provenance: { status: 'pending-stage', verification: 'pending-owner-cryptographic-verification' },
    registrySignatures: { status: 'pending-publication' },
    privateContentReview: {
      status: 'pending-owner-review', commit: approval.commit, artifact: digest(bytes),
    },
    publicationApproval: { status: 'not-authorized' },
  };
  save(join(output, 'prepared.json'), prepared);
  assert.deepEqual(readdirSync(output).sort(), ['candidate.tgz', 'prepared.json', 'source-gates.json']);
  const preparedSha256 = digest(readFileSync(join(output, 'prepared.json'))).sha256;
  writeFileSync(process.env.GITHUB_OUTPUT, [
    `prepared-sha256=${preparedSha256}`, `tarball-sha256=${prepared.artifact.sha256}`,
    `tarball-sha512=${prepared.artifact.sha512}`, `tarball-integrity=${prepared.artifact.integrity}`, '',
  ].join('\n'), { flag: 'a' });
  console.log(JSON.stringify({ preparedSha256, artifact: digest(bytes), status: prepared.status }, null, 2));
}

async function finalize(approval) {
  const ci = await sourceAndCi(approval);
  const input = join(resolve(process.env.RUNNER_TEMP), 'npm-prepared');
  const { prepared, inspection, sourceArtifact } = await verifyPreparedBundle({
    directory: input, approval, env: process.env,
  });
  assert.deepEqual(prepared.publicPackages, approval.publicPackages);
  assert.deepEqual(prepared.ci, ci);
  assert.deepEqual(prepared.preparationApproval,
    { approver: approval.approver, approvedAt: approval.approvedAt, scope: 'prepare' });
  const matrix = await verifyMatrixReports({
    directory: join(resolve(process.env.RUNNER_TEMP), 'npm-consumer-reports'),
    approval, prepared, env: process.env,
  });
  // The other patch is passive comparison input, never this run's provenance subject.
  const peer = await downloadPeer({ approval, env: process.env,
    directory: join(resolve(process.env.RUNNER_TEMP), 'npm-publication-peer') });
  const cli = toolchain();
  const { output, home } = workspace();
  const env = { ...cleanNpmEnvironment(process.env, home), NPM_PUBLICATION_CLI: cli };
  const context = join(home, 'context.json');
  save(context, { publicPackages: approval.publicPackages, matrix, peer });
  const bytes = readFileSync(join(input, 'candidate.tgz'));
  sameDigests(digest(bytes), prepared.artifact);
  const tarball = join(output, 'candidate.tgz');
  writeFileSync(tarball, bytes, { flag: 'wx' });
  const reportPath = join(output, 'gates.json');
  run(process.execPath, [join(root, 'tools/npm-publication/artifact-gates.mjs'),
    '--tarball', tarball, '--source-report', join(input, 'source-gates.json'),
    '--context', context, '--output', reportPath], { env, showOutput: true });
  const report = json(reportPath);
  validateGates(report, approval, prepared.artifact);
  assert.equal(report.sourceReportSha256, prepared.sourceReportSha256, 'Finalizer consumed different source evidence');
  sameDigests(digest(readFileSync(tarball)), prepared.artifact);
  validateSource(source(approval), approval);
  assert.deepEqual(prepared.producerLocks, {
    root: digest(readFileSync(join(root, 'package-lock.json'))).sha256,
    ui: digest(readFileSync(join(root, 'ui/package-lock.json'))).sha256,
  });
  const { status, ...sourceManifest } = prepared;
  const manifest = { ...sourceManifest, phase: 'prepared-not-staged',
    artifact: { filename: 'candidate.tgz', ...digest(bytes), files: inspection.files },
    gateReportSha256: digest(readFileSync(reportPath)).sha256,
    sourceArtifact, matrixArtifacts: matrix.artifactEvidence, peerArtifact: peer.evidence };
  save(join(output, 'manifest.json'), manifest);
  assert.deepEqual(readdirSync(output).sort(), ['candidate.tgz', 'gates.json', 'manifest.json']);
  console.log(JSON.stringify({ manifestSha256: digest(readFileSync(join(output, 'manifest.json'))).sha256,
    artifact: digest(bytes), status: manifest.phase }, null, 2));
}

async function transfer(approval) {
  const artifact = approval.artifact;
  const runInfo = await github(`actions/runs/${artifact.runId}`);
  const preparedJobs = await jobs(artifact.runId, 1);
  const metadata = await github(`actions/artifacts/${artifact.artifactId}`);
  validateTransfer(runInfo, preparedJobs, metadata, approval);
  const archive = await githubReaders(process.env).readArtifactArchive(artifact.artifactId);
  assert.equal(`sha256:${digest(archive).sha256}`, artifact.artifactDigest, 'Actual candidate ZIP digest mismatch');
  const files = zipFiles(archive);
  assert.deepEqual([...files.keys()].sort(), ['candidate.tgz', 'gates.json', 'manifest.json']);
  assert.equal(digest(files.get('manifest.json')).sha256, artifact.manifestSha256);
  sameDigests(digest(files.get('candidate.tgz')), artifact);
}

async function stage(approval) {
  await sourceAndCi(approval);
  const environment = await github(`environments/${POLICY.environment}`);
  const policies = await github(`environments/${POLICY.environment}/deployment-branch-policies?per_page=100`);
  assert.equal(policies.total_count, policies.branch_policies.length, 'Incomplete environment policies');
  validateEnvironment(environment, policies.branch_policies,
    await github(`actions/runs/${process.env.GITHUB_RUN_ID}/approvals`), approval);
  await transfer(approval);
  const input = join(resolve(process.env.RUNNER_TEMP), 'npm-candidate');
  assert.deepEqual(readdirSync(input).sort(), ['candidate.tgz', 'gates.json', 'manifest.json']);
  for (const name of readdirSync(input)) assert.equal(lstatSync(join(input, name)).isFile(), true);
  assert.equal(digest(readFileSync(join(input, 'manifest.json'))).sha256, approval.artifact.manifestSha256);
  const manifest = json(join(input, 'manifest.json'));
  assert.equal(manifest.phase, 'prepared-not-staged');
  assert.equal(manifest.name, approval.name);
  assert.equal(manifest.version, approval.version);
  assert.equal(manifest.channel, validateApproval(approval, 'stage'));
  assert.deepEqual(manifest.source, {
    ref: approval.ref, tagObject: approval.tagObject, commit: approval.commit, tree: approval.tree,
  });
  assert.equal(manifest.workflow.ref, process.env.GITHUB_WORKFLOW_REF);
  assert.equal(manifest.workflow.commit, approval.commit);
  assert.equal(String(manifest.workflow.runId), String(approval.artifact.runId));
  assert.equal(manifest.workflow.attempt, 1);
  assert.equal(String(manifest.ci.runId), String(approval.ciRunId));
  assert.equal(manifest.ci.attempt, Number(approval.ciAttempt));
  assert.deepEqual(manifest.toolchain, { node: POLICY.node, npm: POLICY.npm });
  assert.deepEqual(manifest.producerLocks, {
    root: digest(readFileSync(join(root, 'package-lock.json'))).sha256,
    ui: digest(readFileSync(join(root, 'ui/package-lock.json'))).sha256,
  });
  assert.equal(manifest.gateReportSha256, digest(readFileSync(join(input, 'gates.json'))).sha256);
  const tarball = join(input, 'candidate.tgz');
  const bytes = readFileSync(tarball);
  sameDigests(digest(bytes), approval.artifact);
  sameDigests(manifest.artifact, approval.artifact);
  assert.equal(manifest.privateContentReview?.status, 'pending-owner-review');
  assert.equal(manifest.privateContentReview.commit, approval.commit);
  sameDigests(manifest.privateContentReview.artifact, approval.artifact);
  assert.deepEqual(inspectTarball(bytes, approval).files, manifest.artifact.files);
  validateGates(json(join(input, 'gates.json')), approval, digest(bytes));
  const cli = toolchain();
  const { output, home, config } = workspace();
  const env = cleanNpmEnvironment(process.env, home, true);
  let sequence = 0;
  await submitOnce({
    approval, bytes, tarball, config,
    readRegistry: async () => {
      const response = await fetch(`${POLICY.registry}${POLICY.name}`, {
        redirect: 'error', signal: AbortSignal.timeout(30_000), headers: { accept: 'application/json' },
      });
      assert.equal(response.status, 200,
        `Registry read failed (${response.status}); bootstrap/ownership remains unverified, no write`);
      return response.json();
    },
    execute: args => {
      validateContext(process.env, json(process.env.GITHUB_EVENT_PATH), approval);
      validateSource(source(approval), approval);
      sameDigests(digest(readFileSync(tarball)), approval.artifact);
      return run(process.execPath, [cli, ...args], { cwd: home, env });
    },
    record: state => {
      save(join(output, `stage-${sequence++}.json`), {
        schemaVersion: 1, source: manifest.source, artifact: digest(bytes), name: approval.name,
        version: approval.version, channel: manifest.channel, workflow: {
          ref: process.env.GITHUB_WORKFLOW_REF, commit: process.env.GITHUB_WORKFLOW_SHA,
          runId: process.env.GITHUB_RUN_ID, attempt: 1,
        },
        authorization: { approver: approval.approver, approvedAt: approval.approvedAt, scope: 'stage' },
        ownerPreflight: approval.ownerPreflight, recordedAt: new Date().toISOString(), ...state,
      });
      console.log(JSON.stringify(state));
    },
  });
}

async function signBootstrap(approval) {
  validateBootstrapContext({ env: process.env, event: json(process.env.GITHUB_EVENT_PATH), approval });
  // Reject inherited credentials/config before loading a signing library or starting a child.
  cleanNpmEnvironment(process.env, resolve(process.env.RUNNER_TEMP), true);
  const api = npmProvenance(process.env.NPM_PUBLICATION_CLI);
  const readers = githubReaders(process.env);
  const workflow = bootstrapWorkflow(process.env);
  const locks = sourceLocks();
  let candidate;
  const revalidate = async () => {
    validateBootstrapContext({ env: process.env, event: json(process.env.GITHUB_EVENT_PATH), approval });
    await sourceAndCi(approval);
    const source = await readRemoteSource(approval, readers);
    assert.equal(source.repositoryId, workflow.repositoryId);
    assert.equal(source.ownerId, workflow.ownerId);
    assert.deepEqual(await readSigningRun(approval, workflow.runId, readers, false), workflow);
    const environment = await readProtectedEnvironment(approval, workflow.runId, readers);
    assert.deepEqual(sourceLocks(), locks);
    candidate = await readCandidateEvidence(approval, locks, readers);
    assert.equal(String(candidate.repository.id), workflow.repositoryId);
    return { source, environment, preparation: candidate.evidence, registry: await readAbsentRegistry() };
  };
  await revalidate();
  const { output: ledger, home } = workspace('npm-bootstrap-ledger');
  const env = bootstrapEnvironment(process.env, home);
  const tarball = join(home, 'candidate.tgz');
  const context = join(home, 'bootstrap-context.json');
  const bundle = join(home, 'provenance.sigstore');
  const files = candidate.files;
  writeFileSync(tarball, files.get('candidate.tgz'), { flag: 'wx', mode: 0o600 });
  save(context, { approval, workflow });
  let sequence = 0;
  const result = await signBootstrapOnce({
    approval, files, locks, workflow, revalidate, verifyBundle: api.verifyBundle, cache: join(home, 'tuf'),
    record: state => save(join(ledger, `sign-${sequence++}.json`), state),
    sign: () => {
      validateBootstrapContext({ env: process.env, event: json(process.env.GITHUB_EVENT_PATH), approval });
      validateSource(source(approval), approval);
      sameDigests(digest(readFileSync(tarball)), approval.artifact);
      run(process.execPath, [join(root, 'tools/npm-publication/sign-provenance.mjs'),
        context, tarball, bundle], { cwd: home, env });
      sameDigests(digest(readFileSync(tarball)), approval.artifact);
      return readFileSync(bundle);
    },
  });
  sameDigests(digest(readFileSync(tarball)), approval.artifact);
  const output = join(resolve(process.env.RUNNER_TEMP), 'npm-bootstrap-signed');
  mkdirSync(output, { mode: 0o700 });
  for (const [name, bytes] of files) writeFileSync(join(output, name), bytes, { flag: 'wx', mode: 0o600 });
  writeFileSync(join(output, 'provenance.sigstore'), result.bundleBytes, { flag: 'wx', mode: 0o600 });
  save(join(output, 'bootstrap.json'), result.receipt);
  console.log(JSON.stringify({ status: result.receipt.phase,
    receiptSha256: digest(readFileSync(join(output, 'bootstrap.json'))).sha256,
    bundleSha256: result.receipt.provenance.sha256, npmWrite: 'not-performed' }));
}

export async function main(command) {
  assert.ok(['prepare', 'finalize', 'transfer', 'stage', 'sign-bootstrap'].includes(command), 'Unknown publication command');
  const event = json(process.env.GITHUB_EVENT_PATH);
  const action = event.inputs?.action;
  const approval = JSON.parse(event.inputs?.approval ?? '');
  // Finalization continues the same source-approved run; it does not consume a new approval.
  if (command === 'finalize') validateMatrixContext(process.env, approval, event);
  else validateApproval(approval, action);
  validateContext(process.env, event, approval);
  assert.equal(action, command === 'sign-bootstrap' ? command : ['prepare', 'finalize'].includes(command) ? 'prepare' : 'stage');
  if (command === 'prepare') await prepare(approval);
  else if (command === 'finalize') await finalize(approval);
  else if (command === 'sign-bootstrap') await signBootstrap(approval);
  else if (command === 'transfer') {
    await sourceAndCi(approval);
    await transfer(approval);
    // Only validated decimal IDs are written as action outputs.
    writeFileSync(process.env.GITHUB_OUTPUT,
      `run-id=${approval.artifact.runId}\nartifact-id=${approval.artifact.artifactId}\n`, { flag: 'a' });
  } else await stage(approval);
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch(error => {
    console.error(`Publication stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
