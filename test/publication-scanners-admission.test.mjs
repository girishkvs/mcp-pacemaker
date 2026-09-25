import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { inventory, sha256, LIMITS } from '../tools/publication-scanners/core.mjs';
import { collectFindingIdentities, readReviewSource, SYNTHETIC_URI_LOCATIONS } from '../tools/publication-scanners/review-source.mjs';
import { correlateSecretReport, main as correlateCli } from '../tools/publication-scanners/correlate.mjs';
import { executeScanners, parseGitleaks, parseTrufflehog, scannerArguments, TOOL_PINS } from '../tools/publication-scanners/secrets.mjs';
import { SCANNER_RELEASES } from '../tools/npm-publication/install-scanners.mjs';
import { publicationSecretGates, scanPublicationRequest } from '../tools/publication-scanners/publication.mjs';
import { main as scannerCli } from '../tools/publication-scanners/cli.mjs';
import {
  consumeSecretAdmission, readSecretAdmission, validateCollectionJobs, verifyCollectionSource,
} from '../tools/npm-publication/secret-admission.mjs';
import {
  assertCollectionJobSkipped, makeSecretCollection, reviewedFindings, validateSecretCollection, validateSecretReview,
} from '../tools/npm-publication/secret-report.mjs';
import { collectSecrets } from '../tools/npm-publication/run.mjs';
import { aggregateExternalGates, externalCli } from '../tools/npm-publication/external-gates.mjs';
import { POLICY, REQUIRED_GATES, validateApproval, validateGates, validateTransfer } from '../tools/npm-publication/policy.mjs';
import { validateLocalApproval } from '../tools/npm-publication/local-regression.mjs';
import { syntheticLocalApproval } from './helpers/local-regression-fixture.mjs';

const NATIVE_URI_FIXTURES = [
  { blob: '2abc5b2058695c2274c3913b99b1be6d5427af5d', rawBytes: 44, fullBytes: 50,
    rawSha256: '26186b00db0c3b3805718b9b75394f26fc14cc8c98539d4b1ad83b916cdf77b1',
    fullSha256: '04d7df8ca05cb24d14cc42cbc1bf9147911453b65cd6114a6ca3cada68534e59' },
  { blob: '0aebdd4a2945cbf1cca60c6bc21ce0d5631faf0f', rawBytes: 37, fullBytes: 56,
    rawSha256: '21d0bd781fbbee210dba0d184c249ded57230825ec5ebe02650262d8dc068e18',
    fullSha256: '424592cb5945aa8ab78bb0be0d527511e21a0d1c1e2bfadcf528f4a8f1d1a9b8' },
  { blob: '7dbaed1775a2aa3b83c963fa1d56ff479ceaca7f', rawBytes: 40, fullBytes: 45,
    rawSha256: 'c8348334ee6dfac5306189aaee5556a286036ea3168044dd36b330703d060aa8',
    fullSha256: '618386be8b79f7991b70268ae66b5dfbeaed06c2efb02a36c0027683980f388a' },
];

// Synthetic execution, GitHub, Git and owner inputs only. No genuine approval is generated.
class Fixture {
  async init(t, { nativeUri = false, nativeCheckouts } = {}) {
    this.nativeUri = nativeUri;
    if (nativeCheckouts !== undefined) {
      assert.ok(nativeUri && nativeCheckouts instanceof Map && nativeCheckouts.size === 3);
    }
    this.temp = await mkdtemp(join(await realpath(tmpdir()), 'secret-admission-unit-'));
    t.after(() => rm(this.temp, { recursive: true }));
    this.root = join(this.temp, 'source');
    this.history = join(this.temp, 'history');
    await mkdir(this.root);
    await mkdir(this.history);
    await mkdir(join(this.root, 'test'));
    this.now = Date.now();
    this.commit = 'a'.repeat(40);
    this.tree = 'b'.repeat(40);
    this.entries = [];
    this.attributes = { text: 'set', eol: 'lf', filter: 'unspecified',
      'working-tree-encoding': 'unspecified', ident: 'unspecified' };
    this.values = [1, 2, 3].map(index => ['https:', '',
      `${['fixture', index].join('-')}:${['not', 'real', index].join('-')}@example.invalid`, 'reject'].join('/'));
    for (const [index, value] of this.values.entries()) {
      const { path, line } = SYNTHETIC_URI_LOCATIONS[index];
      let bytes = Buffer.from(`${'// Synthetic rejection test\n'.repeat(line - 1)}reject(${JSON.stringify(value)});\n`);
      if (nativeUri) {
        const checkout = nativeCheckouts === undefined
          ? await readFile(new URL(`../${path}`, import.meta.url)) : nativeCheckouts.get(path);
        bytes = this.nativeFixtureBytes(checkout, index);
        const sourceLine = bytes.toString('utf8').split(/\r?\n/)[line - 1];
        const literals = [...sourceLine.matchAll(/(['"])(https:\/\/[^'"\s]+)\1/g)]
          .map(match => match[2]).filter(literal => sha256(literal) === NATIVE_URI_FIXTURES[index].fullSha256);
        assert.equal(literals.length, 1, 'Expected one pinned public rejection-test literal');
        this.values[index] = literals[0];
      }
      const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
      if (nativeUri) assert.equal(blob, NATIVE_URI_FIXTURES[index].blob);
      this.entries.push({ path, line, blob, bytes });
      await mkdir(dirname(join(this.root, path)), { recursive: true });
      await writeFile(join(this.root, path), bytes);
      await writeFile(join(this.history, `${blob}.blob`), bytes);
    }
    this.readSource = (root, options) => readReviewSource(root, { ...options, run: (...args) => this.git(...args) });
    this.source = await this.readSource(this.root, { tools: {}, context: {} });
    this.secrets = await this.scan();
    this.workflow = { runId: '11', runNumber: '7', attempt: 1, repositoryId: '23', ownerId: '17',
      ref: 'refs/tags/npm-r5/v2.0.1' };
    this.report = makeSecretCollection(this.secrets, this.workflow, this.producerContext);
    this.approval = syntheticLocalApproval({
      schemaVersion: 1, scope: 'prepare', name: POLICY.name, version: '2.0.1', commit: this.commit,
      tree: this.tree, tagObject: 'c'.repeat(40), ref: this.workflow.ref, ciRunId: '100', ciAttempt: 1,
      approver: POLICY.owner, approvedAt: this.time(-15), publicPackages: ['synthetic-public-package'],
    });
    this.approval.secretReview = { schemaVersion: 1, scope: 'exact-source-secret-report',
      classification: 'synthetic-uri-userinfo-rejection-input', reviewer: POLICY.owner,
      reviewedAt: this.time(-20), admissionRunNumber: '8', collection: { runId: '11', jobId: '111', artifactId: '211' },
      findingIds: this.report.raw.executions.flatMap(item => item.identities.map(finding => finding.id)) };
    this.owner = { login: POLICY.owner, id: 17 };
    this.repository = { full_name: POLICY.repository, id: 23, owner: this.owner, private: false, fork: false };
    this.current = this.run('12', '8', false);
    this.original = this.run('11', '7', true);
    this.env = {
      GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
      GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_REPOSITORY_ID: '23', GITHUB_REPOSITORY_OWNER_ID: '17',
      GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner,
      GITHUB_SHA: this.commit, GITHUB_REF: this.approval.ref, GITHUB_WORKFLOW_SHA: this.commit,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${this.approval.ref}`,
      GITHUB_RUN_ID: '12', GITHUB_RUN_NUMBER: '8', GITHUB_RUN_ATTEMPT: '1', GITHUB_JOB: 'source',
      ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Linux',
      RUNNER_ARCH: 'X64', RUNNER_TEMP: this.temp,
      MCP_SCANNER_PROVENANCE_FILE: this.bootstrapFile,
    };
    this.jobs = [{
      id: 111, run_id: 11, run_attempt: 1, head_sha: this.commit, name: 'secret-collection',
      status: 'completed', conclusion: 'success', runner_id: 55, runner_name: 'synthetic-host',
      labels: ['ubuntu-24.04'], started_at: this.time(-59), completed_at: this.time(-21),
      steps: ['Set up job', 'Require supported hosted runner before any credentials can be requested',
        'Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
        'Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
        'Install pinned publication scanners', 'Collect redacted source secret evidence only', 'Retain non-eligible secret collection',
        'Post Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
        'Post Run actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'Complete job']
        .map((name, index) => ({ name, number: index + 1, status: 'completed', conclusion: 'success',
          started_at: this.time(index === 5 ? -53 : -59), completed_at: this.time(index === 4 ? -54 : index === 5 ? -29 : -21) })),
    }, ...['source', 'prepare', 'stage', 'consumers',
      ...(this.approval.version === '2.0.1' ? ['sign-bootstrap', 'publish-bootstrap'] : [])].map((name, index) =>
      ({ id: 112 + index, run_id: 11, run_attempt: 1, head_sha: this.commit, name,
        status: 'completed', conclusion: 'skipped', steps: [] }))];
    this.repack();
    this.readers = {
      readJson: async path => {
        if (path === 'actions/runs/12') return this.current;
        if (path === 'actions/runs/11') return this.original;
        assert.fail('Unexpected synthetic API read');
      },
      readArtifacts: async () => [this.metadata],
      readArtifactMetadata: async () => this.metadata,
      readArtifactArchive: async () => this.archive,
      readJobs: async () => this.jobs,
    };
    this.request = { schemaVersion: 1, phase: 'source', root: this.root, sourceRoot: this.root,
      commit: this.commit, name: POLICY.name, version: '2.0.1', requiredGates: ['source-gitleaks', 'source-trufflehog'] };
    return this;
  }

  time(seconds) { return new Date(this.now + seconds * 1000).toISOString(); }

  async withCi(value, action) {
    const previous = process.env.CI;
    try {
      if (value === undefined) delete process.env.CI;
      else process.env.CI = value;
      return await action();
    } finally {
      if (previous === undefined) delete process.env.CI;
      else process.env.CI = previous;
    }
  }

  run(id, runNumber, completed) {
    return { id, run_number: runNumber, workflow_id: 333, run_attempt: 1, head_sha: this.commit, path: POLICY.workflow,
      event: 'workflow_dispatch', repository: this.repository, head_repository: this.repository,
      actor: this.owner, triggering_actor: this.owner, status: completed ? 'completed' : 'in_progress',
      conclusion: completed ? 'success' : null, created_at: this.time(completed ? -60 : -10) };
  }

  async git(_file, args) {
    const command = args.slice(args.indexOf('-C') + 2);
    while (command[0] === '-c' || command[0]?.startsWith('--attr-source=')) {
      command.splice(0, command[0] === '-c' ? 2 : 1);
    }
    let stdout;
    if (command[0] === 'status') stdout = this.dirty ? ' M fixture\n' : '';
    else if (command[0] === 'rev-parse') {
      stdout = command.includes('--show-toplevel') ? `${this.root}\n${this.commit}\n${this.tree}\n`
        : command.includes('--git-path') ? join(this.root, '.git/info/attributes') : `${this.commit}\n`;
    } else if (command[0] === 'ls-tree') {
      stdout = this.entries.map(item => `100644 blob ${item.blob}\t${item.path}\0`).join('');
    } else if (command[0] === 'cat-file') {
      stdout = this.entries.find(item => item.blob === command.at(-1)).bytes;
      if (command[1] === '--filters' && this.attributes.eol === 'crlf') stdout = Buffer.from(stdout.toString().replaceAll('\n', '\r\n'));
    } else if (command[0] === 'hash-object') {
      stdout = this.entries.find(item => `--path=${item.path}` === command[1]).blob;
    }
    else if (command[0] === 'check-attr') {
      stdout = Object.entries(this.attributes).flatMap(([name, value]) => [command.at(-1), name, value]).join('\0') + '\0';
    } else assert.fail('Unexpected synthetic read-only Git command');
    return { code: 0, stdout, stderr: '' };
  }

  raw(scope) {
    const target = scope === 'history' ? this.history : this.root;
    const rows = this.entries.map((item, index) => this.nativeUri ? this.nativeRow(scope, item, index)
      : ({ DetectorName: 'URI', Raw: this.values[index], Verified: false,
        SourceMetadata: { Data: { Filesystem: { file: join(target, scope === 'history' ? `${item.blob}.blob` : item.path), line: item.line } } } }));
    return { code: 183, stdout: rows.map(row => JSON.stringify(row)).join('\n'), stderr: JSON.stringify({
      level: 'info-0', msg: 'finished scanning', bytes: 300, chunks: 3, verified_secrets: 0,
      unverified_secrets: 3, trufflehog_version: '3.97.1',
    }) };
  }

  nativeFixtureBytes(checkout, index) {
    assert.ok(Buffer.isBuffer(checkout), 'Synthetic fixture checkout must be bytes');
    let bytes = checkout;
    if (SYNTHETIC_URI_LOCATIONS[index].path === 'tools/npm-publication/offline-stage/npm.cjs') {
      // Only this synthetic seed accepts the CJS checkout's LF/CRLF rendering.
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(checkout);
      const lf = text.replaceAll('\r\n', '\n');
      assert.ok(!lf.includes('\r'), 'Unsupported synthetic fixture checkout form');
      const canonical = Buffer.from(lf);
      const crlf = Buffer.from(lf.replaceAll('\n', '\r\n'));
      const supported = checkout.equals(canonical) || checkout.equals(crlf);
      assert.ok(supported, 'Unsupported synthetic fixture checkout form');
      bytes = canonical;
    }
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    assert.equal(blob, NATIVE_URI_FIXTURES[index].blob, 'Synthetic fixture differs from pinned Git blob');
    return bytes;
  }

  async nativeCheckoutInputs(form) {
    assert.ok(form === 'lf' || form === 'crlf');
    const inputs = new Map();
    for (const [index, { path }] of SYNTHETIC_URI_LOCATIONS.entries()) {
      const bytes = this.nativeFixtureBytes(await readFile(new URL(`../${path}`, import.meta.url)), index);
      const renderCrlf = path === 'tools/npm-publication/offline-stage/npm.cjs' && form === 'crlf';
      inputs.set(path, renderCrlf ? Buffer.from(bytes.toString('utf8').replaceAll('\n', '\r\n')) : Buffer.from(bytes));
    }
    return inputs;
  }

  nativeRow(scope, item, index) {
    // Public fixture bytes, synthetic process/location metadata; never copied native reports.
    const full = this.values[index];
    const scheme = 'https://';
    const pathStart = full.indexOf('/', scheme.length);
    assert.ok(pathStart > scheme.length);
    const raw = full.slice(0, pathStart);
    const authority = raw.slice(scheme.length);
    const at = authority.indexOf('@');
    const colon = authority.indexOf(':');
    assert.ok(colon > 0 && at > colon);
    const username = authority.slice(0, colon);
    const password = authority.slice(colon + 1, at);
    const host = authority.slice(at + 1);
    const target = scope === 'history' ? this.history : this.root;
    return {
      SourceMetadata: { Data: { Filesystem: {
        file: join(target, scope === 'history' ? `${item.blob}.blob` : item.path), line: item.line,
      } } },
      SourceID: 1, SourceType: 15, SourceName: 'trufflehog - filesystem',
      DetectorType: 17, DetectorName: 'URI',
      DetectorDescription: 'This detector identifies URLs with embedded credentials, which can be used to access web resources without explicit user interaction.',
      DecoderName: 'PLAIN', Verified: false, VerificationFromCache: false,
      Raw: raw, RawV2: full,
      Redacted: `${scheme}${username}:********@${host}${full.slice(pathStart)}`,
      ExtraData: null, StructuredData: null, SecretParts: { host, username, password },
    };
  }

  nativeTool() {
    return { name: 'trufflehog', version: TOOL_PINS.trufflehog.version, sha256: this.tools.trufflehog.sha256 };
  }

  changedNative(scope, mutate) {
    const result = this.raw(scope);
    const rows = result.stdout.split('\n').map(line => JSON.parse(line));
    mutate(rows[0], rows);
    return { ...result, stdout: rows.map(row => JSON.stringify(row)).join('\n') };
  }

  async nativeIdentities(scope, result = this.raw(scope), tool = this.nativeTool(), source = this.source) {
    const target = scope === 'history' ? this.history : this.root;
    return collectFindingIdentities(result, scope, target, source, (await inventory(target)).entries, tool);
  }

  async scan() {
    const executions = [];
    this.tools ??= {};
    for (const name of ['gitleaks', 'trufflehog']) {
      const path = join(this.temp, `SYNTHETIC-NOT-EXECUTABLE-${name}`);
      const bytes = Buffer.from(`SYNTHETIC UNIT TOOL ${name}`);
      await writeFile(path, bytes);
      this.tools[name] = { path, sha256: sha256(bytes) };
    }
    const config = join(this.temp, 'synthetic-config');
    const ignore = join(this.temp, 'empty-ignore');
    await writeFile(config, 'SYNTHETIC UNIT CONFIG'); await writeFile(ignore, '');
    const configEvidence = { upstreamSha256: TOOL_PINS.gitleaks.configSha256,
      effectiveSha256: sha256('SYNTHETIC UNIT CONFIG'), globalPathExclusions: 'removed', upstreamVersion: TOOL_PINS.gitleaks.version };
    const objects = (await inventory(this.history)).evidence;
    const historyEvidence = { commit: this.commit, reachableCommits: 1,
      bundle: { bytes: 23, sha256: sha256('SYNTHETIC UNIT BUNDLE') },
      objects: { ...objects, files: 5, objects: 5, objectTypes: { blob: 3, tree: 1, commit: 1, tag: 0 },
        objectMetadataSha256: sha256('SYNTHETIC UNIT OBJECT METADATA'),
        exportLimits: { objects: LIMITS.files, objectBytes: LIMITS.fileBytes, rawBytes: LIMITS.treeBytes, batchOutputBytes: objects.bytes + 1000 },
        selection: 'all-raw-objects-reachable-from-HEAD; complete blobs, trees and commit metadata',
        objectIdentity: 'Git object IDs recomputed over every exported body' } };
    const bootstrap = { schemaVersion: 1, platform: 'linux-x64', configSha256: TOOL_PINS.gitleaks.configSha256,
      tools: ['gitleaks', 'trufflehog'].map(name => ({ name, version: TOOL_PINS[name].version,
        archiveSha256: SCANNER_RELEASES[name].sha256, checksumsSha256: SCANNER_RELEASES[name].checksumsSha256,
        executableSha256: this.tools[name].sha256,
        digestBasis: 'Executable extracted from independently pinned official release archive; not a separate upstream executable checksum' })) };
    this.producerContext = { ci: { runId: '100', attempt: 1, commit: this.commit, completedAt: this.time(-120) },
      runtime: { platform: 'linux', arch: 'x64', node: '24.21.0' }, bootstrap };
    this.bootstrapFile = join(this.temp, 'synthetic-bootstrap.json');
    await writeFile(this.bootstrapFile, JSON.stringify(bootstrap));
    let executionIndex = 0;
    for (const scope of ['working-tree', 'history']) {
      const target = scope === 'history' ? this.history : this.root;
      await executeScanners(target, scope, this.tools, {
        config, ignore, configEvidence, commit: this.commit, historyObjects: this.history,
        historyEvidence, reviewSource: this.source,
        verifyTool: async name => ({ name, version: TOOL_PINS[name].version, sha256: this.tools[name].sha256 }),
        run: async (file, args) => {
          const name = file === this.tools.gitleaks.path ? 'gitleaks' : 'trufflehog';
          const raw = name === 'gitleaks' ? { code: 0, stdout: '[]',
            stderr: `${scope === 'history' ? 'INF 1 commits scanned.\n' : ''}` +
              '12:00PM INF scanned ~300 bytes (300 bytes) in 1s\n12:00PM INF no leaks found\n' } : this.raw(scope);
          if (name === 'gitleaks' &&
              this.gitleaksDiagnosticMutation) {
            raw.stderr = this.gitleaksDiagnosticMutation(raw.stderr, scope);
          }
          const index = executionIndex++;
          const result = { ...raw, audit: { schemaVersion: 1, kind: 'bounded-native-execution',
            executablePathSha256: sha256(file), argumentsSha256: sha256(JSON.stringify(args)),
            startedAt: this.time(-50 + index * 4), completedAt: this.time(-49 + index * 4),
            code: raw.code, signal: null, timeoutMs: LIMITS.timeoutMs, maxOutputBytes: LIMITS.outputBytes,
            streams: Object.fromEntries(['stdout', 'stderr'].map(key => [key,
              { sha256: sha256(raw[key]), bytes: Buffer.byteLength(raw[key]), receivedBytes: Buffer.byteLength(raw[key]) }])) } };
          return this.mutateNative ? this.mutateNative(result, name, scope) : result;
        },
      }, executions);
    }
    return { status: 'findings', completedAt: this.time(-30), onlineVerification: 'disabled', automaticUpdates: 'disabled',
      reviewSource: this.source.binding, producerSource: await this.source.producerEvidence(),
      producerHistory: historyEvidence, executions, scope: { ...(await inventory(this.root)).evidence,
        history: { commit: this.commit, reachableCommits: 1, trufflehogObjects: historyEvidence.objects } } };
  }

  zip(entries) {
    const local = [];
    const central = [];
    let offset = 0;
    for (const [name, value] of Object.entries(entries)) {
      const bytes = Buffer.from(value);
      const encoded = Buffer.from(name);
      const header = Buffer.alloc(30);
      header.writeUInt32LE(0x04034b50);
      header.writeUInt32LE(bytes.length, 18);
      header.writeUInt32LE(bytes.length, 22);
      header.writeUInt16LE(encoded.length, 26);
      const index = Buffer.alloc(46);
      index.writeUInt32LE(0x02014b50);
      index.writeUInt32LE(bytes.length, 20);
      index.writeUInt32LE(bytes.length, 24);
      index.writeUInt16LE(encoded.length, 28);
      index.writeUInt32LE(offset, 42);
      local.push(header, encoded, bytes);
      central.push(index, encoded);
      offset += header.length + encoded.length + bytes.length;
    }
    const directory = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50);
    end.writeUInt16LE(central.length / 2, 8);
    end.writeUInt16LE(central.length / 2, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...local, directory, end]);
  }

  repack(extra = {}) {
    this.reportBytes = Buffer.from(`${JSON.stringify(this.report, null, 2)}\n`);
    this.archive = this.zip({ 'report.json': this.reportBytes,
      ...Object.fromEntries(this.report.producerEvidence.receipts.map(item => [item.file, `${JSON.stringify(item.record, null, 2)}\n`])), ...extra });
    this.approval.secretReview.collection.reportSha256 = sha256(this.reportBytes);
    this.approval.secretReview.collection.artifactDigest = `sha256:${sha256(this.archive)}`;
    this.metadata = { id: 211, name: 'npm-secret-collection-11-1', expired: false,
      digest: this.approval.secretReview.collection.artifactDigest,
      workflow_run: { id: 11, head_sha: this.commit, repository_id: 23, head_repository_id: 23 } };
  }

  updateCountReceipt(index) {
    const raw = this.report.raw.executions[index];
    const receipt = this.report.producerEvidence.receipts[index];
    receipt.record.native.code = raw.exitCode;
    Object.assign(receipt.record.parser, { status: raw.status, findings: raw.findings,
      ...(raw.tool.name === 'trufflehog' ? { unverified: raw.findings } : {}) });
    receipt.sha256 = sha256(`${JSON.stringify(receipt.record, null, 2)}\n`);
  }

  admit() {
    return readSecretAdmission({ approval: this.approval, env: this.env,
      event: { sender: this.owner, repository: this.repository,
        inputs: { action: 'prepare', approval: JSON.stringify(this.approval) } }, readers: this.readers,
      inspectSource: (report, root, tools) => verifyCollectionSource(report, root, tools, this.readSource) });
  }

  publication(secretAdmission, extra = {}) {
    return scanPublicationRequest({ request: this.request, secretAdmission,
      bindingReader: async () => ({ sourceManifestSha256: 'f'.repeat(64) }),
      sourceScanner: async () => this.secrets, ...extra });
  }
}

test('SYNTHETIC end-to-end collection is non-eligible; fresh exact owner admission preserves raw findings/183/3 per scope', async t => {
  const f = await new Fixture().init(t);
  let preflight = 0;
  let postflight = 0;
  const collecting = { ...f.approval, scope: 'collect-secrets' };
  delete collecting.secretReview;
  delete collecting.publicPackages;
  validateApproval(collecting, 'collect-secrets');
  validateLocalApproval(collecting);
  const report = await collectSecrets(collecting, {
    env: { ...f.env, GITHUB_JOB: 'secret-collection', GITHUB_RUN_ID: '11', GITHUB_RUN_NUMBER: '7' },
    sourceRoot: f.root, tools: {}, runtime: { platform: 'linux', arch: 'x64', versions: { node: '24.21.0' } },
    preflight: async () => { preflight++; return f.producerContext.ci; },
    postflight: async () => { postflight++; }, scan: async input => {
      assert.equal(input.collectReview, true);
      return f.secrets;
    },
  });
  assert.deepEqual(report, f.report);
  assert.equal(preflight, 1);
  assert.equal(postflight, 1);
  assert.equal(report.eligibility, 'none');
  assert.deepEqual(await readFile(join(f.temp, 'npm-secret-collection/report.json')), f.reportBytes);
  await assert.rejects(collectSecrets(collecting, {
    env: { ...f.env, GITHUB_JOB: 'secret-collection' },
    preflight: () => assert.fail('Existing collection must not retry preflight'),
    scan: () => assert.fail('Existing collection must not scan again'),
  }), /Secret collection rejected/);
  const noReview = await f.publication();
  assert.equal(noReview.status, 'findings');
  assert.equal(noReview.gates['source-trufflehog'].status, 'failed');
  validateApproval(f.approval, 'prepare');
  const capability = await f.admit();
  const result = await f.publication(capability, { sourceScanner: () => assert.fail('No rescan of admitted report') });
  assert.equal(result.status, 'passed');
  assert.equal(result.gates['source-trufflehog'].admission.reviewedFalsePositives, 6);
  assert.equal(result.gates['source-trufflehog'].admission.remainingFindings, 0);
  for (const item of result.scannerDetails.secrets.executions.filter(item => item.tool.name === 'trufflehog')) {
    assert.equal(item.status, 'findings');
    assert.equal(item.exitCode, 183);
    assert.equal(item.findings, 3);
  }
  assert.equal(result.privateContentReview.status, 'pending');
  assert.equal((await f.publication(capability)).status, 'error', 'Capabilities are single consumption');
  for (const value of [...f.values, f.root, f.history, 'private-policy-example', 'fixture@example.invalid']) {
    assert.equal(JSON.stringify(report).includes(value), false);
    assert.equal(JSON.stringify(result).includes(value), false);
  }
});

test('original collector hosted boundary rejects mixed self-hosted labels before creating a capability', async t => {
  const f = await new Fixture().init(t);
  const raw = structuredClone(f.report.raw);
  f.jobs[0].labels = ['self-hosted', 'linux', 'x64', 'ubuntu-24.04'];
  let capability;
  let consumerReached = false;
  await assert.rejects(async () => {
    capability = await f.admit();
    consumerReached = true;
    const result = await f.publication(capability);
    assert.equal(result.status, 'passed');
  });
  assert.equal(capability, undefined, 'The original collector must be rejected before capability creation');
  assert.equal(consumerReached, false);
  assert.deepEqual(f.report.raw, raw);
});

for (const target of ['working-tree', 'history']) {
  test(`original ${target} Gitleaks count contradiction blocks before five-member artifact creation`, async t => {
    const f = await new Fixture().init(t);
    let injected = 0;
    f.gitleaksDiagnosticMutation = (stderr, scope) => {
      if (scope !== target) return stderr;
      injected++;
      return stderr.replace('INF no leaks found', 'WRN leaks found: 1');
    };
    const approval = { ...f.approval, scope: 'collect-secrets' };
    delete approval.secretReview; delete approval.publicPackages;
    await assert.rejects(collectSecrets(approval, { env: { ...f.env, GITHUB_JOB: 'secret-collection' },
      sourceRoot: f.root, runtime: { platform: 'linux', arch: 'x64', versions: { node: '24.21.0' } },
      preflight: async () => f.producerContext.ci, postflight: async () => {}, scan: () => f.scan() }),
    /Secret collection rejected/);
    assert.equal(injected, 1);
    assert.equal(existsSync(join(f.temp, 'npm-secret-collection/report.json')), false);
    assert.equal(existsSync(join(f.temp, `npm-secret-collection/execution-${target}-gitleaks.json`)), false);
  });
}

test('versioned producer receipts reject independent substitutions before capability creation', async t => {
  const f = await new Fixture().init(t);
  const original = structuredClone(f.report);
  for (const mutate of [
    report => { report.schemaVersion = 1; },
    report => { report.producerEvidence.receipts.pop(); },
    report => { report.producerEvidence.receipts.reverse(); },
    report => { report.producerEvidence.receipts[0].record.native.argumentsSha256 = '0'.repeat(64); },
    report => { report.producerEvidence.receipts[0].record.argv.push('--synthetic-extra'); },
    report => { report.producerEvidence.receipts[0].record.argv[1].role = 'config'; },
    report => { report.producerEvidence.receipts[0].record.native.streams.stdout.receivedBytes++; },
    report => { report.producerEvidence.receipts[0].record.native.signal = 'SIGTERM'; },
    report => { report.producerEvidence.receipts[0].record.native.startedAt = f.time(-200); },
    report => { report.producerEvidence.receipts[1].record.parser.unverified++; },
    report => { report.producerEvidence.receipts[1].record.parser.completionCount++; },
    report => { report.producerEvidence.receipts[1].record.parser.scannedBytes = 0; },
    report => { report.producerEvidence.receipts[2].record.parser.reportedCommits++; },
    report => { report.producerEvidence.history.objects.objectTypes.commit++; },
    report => { report.producerEvidence.history.bundle.sha256 = '0'.repeat(64); },
    report => { report.producerEvidence.bootstrap.tools[0].archiveSha256 = '0'.repeat(64); },
    report => { report.producerEvidence.source.inventoryFormat = report.producerEvidence.source.privateFormat; },
    report => { report.producerEvidence.source.files.push(report.producerEvidence.source.files[0]); },
    report => { report.producerEvidence.source.files[0].attributes.filter = 'SYNTHETIC-FILTER'; },
    report => { report.producerEvidence.runtime.node = '20.20.2'; },
    report => { report.producerEvidence.ci.runId = '999'; },
    report => { report.producerEvidence.receipts[0].record.stderr = 'SYNTHETIC-PRIVATE-CANARY'; },
    report => { report.producerEvidence.source.path = 'SYNTHETIC-PRIVATE-PATH'; },
    report => { report.producerEvidence.authenticated = true; },
  ]) {
    f.report = structuredClone(original);
    mutate(f.report);
    for (const receipt of f.report.producerEvidence.receipts) receipt.sha256 = sha256(`${JSON.stringify(receipt.record, null, 2)}\n`);
    f.repack();
    let capability;
    await assert.rejects(async () => { capability = await f.admit(); }, error =>
      !error.message.includes('SYNTHETIC-PRIVATE'));
    assert.equal(capability, undefined);
  }
});

test('native producer failures cannot emit a public artifact or leak native diagnostics', async t => {
  for (const mutate of [
    result => { result.code = 1; },
    result => { result.stderr = 'SYNTHETIC-PRIVATE-CANARY'; },
    result => { result.audit.argumentsSha256 = '0'.repeat(64); },
    result => { result.audit.streams.stdout.bytes++; },
    result => { result.audit.streams.stderr.receivedBytes++; },
    result => { result.audit.signal = 'SIGTERM'; },
    result => { result.audit.privateDiagnostic = 'SYNTHETIC-PRIVATE-CANARY'; },
    result => { result.audit.streams.stdout.sha256 = sha256(Buffer.from([0xff])); },
  ]) {
    const f = await new Fixture().init(t);
    f.mutateNative = result => { mutate(result); return result; };
    const approval = { ...f.approval, scope: 'collect-secrets' };
    delete approval.secretReview; delete approval.publicPackages;
    await assert.rejects(collectSecrets(approval, { env: { ...f.env, GITHUB_JOB: 'secret-collection' },
      sourceRoot: f.root, runtime: { platform: 'linux', arch: 'x64', versions: { node: '24.21.0' } },
      preflight: async () => f.producerContext.ci, postflight: async () => {}, scan: () => f.scan() }),
    error => error.message === 'Secret collection rejected; no eligible evidence was produced');
    assert.equal(existsSync(join(f.temp, 'npm-secret-collection')), false);
  }
});

test('full source proof rejects unsupported attributes and undeclared checkout transformations', async t => {
  const f = await new Fixture().init(t);
  for (const [name, value] of [['filter', 'SYNTHETIC-FILTER'], ['working-tree-encoding', 'UTF-16LE'], ['ident', 'set']]) {
    const old = f.attributes[name];
    f.attributes[name] = value;
    await assert.rejects(f.source.producerEvidence(), /review-source-conversion/);
    f.attributes[name] = old;
  }
  const item = f.entries[0];
  await writeFile(join(f.root, item.path), Buffer.from(item.bytes.toString().replaceAll('\n', '\r\n')));
  const changed = await f.readSource(f.root, { tools: {}, context: {} });
  await assert.rejects(changed.producerEvidence(), /producer-source-not-lf-checkout/);
  await writeFile(join(f.root, item.path), item.bytes);
  await writeFile(join(f.root, 'ignored-private-extra.txt'), 'SYNTHETIC PRIVATE EXTRA');
  const extra = await f.readSource(f.root, { tools: {}, context: {} });
  await assert.rejects(extra.producerEvidence(), /producer-source-membership/);
});

test('original collector hosted boundary rejects missing malformed and case-variant labels without normalization', async t => {
  for (const [name, labels] of [
    ['missing labels', undefined], ['null labels', null], ['string instead of label array', 'ubuntu-24.04'],
    ['empty array', []], ['missing exact image', ['linux', 'x64']],
    ['non-string member', ['ubuntu-24.04', 42]], ['null member', ['ubuntu-24.04', null]],
    ['empty member', ['ubuntu-24.04', '']], ['padded member', ['ubuntu-24.04', ' self-hosted ']],
    ['padded image', ['ubuntu-24.04 ']], ['case-variant image', ['Ubuntu-24.04']],
    ['uppercase image', ['UBUNTU-24.04']],
    ['case-variant self-hosted', ['Self-Hosted', 'linux', 'x64', 'ubuntu-24.04']],
    ['uppercase self-hosted', ['SELF-HOSTED', 'ubuntu-24.04']],
  ]) {
    await t.test(name, async child => {
      const f = await new Fixture().init(child);
      const raw = structuredClone(f.report.raw);
      if (labels === undefined) delete f.jobs[0].labels;
      else f.jobs[0].labels = labels;
      let capability;
      await assert.rejects(async () => { capability = await f.admit(); });
      assert.equal(capability, undefined);
      assert.deepEqual(f.report.raw, raw);
    });
  }
});

test('original collector hosted boundary preserves exact hosted-label positive and original raw findings', async t => {
  for (const labels of [['ubuntu-24.04'], ['linux', 'x64', 'ubuntu-24.04']]) {
    const f = await new Fixture().init(t);
    f.jobs[0].labels = labels;
    const raw = structuredClone(f.report.raw);
    const result = await f.publication(await f.admit());
    assert.equal(result.status, 'passed');
    assert.deepEqual(result.scannerDetails.secrets.collection.raw, raw);
    assert.equal(result.scannerDetails.secrets.status, 'findings');
    assert.equal(result.gates['source-trufflehog'].admission.reviewedFalsePositives, 6);
    for (const execution of result.scannerDetails.secrets.executions.filter(item => item.tool.name === 'trufflehog')) {
      assert.equal(execution.exitCode, 183);
      assert.equal(execution.findings, 3);
    }
  }
});

test('collection preflight/source/CI failure never scans, packs or creates eligibility', async t => {
  const f = await new Fixture().init(t);
  await assert.rejects(collectSecrets({ ...f.approval, scope: 'collect-secrets' }, {
    env: { ...f.env, GITHUB_JOB: 'secret-collection' }, sourceRoot: f.root,
    preflight: () => { throw new Error('synthetic CI rejected'); },
    scan: () => assert.fail('No scanner after failed prerequisites'),
  }));
  for (const status of ['error', 'not-run', 'unknown']) {
    assert.throws(() => makeSecretCollection({ ...f.secrets, status }, f.workflow, f.producerContext));
  }
  for (const mutate of [
    value => { value.executions.pop(); }, value => { value.executions.push(value.executions[0]); },
    value => { value.executions[1].review.exitCode = 0; },
    value => { value.executions[1].findings = 0; },
    value => { value.executions[3].historyMechanism = 'unverified-path-mapping'; },
    value => { value.executions[0].config.globalPathExclusions = 'kept'; },
    value => { value.onlineVerification = 'enabled'; },
  ]) {
    const changed = structuredClone(f.secrets);
    mutate(changed);
    assert.throws(() => makeSecretCollection(changed, f.workflow, f.producerContext));
  }
});

test('raw parsing precedes collection; errors, unknown diagnostics, truncation, missing completion and verification block', async t => {
  const f = await new Fixture().init(t);
  const raw = f.raw('working-tree');
  for (const changed of [
    { ...raw, code: 1 }, { ...raw, code: 0 }, { ...raw, stderr: '' },
    { ...raw, stderr: `${raw.stderr}\n${raw.stderr}` },
    { ...raw, stderr: `${raw.stderr}\n${JSON.stringify({ level: 'info-0', msg: 'truncated output' })}` },
    { ...raw, stderr: `${raw.stderr}\n${JSON.stringify({ level: 'other', msg: 'unknown' })}` },
    { ...raw, stdout: raw.stdout.replace('"Verified":false', '"Verified":true') },
    { ...raw, stdout: `${raw.stdout}\n{` },
  ]) assert.throws(() => parseTrufflehog(changed));
});

for (const [name, mutate] of [
  ['different report', f => { f.approval.secretReview.collection.reportSha256 = '0'.repeat(64); }],
  ['different artifact', f => { f.approval.secretReview.collection.artifactId = '999'; }],
  ['different job', f => { f.approval.secretReview.collection.jobId = '999'; }],
  ['different owner ID', f => { f.current.actor = { login: POLICY.owner, id: 999 }; }],
  ['different repository', f => { f.original.repository = { ...f.repository, id: 999 }; }],
  ['wrong source', f => { f.original.head_sha = '0'.repeat(40); }],
  ['later dispatch replay', f => { f.current.run_number = '9'; f.env.GITHUB_RUN_NUMBER = '9'; }],
  ['recreated workflow replay', f => { f.current.workflow_id = 444; }],
  ['rerun', f => { f.env.GITHUB_RUN_ATTEMPT = '2'; }],
  ['stale consent', f => { f.approval.secretReview.reviewedAt = f.time(-4000); }],
  ['review before collection', f => { f.approval.secretReview.reviewedAt = f.time(-45); }],
  ['old dispatch approval', f => { f.approval.approvedAt = f.time(-4000); }],
  ['wrong consuming job', f => { f.env.GITHUB_JOB = 'prepare'; }],
  ['duplicate consent', f => { f.approval.secretReview.findingIds.push(f.approval.secretReview.findingIds[0]); }],
  ['missing consent', f => { f.approval.secretReview.findingIds.pop(); }],
  ['extra consent', f => { f.approval.secretReview.findingIds.push('0'.repeat(64)); }],
  ['collection prepared something', f => { f.jobs[1].conclusion = 'success'; }],
  ['failed collection step', f => { f.jobs[0].steps[0].conclusion = 'failure'; }],
  ['wrong runner', f => { f.jobs[0].labels = ['self-hosted']; }],
  ['extra raw artifact', f => { f.repack({ 'raw-output.txt': 'synthetic-must-not-upload' }); }],
  ['forged authentication flag', f => { f.approval.secretReview.authenticated = true; }],
]) {
  for (const nativeUri of [false, true]) {
    test(`${nativeUri ? 'SYNTHETIC native URI ' : ''}exact admission rejects ${name}`, async t => {
      const f = await new Fixture().init(t, { nativeUri });
      if (nativeUri) assert.equal((await f.publication(await f.admit())).status, 'passed');
      mutate(f);
      await assert.rejects(f.admit());
    });
  }
}

test('independently rehashed malformed collection contents cannot waive identity/schema/coverage errors', async t => {
  const f = await new Fixture().init(t);
  const original = structuredClone(f.report);
  for (const mutate of [
    value => { value.raw.executions.pop(); },
    value => { value.raw.executions.push(value.raw.executions[0]); },
    value => { value.raw.executions[1].identities.pop(); },
    value => { value.raw.executions[1].identities[0].valueSha256 = '0'.repeat(64); },
    value => { value.raw.executions[1].identities[0].binding.line++; },
    value => { value.raw.executions[1].identities[0].binding.blob = '0'.repeat(40); },
    value => { value.raw.executions[1].identities[0].binding = null; },
    value => { value.source.tree = '0'.repeat(40); },
    value => { value.raw.status = 'error'; },
    value => { value.raw.executions[1].exitCode = 1; },
    value => { value.raw.executions[1].stdout = 'synthetic-must-not-upload'; },
    value => { value.eligibility = 'prepared'; },
    value => { value.authenticated = true; },
  ]) {
    f.report = structuredClone(original);
    mutate(f.report);
    f.repack();
    await assert.rejects(f.admit());
  }
});

test('well-formed identities still reject other detectors, unmapped histories, unsupported locations and Gitleaks findings', async t => {
  const f = await new Fixture().init(t);
  const original = structuredClone(f.report);
  for (const mutate of [
    finding => { finding.detector = 'other'; finding.detectorSha256 = sha256('synthetic-other-detector'); },
    finding => { finding.binding = null; },
    finding => { finding.binding.line++; },
    finding => { finding.binding.pathSha256 = sha256('test/arbitrary-other-test.mjs'); },
  ]) {
    f.report = structuredClone(original);
    const execution = f.report.raw.executions[3];
    const finding = execution.identities[0];
    mutate(finding);
    const { id, ...identity } = finding;
    finding.id = sha256(JSON.stringify({ scope: execution.scope, ...identity }));
    f.approval.secretReview.findingIds = f.report.raw.executions.flatMap(item => item.identities.map(value => value.id));
    f.repack();
    validateSecretCollection(f.report);
    await assert.rejects(f.admit());
  }
  f.report = structuredClone(original);
  Object.assign(f.report.raw.executions[0], { status: 'findings', findings: 1, exitCode: 183 });
  f.updateCountReceipt(0);
  f.approval.secretReview.findingIds = f.report.raw.executions.flatMap(item => item.identities.map(value => value.id));
  f.repack();
  validateSecretCollection(f.report);
  await assert.rejects(f.admit());
  f.report = structuredClone(original);
  const execution = f.report.raw.executions[1];
  const duplicate = structuredClone(execution.identities[0]);
  duplicate.recordSha256 = sha256('different-record-same-source-location');
  const { id, ...identity } = duplicate;
  duplicate.id = sha256(JSON.stringify({ scope: execution.scope, ...identity }));
  execution.identities.push(duplicate);
  execution.findings++;
  f.updateCountReceipt(1);
  f.approval.secretReview.findingIds = f.report.raw.executions.flatMap(item => item.identities.map(value => value.id));
  f.repack();
  validateSecretCollection(f.report);
  await assert.rejects(f.admit());
});

test('missing and duplicate raw rows and tampered history object bytes cannot be summarized into admission', async t => {
  const f = await new Fixture().init(t);
  const raw = f.raw('working-tree');
  const lines = raw.stdout.split('\n');
  const entries = (await inventory(f.root)).entries;
  const partial = { ...raw, stdout: lines.slice(0, 2).join('\n') };
  for (const extra of [{ VerificationError: 'synthetic scanner error' }, { VerificationFromCache: true }]) {
    const rows = lines.map(line => JSON.parse(line));
    Object.assign(rows[0], extra);
    await assert.rejects(collectFindingIdentities({ ...raw, stdout: rows.map(row => JSON.stringify(row)).join('\n') },
      'working-tree', f.root, f.source, entries), /review-verification-error-or-cache/);
  }
  assert.equal(parseTrufflehog(partial).findings, 2);
  await assert.rejects(collectFindingIdentities(partial, 'working-tree', f.root, f.source, entries),
    /review-completion-count-mismatch/);
  const duplicate = { ...raw, stdout: [...lines, lines[0]].join('\n'),
    stderr: raw.stderr.replace('"unverified_secrets":3', '"unverified_secrets":4') };
  await assert.rejects(collectFindingIdentities(duplicate, 'working-tree', f.root, f.source, entries),
    /review-duplicate-finding/);
  await writeFile(join(f.history, `${f.entries[0].blob}.blob`), Buffer.concat([f.entries[0].bytes, Buffer.from('\n')]));
  await assert.rejects(collectFindingIdentities(f.raw('history'), 'history', f.history, f.source,
    (await inventory(f.history)).entries), /review-source-scanned-bytes/);
  await writeFile(join(f.history, `${f.entries[0].blob}.blob`), f.entries[0].bytes);
  const ambiguous = { ...f.source, entries: [...f.source.entries, { ...f.source.entries[0], path: 'ambiguous.mjs' }] };
  const identities = await collectFindingIdentities(f.raw('history'), 'history', f.history, ambiguous,
    (await inventory(f.history)).entries);
  assert.equal(identities[0].binding, null);
});

test('source is rechecked after admission rather than trusting earlier success flags', async t => {
  const f = await new Fixture().init(t);
  const original = f.readSource;
  let captures = 0;
  f.readSource = async (...args) => {
    const source = await original(...args);
    captures++;
    if (captures === 2) await writeFile(join(f.root, f.entries[0].path), 'changed after first inspection');
    return source;
  };
  assert.equal((await f.publication(await f.admit())).status, 'error');
  assert.ok(captures >= 3);
});

test('changed roots/files/blobs/attributes and source-artifact substitutions fail after authenticated readback', async t => {
  const f = await new Fixture().init(t);
  const bytes = Buffer.from(f.entries[0].bytes);
  for (const changed of [Buffer.concat([bytes, Buffer.from('\n')]), Buffer.from(bytes.toString().replaceAll('\n', '\r\n'))]) {
    const capability = await f.admit();
    await writeFile(join(f.root, f.entries[0].path), changed);
    assert.equal((await f.publication(capability)).status, 'error');
    await writeFile(join(f.root, f.entries[0].path), bytes);
  }
  const capability = await f.admit();
  const changedRoot = join(f.temp, 'other-root');
  await mkdir(changedRoot);
  const request = { ...f.request, root: changedRoot, sourceRoot: changedRoot };
  assert.equal((await f.publication(capability, { request })).status, 'error');
  await assert.rejects(consumeSecretAdmission(await f.admit(), { ...f.request, phase: 'artifact' }, {}));
  f.attributes.filter = 'unreviewed-driver';
  assert.equal((await f.publication(await f.admit())).status, 'error');
});

test('source and raw-object locations require exact verified mapping and explicit Git EOL rendering', async t => {
  const f = await new Fixture().init(t);
  const raw = f.raw('working-tree');
  const entries = (await inventory(f.root)).entries;
  for (const transform of [
    rows => { rows[0].SourceMetadata.Data.Filesystem.file = join(f.root, '../outside.mjs'); },
    rows => { rows[0].SourceMetadata.Data.Filesystem.line = -1; },
    rows => { rows[0].SourceMetadata.Data.Filesystem.file = `${f.root}/test/../${f.entries[0].path}`; },
  ]) {
    const rows = raw.stdout.split('\n').map(line => JSON.parse(line));
    transform(rows);
    await assert.rejects(collectFindingIdentities({ ...raw, stdout: rows.map(row => JSON.stringify(row)).join('\n') },
      'working-tree', f.root, f.source, entries));
  }
  f.attributes.eol = 'crlf';
  for (const entry of f.entries) await writeFile(join(f.root, entry.path), entry.bytes.toString().replaceAll('\n', '\r\n'));
  f.source = await f.readSource(f.root, { tools: {}, context: {} });
  const crlf = await collectFindingIdentities(f.raw('working-tree'), 'working-tree', f.root, f.source,
    (await inventory(f.root)).entries);
  assert.ok(crlf.every(item => item.binding.checkoutForm === 'declared-crlf'));
  f.attributes.eol = 'lf';
  await assert.rejects(collectFindingIdentities(f.raw('working-tree'), 'working-tree', f.root, f.source,
    (await inventory(f.root)).entries));
  f.attributes.eol = 'crlf';
  await writeFile(join(f.root, f.entries[0].path), f.entries[0].bytes.toString().replace('\n', '\r\n'));
  await assert.rejects(collectFindingIdentities(f.raw('working-tree'), 'working-tree', f.root, f.source,
    (await inventory(f.root)).entries));
});

test('public boundaries reject plain flags; authenticated admission does not supply other external gates', async t => {
  const f = await new Fixture().init(t);
  assert.equal((await f.publication({ authenticated: true })).status, 'error');
  assert.equal(publicationSecretGates({ ...f.secrets, reviewedFalsePositives: 6, remainingFindings: 0 },
    'source', ['source-trufflehog'])['source-trufflehog'].status, 'failed');
  let laterChecks = 0;
  const result = await aggregateExternalGates({ ...f.request, publicPackages: ['synthetic-public-package'] }, {
    secretAdmission: await f.admit(),
    scanPublication: async ({ secretAdmission }) => {
      const report = await f.publication(secretAdmission);
      report.gates['source-private-identifiers'] = { status: 'not-run', ownerReview: 'pending',
        evidence: [{ sha256: 'd'.repeat(64), description: 'Synthetic absent private policy' }] };
      report.gates['producer-advisories'] = { status: 'passed',
        evidence: [{ sha256: 'e'.repeat(64), description: 'Synthetic advisory boundary' }] };
      return report;
    },
    run: () => { laterChecks++; throw new Error('Synthetic author gate remains required'); },
  });
  assert.equal(result.gates['source-trufflehog'].status, 'passed');
  assert.equal(result.gates['source-private-identifiers'].status, 'not-run');
  assert.equal(result.status, 'failed');
  assert.equal(result.error.gate, 'author-identity');
  assert.equal(laterChecks, 1);
});

test('CLI cannot turn local approval JSON or forged flags into owner authentication', async t => {
  const f = await new Fixture().init(t);
  const input = join(f.temp, 'request.json');
  const output = join(f.temp, 'scanner.json');
  await writeFile(input, JSON.stringify({ ...f.request, approval: f.approval }));
  assert.equal((await scannerCli(['--request', input, '--output', output])).status, 'error');
  let admissions = 0;
  await assert.rejects(externalCli(['--request', input, '--output', join(f.temp, 'external.json')], {
    admitPreparation: async () => {},
    readAdmission: async () => { admissions++; throw new Error('Synthetic missing real dispatch'); },
  }));
  assert.equal(admissions, 1);
});

test('local correlation never authenticates, approves or exposes finding material', async t => {
  const f = await new Fixture().init(t);
  await f.withCi(undefined, async () => {
    const result = await correlateSecretReport({ root: f.root, report: f.report, localOnly: true, readSource: f.readSource });
    assert.equal(result.eligibility, 'none');
    assert.equal(result.ownerApproval, 'not-supplied');
    assert.equal(result.findings.length, 6);
    assert.ok(result.findings.every(item => item.classification === 'not-assessed'));
    for (const value of f.values) assert.equal(JSON.stringify(result).includes(value), false);
    await assert.rejects(correlateSecretReport({ root: f.root, report: f.report, readSource: f.readSource }));
    assert.equal((await correlateCli(['--root', f.root])).error, 'local-correlation-not-for-ci');
  });
});

test('local correlation rejects CI in both API and CLI before source reads', async t => {
  const f = await new Fixture().init(t);
  const inherited = process.env.CI;
  let sourceReads = 0;
  for (const value of ['true', '1', 'false']) {
    await f.withCi(value, async () => {
      await assert.rejects(correlateSecretReport({ root: f.root, report: f.report, localOnly: true,
        readSource: async () => { sourceReads++; return f.source; } }), { code: 'local-correlation-not-for-ci' });
      assert.equal((await correlateCli(['--local-only', '--root', f.root])).error, 'local-correlation-not-for-ci');
    });
    assert.equal(process.env.CI, inherited);
  }
  assert.equal(sourceReads, 0);
  const failure = new Error('Synthetic local fixture failure');
  await assert.rejects(f.withCi(undefined, async () => { throw failure; }), error => error === failure);
  assert.equal(process.env.CI, inherited);
});

test('collection action and strict topology remain separate from preparation, signing and publication', async t => {
  const f = await new Fixture().init(t);
  const skipped = { ...f.jobs[0], run_id: 12, conclusion: 'skipped' };
  assertCollectionJobSkipped([skipped]);
  assert.throws(() => assertCollectionJobSkipped(f.jobs));
  assert.throws(() => validateCollectionJobs([...f.jobs, f.jobs[0]], f.approval, f.report));
  assert.throws(() => validateTransfer({}, f.jobs, {}, f.approval));
  const bootstrap = new URL('../tools/npm-publication/bootstrap-readers.mjs', import.meta.url);
  if (existsSync(bootstrap)) {
    const { readOwnerRun, readSigningRun } = await import(bootstrap.href);
    for (const [name, reader] of [['sign-bootstrap', readSigningRun], ['publish-bootstrap', readOwnerRun]]) {
      const active = { ...skipped, name, id: 222, status: 'in_progress', conclusion: null };
      const readers = { readJson: async () => f.current, readJobs: async () => [active, skipped] };
      await reader(f.approval, '12', readers, false);
      readers.readJobs = async () => [active, { ...skipped, conclusion: 'success' }];
      await assert.rejects(reader(f.approval, '12', readers, false));
    }
  }
  const workflow = await readFile(new URL('../.github/workflows/npm-publish.yml', import.meta.url), 'utf8');
  const section = workflow.slice(workflow.indexOf('  secret-collection:'), workflow.indexOf('\n  source:'));
  assert.match(section, /if: inputs.action == 'collect-secrets'/);
  assert.match(section, /run.mjs collect-secrets/);
  assert.match(section, /path: \$\{\{ runner\.temp \}\}\/npm-secret-collection\//);
  assert.doesNotMatch(section, /npm-publication-prepared|candidate.tgz|id-token|npm-publication\/run.mjs prepare|always\(\)/);
  assert.match(workflow.slice(workflow.indexOf('\n  source:')), /if: inputs.action == 'prepare'/);
});

test('final gate evidence keeps raw counts and exact original collection hash through artifact transfer', async t => {
  const f = await new Fixture().init(t);
  const admitted = await f.publication(await f.admit());
  const artifact = { sha256: 'd'.repeat(64), sha512: 'e'.repeat(128),
    integrity: `sha512-${Buffer.from('e'.repeat(128), 'hex').toString('base64')}` };
  const report = { schemaVersion: 1, commit: f.commit, artifact, localRegression: f.approval.localRegression,
    sourceSecretEvidence: admitted.scannerDetails.secrets,
    gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, {
      status: 'passed', evidence: [{ description: 'Synthetic independent gate', sha256: 'f'.repeat(64) }],
    }])) };
  report.gates['source-trufflehog'] = admitted.gates['source-trufflehog'];
  validateGates(report, f.approval, artifact);
  for (const mutate of [
    value => { value.sourceSecretEvidence.executions[1].findings = 0; },
    value => { value.gates['source-trufflehog'].admission.rawFindings = 0; },
    value => { delete value.sourceSecretEvidence; },
    value => { value.sourceSecretEvidence.collection.source.tree = '0'.repeat(40); },
  ]) {
    const changed = structuredClone(report);
    mutate(changed);
    assert.throws(() => validateGates(changed, f.approval, artifact));
  }
});

test('SYNTHETIC URI path-bearing native records bind all three fixtures in both source scopes', async t => {
  const f = await new Fixture().init(t, { nativeUri: true });
  const sourceIds = [];
  for (const scope of ['working-tree', 'history']) {
    const raw = f.raw(scope);
    const rows = raw.stdout.split('\n').map(line => JSON.parse(line));
    const parsed = parseTrufflehog(raw);
    assert.equal(parsed.status, 'findings');
    assert.equal(parsed.findings, 3);
    assert.equal(raw.code, 183);
    const identities = await f.nativeIdentities(scope);
    assert.equal(identities.length, 3);
    for (const [index, row] of rows.entries()) {
      const expected = NATIVE_URI_FIXTURES[index];
      assert.equal(typeof row.Raw, 'string');
      assert.equal(typeof row.RawV2, 'string');
      assert.ok(row.Raw !== row.RawV2);
      assert.equal(Buffer.byteLength(row.Raw), expected.rawBytes);
      assert.equal(Buffer.byteLength(row.RawV2), expected.fullBytes);
      assert.equal(sha256(row.Raw), expected.rawSha256);
      assert.equal(sha256(row.RawV2), expected.fullSha256);
      assert.equal(identities[index].binding?.blob, expected.blob);
      assert.equal(identities[index].binding?.line, f.entries[index].line);
      assert.equal(identities[index].recordSha256, sha256(JSON.stringify(row)));
    }
    sourceIds.push(identities.map(item => item.id));
  }
  assert.ok(sourceIds[0].every((id, index) => id !== sourceIds[1][index]));
});

test('SYNTHETIC URI native collection remains non-eligible until separate exact synthetic owner admission', async t => {
  const f = await new Fixture().init(t, { nativeUri: true });
  assert.equal(f.report.eligibility, 'none');
  assert.ok(f.report.raw.executions.filter(item => item.tool.name === 'trufflehog')
    .every(item => item.identities.every(finding => finding.binding !== null)));
  assert.equal((await f.publication()).gates['source-trufflehog'].status, 'failed');
  const admitted = await f.publication(await f.admit());
  assert.equal(admitted.status, 'passed');
  assert.equal(admitted.privateContentReview.status, 'pending');
  assert.equal(admitted.gates['source-trufflehog'].admission.reviewedFalsePositives, 6);
  for (const execution of admitted.scannerDetails.secrets.executions.filter(item => item.tool.name === 'trufflehog')) {
    assert.equal(execution.status, 'findings');
    assert.equal(execution.exitCode, 183);
    assert.equal(execution.findings, 3);
  }
  const correlation = await f.withCi(undefined, () => correlateSecretReport({ root: f.root, report: f.report,
    localOnly: true, readSource: f.readSource }));
  assert.equal(correlation.eligibility, 'none');
  assert.equal(correlation.ownerApproval, 'not-supplied');
  assert.ok((await f.nativeIdentities('artifact')).every(item => item.binding === null));
  await assert.rejects(consumeSecretAdmission(await f.admit(), { ...f.request, phase: 'artifact' }, {}));
  for (const material of [...f.values, ...f.raw('working-tree').stdout.split('\n').map(line => JSON.parse(line).Raw)]) {
    assert.equal(JSON.stringify(f.report).includes(material), false);
    assert.equal(JSON.stringify(admitted).includes(material), false);
    assert.equal(JSON.stringify(correlation).includes(material), false);
  }
});

for (const scope of ['working-tree', 'history']) {
  test(`SYNTHETIC URI native ${scope} rejects every unpinned second representation and metadata change`, async t => {
    const f = await new Fixture().init(t, { nativeUri: true });
    assert.ok((await f.nativeIdentities(scope)).every(item => item.binding));
    for (const [name, mutate] of [
      ['different password', row => { row.RawV2 = row.RawV2.replace(`:${row.SecretParts.password}@`, ':synthetic-other@'); }],
      ['different username', row => { row.RawV2 = row.RawV2.replace(`://${row.SecretParts.username}:`, '://synthetic-other:'); }],
      ['different authority', row => { row.RawV2 = row.RawV2.replace(`@${row.SecretParts.host}`, '@elsewhere.invalid'); }],
      ['added port', row => { row.RawV2 = row.RawV2.replace(`@${row.SecretParts.host}`, `@${row.SecretParts.host}:443`); }],
      ['different path', row => { row.RawV2 += '/other'; }],
      ['query', row => { row.RawV2 += '?synthetic=other'; }],
      ['fragment', row => { row.RawV2 += '#synthetic-other'; }],
      ['swapped pair', (row, rows) => { row.RawV2 = rows[1].RawV2; }],
      ['pathless field includes path', row => { row.Raw += '/other'; }],
      ['percent-encoded equivalent', row => {
        const password = row.SecretParts.password;
        const encoded = `%${password.charCodeAt(0).toString(16)}${password.slice(1)}`;
        row.RawV2 = row.RawV2.replace(`:${password}@`, `:${encoded}@`);
      }],
      ['escaped separators', row => { row.RawV2 = row.RawV2.replaceAll('/', '\\/'); }],
      ['literal unicode escape', row => { row.RawV2 = `\\u0068${row.RawV2.slice(1)}`; }],
      ['control character', row => { row.RawV2 += '\0'; }],
      ['missing parts', row => { delete row.SecretParts; }],
      ['null parts', row => { row.SecretParts = null; }],
      ['array parts', row => { row.SecretParts = []; }],
      ['string parts', row => { row.SecretParts = 'synthetic-other'; }],
      ['missing part', row => { delete row.SecretParts.password; }],
      ['different part', row => { row.SecretParts.password = 'synthetic-other'; }],
      ['different part host', row => { row.SecretParts.host = 'elsewhere.invalid'; }],
      ['different part user', row => { row.SecretParts.username = 'synthetic-other'; }],
      ['non-string part', row => { row.SecretParts.password = 1; }],
      ['extra part', row => { row.SecretParts.other = 'synthetic-other'; }],
      ['different redaction', row => { row.Redacted = row.RawV2; }],
      ['extra data', row => { row.ExtraData = { other: 'synthetic-other' }; }],
      ['structured data', row => { row.StructuredData = { other: 'synthetic-other' }; }],
      ['extra record field', row => { row.OtherCredential = 'synthetic-other'; }],
      ['different detector', row => { row.DetectorName = 'Other'; }],
      ['wrong detector number', row => { row.DetectorType++; }],
      ['wrong detector description', row => { row.DetectorDescription = 'synthetic-other'; }],
      ['decoded result', row => { row.DecoderName = 'BASE64'; }],
      ['wrong source type', row => { row.SourceType++; }],
      ['wrong source ID', row => { row.SourceID++; }],
      ['wrong source name', row => { row.SourceName = 'synthetic-other'; }],
      ['missing cache field', row => { delete row.VerificationFromCache; }],
      ['extra filesystem field', row => { row.SourceMetadata.Data.Filesystem.other = 'synthetic-other'; }],
      ['wrong line', row => { row.SourceMetadata.Data.Filesystem.line++; }],
      ['string line', row => { row.SourceMetadata.Data.Filesystem.line = String(row.SourceMetadata.Data.Filesystem.line); }],
      ...[null, false, 0, [], {}].map(value =>
        [`non-string RawV2 ${JSON.stringify(value)}`, row => { row.RawV2 = value; }]),
    ]) {
      await t.test(name, async () => {
        const result = f.changedNative(scope, mutate);
        const identities = await f.nativeIdentities(scope, result);
        assert.equal(identities[0].binding, null);
        assert.ok(identities.slice(1).every(item => item.binding));
      });
    }
    for (const mutate of [
      row => { row.Raw = null; }, row => { row.Raw = {}; }, row => { row.Verified = true; },
      row => { row.VerificationFromCache = true; }, row => { row.VerificationError = 'synthetic error'; },
    ]) {
      await assert.rejects(f.nativeIdentities(scope, f.changedNative(scope, mutate)));
    }
  });

  test(`SYNTHETIC URI native ${scope} preserves absent empty and equal RawV2 behavior`, async t => {
    const f = await new Fixture().init(t, { nativeUri: true });
    for (const mutate of [
      row => { delete row.RawV2; }, row => { row.RawV2 = ''; }, row => { row.RawV2 = row.Raw; },
    ]) {
      const identities = await f.nativeIdentities(scope, f.changedNative(scope, mutate));
      assert.ok(identities.every(item => item.binding));
    }
  });

  test(`SYNTHETIC URI native ${scope} requires verified tool context and pinned completion version`, async t => {
    const f = await new Fixture().init(t, { nativeUri: true });
    assert.ok((await f.nativeIdentities(scope)).every(item => item.binding));
    for (const tool of [
      null, { ...f.nativeTool(), name: 'gitleaks' }, { ...f.nativeTool(), version: '3.97.2' },
      { ...f.nativeTool(), sha256: '' }, { ...f.nativeTool(), sha256: 'not-a-digest' },
      { ...f.nativeTool(), sha256: [f.nativeTool().sha256] },
    ]) {
      assert.ok((await f.nativeIdentities(scope, f.raw(scope), tool)).every(item => item.binding === null));
    }
    const raw = f.raw(scope);
    const changed = { ...raw, stderr: raw.stderr.replace('"3.97.1"', '"3.97.2"') };
    assert.throws(() => parseTrufflehog(changed));
    assert.ok((await f.nativeIdentities(scope, changed)).every(item => item.binding === null));
    const target = scope === 'history' ? f.history : f.root;
    assert.ok((await collectFindingIdentities(raw, scope, target, f.source,
      (await inventory(target)).entries)).every(item => item.binding === null));
  });

  test(`SYNTHETIC URI native ${scope} requires complete unique quoted source literals`, async t => {
    const f = await new Fixture().init(t, { nativeUri: true });
    const item = f.entries[0];
    const path = scope === 'history' ? join(f.history, `${item.blob}.blob`) : join(f.root, item.path);
    assert.ok((await f.nativeIdentities(scope)).every(finding => finding.binding));
    for (const transform of [
      value => `prefix${value}`, value => `${value}suffix`, value => `${value} ${value}`,
      value => `\\${value}`,
    ]) {
      const changed = Buffer.from(item.bytes.toString().replace(f.values[0], transform(f.values[0])));
      assert.ok(!changed.equals(item.bytes));
      await writeFile(path, changed);
      const identities = await f.nativeIdentities(scope);
      assert.equal(identities[0].binding, null);
      assert.ok(identities.slice(1).every(finding => finding.binding));
      await writeFile(path, item.bytes);
    }
  });
}

test('SYNTHETIC URI native source bindings reject changed blobs attributes and ambiguous history', async t => {
  const f = await new Fixture().init(t, { nativeUri: true });
  for (const scope of ['working-tree', 'history']) {
    assert.ok((await f.nativeIdentities(scope)).every(item => item.binding));
    const entries = f.source.entries.map((entry, index) => index ? entry : { ...entry, blob: '0'.repeat(40) });
    const changed = await f.nativeIdentities(scope, f.raw(scope), f.nativeTool(), { ...f.source, entries });
    assert.equal(changed[0].binding, null);
    assert.ok(changed.slice(1).every(item => item.binding));
  }
  const ambiguous = { ...f.source, entries: [...f.source.entries, { ...f.source.entries[0], path: 'other.mjs' }] };
  assert.equal((await f.nativeIdentities('history', f.raw('history'), f.nativeTool(), ambiguous))[0].binding, null);
  const deleted = { ...f.source, entries: f.source.entries.slice(1) };
  assert.equal((await f.nativeIdentities('history', f.raw('history'), f.nativeTool(), deleted))[0].binding, null);
  for (const name of ['filter', 'working-tree-encoding', 'ident']) {
    f.attributes[name] = 'synthetic-unapproved';
    await assert.rejects(f.nativeIdentities('working-tree'), /review-source-conversion/);
    f.attributes[name] = 'unspecified';
  }
  const item = f.entries[0];
  await writeFile(join(f.root, item.path), item.bytes.toString().replaceAll('\n', '\r\n'));
  await assert.rejects(f.nativeIdentities('working-tree'), /review-source-undeclared-checkout/);
});

test('SYNTHETIC URI native record tool report and scope substitutions cannot reuse old approval', async t => {
  const f = await new Fixture().init(t, { nativeUri: true });
  assert.equal((await f.publication(await f.admit())).status, 'passed');
  const original = structuredClone(f.report);
  for (const mutate of [
    report => { report.raw.executions[1].tool.sha256 = '0'.repeat(64); },
    report => { report.raw.executions[1].scope = 'history'; },
    report => { report.raw.executions[1].stdoutSha256 = '0'.repeat(64); },
    report => { report.source.commit = '0'.repeat(40); },
    report => { report.source.tree = '0'.repeat(40); },
    report => {
      const execution = report.raw.executions[1];
      const finding = execution.identities[0];
      finding.recordSha256 = sha256('SYNTHETIC different complete native record');
      const { id, ...identity } = finding;
      finding.id = sha256(JSON.stringify({ scope: execution.scope, ...identity }));
    },
  ]) {
    f.report = structuredClone(original);
    mutate(f.report);
    f.repack();
    await assert.rejects(f.admit());
  }
  f.report = structuredClone(original);
  f.repack();
  const originalReview = structuredClone(f.approval.secretReview);
  f.report.completedAt = f.time(-31);
  f.repack();
  f.approval.secretReview = originalReview;
  await assert.rejects(f.admit());
});

for (const form of ['lf', 'crlf']) {
  test(`SYNTHETIC URI fixture ${form} initializer reaches both correlation scopes`, async t => {
    const f = new Fixture();
    const inputs = await f.nativeCheckoutInputs(form);
    const path = 'tools/npm-publication/offline-stage/npm.cjs';
    const original = inputs.get(path);
    const inputSha256 = sha256(original);
    assert.equal(original.includes(13), form === 'crlf');
    const checkoutBlob = createHash('sha1').update(`blob ${original.length}\0`).update(original).digest('hex');
    if (form === 'crlf') assert.notEqual(checkoutBlob, NATIVE_URI_FIXTURES[2].blob);
    await f.init(t, { nativeUri: true, nativeCheckouts: inputs });
    assert.equal(f.entries.length, 3);
    for (const [index, entry] of f.entries.entries()) {
      assert.equal(entry.bytes.includes(13), false);
      assert.equal(entry.blob, NATIVE_URI_FIXTURES[index].blob);
    }
    for (const scope of ['working-tree', 'history']) {
      const raw = f.raw(scope);
      assert.equal(raw.code, 183);
      assert.equal(parseTrufflehog(raw).findings, 3);
      const identities = await f.nativeIdentities(scope);
      assert.equal(identities.length, 3);
      assert.deepEqual(identities.map(item => item.binding?.blob), NATIVE_URI_FIXTURES.map(item => item.blob));
      assert.deepEqual(identities.map(item => item.binding?.line), SYNTHETIC_URI_LOCATIONS.map(item => item.line));
    }
    assert.equal(sha256(original), inputSha256, 'Input checkout bytes must not be rewritten');
  });
}

test('SYNTHETIC URI fixture checkout changes are rejected before scanner setup', async t => {
  const cjs = 'tools/npm-publication/offline-stage/npm.cjs';
  const unsupported = /Unsupported synthetic fixture checkout form/;
  const changedBlob = /Synthetic fixture differs from pinned Git blob/;
  for (const [name, form, path, change, expected] of [
    ['changed LF content', 'lf', cjs, bytes => Buffer.concat([bytes, Buffer.from('// SYNTHETIC alteration\n')]), changedBlob],
    ['changed CRLF content', 'crlf', cjs, bytes => Buffer.concat([bytes, Buffer.from('// SYNTHETIC alteration\r\n')]), changedBlob],
    ['added newline', 'lf', cjs, bytes => Buffer.concat([bytes, Buffer.from('\n')]), changedBlob],
    ['mixed endings', 'lf', cjs, bytes => Buffer.from(bytes.toString().replace('\n', '\r\n')), unsupported],
    ['bare carriage return', 'lf', cjs, bytes => Buffer.from(bytes.toString().replace('\n', '\r')), unsupported],
    ['invalid UTF-8', 'lf', cjs, bytes => Buffer.concat([Buffer.from([0xff]), bytes]),
      error => error.code === 'ERR_ENCODING_INVALID_ENCODED_DATA'],
    ['added BOM', 'lf', cjs, bytes => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes]), changedBlob],
    ['unsupported MJS CRLF', 'lf', SYNTHETIC_URI_LOCATIONS[0].path,
      bytes => Buffer.from(bytes.toString().replaceAll('\n', '\r\n')), changedBlob],
  ]) {
    await t.test(name, async child => {
      const f = new Fixture();
      const inputs = await f.nativeCheckoutInputs(form);
      const original = inputs.get(path);
      const changed = change(original);
      assert.ok(!changed.equals(original));
      inputs.set(path, changed);
      let scans = 0;
      const scan = f.scan.bind(f);
      f.scan = async () => { scans++; return scan(); };
      await assert.rejects(f.init(child, { nativeUri: true, nativeCheckouts: inputs }), expected);
      assert.equal(scans, 0);
    });
  }
});
