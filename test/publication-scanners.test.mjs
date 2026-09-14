import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  guarded, inventory, isolatedEnvironment, runBounded, sha256, workspace,
} from '../tools/publication-scanners/core.mjs';
import {
  TOOL_PINS, fullCoverageGitleaksConfig, gitleaksProvenance, parseGitleaks, parseTrufflehog, scanArtifact, scannerArguments,
  scanSource, toolsFromEnvironment, verifyTool,
} from '../tools/publication-scanners/secrets.mjs';
import { scanPrivateContent } from '../tools/publication-scanners/private.mjs';
import { main } from '../tools/publication-scanners/cli.mjs';
import { historyObjectMetadata, writeHistoryObjects } from '../tools/publication-scanners/history.mjs';

const commit = 'a'.repeat(40);
const artifactSha256 = 'b'.repeat(64);

function gitleaksResult(findings = [], code = findings.length ? 183 : 0) {
  return { code, stdout: JSON.stringify(findings),
    stderr: `12:00PM INF scanned ~14 bytes (14 bytes) in 1s\n12:00PM ${
      findings.length ? `WRN leaks found: ${findings.length}` : 'INF no leaks found'}\n` };
}

function trufflehogResult(findings = [], code = findings.length ? 183 : 0) {
  return { code, stdout: findings.map(item => JSON.stringify(item)).join('\n'),
    stderr: JSON.stringify({ level: 'info-0', msg: 'finished scanning', bytes: 14, chunks: 1,
      verified_secrets: 0, unverified_secrets: findings.length, trufflehog_version: '3.97.1' }) };
}

test('T22/T42: scanner arguments disable verification, updates, ignores and silent scan-error success', () => {
  const context = { config: 'owned-config', ignore: 'owned-empty-ignore', commit };
  for (const mode of ['working-tree', 'history', 'unpacked-artifact']) {
    const args = scannerArguments('trufflehog', mode, process.cwd(), context);
    for (const flag of ['--no-update', '--no-verification', '--no-verification-cache', '--fail',
      '--fail-on-scan-errors', '--no-force-skip-binaries', '--no-force-skip-archives']) {
      assert.ok(args.includes(flag), flag);
    }
    assert.ok(!args.includes('--only-verified'));
    const leaks = scannerArguments('gitleaks', mode, process.cwd(), context);
    for (const flag of ['--redact=100', '--ignore-gitleaks-allow', '--max-target-megabytes=0',
      '--exit-code=183', '--report-path=-']) assert.ok(leaks.includes(flag), flag);
    assert.ok(!leaks.includes('--baseline-path'));
    if (mode === 'history') {
      assert.ok(leaks.includes(`--log-opts=--full-history -m ${commit}`));
      assert.equal(args.at(-2), 'filesystem');
      assert.ok(!args.includes('git'));
      assert.ok(!args.includes('--trust-local-git-config'));
    }
  }
  const environment = isolatedEnvironment(process.cwd());
  assert.equal(environment.GIT_CONFIG_KEY_0, 'safe.bareRepository');
  assert.equal(environment.GIT_CONFIG_VALUE_0, 'explicit');
});

test('T42: module-built Gitleaks is identified by exact Go build info, not a fabricated CLI version', () => {
  const text = `tool: go1.26.5\n\tpath\t${TOOL_PINS.gitleaks.module}\n\tmod\t` +
    `${TOOL_PINS.gitleaks.module}\tv8.30.1\t${TOOL_PINS.gitleaks.moduleChecksum}\n`;
  assert.equal(gitleaksProvenance('version is set by build process', text).versionEvidence, 'go-build-info');
  assert.equal(gitleaksProvenance('8.30.1').versionEvidence, 'cli');
  for (const changed of [text.replace('v8.30.1', 'v8.30.0'), text.replace('h1:', 'bad:'),
    `${text}\t=> replaced-module\n`, '']) {
    assert.throws(() => gitleaksProvenance('version is set by build process', changed));
  }
  assert.throws(() => gitleaksProvenance('unknown'));
  assert.throws(() => fullCoverageGitleaksConfig(Buffer.from('unapproved configuration')),
    /gitleaks-default-config-digest-mismatch/);
});

test('T22/T42: tool digest required and checked before execution; missing tools never pass', async () => workspace(async root => {
  const tool = join(root, 'not-an-executable');
  await writeFile(tool, 'fixture');
  const context = { cwd: root, env: isolatedEnvironment(root) };
  await assert.rejects(() => verifyTool('gitleaks', { path: tool, sha256: '0'.repeat(64) }, context),
    /tool-digest-mismatch/);
  const result = await scanArtifact({ root, tools: { gitleaks: {} } });
  assert.equal(result.status, 'error');
  assert.equal(result.error, 'tool-path-and-approved-digest-required');
}));

test('T22: scanner findings redact all raw fields and diagnostics while preserving blocking exit semantics', () => {
  const secret = ['synthetic', 'credential', 'not-real'].join('-');
  const leaks = parseGitleaks(gitleaksResult([{ RuleID: secret, File: secret, Secret: secret, Match: secret }]));
  const hog = parseTrufflehog(trufflehogResult([{ DetectorName: secret, Raw: secret, RawV2: secret,
    Redacted: secret, ExtraData: { secret }, SourceMetadata: { secret }, Verified: false }]));
  for (const result of [leaks, hog]) {
    assert.equal(result.status, 'findings');
    assert.equal(result.findings, 1);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
  assert.equal(parseGitleaks(gitleaksResult()).status, 'passed');
  assert.equal(parseTrufflehog(trufflehogResult()).status, 'passed');
});

test('T42: errors, unsupported output, absent completion and mismatched exits fail closed', () => {
  for (const parse of [parseGitleaks, parseTrufflehog]) {
    assert.throws(() => parse({ code: 1, stdout: 'private-secret', stderr: 'private-secret' }));
    assert.throws(() => parse({ code: 0, stdout: 'private-secret', stderr: '' }));
    assert.throws(() => parse({ code: 183, stdout: '[]', stderr: '' }));
  }
  assert.throws(() => parseGitleaks({ ...gitleaksResult(), stderr: 'partial scan completed' }));
  assert.throws(() => parseGitleaks({ ...gitleaksResult(), code: 183 }));
  assert.throws(() => parseTrufflehog({ ...trufflehogResult(), code: 183 }));
  assert.throws(() => parseTrufflehog(trufflehogResult([{ DetectorName: 'fixture', Raw: 'fixture', Verified: true }])));
  assert.throws(() => parseTrufflehog({ ...trufflehogResult(), stderr: JSON.stringify({
    level: 'error', msg: 'private-secret',
  }) }));
  assert.throws(() => parseTrufflehog({ ...trufflehogResult(), stderr: JSON.stringify({
    level: 'info-2', msg: 'skipping oversize diff line; remainder of file not scanned',
  }) }));
  assert.throws(() => parseTrufflehog({ ...trufflehogResult(), stderr: JSON.stringify({
    level: 'info-0', msg: 'unexpected message', error: 'private-secret',
  }) }));
  for (const diagnostic of [
    { level: 'info-2', msg: 'Error waiting for git command to complete.', error: 'private-secret' },
    { level: 'info-2', msg: 'Diff for private-file exceeded MaxDiffSize(100)' },
  ]) {
    const completed = trufflehogResult();
    assert.throws(() => parseTrufflehog({
      ...completed, stderr: `${JSON.stringify(diagnostic)}\n${completed.stderr}`,
    }), /trufflehog-unexpected-diagnostic/);
  }
  const completed = trufflehogResult();
  assert.throws(() => parseTrufflehog({
    ...completed, stderr: `${JSON.stringify({
      level: 'info-2', msg: 'Error waiting for git command to complete.',
      error: 'exec: canceling Cmd: TerminateProcess: Access is denied.',
    })}\n${completed.stderr}`,
  }), /trufflehog-git-cancellation-race/);
});

test('T22/T42: complete reachable-object export preserves binary bytes and rejects incomplete or changed objects',
  async () => workspace(async root => {
    const body = Buffer.from([0, 255, 128, 10, 13, 0, 97]);
    const id = createHash('sha1').update(`blob ${body.length}\0`).update(body).digest('hex');
    const checked = `${id} blob ${body.length}\n`;
    const { metadata, bytes } = historyObjectMetadata(checked, [id]);
    assert.equal(bytes, body.length);
    const batch = Buffer.concat([Buffer.from(checked), body, Buffer.from('\n')]);
    await writeHistoryObjects(batch, metadata, root);
    assert.deepEqual(await readFile(join(root, `${id}.blob`)), body);
    for (const invalid of [
      `${id} blob -1\n`, `${id} blob 268435457\n`, `${id} unknown 0\n`, `${'0'.repeat(40)} blob 1\n`, '',
    ]) {
      assert.throws(() => historyObjectMetadata(invalid, [id]));
    }
    const changed = Buffer.from(batch);
    changed[Buffer.byteLength(checked)] ^= 1;
    await assert.rejects(() => writeHistoryObjects(changed, metadata, root), /history-object-content-mismatch/);
    await assert.rejects(() => writeHistoryObjects(batch.subarray(0, -1), metadata, root),
      /history-object-body-truncated/);
    const other = join(root, 'trailing');
    await mkdir(other);
    await assert.rejects(() => writeHistoryObjects(Buffer.concat([batch, Buffer.from('extra')]), metadata, other),
      /history-object-trailing-output/);
  }));

test('T22/T42: source inventory includes ignored/untracked bytes and artifact inventory excludes nothing', async () => workspace(async root => {
  const source = join(root, 'candidate');
  const snapshot = join(root, 'snapshot');
  await mkdir(source);
  await mkdir(snapshot);
  await writeFile(join(source, '.gitignore'), 'ignored.txt');
  await writeFile(join(source, 'ignored.txt'), 'must scan even when ignored');
  await writeFile(join(source, 'untracked.txt'), 'new candidate code');
  await writeFile(join(source, 'archive.zip'), Buffer.from([0x50, 0x4b, 0, 0]));
  await mkdir(join(source, 'node_modules'));
  await writeFile(join(source, 'node_modules', 'dependency'), 'generated dependency');
  await mkdir(join(source, '.git'));
  await writeFile(join(source, '.git', 'object'), 'git object');
  const before = await inventory(source, { source: true, copyTo: snapshot });
  assert.deepEqual(before.entries.map(item => item.path), ['.gitignore', 'archive.zip', 'ignored.txt', 'untracked.txt']);
  assert.equal(await readFile(join(snapshot, 'ignored.txt'), 'utf8'), 'must scan even when ignored');
  assert.equal((await inventory(source)).entries.length, 6);
  assert.equal((await inventory(source, {
    source: true, trackedPaths: ['node_modules/dependency'],
  })).entries.length, 5, 'Tracked dependency files must not be treated as generated exclusions');
  await writeFile(join(source, 'untracked.txt'), 'changed');
  assert.notEqual((await inventory(source, { source: true })).evidence.sha256, before.evidence.sha256);
}));

test('T22: private policy absence is not-run; empty policies cannot pass; matches and owner review stay private/pending',
  async () => workspace(async root => {
    const source = join(root, 'source');
    await mkdir(source);
    const pattern = ['private', 'fixture', 'identifier'].join('-');
    await writeFile(join(source, 'file.txt'), pattern);
    const policyPath = join(root, 'policy.json');
    const binding = { commit, artifactSha256 };
    assert.equal((await scanPrivateContent({ root: source, binding })).status, 'not-run');
    await writeFile(policyPath, JSON.stringify({ schemaVersion: 1, literals: [] }));
    assert.equal((await scanPrivateContent({ root: source, policyPath, binding })).status, 'error');
    await writeFile(policyPath, JSON.stringify({ schemaVersion: 1, literals: [{ value: pattern, ignoreCase: true }] }));
    const result = await scanPrivateContent({ root: source, policyPath, binding });
    assert.equal(result.status, 'findings');
    assert.equal(result.ownerReview, 'pending');
    assert.ok(!JSON.stringify(result).includes(pattern));
    assert.ok(!JSON.stringify(result).includes(source));
    await writeFile(join(source, 'file.txt'), 'ordinary public fixture');
    const clean = await scanPrivateContent({ root: source, policyPath, binding });
    assert.equal(clean.status, 'passed');
    assert.equal(clean.ownerReview, 'pending');
    assert.equal((await scanPrivateContent({ root: source, policyPath, binding: { commit } })).status, 'error');
  }));

test('T42: subprocess timeout/output limits and native errors never print their captured contents', async () => workspace(async root => {
  const context = { cwd: root, env: isolatedEnvironment(root) };
  const failure = await guarded('fixture', () => runBounded(process.execPath,
    ['-e', 'process.stdout.write("private-fixture".repeat(1000))'], { ...context, maxOutputBytes: 128 }));
  assert.equal(failure.error, 'scanner-output-limit');
  assert.ok(!JSON.stringify(failure).includes('private-fixture'));
  const timeout = await guarded('fixture', () => runBounded(process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'], { ...context, timeoutMs: 100 }));
  assert.equal(timeout.error, 'scanner-timeout');
  const unknown = await guarded('fixture', () => { throw new Error('private-fixture'); });
  assert.equal(unknown.error, 'scanner-operation-failed');
  const cli = await main(['artifact', '--private-fixture']);
  assert.equal(cli.status, 'error');
  assert.ok(!JSON.stringify(cli).includes('private-fixture'));
}));

test('T22/T42: real pinned scanners cover a tiny owned source/history and unchanged unpacked fixture', {
  skip: process.env.MCP_PUBLICATION_SCANNER_FIXTURES !== '1',
}, async () => workspace(async root => {
  const source = join(root, 'candidate');
  await mkdir(source);
  const git = args => execFileSync('git', ['-C', source, ...args], {
    env: isolatedEnvironment(root), stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000,
  }).toString().trim();
  git(['init', '--quiet']);
  await writeFile(join(source, 'public.txt'), 'An ordinary public fixture.\n');
  git(['add', 'public.txt']);
  // Commits only inside this owned disposable fixture, never in a candidate worktree.
  git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '--quiet', '-m', 'Synthetic scanner fixture']);
  await writeFile(join(source, 'untracked.txt'), 'This untracked fixture must be included.\n');
  const tools = toolsFromEnvironment();
  const result = await scanSource({ root: source, tools });
  assert.equal(result.status, 'passed', JSON.stringify(result));
  assert.equal(result.executions.length, 4);
  assert.equal(result.scope.files, 2);
  assert.equal(result.scope.history.reachableCommits, 1);
  assert.equal(result.scope.history.trufflehogObjects.objectTypes.commit, 1);
  assert.equal(result.scope.history.trufflehogObjects.objectTypes.blob, 1);
  assert.equal(result.executions[3].historyMechanism, 'filesystem-over-verified-reachable-git-objects');
  const artifact = join(root, 'artifact');
  await mkdir(artifact);
  await writeFile(join(artifact, 'payload.txt'), 'Public fixture payload.\n');
  const scanned = await scanArtifact({ root: artifact, tools });
  assert.equal(scanned.status, 'passed', JSON.stringify(scanned));
  assert.equal(scanned.executions.length, 2);
  assert.equal(scanned.executions[0].tool.version, '8.30.1');
  assert.equal(scanned.executions[1].tool.version, '3.97.1');
}));

test('T22: real scanners block ignored/untracked files, deleted history and archive-only synthetic credentials without echoing them', {
  skip: process.env.MCP_PUBLICATION_SCANNER_FIXTURES !== '1',
}, async () => workspace(async root => {
  const source = join(root, 'candidate');
  await mkdir(source);
  const git = args => execFileSync('git', ['-C', source, ...args], {
    env: isolatedEnvironment(root), stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000,
  }).toString().trim();
  const record = () => git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '--quiet', '-m', 'Synthetic scanner fixture']);
  // Generated detector-shaped data, never a real credential or verified with any endpoint.
  const synthetic = `${['gh', 'p'].join('')}_${randomBytes(18).toString('hex')}`;
  const archived = `${['gh', 'p'].join('')}_${randomBytes(18).toString('hex')}`;
  git(['init', '--quiet']);
  await writeFile(join(source, 'removed.txt'), `token = "${synthetic}"\n`);
  await writeFile(join(source, 'removed.gz'), gzipSync(`token = "${archived}"\n`));
  git(['add', '.']);
  record();
  await rm(join(source, 'removed.txt'));
  await rm(join(source, 'removed.gz'));
  await writeFile(join(source, 'public.txt'), 'Public current fixture.\n');
  await writeFile(join(source, '.gitignore'), 'untracked.exe\n');
  git(['add', '-A']);
  record();
  await writeFile(join(source, 'untracked.exe'), `token = "${synthetic}"\n`);
  const tools = toolsFromEnvironment();
  const result = await scanSource({ root: source, tools });
  assert.equal(result.status, 'findings', JSON.stringify(result));
  assert.equal(result.executions.length, 4);
  for (const execution of result.executions) assert.equal(execution.status, 'findings');
  assert.ok(!JSON.stringify(result).includes(synthetic));
  assert.ok(!JSON.stringify(result).includes(archived));
  assert.equal(result.scope.history.trufflehogObjects.objectTypes.commit, 2);
  assert.ok(result.executions[3].findings >= 2, 'TruffleHog must scan the deleted archive as raw history bytes');
  const artifact = join(root, 'artifact');
  await mkdir(artifact);
  await writeFile(join(artifact, 'nested.txt.gz'), gzipSync(`token = "${synthetic}"\n`));
  const scanned = await scanArtifact({ root: artifact, tools });
  assert.equal(scanned.status, 'findings', JSON.stringify(scanned));
  for (const execution of scanned.executions) assert.equal(execution.status, 'findings');
  assert.ok(!JSON.stringify(scanned).includes(synthetic));
}));
