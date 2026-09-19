import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { TOOL_PINS, scannerArguments } from '../publication-scanners/secrets.mjs';
import { LIMITS } from '../publication-scanners/core.mjs';
import { SCANNER_RELEASES } from './install-scanners.mjs';
import { syntheticUriLocation } from '../publication-scanners/review-source.mjs';

export const SECRET_COLLECTION_JOB = 'secret-collection';
export const SECRET_COLLECTION_STEPS = Object.freeze([
  'Collect redacted source secret evidence only', 'Retain non-eligible secret collection',
]);
export const SECRET_EXECUTION_FILES = Object.freeze(['working-tree', 'history'].flatMap(scope =>
  ['gitleaks', 'trufflehog'].map(tool => `execution-${scope}-${tool}.json`)));
export const secretHash = bytes => createHash('sha256').update(bytes).digest('hex');
const keys = (value, expected) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), 'Missing secret evidence object');
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), 'Unexpected secret evidence fields');
};
export const secretKeys = keys;
const sha = value => assert.match(value ?? '', /^[a-f0-9]{64}$/, 'Invalid secret evidence digest');
export const secretId = value => {
  assert.ok(typeof value === 'string' || Number.isSafeInteger(value), 'Invalid secret evidence ID type');
  assert.match(String(value ?? ''), /^[1-9][0-9]*$/, 'Invalid secret evidence ID');
  return String(value);
};
const count = value => assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 64, 'Invalid finding count');

export function validateSecretReview(review, approval, now = Date.now()) {
  assert.equal(approval.scope, 'prepare', 'Secret disposition is source preparation only');
  keys(review, ['schemaVersion', 'scope', 'classification', 'reviewer', 'reviewedAt',
    'admissionRunNumber', 'collection', 'findingIds']);
  assert.equal(review.schemaVersion, 1);
  assert.equal(review.scope, 'exact-source-secret-report');
  assert.equal(review.classification, 'synthetic-uri-userinfo-rejection-input');
  assert.equal(review.reviewer, 'girishkvs');
  secretId(review.admissionRunNumber);
  const reviewed = Date.parse(review.reviewedAt);
  const approved = Date.parse(approval.approvedAt);
  assert.ok(Number.isFinite(reviewed) && reviewed <= approved && approved <= now &&
    approved - reviewed <= 3_600_000, 'Secret review is missing, stale or future dated');
  keys(review.collection, ['runId', 'jobId', 'artifactId', 'artifactDigest', 'reportSha256']);
  for (const key of ['runId', 'jobId', 'artifactId']) secretId(review.collection[key]);
  assert.match(review.collection.artifactDigest, /^sha256:[a-f0-9]{64}$/);
  sha(review.collection.reportSha256);
  assert.ok(Array.isArray(review.findingIds) && review.findingIds.length > 0 && review.findingIds.length <= 128);
  review.findingIds.forEach(sha);
  assert.equal(new Set(review.findingIds).size, review.findingIds.length, 'Duplicate finding approval');
  return review;
}

function validateBinding(binding) {
  keys(binding, ['pathSha256', 'line', 'blob', 'blobSha256', 'checkoutSha256',
    'scanFileSha256', 'attributesSha256', 'checkoutForm']);
  for (const key of ['pathSha256', 'blobSha256', 'checkoutSha256', 'scanFileSha256', 'attributesSha256']) sha(binding[key]);
  assert.match(binding.blob, /^[a-f0-9]{40}$/);
  assert.ok(Number.isSafeInteger(binding.line) && binding.line > 0);
  assert.ok(['exact-git-blob', 'declared-crlf'].includes(binding.checkoutForm));
}

export function validateSecretCollection(report) {
  try { return validateCollection(report); } catch { throw new Error('Invalid bounded original source secret evidence'); }
}

function validateCollection(report) {
  keys(report, ['schemaVersion', 'kind', 'eligibility', 'source', 'workflow', 'completedAt', 'raw', 'history', 'producerEvidence']);
  assert.equal(report.schemaVersion, 2);
  assert.equal(report.kind, 'source-secret-collection');
  assert.equal(report.eligibility, 'none');
  assert.ok(Number.isFinite(Date.parse(report.completedAt)));
  keys(report.source, ['commit', 'tree', 'rootSha256', 'filesSha256', 'treeEntriesSha256']);
  for (const key of ['commit', 'tree']) assert.match(report.source[key], /^[a-f0-9]{40}$/);
  for (const key of ['rootSha256', 'filesSha256', 'treeEntriesSha256']) sha(report.source[key]);
  keys(report.workflow, ['runId', 'runNumber', 'attempt', 'repositoryId', 'ownerId', 'ref']);
  for (const key of ['runId', 'runNumber', 'repositoryId', 'ownerId']) secretId(report.workflow[key]);
  assert.equal(report.workflow.attempt, 1);
  assert.match(report.workflow.ref, /^refs\/tags\/(?:npm(?:-r[2-5])?\/)?v(?:1\.3\.1|2\.0\.1)$/);
  keys(report.history, ['commit', 'reachableCommits', 'inventorySha256', 'metadataSha256', 'objects']);
  assert.equal(report.history.commit, report.source.commit);
  for (const key of ['reachableCommits', 'objects']) assert.ok(Number.isSafeInteger(report.history[key]) && report.history[key] > 0);
  assert.ok(report.history.reachableCommits <= report.history.objects && report.history.objects <= 200_000);
  sha(report.history.inventorySha256);
  sha(report.history.metadataSha256);
  keys(report.raw, ['status', 'executions']);
  assert.ok(['passed', 'findings'].includes(report.raw.status), 'Scanner errors are never reviewable');
  assert.ok(Array.isArray(report.raw.executions) && report.raw.executions.length === 4, 'Incomplete secret coverage');
  const ids = new Set();
  let total = 0;
  for (const scope of ['working-tree', 'history']) {
    for (const name of ['gitleaks', 'trufflehog']) {
      const matches = report.raw.executions.filter(item => item.scope === scope && item.tool.name === name);
      assert.equal(matches.length, 1, 'Missing or duplicate execution');
      const item = matches[0];
      keys(item, ['scope', 'tool', 'commandSha256', 'configurationSha256', 'targetSha256', 'stdoutSha256', 'stderrSha256',
        'exitCode', 'status', 'findings', 'identities']);
      keys(item.tool, ['name', 'version', 'sha256']);
      assert.equal(item.tool.version, TOOL_PINS[name].version);
      sha(item.tool.sha256);
      for (const key of ['commandSha256', 'configurationSha256', 'targetSha256', 'stdoutSha256', 'stderrSha256']) sha(item[key]);
      count(item.findings);
      total += item.findings;
      assert.equal(item.status, item.findings ? 'findings' : 'passed');
      assert.equal(item.exitCode, item.findings ? 183 : 0);
      assert.ok(Array.isArray(item.identities));
      assert.equal(item.identities.length, name === 'trufflehog' ? item.findings : 0);
      for (const finding of item.identities) {
        keys(finding, ['id', 'detector', 'detectorSha256', 'valueSha256', 'recordSha256', 'binding']);
        assert.ok(['URI', 'other'].includes(finding.detector));
        for (const key of ['id', 'detectorSha256', 'valueSha256', 'recordSha256']) sha(finding[key]);
        if (finding.detector === 'URI') assert.equal(finding.detectorSha256, secretHash('URI'));
        if (finding.binding !== null) validateBinding(finding.binding);
        const { id, ...identity } = finding;
        assert.equal(id, secretHash(JSON.stringify({ scope, ...identity })), 'Finding identity mismatch');
        assert.ok(!ids.has(id), 'Duplicate raw finding');
        ids.add(id);
      }
    }
  }
  assert.equal(report.raw.status, total ? 'findings' : 'passed');
  validateProducerEvidence(report);
  return report;
}

export function makeSecretCollection(secrets, workflow, context) {
  assert.ok(['passed', 'findings'].includes(secrets.status), 'Collection scanner failed');
  assert.equal(secrets.onlineVerification, 'disabled');
  assert.equal(secrets.automaticUpdates, 'disabled');
  assert.equal(secrets.scope.sha256, secrets.reviewSource.filesSha256);
  const objects = secrets.scope.history.trufflehogObjects;
  assert.equal(objects.objectIdentity, 'Git object IDs recomputed over every exported body');
  for (const item of secrets.executions) {
    if (item.tool.name === 'gitleaks') {
      assert.equal(item.config.upstreamSha256, TOOL_PINS.gitleaks.configSha256);
      assert.equal(item.config.globalPathExclusions, 'removed');
      sha(item.config.effectiveSha256);
    } else if (item.scope === 'history') {
      assert.equal(item.historyMechanism, 'filesystem-over-verified-reachable-git-objects');
    }
    assert.equal(item.evidenceSha256, item.review.stdoutSha256);
  }
  const report = {
    schemaVersion: 2, kind: 'source-secret-collection', eligibility: 'none',
    source: secrets.reviewSource, workflow, completedAt: secrets.completedAt,
    raw: { status: secrets.status, executions: secrets.executions.map(item => ({
      scope: item.scope, tool: { name: item.tool.name, version: item.tool.version, sha256: item.tool.sha256 },
      commandSha256: item.commandSha256, ...item.review,
      configurationSha256: secretHash(JSON.stringify(item.config ?? null)),
      status: item.status, findings: item.findings,
    })) },
    history: { commit: secrets.scope.history.commit, reachableCommits: secrets.scope.history.reachableCommits,
      inventorySha256: objects.sha256, metadataSha256: objects.objectMetadataSha256, objects: objects.objects },
    producerEvidence: { schemaVersion: 1, kind: 'pinned-hosted-original-source-execution-proof',
      ...context, source: secrets.producerSource, history: secrets.producerHistory,
      receipts: secrets.executions.map((execution, index) => {
        const record = execution.producerReceipt;
        return { file: SECRET_EXECUTION_FILES[index], sha256: secretHash(`${JSON.stringify(record, null, 2)}\n`), record };
      }) },
  };
  return validateSecretCollection(report);
}

const integer = (value, max = LIMITS.treeBytes) => assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= max);
const instant = value => {
  const time = Date.parse(value);
  assert.ok(Number.isFinite(time) && new Date(time).toISOString() === value);
  return time;
};

export function validateProducerEvidence(report) {
  const proof = report.producerEvidence;
  keys(proof, ['schemaVersion', 'kind', 'ci', 'runtime', 'bootstrap', 'source', 'history', 'receipts']);
  assert.equal(proof.schemaVersion, 1);
  assert.equal(proof.kind, 'pinned-hosted-original-source-execution-proof');
  keys(proof.ci, ['runId', 'attempt', 'commit', 'completedAt']);
  secretId(proof.ci.runId);
  assert.equal(proof.ci.attempt, 1);
  assert.equal(proof.ci.commit, report.source.commit);
  let previous = instant(proof.ci.completedAt);
  const completed = instant(report.completedAt);
  assert.deepEqual(proof.runtime, { platform: 'linux', arch: 'x64', node: '24.21.0' });
  const bootstrap = proof.bootstrap;
  keys(bootstrap, ['schemaVersion', 'platform', 'tools', 'configSha256']);
  assert.equal(bootstrap.schemaVersion, 1);
  assert.equal(bootstrap.platform, 'linux-x64');
  assert.equal(bootstrap.configSha256, TOOL_PINS.gitleaks.configSha256);
  assert.deepEqual(bootstrap.tools.map(tool => tool.name), ['gitleaks', 'trufflehog']);
  for (const tool of bootstrap.tools) {
    keys(tool, ['name', 'version', 'archiveSha256', 'checksumsSha256', 'executableSha256', 'digestBasis']);
    const pin = SCANNER_RELEASES[tool.name];
    assert.equal(tool.version, pin.version);
    assert.equal(tool.archiveSha256, pin.sha256);
    assert.equal(tool.checksumsSha256, pin.checksumsSha256);
    sha(tool.executableSha256);
    assert.equal(tool.digestBasis,
      'Executable extracted from independently pinned official release archive; not a separate upstream executable checksum');
  }
  const source = proof.source;
  keys(source, ['schemaVersion', 'kind', 'inventoryFormat', 'privateFormat', 'filesSha256',
    'privateFilesSha256', 'privateTreeSha256', 'checkoutPolicy', 'files']);
  assert.equal(source.schemaVersion, 1);
  assert.equal(source.kind, 'exact-committed-lf-policy-checkout');
  assert.equal(source.inventoryFormat, 'json-ordered-path-size-mode-sha256-v1');
  assert.equal(source.privateFormat, 'localCommitment-path-sorted-path-size-sha256-v1');
  assert.deepEqual(source.checkoutPolicy, { autocrlf: false, eol: 'lf' });
  assert.equal(source.filesSha256, report.source.filesSha256);
  sha(source.privateFilesSha256); sha(source.privateTreeSha256);
  assert.ok(Array.isArray(source.files) && source.files.length > 0 && source.files.length <= 10000);
  const paths = new Set();
  for (const file of source.files) {
    keys(file, ['pathSha256', 'size', 'mode', 'sha256', 'gitMode', 'blob', 'blobSha256', 'attributes']);
    for (const key of ['pathSha256', 'sha256', 'blobSha256']) sha(file[key]);
    assert.ok(!paths.has(file.pathSha256)); paths.add(file.pathSha256);
    integer(file.size, LIMITS.fileBytes); integer(file.mode, 0o777);
    assert.ok(['100644', '100755'].includes(file.gitMode));
    assert.match(file.blob, /^[a-f0-9]{40}$/);
    keys(file.attributes, ['text', 'eol', 'filter', 'working-tree-encoding', 'ident']);
    assert.ok(['set', 'auto', 'unset'].includes(file.attributes.text));
    assert.ok(['lf', 'crlf', 'unspecified'].includes(file.attributes.eol));
    for (const key of ['filter', 'working-tree-encoding', 'ident']) assert.equal(file.attributes[key], 'unspecified');
    if (file.attributes.text === 'unset') assert.equal(file.sha256, file.blobSha256);
  }
  assert.ok(source.files.reduce((sum, file) => sum + file.size, 0) <= LIMITS.treeBytes);
  const history = proof.history;
  keys(history, ['commit', 'reachableCommits', 'bundle', 'objects']);
  assert.equal(history.commit, report.source.commit);
  assert.equal(history.reachableCommits, report.history.reachableCommits);
  keys(history.bundle, ['sha256', 'bytes']); sha(history.bundle.sha256);
  integer(history.bundle.bytes); assert.ok(history.bundle.bytes > 0);
  const objects = history.objects;
  keys(objects, ['files', 'bytes', 'sha256', 'objects', 'objectTypes', 'objectMetadataSha256',
    'exportLimits', 'selection', 'objectIdentity']);
  keys(objects.objectTypes, ['blob', 'tree', 'commit', 'tag']);
  Object.values(objects.objectTypes).forEach(value => integer(value, LIMITS.files));
  assert.equal(objects.objectTypes.commit, history.reachableCommits);
  assert.equal(objects.files, objects.objects);
  assert.equal(objects.objects, Object.values(objects.objectTypes).reduce((sum, value) => sum + value, 0));
  assert.equal(objects.objects, report.history.objects);
  assert.equal(objects.sha256, report.history.inventorySha256);
  assert.equal(objects.objectMetadataSha256, report.history.metadataSha256);
  integer(objects.bytes); assert.ok(objects.bytes > 0);
  keys(objects.exportLimits, ['objects', 'objectBytes', 'rawBytes', 'batchOutputBytes']);
  assert.equal(objects.exportLimits.objects, LIMITS.files);
  assert.equal(objects.exportLimits.objectBytes, LIMITS.fileBytes);
  assert.equal(objects.exportLimits.rawBytes, LIMITS.treeBytes);
  integer(objects.exportLimits.batchOutputBytes, LIMITS.treeBytes + LIMITS.files * 128);
  assert.ok(objects.exportLimits.batchOutputBytes >= objects.bytes);
  assert.equal(objects.selection, 'all-raw-objects-reachable-from-HEAD; complete blobs, trees and commit metadata');
  assert.equal(objects.objectIdentity, 'Git object IDs recomputed over every exported body');
  assert.deepEqual(proof.receipts.map(item => item.file), SECRET_EXECUTION_FILES);
  assert.equal(report.raw.executions.length, proof.receipts.length);
  for (const [index, item] of proof.receipts.entries()) {
    keys(item, ['file', 'sha256', 'record']);
    assert.equal(item.sha256, secretHash(`${JSON.stringify(item.record, null, 2)}\n`));
    const record = item.record;
    const raw = report.raw.executions[index];
    const name = raw.tool.name;
    assert.equal(item.file, `execution-${raw.scope}-${name}.json`);
    keys(record, ['schemaVersion', 'kind', 'source', 'scope', 'tool', 'native', 'argv', 'configuration', 'target', 'parser']);
    assert.equal(record.schemaVersion, 1);
    assert.equal(record.kind, 'redacted-original-native-source-execution');
    assert.deepEqual(record.source, report.source);
    assert.equal(record.scope, raw.scope); assert.deepEqual(record.tool, raw.tool);
    assert.equal(raw.tool.sha256, bootstrap.tools.find(tool => tool.name === name).executableSha256);
    const native = record.native;
    keys(native, ['schemaVersion', 'kind', 'executablePathSha256', 'argumentsSha256', 'startedAt',
      'completedAt', 'code', 'signal', 'timeoutMs', 'maxOutputBytes', 'streams']);
    assert.equal(native.schemaVersion, 1); assert.equal(native.kind, 'bounded-native-execution');
    sha(native.executablePathSha256); assert.equal(native.argumentsSha256, raw.commandSha256);
    assert.equal(native.code, raw.exitCode); assert.equal(native.signal, null);
    assert.equal(native.timeoutMs, LIMITS.timeoutMs); assert.equal(native.maxOutputBytes, LIMITS.outputBytes);
    const start = instant(native.startedAt); const end = instant(native.completedAt);
    assert.ok(start >= previous && end >= start && end <= completed);
    previous = end;
    keys(native.streams, ['stdout', 'stderr']);
    let bytes = 0;
    for (const key of ['stdout', 'stderr']) {
      const stream = native.streams[key]; keys(stream, ['sha256', 'bytes', 'receivedBytes']);
      assert.equal(stream.sha256, raw[`${key}Sha256`]); integer(stream.bytes, LIMITS.outputBytes);
      assert.equal(stream.receivedBytes, stream.bytes); bytes += stream.bytes;
    }
    assert.ok(bytes <= LIMITS.outputBytes);
    keys(record.target, ['sha256', 'kind', 'inventorySha256']);
    assert.equal(record.target.sha256, raw.targetSha256);
    assert.equal(record.target.kind, raw.scope === 'working-tree' ? 'source-snapshot'
      : name === 'gitleaks' ? 'verified-bundle-git-history' : 'verified-reachable-object-corpus');
    assert.equal(record.target.inventorySha256, raw.scope === 'working-tree' ? report.source.filesSha256
      : name === 'gitleaks' ? history.bundle.sha256 : objects.sha256);
    const slot = (value, role) => { keys(value, ['role', 'sha256']); assert.equal(value.role, role); sha(value.sha256); return value; };
    const target = { role: 'target', sha256: raw.targetSha256 };
    const args = name === 'gitleaks'
      ? scannerArguments(name, raw.scope, target, { config: slot(record.argv[3], 'config'),
        ignore: slot(record.argv[5], 'ignore'), commit: report.source.commit })
      : scannerArguments(name, raw.scope, target, {});
    assert.deepEqual(record.argv, args);
    assert.equal(secretHash(JSON.stringify(record.configuration)), raw.configurationSha256);
    if (name === 'gitleaks') {
      keys(record.configuration, ['upstreamSha256', 'effectiveSha256', 'globalPathExclusions', 'upstreamVersion']);
      assert.equal(record.configuration.upstreamSha256, bootstrap.configSha256);
      assert.equal(record.configuration.upstreamVersion, TOOL_PINS.gitleaks.version);
      assert.equal(record.configuration.globalPathExclusions, 'removed'); sha(record.configuration.effectiveSha256);
    } else assert.equal(record.configuration, null);
    const parsed = record.parser;
    keys(parsed, ['status', 'findings', 'scannedBytes', 'chunks', 'completionCount', 'diagnosticFrames',
      'reportedCommits', 'verified', 'unverified']);
    assert.equal(parsed.status, raw.status); assert.equal(parsed.findings, raw.findings);
    integer(parsed.scannedBytes); assert.ok(parsed.scannedBytes > 0);
    assert.equal(parsed.completionCount, 1); integer(parsed.diagnosticFrames); assert.ok(parsed.diagnosticFrames > 0);
    assert.equal(parsed.reportedCommits, name === 'gitleaks' && raw.scope === 'history' ? history.reachableCommits : null);
    if (name === 'trufflehog') {
      integer(parsed.chunks); assert.equal(parsed.verified, 0); assert.equal(parsed.unverified, raw.identities.length);
    } else {
      assert.equal(parsed.chunks, null); assert.equal(parsed.verified, null); assert.equal(parsed.unverified, null);
    }
  }
  return proof;
}

export function secretCollectionFiles(report) {
  validateSecretCollection(report);
  const files = new Map([['report.json', Buffer.from(`${JSON.stringify(report, null, 2)}\n`)],
    ...report.producerEvidence.receipts.map(item => [item.file, Buffer.from(`${JSON.stringify(item.record, null, 2)}\n`)])]);
  assert.ok([...files.values()].every(bytes => bytes.length <= 512 * 1024));
  assert.ok([...files.values()].reduce((sum, bytes) => sum + bytes.length, 0) <= 2 * 1024 * 1024 - 65536);
  return files;
}

export function validateSecretCollectionFiles(files) {
  assert.deepEqual([...files.keys()].sort(), ['report.json', ...SECRET_EXECUTION_FILES].sort());
  const reportBytes = files.get('report.json');
  assert.ok(reportBytes.length <= 512 * 1024);
  const report = validateSecretCollection(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(reportBytes)));
  const expected = secretCollectionFiles(report);
  for (const [name, bytes] of files) {
    assert.ok(bytes.length <= 512 * 1024 && bytes.equals(expected.get(name)), 'Original canonical producer receipt differs');
  }
  return report;
}

export function reviewedFindings(report, review) {
  validateSecretCollection(report);
  const findings = [];
  const locations = new Set();
  for (const execution of report.raw.executions) {
    if (execution.tool.name === 'gitleaks') {
      assert.equal(execution.findings, 0, 'Gitleaks findings are not admissible');
    } else {
      for (const finding of execution.identities) {
        assert.equal(finding.detector, 'URI', 'Only separately reviewed synthetic URI inputs are admissible');
        assert.ok(finding.binding, 'Unverified source/history mapping');
        assert.ok(syntheticUriLocation(finding.binding.pathSha256, finding.binding.line),
          'Finding is outside the three supported negative-test inputs');
        const location = `${execution.scope}/${finding.binding.pathSha256}/${finding.binding.line}`;
        assert.ok(!locations.has(location), 'Repeated finding location cannot consume another approval');
        locations.add(location);
        findings.push({ scope: execution.scope, ...finding });
      }
    }
  }
  assert.deepEqual(review.findingIds.toSorted(), findings.map(item => item.id).toSorted(),
    'Every raw finding requires its own exact approval; unused approvals are rejected');
  return findings;
}

export function assertCollectionJobSkipped(jobs) {
  const found = jobs.filter(job => job.name === SECRET_COLLECTION_JOB);
  assert.ok(found.length <= 1, 'Duplicate collection job');
  for (const job of found) {
    assert.equal(job.status, 'completed');
    assert.equal(job.conclusion, 'skipped', 'Collection is not preparation/signing/staging success');
  }
}
