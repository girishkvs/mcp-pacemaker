import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import {
  LIMITS, ScannerError, fileDigest, guarded, inventory, isolatedEnvironment, parseJson, requireCondition,
  runBounded, sha256, workspace,
} from './core.mjs';
import { materializeHistory } from './history.mjs';
import { diagnosticLocations } from './locations.mjs';

export const TOOL_PINS = Object.freeze({
  gitleaks: {
    version: '8.30.1', module: 'github.com/zricethezav/gitleaks/v8',
    moduleChecksum: 'h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=',
    configSha256: 'e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf',
  },
  trufflehog: { version: '3.97.1', module: 'github.com/trufflesecurity/trufflehog/v3' },
});

export function toolsFromEnvironment(env = process.env) {
  return {
    gitleaks: { path: env.MCP_GITLEAKS_BIN, sha256: env.MCP_GITLEAKS_SHA256,
      configPath: env.MCP_GITLEAKS_CONFIG },
    trufflehog: { path: env.MCP_TRUFFLEHOG_BIN, sha256: env.MCP_TRUFFLEHOG_SHA256 },
    go: env.MCP_GO_BIN ?? 'go', git: env.MCP_GIT_BIN ?? 'git',
  };
}

export function gitleaksProvenance(versionText, buildInfo = '') {
  const pin = TOOL_PINS.gitleaks;
  if (versionText.trim() === pin.version ||
      versionText.trim() === `v${pin.version}`) {
    return { version: pin.version, versionEvidence: 'cli' };
  }
  requireCondition(versionText.trim() === 'version is set by build process', 'gitleaks-version-mismatch');
  const moduleLine = buildInfo.split(/\r?\n/).find(line => line.trim().startsWith('mod\t'));
  const fields = moduleLine?.trim().split(/\s+/);
  requireCondition(fields?.length === 4 && fields[1] === pin.module &&
    fields[2] === `v${pin.version}` && fields[3] === pin.moduleChecksum, 'gitleaks-build-info-mismatch');
  requireCondition(!buildInfo.includes('\n\t=>'), 'gitleaks-replaced-module');
  const goVersion = buildInfo.split(/\r?\n/)[0].match(/: (go\d+\.\d+(?:\.\d+)?)$/)?.[1];
  requireCondition(Boolean(goVersion), 'gitleaks-build-info-missing');
  return { version: pin.version, versionEvidence: 'go-build-info', module: pin.module,
    moduleChecksum: pin.moduleChecksum, goVersion, buildInfoSha256: sha256(buildInfo) };
}

export async function verifyTool(name, tool, context) {
  requireCondition(tool && typeof tool.path === 'string' && isAbsolute(tool.path) &&
    /^[a-f0-9]{64}$/.test(tool.sha256), 'tool-path-and-approved-digest-required');
  const info = await lstat(tool.path);
  requireCondition(info.isFile() && !info.isSymbolicLink(), 'invalid-tool-file');
  const digest = await fileDigest(tool.path);
  requireCondition(digest === tool.sha256, 'tool-digest-mismatch');
  const versionArgs = name === 'gitleaks' ? ['version'] : ['--no-update', '--no-verification', '--version'];
  const version = await runBounded(tool.path, versionArgs, { ...context, timeoutMs: 30_000 });
  requireCondition(version.code === 0, 'tool-version-command-failed');
  const text = `${version.stdout}${version.stderr}`.trim();
  let provenance;
  if (name === 'gitleaks') {
    let buildInfo = '';
    if (text === 'version is set by build process') {
      const result = await runBounded(context.go, ['version', '-m', tool.path], { ...context, timeoutMs: 30_000 });
      requireCondition(result.code === 0 && result.stderr.trim() === '', 'go-build-info-command-failed');
      buildInfo = result.stdout;
    }
    provenance = gitleaksProvenance(text, buildInfo);
  } else {
    requireCondition(text === `trufflehog ${TOOL_PINS.trufflehog.version}`, 'trufflehog-version-mismatch');
    provenance = { version: TOOL_PINS.trufflehog.version, versionEvidence: 'cli' };
  }
  return { name, ...provenance, sha256: digest, binaryApproval: 'caller-supplied-sha256' };
}

export function scannerArguments(name, mode, target, context) {
  if (name === 'gitleaks') {
    return [mode === 'history' ? 'git' : 'dir', target,
      '--config', context.config, '--gitleaks-ignore-path', context.ignore,
      '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--no-color',
      '--log-level=info', '--report-format=json', '--report-path=-', '--exit-code=183',
      `--timeout=${LIMITS.timeoutMs / 1000 - 5}`, '--max-target-megabytes=0',
      `--max-archive-depth=${LIMITS.archiveDepth}`, `--max-decode-depth=${LIMITS.decodeDepth}`,
      ...(mode === 'history' ? ['--platform=none', `--log-opts=--full-history -m ${context.commit}`] : [])];
  }
  return ['--no-update', '--no-verification', '--no-verification-cache', '--json',
    '--fail', '--fail-on-scan-errors', '--no-color', '--concurrency=2', '--log-level=2',
    '--results=verified,unknown,unverified,filtered_unverified', '--no-filter-unverified',
    '--no-drop-unverified-jwt-results', '--no-force-skip-binaries', '--no-force-skip-archives',
    `--max-decode-depth=${LIMITS.decodeDepth}`, `--archive-max-depth=${LIMITS.archiveDepth}`,
    `--archive-max-size=${LIMITS.treeBytes}B`, '--archive-timeout=60s', '--detector-timeout=30s',
    'filesystem', target];
}

export function parseGitleaks(result) {
  requireCondition(result.code === 0 || result.code === 183, 'gitleaks-scan-failed');
  const findings = parseJson(result.stdout);
  requireCondition(Array.isArray(findings), 'gitleaks-report-schema');
  for (const finding of findings) {
    requireCondition(typeof finding.RuleID === 'string' && typeof finding.Secret === 'string' &&
      typeof finding.File === 'string', 'gitleaks-finding-schema');
  }
  const lines = result.stderr.split(/\r?\n/).filter(line => line.trim());
  const bytesLine = lines.find(line => /INF scanned ~\d+ bytes .+ in .+$/.test(line));
  requireCondition(Boolean(bytesLine), 'gitleaks-completion-missing');
  for (const line of lines) {
    const supported = /INF scanned ~\d+ bytes .+ in .+$/.test(line) ||
      /INF no leaks found$/.test(line) ||
      /WRN leaks found: \d+$/.test(line) ||
      /INF \d+ commits scanned\.$/.test(line);
    requireCondition(supported, 'gitleaks-unexpected-diagnostic');
  }
  requireCondition((result.code === 183) === (findings.length > 0), 'gitleaks-exit-report-mismatch');
  return { status: findings.length ? 'findings' : 'passed', findings: findings.length,
    scannedBytes: Number(bytesLine.match(/scanned ~(\d+) bytes/)[1]),
    evidenceSha256: sha256(result.stdout) };
}

export function parseTrufflehog(result) {
  requireCondition(result.code === 0 || result.code === 183, 'trufflehog-scan-failed');
  const findings = result.stdout.split(/\r?\n/).filter(line => line.trim()).map(parseJson);
  for (const finding of findings) {
    requireCondition(typeof finding.DetectorName === 'string' && typeof finding.Raw === 'string' &&
      finding.Verified === false, 'trufflehog-finding-schema-or-online-verification');
  }
  const logs = result.stderr.split(/\r?\n/).filter(line => line.trim()).map(parseJson);
  requireCondition(!logs.some(log => log.msg === 'Error waiting for git command to complete.' &&
    log.error === 'exec: canceling Cmd: TerminateProcess: Access is denied.'), 'trufflehog-git-cancellation-race');
  const invalidDiagnostic = logs.some(log =>
    !['info-0', 'info-1', 'info-2'].includes(log.level) ||
    typeof log.msg !== 'string' ||
    Object.hasOwn(log, 'error') ||
    Object.hasOwn(log, 'errors') ||
    /error|fail(?:ed|ure)|skipp|truncat|remainder|reached max depth|excess discarded|exceeded MaxDiffSize/i.test(log.msg));
  requireCondition(!invalidDiagnostic,
    'trufflehog-unexpected-diagnostic');
  const completion = logs.filter(log => log.msg === 'finished scanning');
  requireCondition(completion.length === 1, 'trufflehog-completion-missing');
  const summary = completion[0];
  requireCondition(Number.isSafeInteger(summary.bytes) && summary.bytes >= 0 &&
    Number.isSafeInteger(summary.chunks) && summary.chunks >= 0 &&
    summary.verified_secrets === 0 && summary.trufflehog_version === TOOL_PINS.trufflehog.version,
  'trufflehog-completion-schema');
  requireCondition((result.code === 183) === (findings.length > 0), 'trufflehog-exit-report-mismatch');
  return { status: findings.length ? 'findings' : 'passed', findings: findings.length,
    scannedBytes: summary.bytes, chunks: summary.chunks, evidenceSha256: sha256(result.stdout) };
}

async function executeScanners(target, mode, tools, context, executions) {
  for (const name of ['gitleaks', 'trufflehog']) {
    // Check the exact executable immediately before every scan, not just once per process lifetime.
    const tool = await verifyTool(name, tools[name], context);
    const startedAt = new Date().toISOString();
    const scanTarget = name === 'trufflehog' && mode === 'history' ? context.historyObjects : target;
    requireCondition(typeof scanTarget === 'string', 'history-object-snapshot-required');
    const args = scannerArguments(name, mode, scanTarget, context);
    const commandSha256 = sha256(JSON.stringify(args));
    let result;
    try {
      result = await runBounded(tools[name].path, args, context);
      requireCondition(await fileDigest(tools[name].path) === tool.sha256, 'tool-changed-during-scan');
      const parsed = name === 'gitleaks' ? parseGitleaks(result) : parseTrufflehog(result);
      if (context.localDiagnostics) {
        const locations = diagnosticLocations(name, result, scanTarget, context.localDiagnostics.entries);
        context.localDiagnostics.executions.push({ tool: name, locations,
          evidenceSha256: sha256(JSON.stringify(locations)) });
      }
      executions.push({ scope: mode, tool, commandSha256, startedAt, completedAt: new Date().toISOString(),
        ...(name === 'trufflehog' && mode === 'history'
          ? { historyMechanism: 'filesystem-over-verified-reachable-git-objects' } : {}),
        ...(name === 'gitleaks' ? { config: context.configEvidence } : {}), ...parsed });
    } catch (error) {
      executions.push({ scope: mode, tool, commandSha256, startedAt, status: 'error',
        error: error instanceof ScannerError ? error.code : 'scanner-operation-failed',
        ...(result ? { exitCode: result.code, diagnosticSha256: sha256(result.stderr) } : {}) });
      throw error;
    }
  }
}

export function fullCoverageGitleaksConfig(bytes) {
  requireCondition(sha256(bytes) === TOOL_PINS.gitleaks.configSha256, 'gitleaks-default-config-digest-mismatch');
  const text = bytes.toString('utf8');
  const start = text.indexOf('[allowlist]\n');
  const paths = text.indexOf('paths = [\n', start);
  const end = text.indexOf('\n]\n', paths);
  requireCondition(start >= 0 && paths > start && end > paths, 'gitleaks-default-config-schema');
  // Remove only the pinned default global filename exclusions (locks, binaries, images, etc.).
  // Rules and detector-specific false-positive handling remain the reviewed upstream defaults.
  return `${text.slice(0, paths)}paths = []${text.slice(end + 2)}`;
}

async function scannerContext(temp, tools) {
  const config = join(temp, 'gitleaks.toml');
  const ignore = join(temp, 'empty.ignore');
  const context = { cwd: temp, env: isolatedEnvironment(temp), go: tools.go ?? 'go', config, ignore };
  // Prove tool provenance before consulting any locally installed configuration.
  await verifyTool('gitleaks', tools.gitleaks, context);
  await verifyTool('trufflehog', tools.trufflehog, context);
  const configPath = tools.gitleaks.configPath;
  requireCondition(typeof configPath === 'string' && isAbsolute(configPath), 'gitleaks-default-config-path-required');
  const bytes = await readFile(configPath);
  const fullConfig = fullCoverageGitleaksConfig(bytes);
  await writeFile(config, fullConfig);
  await writeFile(ignore, '');
  return { ...context, configEvidence: { upstreamSha256: sha256(bytes), effectiveSha256: sha256(fullConfig),
    globalPathExclusions: 'removed', upstreamVersion: TOOL_PINS.gitleaks.version } };
}

async function git(tools, context, root, args) {
  const result = await runBounded(tools.git ?? 'git',
    ['-c', 'core.hooksPath=', '-c', 'credential.helper=', '-C', root, ...args], context);
  requireCondition(result.code === 0, 'git-scope-command-failed');
  return result.stdout.trim();
}

export async function scanSource({ root, tools = toolsFromEnvironment() }) {
  const executions = [];
  let scope;
  const result = await guarded('source-secrets', () => workspace(async temp => {
    const context = await scannerContext(temp, tools);
    requireCondition(await git(tools, context, root, ['rev-parse', '--is-shallow-repository']) === 'false',
      'shallow-history-not-supported');
    const commit = await git(tools, context, root, ['rev-parse', '--verify', 'HEAD^{commit}']);
    requireCondition(/^[a-f0-9]{40,64}$/.test(commit), 'invalid-history-commit');
    const objects = await git(tools, context, root, ['rev-list', '--objects', '--missing=print', commit]);
    requireCondition(!objects.split('\n').some(line => line.startsWith('?')), 'missing-history-objects');
    const index = await git(tools, context, root, ['ls-files', '--stage', '-z']);
    requireCondition(!index.split('\0').some(line => line.startsWith('160000 ')), 'submodule-scope-not-supported');
    const trackedPaths = index.split('\0').filter(Boolean).map(line => line.slice(line.indexOf('\t') + 1));
    const snapshot = join(temp, 'source');
    await mkdir(snapshot);
    const before = await inventory(root, { source: true, copyTo: snapshot, trackedPaths });
    const bundle = join(temp, 'history.bundle');
    await git(tools, context, root, ['bundle', 'create', bundle, 'HEAD']);
    const history = join(temp, 'history.git');
    await git(tools, context, temp, ['clone', '--bare', '--no-local', bundle, history]);
    const historyContext = { ...context, env: { ...context.env, GIT_DIR: history } };
    const count = Number(await git(tools, historyContext, history, ['rev-list', '--count', commit]));
    requireCondition(Number.isSafeInteger(count) && count > 0, 'empty-history');
    const historyObjects = join(temp, 'history-objects');
    const historyEvidence = await materializeHistory({
      history, commit, destination: historyObjects, tools, context: historyContext,
    });
    scope = { workingTree: 'all-files-including-untracked-and-ignored',
      exclusions: ['git-metadata', 'untracked-generated-node_modules-directories'], ...before.evidence,
      history: { commit, reachableCommits: count, selection: 'HEAD-and-all-ancestors',
        trufflehogObjects: historyEvidence } };
    context.commit = commit;
    await executeScanners(snapshot, 'working-tree', tools, context, executions);
    await executeScanners(history, 'history', tools, { ...historyContext, commit, historyObjects }, executions);
    requireCondition((await inventory(historyObjects)).evidence.sha256 === historyEvidence.sha256,
      'history-export-changed-during-scan');
    const after = await inventory(root, { source: true, trackedPaths });
    requireCondition(before.evidence.sha256 === after.evidence.sha256 &&
      commit === await git(tools, context, root, ['rev-parse', 'HEAD']), 'source-changed-during-scan');
    return {
      status: executions.some(item => item.status === 'findings') ? 'findings' : 'passed',
      scope,
    };
  }));
  return { ...result, ...(scope ? { scope } : {}), executions, ...secretLimits() };
}

export async function diagnoseSource({ root, tools = toolsFromEnvironment(), localOnly = false }) {
  const executions = [];
  const diagnostics = [];
  let scope;
  const result = await guarded('local-source-secret-diagnostics', () => workspace(async temp => {
    requireCondition(localOnly === true && !process.env.CI, 'local-diagnostics-not-for-ci');
    const context = await scannerContext(temp, tools);
    const commit = await git(tools, context, root, ['rev-parse', '--verify', 'HEAD^{commit}']);
    requireCondition(/^[a-f0-9]{40,64}$/.test(commit), 'invalid-history-commit');
    const index = await git(tools, context, root, ['ls-files', '--stage', '-z']);
    requireCondition(!index.split('\0').some(line => line.startsWith('160000 ')), 'submodule-scope-not-supported');
    const trackedPaths = index.split('\0').filter(Boolean).map(line => line.slice(line.indexOf('\t') + 1));
    const snapshot = join(temp, 'source');
    await mkdir(snapshot);
    const before = await inventory(root, { source: true, copyTo: snapshot, trackedPaths });
    const snapshotBefore = await inventory(snapshot);
    scope = { commit, selection: 'owned-snapshot-of-working-tree-including-untracked-and-ignored',
      history: 'not-scanned; diagnostic-is-not-a-publication-gate',
      exclusions: ['git-metadata', 'untracked-generated-node_modules-directories'], ...before.evidence };
    context.localDiagnostics = { entries: before.entries, executions: diagnostics };
    await executeScanners(snapshot, 'working-tree', tools, context, executions);
    requireCondition(snapshotBefore.evidence.sha256 === (await inventory(snapshot)).evidence.sha256,
      'diagnostic-snapshot-changed-during-scan');
    requireCondition(before.evidence.sha256 === (await inventory(root, { source: true, trackedPaths })).evidence.sha256 &&
      commit === await git(tools, context, root, ['rev-parse', 'HEAD']), 'source-changed-during-scan');
    return { status: executions.some(item => item.status === 'findings') ? 'findings' : 'passed' };
  }));
  return { ...result, ...(scope ? { scope } : {}), executions, diagnostics,
    purpose: 'local-triage-only; never-upload; not-publication-evidence',
    ...secretLimits() };
}

export async function scanArtifact({ root, tools = toolsFromEnvironment(), artifactSha256 }) {
  const executions = [];
  let scope;
  const result = await guarded('artifact-secrets', () => workspace(async temp => {
    if (artifactSha256 !== undefined) {
      requireCondition(/^[a-f0-9]{64}$/.test(artifactSha256), 'invalid-artifact-sha256');
    }
    const context = await scannerContext(temp, tools);
    const before = await inventory(root);
    scope = { selection: 'all-unpacked-files-no-exclusions', ...before.evidence,
      ...(artifactSha256 ? { callerArtifactSha256: artifactSha256 } : {}) };
    await executeScanners(root, 'unpacked-artifact', tools, context, executions);
    const after = await inventory(root);
    requireCondition(before.evidence.sha256 === after.evidence.sha256, 'artifact-changed-during-scan');
    return { status: executions.some(item => item.status === 'findings') ? 'findings' : 'passed',
      scope };
  }));
  return { ...result, ...(scope ? { scope } : {}), executions, ...secretLimits() };
}

function secretLimits() {
  return { onlineVerification: 'disabled', automaticUpdates: 'disabled',
    gitleaksNetworkFeatures: 'not-present-in-pinned-tool',
    limits: { ...LIMITS, archiveCoverage: 'tool-supported-formats-only',
      binaryCoverage: 'tool-supported-decoding; not a proof every binary format is understood' },
    privateContentReview: 'separate-gate-required' };
}
