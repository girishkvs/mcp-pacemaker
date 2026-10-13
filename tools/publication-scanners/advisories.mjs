import { guarded, readJson, requireCondition, sha256 } from './core.mjs';

const ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 100;
const RESPONSE_LIMIT = 8 * 1024 * 1024;
const SCOPES = new Set(['producer-root', 'producer-ui', 'fresh-consumer']);
const NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ADVISORY = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/;

export const PRODUCER_RISK_REVIEW = Object.freeze({
  release: '2.0.2', phase: 'source', scope: 'producer-root-and-ui',
  reviewedBy: 'girishkvs', approvedOn: '2026-10-06',
  notBefore: '2026-10-06T15:33:00Z', expiresAt: '2026-10-12T00:00:00Z',
  reason: 'Temporary acceptance of exact existing CLI-runtime and UI-build findings for the 2.0.2 documentation release; remediation deferred, not advisory-free.',
  locks: Object.freeze({
    'producer-root': '62f92175cd124818678166381c0acd0376cb9dedb2278d39eb4e4033368e2500',
    'producer-ui': 'b88a73a6212e26f4c4dde985d84eadf39870c8758e4698cdd5544b8a55eb8cca',
  }),
  advisories: Object.freeze([
    Object.freeze({ scope: 'producer-root', exposure: 'cli-runtime', package: 'smol-toml',
      version: '1.8.0', id: 'GHSA-r4xh-jqrq-34v2' }),
    Object.freeze({ scope: 'producer-ui', exposure: 'ui-build', package: 'braces',
      version: '3.0.3', id: 'GHSA-vfj7-8cjw-p6xm' }),
    Object.freeze({ scope: 'producer-ui', exposure: 'ui-build', package: 'postcss-selector-parser',
      version: '6.1.4', id: 'GHSA-rj75-hqrm-r3gf' }),
    Object.freeze({ scope: 'producer-ui', exposure: 'ui-build', package: 'source-map-js',
      version: '1.2.1', id: 'GHSA-68fv-2mgg-jv7q' }),
  ]),
  nativeReports: Object.freeze({
    'producer-root': Object.freeze({
      sha256: '93a12f5109ca8488a8e80f8287a0961cb06f2b9c57122d81a93645c4a9e2159f',
      counts: Object.freeze({ info: 0, low: 0, moderate: 1, high: 0, critical: 0, total: 1 }),
      affectedAncestors: Object.freeze(['smol-toml']),
    }),
    'producer-ui': Object.freeze({
      sha256: '8320a09dc8d1831eb7054034d5148137fb2af784b02716eecc0db860eea826cf',
      counts: Object.freeze({ info: 0, low: 0, moderate: 2, high: 6, critical: 0, total: 8 }),
      affectedAncestors: Object.freeze(['braces', 'chokidar', 'fast-glob', 'micromatch',
        'postcss-nested', 'postcss-selector-parser', 'source-map-js', 'tailwindcss']),
    }),
  }),
});

export function canonicalAdvisoryJson(value) {
  if (Array.isArray(value)) return value.map(canonicalAdvisoryJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalAdvisoryJson(value[key])]));
  }
  return value;
}

export function requiresProducerAdvisoryEvidence(version) {
  return !['1.3.1', '2.0.1'].includes(version);
}

export function validateProducerRiskEvidence(value, now = Date.now()) {
  const expected = { disposition: 'RISK-ACCEPTED', ...PRODUCER_RISK_REVIEW,
    reviewRecordSha256: sha256(JSON.stringify(PRODUCER_RISK_REVIEW)), advisoryFree: false };
  requireCondition(JSON.stringify(canonicalAdvisoryJson(value)) === JSON.stringify(canonicalAdvisoryJson(expected)) &&
    Number.isFinite(now) && now >= Date.parse(expected.notBefore) && now < Date.parse(expected.expiresAt),
  'producer-risk-evidence-invalid-or-expired');
  return value;
}

function sameAdvisory(left, right, code) {
  requireCondition(JSON.stringify(canonicalAdvisoryJson(left)) ===
    JSON.stringify(canonicalAdvisoryJson(right)), code);
}

export function hasProducerAdvisoryEvidence(value) {
  if (!value ||
      typeof value !== 'object') return false;
  return ['riskAcceptance', 'acceptance', 'nativeAudits', 'osv'].some(key => Object.hasOwn(value, key)) ||
    value.disposition === 'RISK-ACCEPTED' || value.advisoryFree === false ||
    value.rawExitCode > 0 || value.rawFindingCount > 0 || value.remainingFindings > 0 ||
    Object.values(value.rawCounts ?? {}).some(count => count > 0) ||
    (value.audits ?? []).some(hasProducerAdvisoryEvidence) ||
    (value.evidence ?? []).some(item => item.exitCode > 0);
}

function validateNativeAdvisories(audits, now) {
  requireCondition(Array.isArray(audits) && audits.length === 2, 'producer-native-audits-required');
  sameAdvisory(audits.map(item => item.scope), ['producer-root', 'producer-ui'], 'producer-native-scopes');
  let risk = false;
  for (const audit of audits) {
    const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
    if (audit.rawExitCode === 0) {
      sameAdvisory(audit, { scope: audit.scope, disposition: 'advisory-free', rawExitCode: 0,
        rawCounts: counts, rawFindingCount: 0 }, 'producer-native-clean-contradiction');
      continue;
    }
    const reviewed = PRODUCER_RISK_REVIEW.nativeReports[audit.scope];
    requireCondition(Boolean(reviewed), 'producer-native-risk-scope');
    validateProducerRiskEvidence(audit.acceptance, now);
    requireCondition(/^[a-f0-9]{64}$/.test(audit.reportSha256 ?? ''), 'producer-native-report-digest');
    requireCondition(Array.isArray(audit.affectedAncestors), 'producer-native-ancestors');
    sameAdvisory([...audit.affectedAncestors].sort(), reviewed.affectedAncestors, 'producer-native-ancestors');
    sameAdvisory(audit, { scope: audit.scope, disposition: 'RISK-ACCEPTED', advisoryFree: false,
      rawExitCode: 1, rawCounts: reviewed.counts, rawFindingCount: reviewed.counts.total,
      rawAdvisoryCount: PRODUCER_RISK_REVIEW.advisories.filter(item => item.scope === audit.scope).length,
      affectedAncestors: audit.affectedAncestors, reportSha256: audit.reportSha256,
      canonicalReportSha256: reviewed.sha256, acceptance: audit.acceptance },
    'producer-native-risk-contradiction');
    risk = true;
  }
  return risk;
}

// A continuation validates retained records; it never reconstructs missing acceptance.
export function validateProducerAdvisories(gate, { source, checks, version, complete = false, now = Date.now() } = {}) {
  const required = complete && requiresProducerAdvisoryEvidence(version);
  if (!required &&
      !hasProducerAdvisoryEvidence(gate) &&
      !hasProducerAdvisoryEvidence(checks)) return false;
  requireCondition(gate?.status === 'passed' && !Object.hasOwn(gate, 'acceptance'), 'producer-advisory-gate-required');
  const osv = gate.osv;
  requireCondition(osv?.status === 'passed' && Array.isArray(osv.findings) &&
    osv.rawFindingCount === osv.findings.length && osv.remainingFindings === 0,
  'producer-osv-report-required');
  requireCondition(Array.isArray(osv.scope) && osv.scope.length === 2, 'producer-osv-scopes');
  sameAdvisory(osv.scope.map(item => item.scope), ['producer-root', 'producer-ui'], 'producer-osv-scopes');
  requireCondition(Array.isArray(gate.evidence) &&
    gate.evidence.some(item => item.sha256 === sha256(JSON.stringify(osv))), 'producer-osv-evidence-digest');
  for (const graph of osv.scope) {
    requireCondition(/^[a-f0-9]{64}$/.test(graph.lockSha256 ?? '') &&
      /^[a-f0-9]{64}$/.test(graph.graphSha256 ?? '') &&
      Number.isSafeInteger(graph.packages) && graph.packages > 0, 'producer-osv-graph');
  }
  requireCondition(Number.isSafeInteger(osv.distinctCoordinates) && osv.distinctCoordinates > 0 &&
    Array.isArray(osv.evidence) && osv.evidence.length > 0 &&
    osv.evidence.reduce((sum, item) => sum + item.queries, 0) === osv.distinctCoordinates,
  'producer-osv-query-evidence');
  for (const item of osv.evidence) {
    requireCondition(['querySha256', 'responseSha256', 'rawResponseSha256']
      .every(key => /^[a-f0-9]{64}$/.test(item[key] ?? '')) &&
      Number.isSafeInteger(item.queries) && item.queries > 0 &&
      Number.isSafeInteger(item.responseBytes) && item.responseBytes > 0, 'producer-osv-query-evidence');
  }
  const osvRisk = osv.findings.length > 0;
  if (osvRisk) {
    requireCondition(osv.findings.length <= PRODUCER_RISK_REVIEW.advisories.length &&
      osv.advisoryFree === false, 'producer-osv-risk-count');
    validateProducerRiskEvidence(osv.riskAcceptance, now);
    const seen = new Set();
    for (const finding of osv.findings) {
      validateProducerRiskEvidence(finding.riskAcceptance, now);
      const reviewed = PRODUCER_RISK_REVIEW.advisories.find(item =>
        finding.name === item.package && finding.version === item.version && finding.id === item.id);
      requireCondition(reviewed && !seen.has(finding.id) &&
        finding.status === 'reviewed-exemption' && Number.isFinite(Date.parse(finding.modified)),
      'producer-osv-risk-finding');
      seen.add(finding.id);
      sameAdvisory(finding, { name: reviewed.package, version: reviewed.version,
        id: reviewed.id, modified: finding.modified, status: 'reviewed-exemption',
        riskAcceptance: finding.riskAcceptance }, 'producer-osv-ambiguous-finding');
    }
    sameAdvisory(osv.scope.map(item => item.lockSha256),
      Object.values(PRODUCER_RISK_REVIEW.locks), 'producer-osv-risk-lock');
  } else {
    requireCondition(!Object.hasOwn(osv, 'riskAcceptance') &&
      osv.advisoryFree !== false, 'producer-osv-clean-contradiction');
  }
  let nativeRisk = false;
  if (complete ||
      Object.hasOwn(gate, 'nativeAudits')) {
    nativeRisk = validateNativeAdvisories(gate.nativeAudits, now);
    const exits = gate.evidence.filter(item => Object.hasOwn(item, 'exitCode'));
    const riskAudits = gate.nativeAudits.filter(item => item.rawExitCode === 1);
    requireCondition(exits.every(item => [0, 1].includes(item.exitCode)) &&
      exits.filter(item => item.exitCode === 1).length === riskAudits.length, 'producer-native-exit-evidence');
    requireCondition(new Set(riskAudits.map(item => item.reportSha256)).size === riskAudits.length,
      'producer-native-stdout-binding');
    for (const audit of riskAudits) {
      requireCondition(exits.filter(item => item.exitCode === 1 &&
        item.stdoutSha256 === audit.reportSha256).length === 1, 'producer-native-stdout-binding');
    }
  }
  const risk = osvRisk || nativeRisk;
  requireCondition(gate.rawFindingCount === osv.rawFindingCount && gate.remainingFindings === 0 &&
    gate.advisoryFree === !risk && gate.disposition === (risk ? 'RISK-ACCEPTED' : 'advisory-free'),
  'producer-advisory-disposition-contradiction');
  if (risk) validateProducerRiskEvidence(gate.riskAcceptance, now);
  else requireCondition(!Object.hasOwn(gate, 'riskAcceptance'), 'producer-clean-acceptance-contradiction');
  if (complete) {
    requireCondition(source?.version === version && /^[a-f0-9]{40}$/.test(source.commit ?? ''),
      'producer-source-version-binding');
    sameAdvisory(checks?.audits, gate.nativeAudits, 'producer-source-checks-drift');
    sameAdvisory(osv.scope.map(item => item.lockSha256), [source.rootLockSha256, source.uiLockSha256],
      'producer-source-lock-binding');
    if (risk) {
      requireCondition(version === PRODUCER_RISK_REVIEW.release, 'producer-risk-source-binding');
      sameAdvisory([source.rootLockSha256, source.uiLockSha256],
        Object.values(PRODUCER_RISK_REVIEW.locks), 'producer-risk-source-binding');
    }
  }
  return risk;
}

export function requireBuildOnlyRiskScope(rootLockBytes, bundleManifestBytes) {
  const root = JSON.parse(rootLockBytes);
  const bundle = JSON.parse(bundleManifestBytes);
  requireCondition(root.packages && bundle.schemaVersion === 1 &&
    Array.isArray(bundle.packages) && Array.isArray(bundle.runtimeNotices) &&
    Array.isArray(bundle.sources), 'ui-risk-runtime-evidence-missing');
  for (const { package: affected } of PRODUCER_RISK_REVIEW.advisories.filter(item => item.exposure === 'ui-build')) {
    requireCondition(!Object.entries(root.packages).some(([path, item]) =>
      path && (item.name ?? path.split('node_modules/').at(-1)) === affected),
    'ui-risk-package-in-root-runtime');
    requireCondition(![...bundle.packages, ...bundle.runtimeNotices].some(item => item.name === affected) &&
      !bundle.sources.some(item => item.path?.includes(`node_modules/${affected}/`)), 'ui-risk-package-bundled');
  }
  return { rootLockSha256: sha256(rootLockBytes), bundleManifestSha256: sha256(bundleManifestBytes),
    affectedPackageAbsentFromRuntimeAndBundle: true };
}

// Replay of the published 2.0.2 record only; fresh scans never consult this review.
export function producerRiskAcceptance(context, now = Date.now(), review = PRODUCER_RISK_REVIEW) {
  if (!review ||
      JSON.stringify(review) !== JSON.stringify(PRODUCER_RISK_REVIEW) ||
      !Number.isFinite(now) ||
      now < Date.parse(review.notBefore) ||
      now >= Date.parse(review.expiresAt) ||
      context?.phase !== review.phase ||
      context.version !== review.release ||
      !Object.hasOwn(review.locks, context.scope) ||
      context.lockSha256 !== review.locks[context.scope] ||
      !Buffer.isBuffer(context.lockBytes) ||
      sha256(context.lockBytes) !== review.locks[context.scope]) return null;
  const lock = JSON.parse(context.lockBytes);
  const chain = context.scope === 'producer-root' ? { 'smol-toml': '1.8.0' } : {
    braces: '3.0.3', chokidar: '3.6.0', micromatch: '4.0.8', 'fast-glob': '3.3.3', tailwindcss: '3.4.19',
    'postcss-nested': '6.2.0', 'postcss-selector-parser': '6.1.4', 'source-map-js': '1.2.1',
  };
  requireCondition(lock.lockfileVersion === 3 && lock.packages[''].version === review.release,
    'producer-risk-lock-schema');
  for (const [name, version] of Object.entries(chain)) {
    const entry = lock.packages[`node_modules/${name}`];
    requireCondition(entry?.version === version && !entry.link &&
      (context.scope === 'producer-ui' ? entry.dev === true : entry.dev !== true),
    'producer-risk-not-exact-chain');
  }
  return { disposition: 'RISK-ACCEPTED', ...review,
    reviewRecordSha256: sha256(JSON.stringify(review)), advisoryFree: false };
}

export function classifyNativeAudit(output, execution = { exitCode: 0 }) {
  requireCondition([0, 1].includes(execution.exitCode) &&
    !execution.error && !execution.signal && !execution.timedOut &&
    !execution.truncated && !execution.incomplete, 'native-audit-execution-failed');
  const report = JSON.parse(output);
  requireCondition(report?.auditReportVersion === 2 && report.vulnerabilities &&
    typeof report.vulnerabilities === 'object' && !Array.isArray(report.vulnerabilities) &&
    report.metadata?.vulnerabilities && !report.error, 'native-audit-schema');
  const counts = report.metadata.vulnerabilities;
  for (const level of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
    requireCondition(Number.isSafeInteger(counts[level]) && counts[level] >= 0, `Producer advisories: ${level}`);
  }
  const findings = Object.keys(report.vulnerabilities);
  requireCondition(counts.total === findings.length &&
    ['info', 'low', 'moderate', 'high', 'critical'].reduce((sum, key) => sum + counts[key], 0) === counts.total,
  'Producer advisories: inconsistent native-audit-counts');
  requireCondition(findings.length === 0, 'Producer advisory findings remain unresolved');
  requireCondition(execution.exitCode === 0 && counts.total === 0, 'native-audit-clean-exit-mismatch');
  return { disposition: 'advisory-free', rawExitCode: 0, rawCounts: counts, rawFindingCount: 0 };
}

function coordinate(name, version) {
  requireCondition(typeof name === 'string' && name.length <= 214 && NAME.test(name) &&
    typeof version === 'string' && version.length <= 128 && VERSION.test(version), 'invalid-public-coordinate');
  return { name, version };
}

function localArtifactBinding(artifact) {
  requireCondition(artifact && typeof artifact.sha256 === 'string' && /^[a-f0-9]{64}$/.test(artifact.sha256) &&
    typeof artifact.integrity === 'string' && /^sha512-[A-Za-z0-9+/]{86}==$/.test(artifact.integrity),
  'local-artifact-binding-required');
  const item = coordinate(artifact.name, artifact.version);
  const digest = Buffer.from(artifact.integrity.slice(7), 'base64');
  requireCondition(digest.length === 64 && `sha512-${digest.toString('base64')}` === artifact.integrity,
    'local-artifact-integrity-schema');
  return { ...item, sha256: artifact.sha256, integrity: artifact.integrity,
    status: 'validated-local-artifact', advisoryQuery: 'excluded' };
}

function requireLocalEntry(item, integrity, artifact) {
  requireCondition(item.version === artifact.version, 'local-artifact-version-mismatch');
  requireCondition(typeof integrity === 'string' && integrity === artifact.integrity,
    'local-artifact-integrity-mismatch');
}

export function lockedCoordinates(lock, { publicPackages, localArtifact } = {}) {
  requireCondition((lock?.lockfileVersion === 2 || lock?.lockfileVersion === 3) &&
    lock.packages && typeof lock.packages === 'object' && !Array.isArray(lock.packages),
  'unsupported-lock-schema');
  requireCondition(Array.isArray(publicPackages) &&
    publicPackages.every(name => typeof name === 'string' && NAME.test(name)), 'public-package-approval-required');
  const candidate = localArtifact === undefined ? undefined : localArtifactBinding(localArtifact);
  const approved = new Set(publicPackages);
  const packages = new Map();
  let candidatePresent = false;
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '') continue;
    requireCondition(entry && typeof entry === 'object' && !entry.link, 'unsupported-linked-dependency');
    const pathName = path.split('node_modules/').at(-1);
    requireCondition(path.includes('node_modules/') && NAME.test(pathName), 'unsupported-lock-entry');
    const item = coordinate(entry.name ?? pathName, entry.version);
    let publicUrl;
    try { publicUrl = new URL(entry.resolved); } catch { /* checked below without exposing value */ }
    if (candidate &&
        item.name === candidate.name) {
      requireLocalEntry(item, entry.integrity, candidate);
      requireCondition(publicUrl?.protocol === 'file:', 'non-local-artifact-resolution');
      candidatePresent = true;
      continue;
    }
    requireCondition(approved.has(item.name), 'dependency-not-approved-for-public-query');
    const registryResolved = publicUrl?.protocol === 'https:' &&
      publicUrl.hostname === 'registry.npmjs.org' &&
      publicUrl.port === '' && publicUrl.username === '' && publicUrl.password === '' &&
      publicUrl.search === '' && publicUrl.hash === '';
    requireCondition(registryResolved, 'non-public-or-unbound-dependency');
    packages.set(`${item.name}@${item.version}`, item);
  }
  requireCondition(!candidate || candidatePresent, 'consumer-candidate-dependency-missing');
  requireCondition(packages.size > 0 || candidatePresent, 'empty-dependency-graph');
  return [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

export function consumerCoordinates(consumer, { publicPackages, localArtifact } = {}) {
  requireCondition(Array.isArray(publicPackages) &&
    publicPackages.every(name => typeof name === 'string' && NAME.test(name)), 'public-package-approval-required');
  localArtifactBinding(localArtifact);
  requireCondition(consumer && consumer.name === localArtifact.name && consumer.version === localArtifact.version &&
    consumer.sha256 === localArtifact.sha256 && consumer.producerLockCopied === false &&
    consumer.installedBin === true && consumer.bridgeAndUi === true, 'consumer-summary-binding-or-coverage');
  requireCondition(typeof consumer.node === 'string' && VERSION.test(consumer.node.replace(/^v/, '')) &&
    typeof consumer.npm === 'string' && VERSION.test(consumer.npm) &&
    ['linux', 'win32', 'darwin'].includes(consumer.platform) &&
    ['npm-default', 'disabled'].includes(consumer.installScripts), 'consumer-summary-lane-schema');
  requireCondition(Array.isArray(consumer.dependencies) && consumer.dependencies.length > 0 &&
    consumer.dependencies.length <= 200_000, 'consumer-summary-dependencies-required');
  const approved = new Set(publicPackages);
  const packages = new Map();
  const integrities = new Map();
  let candidatePresent = false;
  for (const dependency of consumer.dependencies) {
    requireCondition(dependency && typeof dependency === 'object', 'consumer-dependency-schema');
    const item = coordinate(dependency.name, dependency.version);
    if (item.name === localArtifact.name) {
      requireLocalEntry(item, dependency.integrity, localArtifact);
      candidatePresent = true;
      continue;
    }
    requireCondition(approved.has(item.name), 'dependency-not-approved-for-public-query');
    requireCondition(dependency.integrity === null ||
      (typeof dependency.integrity === 'string' &&
        /^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(dependency.integrity)),
    'consumer-dependency-integrity-schema');
    if (dependency.integrity !== null) {
      const [algorithm, encoded] = dependency.integrity.split('-');
      const bytes = Buffer.from(encoded, 'base64');
      requireCondition(bytes.length === { sha1: 20, sha256: 32, sha384: 48, sha512: 64 }[algorithm] &&
        bytes.toString('base64') === encoded, 'consumer-dependency-integrity-schema');
    }
    const key = `${item.name}@${item.version}`;
    requireCondition(!integrities.has(key) || integrities.get(key) === dependency.integrity,
      'consumer-dependency-integrity-conflict');
    integrities.set(key, dependency.integrity);
    packages.set(key, item);
  }
  requireCondition(candidatePresent, 'consumer-candidate-dependency-missing');
  return [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

async function responseJson(response) {
  requireCondition(response?.ok === true && response.status === 200 &&
    /^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? ''),
  'osv-http-or-content-type-error');
  const reader = response.body?.getReader();
  requireCondition(Boolean(reader), 'osv-response-body-missing');
  const parts = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      requireCondition(size <= RESPONSE_LIMIT, 'osv-response-limit');
      parts.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel();
  }
  try {
    const bytes = Buffer.concat(parts);
    return { value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
      rawResponseSha256: sha256(bytes), responseBytes: bytes.length };
  } catch {
    throw new Error('invalid OSV JSON');
  }
}

export function validateBatch(value, count) {
  requireCondition(value && Object.keys(value).every(key => key === 'results') &&
    Array.isArray(value.results) && value.results.length === count, 'osv-batch-schema');
  return value.results.map(result => {
    requireCondition(result && typeof result === 'object' && !Array.isArray(result) &&
      Object.keys(result).every(key => ['vulns', 'next_page_token'].includes(key)), 'osv-result-schema');
    requireCondition(result.next_page_token === undefined || result.next_page_token === '',
      'osv-pagination-incomplete');
    const vulns = result.vulns === undefined ? [] : result.vulns;
    requireCondition(Array.isArray(vulns), 'osv-advisory-schema');
    return vulns.map(vulnerability => {
      requireCondition(vulnerability && typeof vulnerability.id === 'string' && ADVISORY.test(vulnerability.id) &&
        typeof vulnerability.modified === 'string' && Number.isFinite(Date.parse(vulnerability.modified)) &&
        Object.keys(vulnerability).every(key => ['id', 'modified'].includes(key)), 'osv-advisory-schema');
      return { id: vulnerability.id, modified: vulnerability.modified };
    });
  });
}

function reviewedExemptions(value, now) {
  requireCondition(value?.schemaVersion === 1 && Array.isArray(value.exemptions), 'exemption-schema');
  return value.exemptions.map(item => {
    const result = coordinate(item.package, item.version);
    requireCondition(typeof item.id === 'string' && ADVISORY.test(item.id) && typeof item.reviewedBy === 'string' &&
      item.reviewedBy.trim().length > 0 && typeof item.reason === 'string' &&
      item.reason.trim().length > 0 && Number.isFinite(Date.parse(item.expiresAt)) &&
      Date.parse(item.expiresAt) > now, 'invalid-or-expired-reviewed-exemption');
    return `${item.id}\0${result.name}\0${result.version}`;
  });
}

export async function scanAdvisories({
  locks, consumers, publicPackages, publicPackagesPath, exemptionsPath, localArtifact, producerContext,
  fetchImpl = globalThis.fetch,
}) {
  return guarded('dependency-advisories', async () => {
    const contextBefore = JSON.stringify(producerContext);
    const hasConsumers = consumers !== undefined;
    if (hasConsumers) {
      requireCondition(locks === undefined && Array.isArray(consumers) && consumers.length > 0 &&
        consumers.length <= 24, 'exclusive-consumer-summary-input-required');
    } else {
      requireCondition(Array.isArray(locks) && locks.length > 0 &&
        locks.every(lock => SCOPES.has(lock.scope)), 'explicit-lock-scopes-required');
      const scopes = locks.map(lock => lock.scope);
      requireCondition(new Set(scopes).size === scopes.length, 'duplicate-lock-scope');
      const hasProducer = scopes.some(scope => scope.startsWith('producer-'));
      requireCondition(!hasProducer || (scopes.includes('producer-root') && scopes.includes('producer-ui')),
        'both-producer-locks-required');
    }
    let publicApprovalSha256;
    if (publicPackagesPath) {
      const input = await readJson(publicPackagesPath);
      requireCondition(input.value.schemaVersion === 1, 'public-package-approval-schema');
      publicPackages = input.value.packages;
      publicApprovalSha256 = input.sha256;
    } else {
      publicApprovalSha256 = sha256(JSON.stringify(publicPackages ?? null));
    }
    const graphs = [];
    const unique = new Map();
    for (const lock of locks ?? []) {
      const input = await readJson(lock.path);
      const candidate = lock.scope === 'fresh-consumer' ? localArtifact : undefined;
      const packages = lockedCoordinates(input.value, {
        publicPackages, localArtifact: candidate,
      });
      graphs.push({ scope: lock.scope, lockSha256: input.sha256,
        graphSha256: sha256(JSON.stringify(packages)), packages: packages.length,
        ...(candidate ? { localArtifact: localArtifactBinding(candidate) } : {}) });
      for (const item of packages) unique.set(`${item.name}@${item.version}`, item);
    }
    const lanes = new Set();
    for (const consumer of consumers ?? []) {
      const packages = consumerCoordinates(consumer, { publicPackages, localArtifact });
      const lane = { node: consumer.node, npm: consumer.npm,
        platform: consumer.platform, installScripts: consumer.installScripts };
      const key = JSON.stringify(lane);
      requireCondition(!lanes.has(key), 'duplicate-consumer-summary-lane');
      lanes.add(key);
      graphs.push({ scope: 'fresh-consumer', source: 'resolved-consumer-summary', lane,
        consumerSummarySha256: sha256(JSON.stringify(consumer)),
        graphSha256: sha256(JSON.stringify(packages)), packages: packages.length,
        localArtifact: localArtifactBinding(localArtifact) });
      for (const item of packages) unique.set(`${item.name}@${item.version}`, item);
    }
    const now = Date.now();
    let exemptionSha256;
    let exemptions = new Set();
    if (exemptionsPath) {
      const input = await readJson(exemptionsPath);
      exemptions = new Set(reviewedExemptions(input.value, now));
      exemptionSha256 = input.sha256;
    }
    const packages = [...unique.values()];
    const findings = [];
    const evidence = [];
    // Cache/deduplication is deliberately scoped to this invocation; every new run queries OSV again.
    for (let offset = 0; offset < packages.length; offset += BATCH_SIZE) {
      const batch = packages.slice(offset, offset + BATCH_SIZE);
      const body = JSON.stringify({ queries: batch.map(item => ({
        package: { ecosystem: 'npm', name: item.name }, version: item.version,
      })) });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30_000);
      let captured;
      try {
        const response = await fetchImpl(ENDPOINT, {
          method: 'POST', body, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          credentials: 'omit', redirect: 'error', signal: controller.signal,
        });
        captured = await responseJson(response);
      } finally {
        clearTimeout(timer);
      }
      const { value, rawResponseSha256, responseBytes } = captured;
      const results = validateBatch(value, batch.length);
      evidence.push({ querySha256: sha256(body), responseSha256: sha256(JSON.stringify(value)),
        rawResponseSha256, responseBytes, queries: batch.length });
      for (let index = 0; index < batch.length; index++) {
        for (const vulnerability of results[index]) {
          const item = batch[index];
          const exempted = exemptions.has(`${vulnerability.id}\0${item.name}\0${item.version}`);
          findings.push({ ...item, ...vulnerability, status: exempted ? 'reviewed-exemption' : 'blocked' });
        }
      }
    }
    for (const lock of locks ?? []) {
      const original = graphs.find(graph => graph.scope === lock.scope);
      requireCondition((await readJson(lock.path)).sha256 === original.lockSha256, 'advisory-lock-changed');
    }
    requireCondition(JSON.stringify(producerContext) === contextBefore, 'advisory-release-context-changed');
    return { status: findings.some(item => item.status === 'blocked') ? 'findings' : 'passed',
      datasource: ENDPOINT, cache: 'this-run-only',
      ...(packages.length > 0 ? { queriedAt: new Date(now).toISOString() }
        : { noQueryReason: 'only-validated-local-artifact' }),
      scope: graphs, distinctCoordinates: packages.length, publicApprovalSha256,
      coordinateScope: 'external-dependencies-only; exact bound local artifact validated separately',
      ...(exemptionSha256 ? { exemptionSha256 } : {}), findings, evidence,
      rawFindingCount: findings.length,
      remainingFindings: findings.filter(item => item.status === 'blocked').length,
      limits: hasConsumers
        ? 'Exact resolved graph summaries supplied by the trusted consumer runner; no lock reconstructed. ' +
          'Summary authenticity, restore provenance and registry signatures are not independently certified.'
        : 'Exact supplied lock versions only; producer locks do not prove fresh consumer resolution.' };
  });
}
