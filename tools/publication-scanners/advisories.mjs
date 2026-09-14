import { guarded, readJson, requireCondition, sha256 } from './core.mjs';

const ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 100;
const RESPONSE_LIMIT = 8 * 1024 * 1024;
const SCOPES = new Set(['producer-root', 'producer-ui', 'fresh-consumer']);
const NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ADVISORY = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/;

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
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
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
  locks, consumers, publicPackages, publicPackagesPath, exemptionsPath, localArtifact, fetchImpl = globalThis.fetch,
}) {
  return guarded('dependency-advisories', async () => {
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
      let value;
      try {
        const response = await fetchImpl(ENDPOINT, {
          method: 'POST', body, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          credentials: 'omit', redirect: 'error', signal: controller.signal,
        });
        value = await responseJson(response);
      } finally {
        clearTimeout(timer);
      }
      const results = validateBatch(value, batch.length);
      evidence.push({ querySha256: sha256(body), responseSha256: sha256(JSON.stringify(value)), queries: batch.length });
      for (let index = 0; index < batch.length; index++) {
        for (const vulnerability of results[index]) {
          const item = batch[index];
          const exempted = exemptions.has(`${vulnerability.id}\0${item.name}\0${item.version}`);
          findings.push({ ...item, ...vulnerability, status: exempted ? 'reviewed-exemption' : 'blocked' });
        }
      }
    }
    return { status: findings.some(item => item.status === 'blocked') ? 'findings' : 'passed',
      datasource: ENDPOINT, cache: 'this-run-only',
      ...(packages.length > 0 ? { queriedAt: new Date(now).toISOString() }
        : { noQueryReason: 'only-validated-local-artifact' }),
      scope: graphs, distinctCoordinates: packages.length, publicApprovalSha256,
      coordinateScope: 'external-dependencies-only; exact bound local artifact validated separately',
      ...(exemptionSha256 ? { exemptionSha256 } : {}), findings, evidence,
      limits: hasConsumers
        ? 'Exact resolved graph summaries supplied by the trusted consumer runner; no lock reconstructed. ' +
          'Summary authenticity, restore provenance and registry signatures are not independently certified.'
        : 'Exact supplied lock versions only; producer locks do not prove fresh consumer resolution.' };
  });
}
