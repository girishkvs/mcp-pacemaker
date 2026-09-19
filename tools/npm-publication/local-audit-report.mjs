import assert from 'node:assert/strict';

export const AUDIT_TEST_NAME = 'TEST-SETUP full audit oracle verifies ordinary-token staging and retained original policy';
export const AUDIT_MODE_VARIABLE = 'MCP_TEST_AUDIT_WORKER';
export const AUDIT_MODE = 'restricted-token';
export const AUDIT_WORKER_TIMEOUT_MS = 120000;
export const AUDIT_PROCESS_TIMEOUT_MS = 150000;
export const AUDIT_DIAGNOSTIC = 'MCP_WINDOWS_AUDIT_V1 ';

export function auditEnvironment(environment, version) {
  assert.ok(['1.3.1', '2.0.1'].includes(version));
  assert.equal(environment[AUDIT_MODE_VARIABLE], undefined, 'Audit mode must not be inherited');
  return version === '2.0.1' ? { ...environment, [AUDIT_MODE_VARIABLE]: AUDIT_MODE } : environment;
}

export function auditReport(report, node) {
  assert.deepEqual(Object.keys(report).sort(), ['audit', 'normal', 'securityVerified', 'worker']);
  assert.deepEqual(report.normal, {
    medium: true, securityPrivilegeAbsent: true, nodeVersion: node, cases: 19,
  });
  assert.deepEqual(report.audit, {
    sourceExplicit: 1, sourceInherited: 1, candidateExplicit: 0, candidateInherited: 1, previousExact: true,
  });
  assert.equal(report.securityVerified, true);
  assert.deepEqual(Object.keys(report.worker).sort(), ['budgetMilliseconds', 'cleanupVerified', 'elapsedMilliseconds', 'mode']);
  assert.equal(report.worker.cleanupVerified, true);
  assert.equal(report.worker.mode, AUDIT_MODE);
  assert.equal(report.worker.budgetMilliseconds, AUDIT_WORKER_TIMEOUT_MS);
  assert.ok(Number.isSafeInteger(report.worker.elapsedMilliseconds) &&
    report.worker.elapsedMilliseconds > 0 &&
    report.worker.elapsedMilliseconds <= AUDIT_WORKER_TIMEOUT_MS);
  return report;
}

export function auditEvidence(stdout, version, node) {
  assert.ok(['1.3.1', '2.0.1'].includes(version));
  if (version === '1.3.1') return null;
  assert.equal(typeof stdout, 'string');
  const lines = stdout.split('\n').map(line => line.endsWith('\r') ? line.slice(0, -1) : line);
  const prefix = `# ${AUDIT_DIAGNOSTIC}`;
  const diagnostics = lines.filter(line => line.startsWith(prefix));
  assert.equal(diagnostics.length, 1, 'Exactly one non-skipped Windows audit report is required');
  const marker = ` - ${AUDIT_TEST_NAME}`;
  const outcomes = lines.filter(line => (line.startsWith('ok ') ||
    line.startsWith('not ok ')) &&
    line.includes(marker));
  assert.equal(outcomes.length, 1, 'The full Windows audit test must pass without a skip');
  assert.ok(outcomes[0].startsWith('ok ') &&
    outcomes[0].endsWith(marker), 'The full Windows audit test must pass without a skip');
  const ordinal = outcomes[0].slice(3, -marker.length);
  assert.ok(Number.isSafeInteger(Number(ordinal)) &&
    Number(ordinal) > 0 &&
    String(Number(ordinal)) === ordinal, 'Invalid audit test ordinal');
  const body = diagnostics[0].slice(prefix.length);
  assert.ok(body.length > 0 &&
    body.length < 4096, 'Invalid audit report size');
  return auditReport(JSON.parse(body), node);
}
