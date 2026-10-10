import assert from 'node:assert/strict';
import { releaseRole } from './local-regression.mjs';

export const AUDIT_TEST_NAME = 'TEST-SETUP full audit oracle verifies ordinary-token staging and retained original policy';
export const AUDIT_MODE_VARIABLE = 'MCP_TEST_AUDIT_WORKER';
export const AUDIT_MODE = 'restricted-token';
export const AUDIT_WORKER_TIMEOUT_MS = 120000;
export const AUDIT_PROCESS_TIMEOUT_MS = 150000;
export const AUDIT_COMMAND_TIMEOUT_MS = AUDIT_PROCESS_TIMEOUT_MS + 60000;
export const AUDIT_DIAGNOSTIC = 'MCP_WINDOWS_AUDIT_V1 ';

export function auditArguments() {
  return ['--test', '--test-reporter=tap', '--test-name-pattern', `^${AUDIT_TEST_NAME}$`,
    'test/windows-batch-security.test.mjs'];
}

function validateSid(value) {
  assert.ok(typeof value === 'string' &&
    value.length <= 184, 'Missing or oversized Windows SID');
  const parts = value.split('-');
  assert.ok(parts.length >= 4 &&
    parts.length <= 18 &&
    parts[0] === 'S' &&
    parts[1] === '1', 'Invalid Windows SID structure');
  for (let index = 2; index < parts.length; index++) {
    const part = parts[index];
    const number = Number(part);
    assert.ok(Number.isSafeInteger(number) &&
      number >= 0 &&
      number <= (index === 2 ? 0xffffffffffff : 0xffffffff) &&
      String(number) === part, 'Invalid Windows SID authority');
  }
}

export function validateOrdinarySourceContext(context, identity, pid) {
  assert.ok(Number.isSafeInteger(pid) &&
    pid > 0 &&
    pid <= 0x7fffffff, 'Missing or invalid guest process identity');
  validateSid(identity?.sid);
  assert.equal(context?.proofScope, 'cli-effective-context-snapshot');
  assert.equal(context.ordinaryEligible, true, 'Current-line source tests require an ordinary process');
  for (const facts of [context.identity, context.actorFacts]) {
    validateSid(facts?.ownerSid);
    assert.ok(Number.isSafeInteger(facts.sessionId) &&
      facts.sessionId >= 0 &&
      facts.sessionId <= 0xffffffff, 'Missing or invalid native session identity');
  }
  assert.equal(context.identity.pid, pid);
  assert.equal(context.identity.ownerSid, identity.sid);
  assert.equal(context.actorFacts.ownerSid, identity.sid);
  assert.equal(context.actorFacts.sessionId, context.identity.sessionId);
  for (const key of ['elevated', 'enabledAdministrator', 'guardThreadImpersonating']) {
    assert.equal(context.actorFacts[key], false);
  }
  assert.equal(context.actorFacts.parentThreadImpersonation, 'observed-none');
  assert.equal(context.observation.method, 'pss-threads-held-token-query');
  assert.equal(context.observation.processAccess, '0x101400');
  assert.equal(context.observation.captureFlags, '0x80');
  assert.equal(context.observation.threadContextFlags, 0);
  assert.equal(context.observation.completeStableThreadSet, true);
  assert.equal(context.observation.primaryStable, true);
  assert.equal(context.observation.atomicFutureProtection, false);
  assert.ok(Number.isInteger(context.observation.threadCount) &&
    context.observation.threadCount > 0 &&
    context.observation.threadCount <= 128);
  assert.equal(context.helperExit.code, 0);
  assert.equal(context.helperExit.signal, null);
}

export function auditEnvironment(environment, version) {
  releaseRole(version);
  assert.equal(environment[AUDIT_MODE_VARIABLE], undefined, 'Audit mode must not be inherited');
  return releaseRole(version) === 'current' ? { ...environment, [AUDIT_MODE_VARIABLE]: AUDIT_MODE } : environment;
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
  if (releaseRole(version) === 'legacy') return null;
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
