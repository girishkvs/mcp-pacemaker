import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AUDIT_DIAGNOSTIC, AUDIT_MODE, AUDIT_MODE_VARIABLE, AUDIT_TEST_NAME, AUDIT_WORKER_TIMEOUT_MS,
  auditEnvironment, auditEvidence,
} from '../../tools/npm-publication/local-audit-report.mjs';

// Synthetic parser fixtures; no Windows process, policy change or audit operation runs here.
export function syntheticAuditReport(node = 'v24.21.0') {
  return {
    normal: { medium: true, securityPrivilegeAbsent: true, nodeVersion: node, cases: 19 },
    audit: { sourceExplicit: 1, sourceInherited: 1, candidateExplicit: 0, candidateInherited: 1, previousExact: true },
    securityVerified: true,
    worker: { mode: AUDIT_MODE, budgetMilliseconds: AUDIT_WORKER_TIMEOUT_MS, elapsedMilliseconds: 40000, cleanupVerified: true },
  };
}

export function syntheticAuditTap(node = 'v24.21.0') {
  return `ok 1 - ${AUDIT_TEST_NAME}\n# ${AUDIT_DIAGNOSTIC}${JSON.stringify(syntheticAuditReport(node))}\n`;
}

test('local audit environment is explicit for the current lane and never inherited', () => {
  const environment = { PATH: 'owned-system-tools' };
  assert.deepEqual(auditEnvironment(environment, '2.0.1'), { ...environment, [AUDIT_MODE_VARIABLE]: AUDIT_MODE });
  assert.equal(auditEnvironment(environment, '1.3.1'), environment);
  assert.deepEqual(environment, { PATH: 'owned-system-tools' });
  for (const mode of [AUDIT_MODE, '', 'explorer']) {
    assert.throws(() => auditEnvironment({ ...environment, [AUDIT_MODE_VARIABLE]: mode }, '2.0.1'));
  }
  assert.throws(() => auditEnvironment(environment, 'unsupported'));
});

test('local audit admission requires one exact non-skipped report for the selected runtime', () => {
  for (const node of ['v20.20.2', 'v22.23.2', 'v24.21.0']) {
    for (const newline of ['\n', '\r\n']) {
      const stdout = syntheticAuditTap(node).replaceAll('\n', newline);
      assert.deepEqual(auditEvidence(stdout, '2.0.1', node), syntheticAuditReport(node));
    }
  }
  assert.equal(auditEvidence('', '1.3.1', 'v24.21.0'), null);
});

for (const [name, mutate] of [
  ['missing report', () => `ok 1 - ${AUDIT_TEST_NAME}\n`],
  ['duplicate report', stdout => stdout + stdout.split('\n')[1] + '\n'],
  ['missing test', stdout => stdout.split('\n').slice(1).join('\n')],
  ['duplicate test', stdout => `ok 2 - ${AUDIT_TEST_NAME}\n${stdout}`],
  ['failed test', stdout => stdout.replace('ok 1 - ', 'not ok 1 - ')],
  ['skipped test', stdout => stdout.replace(AUDIT_TEST_NAME, `${AUDIT_TEST_NAME} # SKIP unavailable`)],
  ['unknown test', stdout => stdout.replace(AUDIT_TEST_NAME, 'a different test')],
  ['invalid ordinal', stdout => stdout.replace('ok 1 - ', 'ok not-a-number - ')],
  ['leading-zero ordinal', stdout => stdout.replace('ok 1 - ', 'ok 01 - ')],
  ['invalid JSON', stdout => stdout.replace('{"normal"', '{invalid:"normal"')],
  ['oversized report', stdout => stdout.replace('{"normal"', `${' '.repeat(4096)}{"normal"`)],
]) {
  test(`local audit admission rejects ${name}`, () => {
    assert.throws(() => auditEvidence(mutate(syntheticAuditTap()), '2.0.1', 'v24.21.0'));
  });
}

for (const [name, mutate] of [
  ['other runtime', report => { report.normal.nodeVersion = 'v20.20.2'; }],
  ['missing case', report => { report.normal.cases = 18; }],
  ['extra case', report => { report.normal.cases = 20; }],
  ['elevated worker', report => { report.normal.medium = false; }],
  ['security privilege', report => { report.normal.securityPrivilegeAbsent = false; }],
  ['unverified policy', report => { report.securityVerified = false; }],
  ['changed original', report => { report.audit.previousExact = false; }],
  ['cloned explicit audits', report => { report.audit.candidateExplicit = 1; }],
  ['missing inherited audit', report => { report.audit.candidateInherited = 0; }],
  ['other mode', report => { report.worker.mode = 'explorer'; }],
  ['unverified cleanup', report => { report.worker.cleanupVerified = false; }],
  ['unexpected budget', report => { report.worker.budgetMilliseconds = 20000; }],
  ['missing duration', report => { delete report.worker.elapsedMilliseconds; }],
  ['zero duration', report => { report.worker.elapsedMilliseconds = 0; }],
  ['late completion', report => { report.worker.elapsedMilliseconds = AUDIT_WORKER_TIMEOUT_MS + 1; }],
  ['unavailable', report => { report.unavailable = 'capability'; }],
]) {
  test(`local audit admission rejects ${name}`, () => {
    const report = syntheticAuditReport();
    mutate(report);
    const stdout = `ok 1 - ${AUDIT_TEST_NAME}\n# ${AUDIT_DIAGNOSTIC}${JSON.stringify(report)}\n`;
    assert.throws(() => auditEvidence(stdout, '2.0.1', 'v24.21.0'));
  });
}
