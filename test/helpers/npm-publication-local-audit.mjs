import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AUDIT_DIAGNOSTIC, AUDIT_MODE, AUDIT_MODE_VARIABLE, AUDIT_TEST_NAME, AUDIT_WORKER_TIMEOUT_MS,
  auditArguments, auditEnvironment, auditEvidence, validateOrdinarySourceContext,
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
  assert.deepEqual(auditArguments(), ['--test', '--test-reporter=tap', '--test-name-pattern',
    `^${AUDIT_TEST_NAME}$`, 'test/windows-batch-security.test.mjs']);
  const environment = { PATH: 'owned-system-tools' };
  assert.deepEqual(auditEnvironment(environment, '2.0.1'), { ...environment, [AUDIT_MODE_VARIABLE]: AUDIT_MODE });
  assert.equal(auditEnvironment(environment, '1.3.1'), environment);
  assert.deepEqual(environment, { PATH: 'owned-system-tools' });
  for (const mode of [AUDIT_MODE, '', 'explorer']) {
    assert.throws(() => auditEnvironment({ ...environment, [AUDIT_MODE_VARIABLE]: mode }, '2.0.1'));
  }
  assert.throws(() => auditEnvironment(environment, 'unsupported'));
});

test('ordinary source proof rejects elevated, unbound, incomplete and impersonating snapshots', () => {
  const identity = { sid: 'S-1-5-21-1-2-3-1000' };
  const context = {
    proofScope: 'cli-effective-context-snapshot', ordinaryEligible: true,
    identity: { pid: 42, ownerSid: identity.sid, sessionId: 1 },
    actorFacts: { ownerSid: identity.sid, sessionId: 1, elevated: false,
      enabledAdministrator: false, guardThreadImpersonating: false, parentThreadImpersonation: 'observed-none' },
    observation: { method: 'pss-threads-held-token-query', processAccess: '0x101400',
      captureFlags: '0x80', threadContextFlags: 0, completeStableThreadSet: true,
      primaryStable: true, atomicFutureProtection: false, threadCount: 4 },
    helperExit: { code: 0, signal: null },
  };
  validateOrdinarySourceContext(context, identity, 42);
  for (const mutate of [
    value => { value.ordinaryEligible = false; },
    value => { value.identity.pid++; },
    value => { value.identity.ownerSid += '-1'; },
    value => { value.actorFacts.ownerSid += '-1'; },
    value => { value.actorFacts.sessionId++; },
    value => { value.actorFacts.elevated = true; },
    value => { value.actorFacts.enabledAdministrator = true; },
    value => { value.actorFacts.guardThreadImpersonating = true; },
    value => { value.actorFacts.parentThreadImpersonation = 'unverified'; },
    value => { value.observation.completeStableThreadSet = false; },
    value => { value.observation.primaryStable = false; },
    value => { value.observation.threadCount = 0; },
    value => { value.observation.threadCount = 129; },
    value => { value.helperExit.code = 1; },
    value => { value.helperExit.signal = 'SIGTERM'; },
  ]) {
    const changed = structuredClone(context);
    mutate(changed);
    assert.throws(() => validateOrdinarySourceContext(changed, identity, 42));
  }
  const missing = structuredClone(context);
  delete missing.identity.pid;
  delete missing.identity.ownerSid;
  delete missing.actorFacts.ownerSid;
  delete missing.identity.sessionId;
  delete missing.actorFacts.sessionId;
  assert.throws(() => validateOrdinarySourceContext(missing, {}, undefined));
  for (const pid of [undefined, null, 0, -1, '42', 0x80000000]) {
    assert.throws(() => validateOrdinarySourceContext({ ...context, identity: { ...context.identity, pid } }, identity, pid));
  }
  for (const sid of [undefined, null, '', 'not-a-sid', 42, `S-1-${'1'.repeat(185)}`,
    `S-1-5${'-1'.repeat(16)}`, 'S-1-281474976710656-1', 'S-1-5-4294967296', 'S-1-05-1', 'S-1-5-01']) {
    const changed = structuredClone(context);
    changed.identity.ownerSid = sid;
    changed.actorFacts.ownerSid = sid;
    assert.throws(() => validateOrdinarySourceContext(changed, { sid }, 42));
  }
  for (const sessionId of [undefined, null, -1, '1', 0x100000000]) {
    const changed = structuredClone(context);
    changed.identity.sessionId = sessionId;
    changed.actorFacts.sessionId = sessionId;
    assert.throws(() => validateOrdinarySourceContext(changed, identity, 42));
  }
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
