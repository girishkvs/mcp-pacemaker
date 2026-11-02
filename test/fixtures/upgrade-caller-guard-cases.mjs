import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { THREAD_CHURN } from './thread-churn-reasons.mjs';

for (const mode of ['ordinary', 'model-elevated', 'model-unknown']) {
  test(`Windows upgrade entry guard ${mode} before any mutation or launch`, { skip: process.platform !== 'win32' }, () => {
    const output = execFileSync(process.execPath, [
      fileURLToPath(new URL('./upgrade-caller-guard-host.mjs', import.meta.url)), mode,
    ], { encoding: 'utf8', windowsHide: true, timeout: 30000 });
    const result = JSON.parse(output);
    assert.equal(result.results.length, 4);
    assert.equal(result.counters.writes, 0);
    assert.equal(result.counters.runtimeLaunches, 0);
    assert.equal(result.actualContext.ordinaryEligible, true);
  });
}

// A caller whose thread starts or exits during the native observation gets a new, equally strict
// observation. A change that persists is still refused, and any other refusal is final.
function observeVariant(variant) {
  const output = execFileSync(process.execPath, [
    fileURLToPath(new URL('./upgrade-caller-churn-host.mjs', import.meta.url)), variant,
  ], { encoding: 'utf8', windowsHide: true, timeout: 300000 });
  const result = JSON.parse(output);
  const reasons = result.observations.map(observation => observation.reason);
  const detail = JSON.stringify({ reasons, failure: result.failure, warmup: result.warmup, removed: result.removed });
  assert.ok(reasons.length <= 5, detail);
  for (const reason of reasons.slice(0, -1)) assert.ok(THREAD_CHURN.includes(reason), detail);
  return { ...result, reasons, detail };
}

test('Windows upgrade entry guard observes again after a caller thread ends', { skip: process.platform !== 'win32' }, () => {
  const result = observeVariant('end-after-snapshot');
  assert.equal(result.accepted, true, result.detail);
  assert.ok(result.reasons.length >= 2, result.detail);
  assert.equal(result.observations.at(-1).ordinaryEligible, true, result.detail);
});

test('Windows upgrade entry guard refuses thread churn that persists', { skip: process.platform !== 'win32' }, () => {
  const result = observeVariant('churn');
  assert.equal(result.accepted, false, result.detail);
  assert.equal(result.reasons.length, 5, result.detail);
  assert.ok(THREAD_CHURN.includes(result.reasons[4]), result.detail);
  assert.ok(result.failure.endsWith(`Observed: ${result.reasons[4]} after 5 observations.`), result.detail);
});

test('Windows upgrade entry guard refuses an impersonating caller without observing again', { skip: process.platform !== 'win32' }, () => {
  const result = observeVariant('token');
  assert.equal(result.accepted, false, result.detail);
  assert.equal(result.reasons.at(-1), 'THREAD_TOKEN_OBSERVED', result.detail);
  assert.ok(result.failure.endsWith('Observed: THREAD_TOKEN_OBSERVED.'), result.detail);
});

test('Windows upgrade entry guard observes again for thread churn reasons only', { skip: process.platform !== 'win32' }, () => {
  // These end the check at once, including the two left off the churn list on purpose.
  const final = ['THREAD_TOKEN_OBSERVED', 'THREAD_SNAPSHOT_COUNT_CHANGED', 'CONTEXT_QUERY_FAILED_5',
    'PRIMARY_CONTEXT_PRIVILEGED', 'THREAD_SNAPSHOT_INCOMPLETE'];
  const output = execFileSync(process.execPath, [
    fileURLToPath(new URL('./upgrade-caller-reason-host.mjs', import.meta.url)), ...THREAD_CHURN, ...final,
  ], { encoding: 'utf8', windowsHide: true, timeout: 30000 });
  const results = JSON.parse(output);
  assert.equal(results.length, THREAD_CHURN.length + final.length);
  for (const result of results) {
    const churn = THREAD_CHURN.includes(result.reason);
    assert.equal(result.observations, churn ? 5 : 1, result.reason);
    assert.ok((result.failure ?? '').endsWith(`Observed: ${result.reason}${churn ? ' after 5 observations' : ''}.`),
      `${result.reason}: ${result.failure}`);
  }
});
