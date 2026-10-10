import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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
