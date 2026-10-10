import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LegacyUpgradeFixture } from './helpers/legacy-upgrade-fixture.mjs';
import { prepareLegacyProcesses } from '../bin/windows-legacy-process.mjs';

test('original-user rollback launcher starts exact retained supervisor without task.Run or admin spawn', {
  skip: process.platform !== 'win32', timeout: 90000,
}, async () => {
  const fixture = new LegacyUpgradeFixture({ taskOwner: 'builtin-administrators' });
  try {
    await fixture.start();
    const held = await prepareLegacyProcesses({ root: fixture.root, port: fixture.port });
    try { assert.equal((await held.stop()).legacyRootStopVerified, true); }
    finally { await held.close(); }
    const destination = join(fixture.directory, 'rollback');
    mkdirSync(destination);
    const image = fixture.initialProcesses.roots.supervisor;
    const input = join(fixture.directory, 'probe.json');
    writeFileSync(input, JSON.stringify({
      binding: {
        root: fixture.root, config: fixture.config, port: fixture.port, destination,
        legacySupervisorImage: { path: image.imagePath, sha256: image.imageSha256 },
      },
      original: fixture.originalTask,
    }));
    const code = await fixture.launchWorker([
      fileURLToPath(new URL('./fixtures/account-rollback-probe.mjs', import.meta.url)), input,
    ], fixture.env());
    const exit = join(destination, 'rollback-launch-exit.json');
    assert.equal(code, 0, readFileSync(join(destination, 'rollback-launcher.log'), 'utf8') +
      (existsSync(exit) ? readFileSync(exit, 'utf8') : '\nNo child exit observed.') + '\n' + fixture.log);
  } finally { await fixture.cleanup(); }
});
