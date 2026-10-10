import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { LegacyUpgradeFixture } from './legacy-upgrade-fixture.mjs';

export class LegacyFailureFixture {
  async run({ sourceRoot, expectedRed = false } = {}) {
    const fixture = new LegacyUpgradeFixture();
    const results = [];
    try {
      await fixture.start();
      const root = fixture.initialProcesses.roots.bridge;
      const cases = [
        ['deny-query-open', 'OpenProcessQuery', 'CaptureOpenQuery', false, null],
        ['deny-token-owner', 'OpenProcessToken', 'CaptureOwner', true, null],
        ['deny-terminate-open', 'OpenProcessTerminate', 'CaptureOpenTerminate', true, true],
        ['deny-image', 'QueryFullProcessImageName', 'CaptureImage', true, true],
      ];
      for (const [variant, api, substage, known, ownerMatched] of cases) {
        const directory = join(fixture.directory, variant);
        mkdirSync(directory);
        const builder = fileURLToPath(new URL('../fixtures/windows-legacy/build-variant.ps1', import.meta.url));
        const args = ['-NoProfile', '-NonInteractive', '-File', builder, '-OutputDirectory', directory, '-Variant', variant];
        if (sourceRoot) args.push('-SourceRoot', sourceRoot);
        const build = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 30000 });
        assert.equal(build.status, 0, build.stderr);
        const module = await import(pathToFileURL(join(directory, 'windows-legacy-process.mjs')).href);
        const metadata = JSON.parse(readFileSync(join(directory, 'windows-legacy/LegacyProcessBroker.build.json')));
        let failure;
        await assert.rejects(module.prepareLegacyProcesses({ port: fixture.port, root: fixture.root }), error => {
          assert.equal(error.code, 'LEGACY_PROCESS_REFUSED');
          failure = error.detail;
          results.push({ variant, variantSha256: metadata.binarySha256, failure });
          assert.equal(failure.ok, false);
          assert.equal(failure.stage, 'capture-roots');
          assert.equal(failure.type, 'Win32Exception');
          assert.equal(failure.nativeError, 5);
          assert.equal(failure.reason, null);
          assert.equal(failure.mutationStarted, false);
          assert.equal(failure.treeCompleteness, 'unproven');
          if (expectedRed) {
            assert.equal(failure.captureFailure, null);
          } else {
            const details = failure.captureFailure;
            assert.deepEqual(Object.keys(details).sort(), [
              'actualParentPid', 'alive', 'api', 'creationTime', 'expectedParentCreationTime',
              'expectedParentPid', 'generationKnown', 'observation', 'ownerMatched', 'parentAlive',
              'requestedPid', 'substage',
            ].sort());
            assert.equal(details.api, api);
            assert.equal(details.substage, substage);
            assert.equal(details.requestedPid, root.pid);
            assert.equal(details.generationKnown, known);
            assert.equal(details.creationTime, known ? root.creationTime : null);
            assert.equal(details.actualParentPid, known ? root.parentPid : null);
            assert.equal(details.alive, known ? true : null);
            assert.equal(details.ownerMatched, ownerMatched);
            assert.equal(details.parentAlive, null);
            assert.equal(details.expectedParentPid, null);
            assert.equal(details.expectedParentCreationTime, null);
            assert.equal(details.observation, 'stored-observations-not-fresh-proof');
            const serialized = JSON.stringify(details);
            assert.ok(Buffer.byteLength(serialized, 'utf8') < 1024);
            assert.doesNotMatch(serialized, /commandLine|argv|imagePath|ownerSid|S-1-|[A-Z]:\\\\|exceptionMessage/i);
          }
          return true;
        });
      }
      const actual = await import('../../bin/windows-legacy-process.mjs');
      const unchanged = await actual.prepareLegacyProcesses({ port: fixture.port, root: fixture.root });
      try { assert.deepEqual(unchanged.plan.roots, fixture.initialProcesses.roots); }
      finally { await unchanged.close(); }
      assert.deepEqual(fixture.task.read().actions, ['fixture-registered']);
      return { expectedRed, results, rootsUnchanged: true, taskActionsUnchanged: true };
    } finally {
      if (process.env.MCP_LEGACY_TEST_EVIDENCE) {
        const name = `failure-diagnostics-${expectedRed ? 'old-red' : 'green'}.json`;
        writeFileSync(join(process.env.MCP_LEGACY_TEST_EVIDENCE, name),
          JSON.stringify({ expectedRed, results }, null, 2), { flag: 'wx' });
      }
      await fixture.cleanup();
    }
  }
}
