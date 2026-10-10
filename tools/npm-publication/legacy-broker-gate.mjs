import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LEGACY_BROKER_FILES, LEGACY_BROKER_TEST, LEGACY_BROKER_REQUIRED_TESTS, verifyLegacyBrokerAssets } from '../windows-legacy/inventory.mjs';

export function legacyBrokerRequired(files) {
  return files.some(file => file.path === 'bin/legacy-upgrade.mjs');
}

export function verifyLegacyFeature(root) {
  if (!existsSync(join(root, 'bin', 'legacy-upgrade.mjs'))) return undefined;
  const capability = JSON.parse(readFileSync(join(root, 'bin', 'upgrade-capability.json'), 'utf8'));
  assert.equal(capability.legacyRestartProtocol, 1, 'Legacy migration requires its declared recovery protocol.');
  return verifyLegacyBrokerAssets(root);
}

export function verifyLegacyExecution(report, inspection) {
  if (!legacyBrokerRequired(inspection.files)) {
    assert.equal(report.legacyBroker, undefined);
    return;
  }
  assert.equal(report.legacyBroker?.status, 'source-and-binary-hashes-verified');
  assert.deepEqual(report.legacyBroker.files.map(file => file.path), [...LEGACY_BROKER_FILES]);
  for (const file of report.legacyBroker.files) {
    assert.equal(inspection.files.find(item => item.path === file.path)?.sha256, file.sha256);
  }
  assert.ok(report.evidence.command.args.includes(LEGACY_BROKER_TEST),
    'Actual separate legacy broker tests must execute for a package containing legacy migration.');
  for (const name of LEGACY_BROKER_REQUIRED_TESTS) {
    assert.ok(report.stdout.split(/\r?\n/).some(line => /^ok \d+ - /.test(line) && line.endsWith(name)),
      `Missing executed legacy broker test: ${name}`);
  }
}
