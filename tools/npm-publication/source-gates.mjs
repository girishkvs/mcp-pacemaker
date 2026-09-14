import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { GateRunner, gateOptions, passed, readJson, ROOT } from './gates.mjs';
import { POLICY } from './policy.mjs';

export function validateAudit(output) {
  const report = JSON.parse(output);
  assert.equal(report.auditReportVersion, 2, 'Unexpected npm12 audit report');
  assert.deepEqual(report.vulnerabilities, {}, 'Producer advisory findings remain unresolved');
  for (const severity of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
    assert.equal(report.metadata?.vulnerabilities?.[severity], 0, `Producer advisories: ${severity}`);
  }
}

export function runSourceChecks(runner) {
  runner.requireScripts(['test']);
  runner.requireScripts(['typecheck', 'build'], runner.uiPackage);
  const source = runner.snapshot();
  runner.publicCoordinates();
  assert.equal(runner.npm(['--version'], 'Verify publishing npm version').stdout, POLICY.npm);
  const restores = [];
  const audits = [];
  for (const prefix of [[], ['--prefix', 'ui']]) {
    restores.push(runner.npm([...prefix, 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
      `Restore exact ${prefix.length ? 'UI' : 'root'} producer lock`).evidence);
    const audit = runner.npm([...prefix, 'audit', '--json', '--audit-level=low'],
      `Audit actual ${prefix.length ? 'UI' : 'root'} producer graph`);
    validateAudit(audit.stdout);
    audits.push(audit.evidence);
  }
  const ui = [runner.npm(['--prefix', 'ui', '--silent', 'run', 'typecheck'], 'UI typecheck').evidence];
  let uiTests = { status: 'not-applicable', reason: 'No UI test script is declared' };
  if (runner.uiPackage.scripts.test) {
    const result = runner.npm(['--prefix', 'ui', '--silent', 'run', 'test'], 'UI tests');
    ui.push(result.evidence);
    uiTests = passed(result.evidence);
  }
  ui.push(runner.npm(['--prefix', 'ui', '--silent', 'run', 'build'], 'Build actual UI and bundled notices').evidence);
  ui.push(runner.node('tools/third-party-notices/check.mjs', [],
    'Rebuild and verify source UI/license artifacts').evidence);
  const sourceTests = runner.script('test').evidence;
  const external = runner.external('source', source);
  assert.deepEqual(runner.snapshot(), source, 'Source, generated files or producer locks changed during gates');
  return {
    schemaVersion: 1, phase: 'source', source,
    toolchain: { node: POLICY.node, npm: POLICY.npm },
    checks: { restores, sourceTests, uiTests, compatibility: 'pending-exact-tarball' },
    nativeIdentity: external.nativeIdentity, authorIdentity: external.authorIdentity,
    gates: { ...external.gates,
      'producer-advisories': passed(...external.gates['producer-advisories'].evidence, ...audits),
      'ui-build': passed(...ui) },
  };
}

export function main(args = process.argv.slice(2)) {
  const options = gateOptions(args, ['--context', '--output']);
  const runner = new GateRunner(ROOT, readJson(options['--context']));
  let success = false;
  try {
    runner.writeReport(options['--output'], runSourceChecks(runner));
    success = true;
    console.log('Automated source checks completed; owner review and exact-tarball gates remain pending.');
  } finally {
    runner.finish(success);
  }
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
