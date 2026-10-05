import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { GateRunner, gateOptions, passed, readJson, ROOT } from './gates.mjs';
import { POLICY } from './policy.mjs';
import { validateLocalApproval } from './local-regression.mjs';
import { requireHostedLocalPreparation } from './local-regression-hosted.mjs';
import { classifyNativeAudit, uiBuildRiskAcceptance, requireBuildOnlyRiskScope, validateProducerAdvisories } from '../publication-scanners/advisories.mjs';

export function validateAudit(output, context, execution) {
  return classifyNativeAudit(output, execution, context);
}

export function runSourceChecks(runner) {
  validateLocalApproval(runner.context.approval, { continuing: true });
  runner.requireScripts(['test']);
  runner.requireScripts(['typecheck', 'build'], runner.uiPackage);
  const source = runner.snapshot();
  runner.publicCoordinates();
  assert.equal(runner.npm(['--version'], 'Verify publishing npm version').stdout, POLICY.npm);
  const restores = [];
  const audits = [];
  const auditDetails = [];
  const acceptedContexts = [];
  for (const prefix of [[], ['--prefix', 'ui']]) {
    restores.push(runner.npm([...prefix, 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
      `Restore exact ${prefix.length ? 'UI' : 'root'} producer lock`).evidence);
    const audit = runner.npm([...prefix, 'audit', '--json', '--audit-level=low'],
      `Audit actual ${prefix.length ? 'UI' : 'root'} producer graph`);
    const context = audit.auditContext;
    if (context) {
      assert.equal(context.phase, 'source');
      assert.equal(context.scope, prefix.length ? 'producer-ui' : 'producer-root');
      assert.equal(context.version, source.version);
      assert.equal(context.lockSha256, prefix.length ? source.uiLockSha256 : source.rootLockSha256);
    }
    const detail = validateAudit(audit.rawStdout ?? audit.stdout, context,
      { exitCode: audit.evidence.exitCode ?? 0 });
    auditDetails.push({ scope: prefix.length ? 'producer-ui' : 'producer-root', ...detail });
    if (detail.acceptance) acceptedContexts.push(context);
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
  for (const context of acceptedContexts) {
    assert.ok(uiBuildRiskAcceptance(context), 'Producer UI risk acceptance expired before source completion');
  }
  const riskApplied = acceptedContexts.length > 0 || Boolean(external.gates['producer-advisories'].riskAcceptance);
  const buildOnlyEvidence = riskApplied ? requireBuildOnlyRiskScope(
    readFileSync(join(runner.root, 'package-lock.json')),
    readFileSync(join(runner.root, 'ui/dist/third-party-manifest.json'))) : undefined;
  const producerGate = { ...external.gates['producer-advisories'],
    ...passed(...external.gates['producer-advisories'].evidence, ...audits),
    ...(buildOnlyEvidence ? { buildOnlyEvidence } : {}) };
  if (source.version === '2.0.2') {
    producerGate.nativeAudits = auditDetails;
    producerGate.disposition = riskApplied ? 'RISK-ACCEPTED' : 'advisory-free';
    producerGate.advisoryFree = !riskApplied;
    if (!producerGate.riskAcceptance &&
        acceptedContexts.length > 0) producerGate.riskAcceptance = auditDetails[1].acceptance;
  }
  const report = {
    schemaVersion: 1, phase: 'source', source,
    localRegression: runner.context.approval.localRegression,
    toolchain: { node: POLICY.node, npm: POLICY.npm },
    checks: { restores, sourceTests, uiTests, audits: auditDetails, compatibility: 'pending-exact-tarball' },
    nativeIdentity: external.nativeIdentity, authorIdentity: external.authorIdentity,
    ...(external.scannerDetails?.secrets?.collection
      ? { secretEvidence: external.scannerDetails.secrets } : {}),
    gates: { ...external.gates,
      'producer-advisories': producerGate,
      'ui-build': passed(...ui) },
  };
  validateProducerAdvisories(producerGate, { source, version: source.version, checks: report.checks, complete: true });
  return report;
}

export async function main(args = process.argv.slice(2)) {
  const options = gateOptions(args, ['--context', '--output']);
  const context = readJson(options['--context']);
  await requireHostedLocalPreparation(context.approval);
  const runner = new GateRunner(ROOT, context);
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
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
