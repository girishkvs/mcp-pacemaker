import assert from 'node:assert/strict';
import { mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyArtifacts } from '../third-party-notices/inventory.mjs';
import {
  GateRunner, evidenceFor, gateOptions, ROOT,
  passed, readJson, validateConsumerMatrix,
} from './gates.mjs';
import { POLICY, digest, sameDigests, validateGates } from './policy.mjs';
import { extractTarball } from './tarball.mjs';
import { validateLocalApproval } from './local-regression.mjs';
import { requireHostedLocalPreparation } from './local-regression-hosted.mjs';

export function runArtifactChecks(runner, binding, sourceReport, noticesEvidence) {
  validateLocalApproval(runner.context.approval, { continuing: true });
  assert.deepEqual(sourceReport?.localRegression, runner.context.approval.localRegression);
  runner.requireScripts(['compat:prepare', 'compat:clean', 'test:compat', 'test:compat:browser']);
  assert.equal(sourceReport?.schemaVersion, 1);
  assert.equal(sourceReport.phase, 'source', 'A real source-gate report is required');
  assert.deepEqual(sourceReport.source, binding.source, 'Source-gate report is not bound to this source');
  assert.deepEqual(sourceReport.toolchain, { node: POLICY.node, npm: POLICY.npm });
  assert.match(binding.sourceReportSha256 ?? '', /^[a-f0-9]{64}$/, 'Exact source report file digest required');
  const matrix = runner.context.matrix;
  const consumers = matrix?.consumerLanes?.map(lane => lane.result);
  validateConsumerMatrix(consumers, binding);
  const peer = runner.context.peer;
  assert.ok(peer?.tarball, 'Approved peer source artifact is required for actual T32 execution');
  const comparison = peer.comparison;
  assert.equal(comparison?.version, binding.version === '1.3.1' ? '2.0.1' : '1.3.1');
  sameDigests(comparison.artifact, peer.evidence);
  assert.equal(peer.evidence.purpose, 'service-comparison-only');
  assert.equal(peer.evidence.stageEligible, false);
  if (peer.evidence.origin === 'npm-registry-published') {
    assert.equal(peer.prepared, undefined, 'Published peer must not impersonate a preparation');
  }
  runner.publicCoordinates();
  assert.equal(runner.npm(['--version'], 'Verify artifact npm version').stdout, POLICY.npm);
  const restores = [];
  for (const prefix of [[], ['--prefix', 'ui']]) {
    restores.push(runner.npm([...prefix, 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
      `Restore finalizer ${prefix.length ? 'UI' : 'root'} dependencies`).evidence);
  }
  const browser = runner.node('ui/node_modules/playwright/cli.js',
    ['install', '--with-deps', 'chromium'], 'Install locked Chromium for exact-tarball compatibility').evidence;
  const compatibility = runner.compatibility(binding);
  const own = { tarball: binding.tarball, version: binding.version, ...binding.artifact, files: binding.files };
  const opposite = { tarball: peer.tarball, version: comparison.version,
    ...comparison.artifact, files: peer.inspection.files };
  const pair = binding.version === '1.3.1' ? { legacy: own, current: opposite } : { legacy: opposite, current: own };
  const replacementRun = runner.node('tools/service-replacement/check.mjs', [
    '--legacy-tarball', pair.legacy.tarball, '--legacy-sha256', pair.legacy.sha256,
    '--current-tarball', pair.current.tarball, '--current-sha256', pair.current.sha256,
  ], 'Run actual exact-two-patch-tarball T32 service replacement');
  runner.verifyArtifact(peer.tarball, comparison.artifact);
  const replacement = {
    result: JSON.parse(replacementRun.stdout), stdout: replacementRun.rawStdout,
    evidence: replacementRun.evidence, approvedArtifacts: pair,
  };
  const external = runner.external('artifact', binding, {
    extractedRoot: binding.extractedRoot,
    consumers: consumers.filter(item => item.platform === 'linux' &&
      item.npm === POLICY.npm), matrix, sourceReport, replacement,
  });
  const gates = {
    ...sourceReport.gates, ...external.gates,
    compatibility: passed(browser, ...compatibility),
  };
  gates['licenses-notices'].evidence.push(noticesEvidence);
  gates['runtime-closure'].evidence.push(noticesEvidence, ...compatibility);
  const report = {
    schemaVersion: 1, commit: binding.commit, artifact: binding.artifact,
    localRegression: runner.context.approval.localRegression,
    source: binding.source, toolchain: sourceReport.toolchain,
    sourceReportSha256: binding.sourceReportSha256,
    ...(sourceReport.secretEvidence ? { sourceSecretEvidence: sourceReport.secretEvidence } : {}),
    gates, consumers, sourceChecks: sourceReport.checks, restores,
    matrixArtifacts: matrix.artifactEvidence, peerArtifact: peer.evidence,
    nativeIdentity: sourceReport.nativeIdentity, nativeWindows: external.nativeWindows,
    serviceReplacement: external.serviceReplacement, runtimeLicenses: external.runtimeLicenses,
    coverage: {
      consumerLanes: consumers.map(item => ({
        node: item.node, npm: item.npm, platform: item.platform, installScripts: item.installScripts,
        reportSha256: evidenceFor('Consumer lane report', JSON.stringify(item)).sha256,
      })),
      registrySignatures: 'pending-publication', provenance: 'pending-stage',
      privateContentReview: 'pending-owner-review',
    },
  };
  validateGates(report, { commit: binding.commit }, binding.artifact);
  return report;
}

export async function main(args = process.argv.slice(2)) {
  const options = gateOptions(args, ['--tarball', '--source-report', '--context', '--output']);
  const context = readJson(options['--context']);
  await requireHostedLocalPreparation(context.approval);
  const runner = new GateRunner(ROOT, context);
  let success = false;
  try {
    const source = runner.snapshot();
    const bytes = readFileSync(options['--tarball']);
    const artifact = digest(bytes);
    const extractedRoot = join(runner.owned.dir, 'package');
    mkdirSync(extractedRoot);
    const inspection = extractTarball(bytes, { version: source.version, commit: source.commit }, extractedRoot);
    const manifest = verifyArtifacts(extractedRoot);
    const noticesEvidence = evidenceFor('verifyArtifacts over the actual extracted npm payload',
      JSON.stringify(manifest));
    const binding = {
      source, commit: source.commit, version: source.version,
      artifact, tarball: options['--tarball'], extractedRoot, files: inspection.files,
      sourceReportSha256: digest(readFileSync(options['--source-report'])).sha256,
    };
    const report = runArtifactChecks(runner, binding, readJson(options['--source-report']), noticesEvidence);
    sameDigests(digest(readFileSync(binding.tarball)), artifact);
    assert.deepEqual(runner.snapshot(), source, 'Source or locks changed during artifact gates');
    runner.writeReport(options['--output'], report);
    success = true;
    console.log('Automated exact-tarball gates completed; owner review, provenance and registry signatures remain pending.');
  } finally {
    runner.finish(success);
  }
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
