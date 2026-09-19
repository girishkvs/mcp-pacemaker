import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { guarded, isolatedEnvironment, readJson, requireCondition, sha256, workspace } from './core.mjs';
import { diagnosticOutputPath } from './diagnose.mjs';
import { findingSourceBinding, readReviewSource } from './review-source.mjs';
import { validateSecretCollection } from '../npm-publication/secret-report.mjs';

export async function correlateSecretReport({ root, report, localOnly = false, tools = {},
  readSource = readReviewSource }) {
  requireCondition(localOnly === true && !process.env.CI, 'local-correlation-not-for-ci');
  validateSecretCollection(report);
  return workspace(async temp => {
    const context = { cwd: temp, env: isolatedEnvironment(temp) };
    const source = await readSource(root, { tools, context });
    for (const key of ['commit', 'tree', 'treeEntriesSha256']) {
      requireCondition(source.binding[key] === report.source[key], 'correlation-source-mismatch');
    }
    const findings = [];
    for (const execution of report.raw.executions) {
      for (const finding of execution.identities) {
        requireCondition(finding.binding !== null, 'correlation-unmapped-finding');
        const matches = source.entries.filter(item => sha256(item.path) === finding.binding.pathSha256);
        requireCondition(matches.length === 1, 'correlation-path-mismatch');
        const entry = matches[0];
        const binding = await findingSourceBinding(source, entry, finding.binding.line, execution.scope);
        requireCondition(JSON.stringify(binding) === JSON.stringify(finding.binding), 'correlation-bytes-mismatch');
        findings.push({ id: finding.id, scope: execution.scope, path: entry.path,
          line: binding.line, valueSha256: finding.valueSha256, classification: 'not-assessed' });
      }
    }
    requireCondition(JSON.stringify(source.binding) ===
      JSON.stringify((await readSource(root, { tools, context })).binding), 'correlation-source-changed');
    return { schemaVersion: 1, kind: 'local-secret-report-correlation', eligibility: 'none',
      authenticity: 'not-verified-by-correlation', ownerApproval: 'not-supplied',
      source: { commit: report.source.commit, tree: report.source.tree }, findings };
  });
}

export async function main(args = process.argv.slice(2)) {
  return guarded('local-secret-correlation', async () => {
    const { values } = parseArgs({ args, strict: true, allowPositionals: false, options: {
      root: { type: 'string' }, report: { type: 'string' }, output: { type: 'string' },
      'local-only': { type: 'boolean' },
    } });
    requireCondition(values['local-only'] === true && !process.env.CI, 'local-correlation-not-for-ci');
    const destination = await diagnosticOutputPath(values.output, values.root);
    const input = await readJson(values.report);
    requireCondition((await readFile(values.report)).length <= 512 * 1024, 'correlation-report-size');
    const result = await correlateSecretReport({ root: values.root, report: input.value, localOnly: true });
    requireCondition(await diagnosticOutputPath(values.output, values.root) === destination,
      'correlation-output-changed');
    const bytes = `${JSON.stringify({ ...result, reportSha256: input.sha256 })}\n`;
    await writeFile(destination, bytes, { flag: 'wx', mode: 0o600 });
    return { status: 'correlated-not-approved', reportSha256: sha256(bytes), findings: result.findings.length };
  });
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await main();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.status === 'correlated-not-approved' ? 0 : 2;
}
