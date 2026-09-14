import { realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { guarded, readJson, requireCondition } from './core.mjs';
import {
  scanAdvisories, scanArtifact, scanPrivateContent, scanPublicationRequest, scanSource, toolsFromEnvironment,
} from './index.mjs';

async function publicationReportPath(path, request) {
  requireCondition(typeof path === 'string' && isAbsolute(path), 'absolute-report-path-required');
  const destination = join(await realpath(dirname(path)), relative(dirname(path), path));
  for (const root of [request?.root, request?.sourceRoot]) {
    requireCondition(typeof root === 'string' && isAbsolute(root), 'publication-absolute-roots-required');
    const distance = relative(await realpath(root), destination);
    requireCondition(distance === '..' || distance.startsWith(`..${sep}`) || isAbsolute(distance),
      'report-must-be-outside-scan-roots');
  }
  return destination;
}

export async function main(args = process.argv.slice(2)) {
  return guarded('scanner-cli', async () => {
    const { values, positionals } = parseArgs({
      args, allowPositionals: true, strict: true,
      options: Object.fromEntries(['root', 'gitleaks-bin', 'gitleaks-sha256', 'trufflehog-bin',
        'trufflehog-sha256', 'gitleaks-config', 'go-bin', 'git-bin', 'artifact-sha256', 'commit',
        'producer-root-lock', 'producer-ui-lock', 'consumer-lock', 'public-packages',
        'exemptions', 'local-artifact', 'policy', 'request', 'output'].map(name => [name, { type: 'string' }]).concat([
        ['source', { type: 'boolean', default: false }],
      ])),
    });
    const tools = toolsFromEnvironment();
    for (const name of ['gitleaks', 'trufflehog']) {
      tools[name].path = values[`${name}-bin`] ?? tools[name].path;
      tools[name].sha256 = values[`${name}-sha256`] ?? tools[name].sha256;
    }
    tools.go = values['go-bin'] ?? tools.go;
    tools.git = values['git-bin'] ?? tools.git;
    tools.gitleaks.configPath = values['gitleaks-config'] ?? tools.gitleaks.configPath;
    if (values.request !== undefined) {
      requireCondition(isAbsolute(values.request) && typeof values.output === 'string' &&
        isAbsolute(values.output) && positionals.length === 0 && !values.source &&
        ['root', 'commit', 'artifact-sha256', 'producer-root-lock', 'producer-ui-lock',
          'consumer-lock', 'local-artifact'].every(name => values[name] === undefined),
      'publication-request-options');
      const input = await readJson(values.request);
      const destination = await publicationReportPath(values.output, input.value);
      const report = await scanPublicationRequest({
        request: input.value, tools,
        policyPath: values.policy ?? process.env.MCP_PUBLICATION_PRIVATE_POLICY,
        publicPackagesPath: values['public-packages'] ?? process.env.MCP_PUBLICATION_PUBLIC_PACKAGES,
        exemptionsPath: values.exemptions ?? process.env.MCP_PUBLICATION_ADVISORY_EXEMPTIONS,
      });
      report.requestFileSha256 = input.sha256;
      requireCondition(await publicationReportPath(values.output, input.value) === destination,
        'publication-output-directory-changed');
      await writeFile(destination, `${JSON.stringify(report)}\n`, { flag: 'wx', mode: 0o600 });
      return report;
    }
    requireCondition(positionals.length === 1 && values.output === undefined, 'single-scanner-command-required');
    const command = positionals[0];
    const root = values.root ? resolve(values.root) : undefined;
    if (command === 'source') return scanSource({ root, tools });
    if (command === 'artifact') return scanArtifact({ root, tools, artifactSha256: values['artifact-sha256'] });
    if (command === 'private') {
      return scanPrivateContent({
        root, policyPath: values.policy, source: values.source,
        binding: { commit: values.commit, artifactSha256: values['artifact-sha256'] },
      });
    }
    requireCondition(command === 'advisories', 'unknown-scanner-command');
    const locks = [
      { path: values['producer-root-lock'], scope: 'producer-root' },
      { path: values['producer-ui-lock'], scope: 'producer-ui' },
      { path: values['consumer-lock'], scope: 'fresh-consumer' },
    ].filter(lock => lock.path);
    const localArtifact = values['local-artifact'] ? (await readJson(values['local-artifact'])).value : undefined;
    return scanAdvisories({ locks, publicPackagesPath: values['public-packages'],
      exemptionsPath: values.exemptions, localArtifact });
  });
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await main();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = ({ passed: 0, findings: 1, error: 2, 'not-run': 3 })[result.status] ?? 2;
}
