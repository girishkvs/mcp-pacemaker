import { lstat, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { guarded, requireCondition, sha256 } from './core.mjs';
import { diagnoseSource } from './secrets.mjs';

export async function diagnosticOutputPath(output, root) {
  requireCondition(typeof output === 'string' && isAbsolute(output) &&
    typeof root === 'string' && isAbsolute(root), 'diagnostic-absolute-paths-required');
  let directory = await realpath(dirname(output));
  const destination = join(directory, relative(dirname(output), output));
  const distance = relative(await realpath(root), destination);
  requireCondition(distance === '..' || distance.startsWith(`..${sep}`) || isAbsolute(distance),
    'diagnostic-output-inside-candidate');
  for (;;) {
    let git;
    try { git = await lstat(join(directory, '.git')); } catch (error) {
      requireCondition(error.code === 'ENOENT', 'diagnostic-output-directory-unreadable');
    }
    requireCondition(!git, 'diagnostic-output-inside-git-checkout');
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return destination;
}

export async function main(args = process.argv.slice(2)) {
  return guarded('local-diagnostic-cli', async () => {
    const { values } = parseArgs({ args, strict: true, allowPositionals: false, options: {
      root: { type: 'string' }, output: { type: 'string' }, 'local-only': { type: 'boolean' },
    } });
    requireCondition(values['local-only'] === true && !process.env.CI, 'local-diagnostics-not-for-ci');
    const destination = await diagnosticOutputPath(values.output, values.root);
    try {
      await lstat(destination);
      requireCondition(false, 'diagnostic-output-exists');
    } catch (error) {
      requireCondition(error.code === 'ENOENT', 'diagnostic-output-exists');
    }
    const report = await diagnoseSource({ root: values.root, localOnly: true });
    requireCondition(await diagnosticOutputPath(values.output, values.root) === destination,
      'diagnostic-output-directory-changed');
    const bytes = `${JSON.stringify(report)}\n`;
    await writeFile(destination, bytes, { flag: 'wx', mode: 0o600 });
    return { status: report.status, reportSha256: sha256(bytes),
      executions: report.executions.map(item => ({ tool: item.tool.name, status: item.status, findings: item.findings })),
      ...(report.error ? { error: report.error } : {}) };
  });
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await main();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = ({ passed: 0, findings: 1, error: 2 })[result.status] ?? 2;
}
