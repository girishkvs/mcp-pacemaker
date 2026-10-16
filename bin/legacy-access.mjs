import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { durableJson } from './managed-state.mjs';
import { WindowsLegacyTaskAdapter } from './legacy-task.mjs';
import {
  ACCESS_FIXES, legacyAccessProblems, legacyAccessReport, legacyStatePort, parseLegacyRegistration, verifyLegacyPackage,
} from './legacy-installation.mjs';

const NEXT = 'Run mcp-pacemaker upgrade --to <version> from a normal (non-administrator) terminal.';

export async function inspectLegacyAccess(home, { task = new WindowsLegacyTaskAdapter() } = {}) {
  if (process.platform !== 'win32') throw new Error('--fix-legacy-access applies only to the known Windows 1.3 registration. Nothing was changed.');
  const { port } = legacyStatePort(home);
  const { root, registration } = parseLegacyRegistration(await task.inspect(port), port);
  verifyLegacyPackage(root);
  const cliPath = join(root, 'bin', 'cli.mjs');
  const report = legacyAccessReport(await task.access(port, cliPath), registration);
  return { port, cliPath, registration, report };
}

export function describeLegacyAccessFix({ port, report }) {
  return [
    `Legacy 1.3 access fix for port ${port}. It will only:`,
    ...report.fixable.map(id => `  - ${ACCESS_FIXES[id](report)}`),
    'Unchanged: task XML, triggers and run-as account (it keeps running as you, not elevated), other permissions and file contents.',
  ].join('\n');
}

// Elevated, explicit and bound to the inspected descriptors: makes an install done from an
// administrator terminal look like one done from a normal terminal, so the ordinary upgrade can run.
export async function fixLegacyAccess({
  home, plan = false, yes = false, interactive = false, confirm,
  task = new WindowsLegacyTaskAdapter(), log = console.log, now = () => new Date(),
} = {}) {
  const selected = await inspectLegacyAccess(home, { task });
  const { port, cliPath, registration, report } = selected;
  const summary = { port, task: registration.path, cli: cliPath };
  if (!report.missing.length) return { status: 'unchanged', ...summary, next: NEXT };
  if (!report.elevated) {
    throw new Error('Run --fix-legacy-access from an administrator terminal (Run as administrator). Nothing was changed.');
  }
  const manual = report.missing.filter(id => !report.fixable.includes(id));
  if (manual.length) {
    throw new Error([
      'These permissions need an administrator to change them by hand; --fix-legacy-access does not. Nothing was changed.',
      ...legacyAccessProblems(report).map(problem => `  - ${problem}`),
    ].join('\n'));
  }
  log(describeLegacyAccessFix(selected));
  if (plan) return { status: 'planned', ...summary, changes: report.fixable };
  if (!yes) {
    if (!interactive) throw new Error('--fix-legacy-access needs an interactive confirmation or --yes. Nothing was changed.');
    if (await confirm('Apply this access fix?') !== true) return { status: 'cancelled', ...summary };
  }
  const directory = join(home, 'legacy-upgrade');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const journal = join(directory, `access-${now().toISOString().replaceAll(':', '-')}.json`);
  const record = {
    protocol: 1, kind: 'legacy-access-fix', createdAt: now().toISOString(), ...summary,
    changes: report.fixable, before: report.expected,
  };
  durableJson(journal, record);
  let result;
  try { result = await task.grantAccess(port, cliPath, report.expected); }
  catch (error) {
    durableJson(journal, { ...record, failed: error.message, changed: error.changed ?? [] });
    throw new Error(`${error.message}\nRecorded before-state: ${journal}`, { cause: error });
  }
  durableJson(journal, { ...record, changed: result.changed, after: result.after });
  const after = legacyAccessReport(await task.access(port, cliPath), registration);
  if (after.missing.length) throw new Error(`Access is still missing after the fix: ${after.missing.join(', ')}. Recorded before-state: ${journal}`);
  return { status: 'fixed', ...summary, changed: result.changed, journal, next: NEXT };
}
