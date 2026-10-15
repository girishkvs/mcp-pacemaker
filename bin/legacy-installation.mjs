import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { get } from 'node:http';
import { dirname, join, resolve, win32 } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { backendStatus } from './managed-runtime.mjs';
import { directoryIdentity, readManagedJson } from './managed-state.mjs';
import { PoolingFiles, hasPoolingTransaction } from './pooling-files.mjs';
import { canonicalPort } from './cli-selection.mjs';
import { eligibleTaskOwner, WindowsLegacyTaskAdapter } from './legacy-task.mjs';
import { assertDurableRoot } from './service-control.mjs';

const approved = new WeakMap();
const inventory = readManagedJson(new URL('./legacy-1.3.json', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const ACCESS_PROBLEMS = {
  'task-write': report => `Task ${report.task.path} (owner ${report.task.ownerName}): your account can only read it.`,
  'cli-owner': report => `${report.cli.path} (owner ${report.cli.ownerName}): your account cannot copy it with its permissions.`,
  'cli-write': report => `${report.cli.path}: your account cannot write it.`,
  'cli-delete': report => `${report.cli.path}: your account cannot rename it.`,
  'bin-add-file': report => `${report.cli.directory}: your account cannot create files in it.`,
};
export const ACCESS_FIXES = {
  'task-write': report => `give your account full control of task ${report.task.path}`,
  'cli-owner': report => `make your account the owner of ${report.cli.path}`,
};
export const LEGACY_WARNING = [
  'Upgrade this 1.3 installation? Its supervisor, its bridge and the processes the bridge started will be stopped.',
  'Open sessions and calls in progress end, and clients reconnect to the new version. No call is retried.',
  'servers.json, every server setting in it and your client setup are kept as they are.',
].join('\n');

export function legacyPlanDigest(plan) {
  return hash(JSON.stringify({
    contract: 'legacy-restart-observed-set-v1', to: plan.to, registry: plan.registry,
    instance: plan.instance, legacy: plan.legacy,
  }));
}

export async function confirmLegacyUpgrade(plan, { yes = false, interactive = false, confirm } = {}) {
  if (!plan.legacy) throw new Error('Expected a legacy restart plan.');
  const digest = legacyPlanDigest(plan);
  if (!yes) {
    if (!interactive) throw new Error('Legacy migration needs confirmation. Run upgrade --to <version> in an interactive terminal, or add --yes to confirm the plan shown.');
    const answer = await confirm(`${LEGACY_WARNING}\nPlan: ${digest}`);
    if (answer !== true) return false;
  }
  if (legacyPlanDigest(plan) !== digest) throw new Error('Legacy plan changed during confirmation.');
  approved.set(plan, digest);
  return true;
}

export function requireLegacyApproval(plan) {
  if (approved.get(plan) !== legacyPlanDigest(plan)) throw new Error('This legacy plan has no matching confirmation.');
  approved.delete(plan);
}

export function verifyLegacyPackage(root, { cliPath = join(root, 'bin', 'cli.mjs') } = {}) {
  assertDurableRoot(root);
  if (realpathSync.native(root) !== root) throw new Error('Legacy package root is not canonical.');
  const identity = directoryIdentity(root);
  for (const [relative, expected] of Object.entries(inventory.files)) {
    const path = relative === 'bin/cli.mjs' ? cliPath : join(root, relative);
    const stat = lstatSync(path);
    if (!stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.nlink !== 1 ||
        stat.size > 4 * 1024 * 1024 ||
        realpathSync.native(path) !== path) throw new Error('Legacy package contains linked or unsupported files.');
    const bytes = readFileSync(path);
    const normalized = relative.endsWith('.exe') ? bytes : Buffer.from(bytes.toString('utf8').replaceAll('\r\n', '\n'));
    if (hash(normalized) !== expected) throw new Error(`Unsupported or changed legacy 1.3 package file: ${relative}. Nothing was stopped.`);
  }
  return identity;
}

export function parseLegacyRegistration(records, port) {
  if (!Array.isArray(records) ||
      records.length !== 1) throw new Error('Exactly one known legacy Windows registration must match the selected installation.');
  const record = records[0];
  const security = record.security;
  const completeSecurity = security?.protocol === 1 &&
    security.information === 31 &&
    security.complete === true &&
    eligibleTaskOwner(security.ownerSid, record.currentUserSid) &&
    typeof security.groupSid === 'string' &&
    security.groupSid.startsWith('S-1-') &&
    Number.isInteger(security.controlFlags) &&
    typeof security.sddl === 'string' &&
    security.sddl.length > 0 &&
    security.sddl.length <= 65536 &&
    hash(security.sddl) === security.sha256;
  if (!completeSecurity) throw new Error('TASK_SECURITY_UNVERIFIED: Full task security and a supported runtime-user or builtin Administrators owner are required.');
  const action = record.actions?.[0];
  const settings = record.settings;
  const expectedSettings = {
    multipleInstances: 2, restartCount: 3, restartInterval: 'PT1M', executionTimeLimit: 'PT0S',
    startWhenAvailable: true, disallowStartIfOnBatteries: false, stopIfGoingOnBatteries: false,
  };
  const triggers = record.triggers ?? [];
  const exactTriggers = triggers.length === 2 &&
    triggers.every(trigger => trigger.userSid === record.currentUserSid && trigger.enabled === true) &&
    triggers.some(trigger => trigger.type === 9 && trigger.stateChange === 0) &&
    triggers.some(trigger => trigger.type === 11 && trigger.stateChange === 8);
  const valid = [`McpPacemaker-${port}`, 'McpPacemaker'].includes(record.name) &&
    record.path === `\\${record.name}` &&
    record.enabled === true &&
    record.userSid === record.currentUserSid &&
    typeof record.userSid === 'string' &&
    record.userSid.startsWith('S-1-') &&
    record.logonType === 3 &&
    record.runLevel === 0 &&
    record.actions?.length === 1 &&
    action.type === 0 &&
    ['wscript.exe', `${process.env.SystemRoot}\\System32\\wscript.exe`.toLowerCase()].includes(action.path.toLowerCase()) &&
    action.workingDirectory === '' &&
    isDeepStrictEqual(settings, expectedSettings) &&
    exactTriggers &&
    typeof record.xml === 'string' &&
    record.xml.length <= 524288 &&
    hash(record.xml) === record.xmlSha256;
  if (!valid) throw new Error('Unknown or changed legacy registration shape/run-as identity; no task or process was changed.');
  const suffix = `" ${port}`;
  const args = action.arguments;
  if (typeof args !== 'string' ||
      args.length > 4096 ||
      !args.startsWith('"') ||
      !args.endsWith(suffix)) throw new Error('Unsupported legacy launcher arguments.');
  const launcher = args.slice(1, -suffix.length);
  if (launcher.includes('"') ||
      launcher.includes('\n') ||
      launcher.includes('\r') ||
      !win32.isAbsolute(launcher)) throw new Error('Unsupported legacy launcher path.');
  const canonical = realpathSync.native(launcher);
  const root = dirname(dirname(dirname(canonical)));
  if (canonical !== join(root, 'autostart', 'windows', 'launcher.vbs')) throw new Error('Unexpected legacy launcher location.');
  return { root, registration: record };
}

export function legacySessionState(config) {
  const path = join(dirname(config), 'sessions.json');
  return existsSync(path) ? new PoolingFiles(config).inspect(path) : null;
}

export function legacyStatePort(home) {
  const statePath = join(home, 'state.json');
  if (!existsSync(statePath)) throw new Error('No stable managed installation or exact legacy install state was found. Nothing was changed.');
  const state = readManagedJson(statePath);
  const ports = [...new Set((state.hosts ?? []).map(host => canonicalPort(host.port)))];
  if (ports.length !== 1) throw new Error('Legacy migration requires exactly one selected port in existing install state.');
  return { statePath, port: ports[0] };
}

export function legacyAccessReport(report, registration) {
  const bound = report?.protocol === 1 &&
    report.task?.path === registration.path &&
    report.expected?.xmlSha256 === registration.xmlSha256 &&
    Array.isArray(report.missing) &&
    Array.isArray(report.fixable) &&
    report.missing.every(id => Object.hasOwn(ACCESS_PROBLEMS, id)) &&
    report.fixable.every(id => Object.hasOwn(ACCESS_FIXES, id) && report.missing.includes(id));
  if (!bound) throw new Error('Legacy access check did not match the selected registration. Nothing was changed.');
  return report;
}

export function legacyAccessProblems(report) {
  return report.missing.map(id => ACCESS_PROBLEMS[id](report));
}

// A certain gap here would otherwise fail after the journal is published (task hold) or after staging (CLI copy).
export function assertLegacyAccess(report, registration) {
  legacyAccessReport(report, registration);
  if (!report.missing.length) return;
  const lines = [
    'Your account cannot make the changes this upgrade needs. Nothing was changed.',
    ...legacyAccessProblems(report).map(problem => `  - ${problem}`),
  ];
  if (report.fixable.length) {
    lines.push(
      'This usually means 1.3 was set up from an administrator terminal.',
      `Run this once from ${report.elevated ? 'this' : 'an'} administrator terminal. It will only ${report.fixable.map(id => ACCESS_FIXES[id](report)).join(' and ')}:`,
      '  mcp-pacemaker upgrade --fix-legacy-access',
      'Then run this upgrade again from a normal (non-administrator) terminal.',
    );
  }
  if (report.missing.some(id => !report.fixable.includes(id))) {
    lines.push('--fix-legacy-access does not change the other permissions listed; an administrator must grant them.');
  }
  throw Object.assign(new Error(lines.join('\n')), { code: 'LEGACY_ACCESS_MISSING' });
}

// 1.3 rewrites sessions.json whenever a session starts or ends, and an upgrade may end
// sessions, so only the config is compared.
export function verifyLegacyConfig(config, legacy) {
  new PoolingFiles(config).verify(config, legacy.authority);
  if (hasPoolingTransaction(config)) throw new Error('Legacy configuration has an unresolved transaction.');
}

async function nonceChallenge(port, nonce) {
  return new Promise((resolveChallenge, reject) => {
    const request = get({
      hostname: '127.0.0.1', port, path: '/admin/upgrade-identity-check',
      headers: { 'x-mcp-nonce': nonce }, agent: false,
    }, response => {
      let body = '';
      response.on('data', data => {
        body += data;
        if (body.length > 1024) request.destroy(new Error('Oversized legacy identity response.'));
      });
      response.on('end', () => {
        if (response.statusCode !== 404 ||
            body !== 'unknown admin action') reject(new Error('Legacy listener does not match the selected config nonce.'));
        else resolveChallenge();
      });
    });
    request.on('error', reject);
    request.setTimeout(2000, () => request.destroy(new Error('Legacy identity challenge timed out.')));
  });
}

export async function verifyLegacyListener(instance, legacy, { sameGeneration = true } = {}) {
  verifyLegacyConfig(instance.config, legacy);
  const files = new PoolingFiles(instance.config);
  const noncePath = join(dirname(instance.config), 'admin.nonce');
  const authority = files.inspect(noncePath);
  if (sameGeneration &&
      !isDeepStrictEqual(authority, legacy.nonceAuthority)) throw new Error('Legacy nonce identity changed.');
  const nonce = readFileSync(noncePath, 'utf8').trim();
  if (nonce.length !== 36) throw new Error('Invalid legacy nonce.');
  const status = await backendStatus(instance.port);
  if (status.service !== 'mcp-pacemaker' ||
      status.version !== '1.3.0' ||
      status.port !== instance.port ||
      typeof status.instanceId !== 'string' ||
      (sameGeneration && status.instanceId !== legacy.backendInstanceId)) throw new Error('Legacy backend generation changed.');
  await nonceChallenge(instance.port, nonce);
  files.verify(noncePath, authority);
  return { status, nonceAuthority: authority };
}

export async function prepareLegacyPlan(options, { home, task = new WindowsLegacyTaskAdapter(), processes } = {}) {
  if (process.platform !== 'win32') throw new Error('Legacy restart migration has no supported adapter on this OS. Nothing was changed.');
  if (options.sxs) throw new Error('Legacy-source SxS is not supported; no existing service was changed.');
  const { statePath, port } = legacyStatePort(home);
  const records = task.inspectLegacySource ? await task.inspectLegacySource(port) : await task.inspect(port);
  const { root, registration } = parseLegacyRegistration(records, port);
  const rootIdentity = verifyLegacyPackage(root);
  if (typeof task.access === 'function') assertLegacyAccess(await task.access(port, join(root, 'bin', 'cli.mjs')), registration);
  const config = realpathSync.native(join(home, 'servers.json'));
  const files = new PoolingFiles(config);
  // 1.3 rewrites sessions.json on every session start and end, so it is read only after the
  // old bridge has stopped.
  const legacy = {
    protocol: 1, root, rootIdentity, registration,
    stateAuthority: files.inspect(statePath),
    authority: files.inspect(config), sessions: null,
  };
  const instance = {
    id: randomUUID(), directory: join(home, 'managed', `legacy-${port}-${randomUUID()}`),
    config, cwd: dirname(config), port, node: realpathSync.native(process.execPath),
  };
  const api = processes ?? await import('./windows-legacy-process.mjs');
  const session = await api.prepareLegacyProcesses({ port, root });
  try {
    legacy.processes = session.plan;
    const listener = await verifyLegacyListener(instance, legacy, { sameGeneration: false });
    legacy.backendInstanceId = listener.status.instanceId;
    legacy.nonceAuthority = listener.nonceAuthority;
    if (session.plan.roots.supervisor.ownerSid !== registration.currentUserSid ||
        session.plan.roots.bridge.ownerSid !== registration.currentUserSid) throw new Error('Task and process owners do not match.');
  } finally { await session.close(); }
  return { instance, legacy, task, processes: api };
}
