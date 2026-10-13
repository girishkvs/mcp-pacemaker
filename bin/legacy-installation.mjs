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
export const LEGACY_WARNING = [
  'Restart this legacy Pacemaker installation? Pause its callers before confirming.',
  'Clients will disconnect. Legacy 1.3 cannot drain or certify every in-flight HTTP outcome.',
  'Only the selected supervisor, bridge and captured provably owned descendants will be verified stopped.',
  'Historical orphan coverage remains unproven; uncaptured or unattributed processes are left untouched and are not enumerated as a complete set.',
  'No unknown call is automatically replayed. The new managed runtime contains future children from birth.',
].join('\n');

export function legacyPlanDigest(plan) {
  return hash(JSON.stringify({
    contract: 'legacy-restart-observed-set-v1', to: plan.to, registry: plan.registry,
    instance: plan.instance, legacy: plan.legacy,
  }));
}

export async function confirmLegacyUpgrade(plan, { yes = false, interactive = false, confirm } = {}) {
  if (!plan.legacy) throw new Error('Expected a legacy restart plan.');
  if (yes ||
      !interactive) throw new Error('Legacy migration requires interactive acknowledgement of this exact restart/uncertain-HTTP/partial-tree plan. Run upgrade --to <version> without --yes in an interactive terminal; pause callers before confirming.');
  const digest = legacyPlanDigest(plan);
  const answer = await confirm(`${LEGACY_WARNING}\nPlan: ${digest}`);
  if (answer !== true) return false;
  if (legacyPlanDigest(plan) !== digest) throw new Error('Legacy plan changed during confirmation.');
  approved.set(plan, digest);
  return true;
}

export function requireLegacyApproval(plan) {
  if (approved.get(plan) !== legacyPlanDigest(plan)) throw new Error('This legacy plan has no matching interactive acknowledgement.');
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

export function verifyLegacyConfig(config, legacy) {
  new PoolingFiles(config).verify(config, legacy.authority);
  if (!isDeepStrictEqual(legacySessionState(config), legacy.sessions) ||
      hasPoolingTransaction(config)) throw new Error('Legacy configuration/session state changed or has an unresolved transaction.');
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
  const statePath = join(home, 'state.json');
  if (!existsSync(statePath)) throw new Error('No stable managed installation or exact legacy install state was found. Nothing was changed.');
  const state = readManagedJson(statePath);
  const ports = [...new Set((state.hosts ?? []).map(host => canonicalPort(host.port)))];
  if (ports.length !== 1) throw new Error('Legacy migration requires exactly one selected port in existing install state.');
  const port = ports[0];
  const records = task.inspectLegacySource ? await task.inspectLegacySource(port) : await task.inspect(port);
  const { root, registration } = parseLegacyRegistration(records, port);
  const rootIdentity = verifyLegacyPackage(root);
  const config = realpathSync.native(join(home, 'servers.json'));
  const files = new PoolingFiles(config);
  const legacy = {
    protocol: 1, root, rootIdentity, registration,
    stateAuthority: files.inspect(statePath),
    authority: files.inspect(config), sessions: legacySessionState(config),
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
