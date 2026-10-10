import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

export function readAutostart(port) {
  if (port === 0) return [];
  if (process.platform === 'win32') {
    const script = fileURLToPath(new URL('../autostart/windows/inspect-task.ps1', import.meta.url));
    let stdout;
    try {
      stdout = execFileSync('pwsh', ['-NoProfile', '-File', script, '-Port', String(port)], {
        encoding: 'utf8', windowsHide: true, timeout: 10000,
      });
    } catch {
      throw new Error('Selected Windows autostart could not be inspected. No migration or stop was attempted.');
    }
    const result = JSON.parse(stdout);
    if (!Array.isArray(result)) throw new Error('Invalid Windows autostart inspection.');
    return result;
  }
  const paths = process.platform === 'darwin'
    ? [
      join(homedir(), 'Library', 'LaunchAgents', `io.github.girishkvs.mcp-pacemaker.${port}.plist`),
      join(homedir(), 'Library', 'LaunchAgents', 'io.github.girishkvs.mcp-pacemaker.plist'),
    ]
    : [
      join(homedir(), '.config', 'systemd', 'user', `mcp-pacemaker-${port}.service`),
      join(homedir(), '.config', 'systemd', 'user', 'mcp-pacemaker.service'),
    ];
  return paths.filter(existsSync).map(path => ({ path, content: readFileSync(path, 'utf8') }));
}

export function inspectAutostart(instance) {
  const actual = readAutostart(instance.port);
  if (instance.autostart?.kind === 'none') {
    if (actual.length) throw new Error('Unknown OS autostart registration exists. Exact legacy migration is required before upgrade.');
    return { kind: 'none' };
  }
  if (instance.autostart?.kind !== 'stable' ||
      !isDeepStrictEqual(actual, instance.autostart.records)) {
    throw new Error('Selected autostart registration changed or is unknown; refusing before stop.');
  }
  return { kind: 'stable', launcher: join(instance.directory, 'stable-launcher.mjs') };
}
