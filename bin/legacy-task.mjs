import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { readAutostart } from './upgrade-autostart.mjs';
import { readManagedJson } from './managed-state.mjs';

const ownerPolicy = readManagedJson(new URL('./legacy-1.3.json', import.meta.url)).taskOwnerPolicy;

export function eligibleTaskOwner(ownerSid, runtimeSid) {
  if (ownerPolicy?.protocol !== 1 ||
      ownerPolicy.allowRuntimeUser !== true ||
      !Array.isArray(ownerPolicy.allowedOwnerSids)) throw new Error('Unsupported task owner policy.');
  return typeof ownerSid === 'string' &&
    (ownerSid === runtimeSid || ownerPolicy.allowedOwnerSids.includes(ownerSid));
}

export class WindowsLegacyTaskAdapter {
  call(operation, port, input) {
    if (process.platform !== 'win32') throw new Error('Legacy restart migration is supported only for the known Windows 1.3 registration.');
    const script = fileURLToPath(new URL('../autostart/windows/legacy-task.ps1', import.meta.url));
    const output = execFileSync('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', script, '-Operation', operation, '-Port', String(port),
    ], {
      input: input ? JSON.stringify(input) : '', encoding: 'utf8',
      windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024,
    });
    return JSON.parse(output);
  }

  inspect(port) { return this.call('inspect', port); }
  hold(port, expected) { return this.call('hold', port, { expected }); }
  repoint(port, expected, launcher) { return this.call('repoint', port, { expected, launcher }); }
  enable(port, expected) { return this.call('enable', port, { expected }); }
  restore(port, expected, original) { return this.call('restore', port, { expected, original }); }
  assertRestored(port, actual, original) {
    const { xml: actualXml, xmlSha256: actualHash, ...actualFields } = actual;
    const { xml: originalXml, xmlSha256: originalHash, ...originalFields } = original;
    if (!isDeepStrictEqual(actualFields, originalFields) ||
        typeof actualXml !== 'string' ||
        typeof originalXml !== 'string' ||
        createHash('sha256').update(actualXml).digest('hex') !== actualHash ||
        createHash('sha256').update(originalXml).digest('hex') !== originalHash) {
      throw new Error('Restored legacy registration fields, security or raw XML identity differ.');
    }
    if (actualXml === originalXml) return;
    const proof = this.call('compare-restored', port, { actual, original });
    if (proof.equivalent !== true) throw new Error('Legacy restoration equivalence was not verified.');
  }
  start(port, expected) { return this.call('start', port, { expected }); }
  stableRecords(port) { return readAutostart(port); }
}
