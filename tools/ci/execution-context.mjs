import { execFile } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import { promisify } from 'node:util';
import { requireUserRuntimeContext } from '../../bin/runtime-context.mjs';
import { queryCurrentUserSession, queryTaskChannelCaller } from '../../bin/windows-task-channel.mjs';

export class ExecutionContext {
  constructor({
    platform = process.platform,
    ordinary = requireUserRuntimeContext,
    windowsSession = queryCurrentUserSession,
    privileged = queryTaskChannelCaller,
    inspect = lstatSync,
    canonical = realpathSync.native,
    run = promisify(execFile),
  } = {}) {
    Object.assign(this, { platform, ordinary, windowsSession, privileged, inspect, canonical, run });
  }

  blocked(reason, cause) {
    throw Object.assign(new Error(`CI execution contract is blocked: ${reason}. Supply a preconfigured runner; no context repair was attempted.`,
      cause ? { cause } : undefined), { code: 'CI_CONTEXT_UNAVAILABLE' });
  }

  async require(contract) {
    if (contract.platform !== this.platform) this.blocked('the selected platform does not match the process');
    if (contract.role === 'privileged-fixture') {
      if (this.platform !== 'win32') this.blocked('no privileged fixture is declared for this platform');
      const result = await this.privileged();
      const facts = result.actorFacts;
      if (facts?.elevated !== true ||
          facts?.enabledAdministrator !== true ||
          facts?.restricted !== false ||
          facts?.appContainer !== false ||
          facts?.guardThreadImpersonating !== false ||
          facts?.parentThreadImpersonation !== 'observed-none' ||
          result.helperExit?.code !== 0 ||
          result.helperExit?.signal !== null) this.blocked('the privileged fixture caller is unverified');
      return { platform: this.platform, role: contract.role, verified: true };
    }
    if (contract.role !== 'user-runtime') this.blocked('the test role is unknown');
    const caller = await this.ordinary();
    if (caller?.ordinary !== true ||
        caller.platform !== this.platform) this.blocked('the ordinary caller observation is invalid');
    if (!contract.session) return { platform: this.platform, role: contract.role, verified: true };
    try {
      if (this.platform === 'win32') {
        const observed = await this.windowsSession();
        const expected = caller.native?.identity;
        if (!expected ||
            observed.proofScope !== 'current-user-session-snapshot' ||
            observed.identity?.pid !== expected.pid ||
            observed.identity?.creationTime !== expected.creationTime ||
            observed.identity?.ownerSid !== expected.ownerSid ||
            observed.identity?.sessionId !== expected.sessionId ||
            observed.session?.ownerSid !== expected.ownerSid ||
            observed.session?.sessionId !== expected.sessionId ||
            !['active', 'disconnected'].includes(observed.session?.state) ||
            !/^[1-9][0-9]{0,18}$/.test(observed.session?.logonTime ?? '')) {
          this.blocked('the Windows session caller changed or its logon is unverified');
        }
      } else if (this.platform === 'linux') {
        const uid = caller.identity.euid;
        const directory = `/run/user/${uid}`;
        const runtime = this.inspect(directory);
        const bus = this.inspect(`${directory}/bus`);
        if (!runtime.isDirectory() ||
            runtime.isSymbolicLink() ||
            runtime.uid !== uid ||
            (runtime.mode & 0o022) !== 0 ||
            !bus.isSocket() ||
            bus.uid !== uid ||
            this.canonical(directory) !== directory) this.blocked('the user service-manager endpoint is unverified');
        const result = await this.run('/usr/bin/systemctl', ['--user', 'show', '--property=Version', '--value'],
          { timeout: 10000, maxBuffer: 65536, encoding: 'utf8', env: {
            PATH: '/usr/bin:/bin', XDG_RUNTIME_DIR: directory,
            DBUS_SESSION_BUS_ADDRESS: `unix:path=${directory}/bus`,
          } });
        if (!result.stdout.trim()) this.blocked('the user service manager did not identify itself');
      } else if (this.platform === 'darwin') {
        await this.run('/bin/launchctl', ['print', `gui/${caller.identity.euid}`],
          { timeout: 10000, maxBuffer: 1024 * 1024, encoding: 'utf8' });
      } else this.blocked('there is no supported session observer');
    } catch (error) {
      if (error.code === 'CI_CONTEXT_UNAVAILABLE') throw error;
      this.blocked('the required native user session or service manager is unavailable', error);
    }
    return { platform: this.platform, role: contract.role, verified: true, sessionVerified: true };
  }
}
