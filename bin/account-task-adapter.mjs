import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export function windowsArgument(value) {
  return `"${String(value).replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`;
}

export class AccountTaskAdapter {
  constructor({ taskPath, targetSid, powershell, run = execFileSync }) {
    this.taskPath = taskPath;
    this.targetSid = targetSid;
    this.powershell = powershell;
    this.run = run;
  }

  call(action, input = {}) {
    if (!this.powershell || !existsSync(this.powershell)) throw new Error('A verified absolute PowerShell toolchain is required.');
    const script = fileURLToPath(new URL('../autostart/windows/account-task.ps1', import.meta.url));
    const env = { ...process.env };
    const excluded = ['node_options', 'node_path', 'npm_execpath', 'mcp_pacemaker_cli_context', 'path', 'psmodulepath',
      'dotnet_startup_hooks', 'dotnet_additional_deps', 'dotnet_shared_store', 'complus_profapi_profilercompatibilitysetting'];
    for (const key of Object.keys(env)) {
      const lower = key.toLowerCase();
      if (excluded.includes(lower) ||
          /^(cor_|coreclr_|complus_|dotnet_)/.test(lower)) delete env[key];
    }
    env.PATH = dirname(this.powershell);
    env.PSModulePath = join(dirname(this.powershell), 'Modules');
    const output = this.run(this.powershell, ['-NoProfile', '-NonInteractive', '-File', script, '-Action', action], {
      input: JSON.stringify({ ...input, taskPath: this.taskPath, targetSid: this.targetSid }),
      cwd: dirname(this.powershell), env, encoding: 'utf8', windowsHide: true,
      timeout: 20000, maxBuffer: 65536,
    });
    return JSON.parse(output);
  }

  inspect() { return this.call('inspect'); }
  session(expected, port, root, managed) { return this.call('session', { expected, port, root, managed }); }
  bootstrap(expected, original, bootstrap) { return this.call('bootstrap', { expected, original, bootstrap }); }
  hold(expected, original) { return this.call('hold', { expected, original }); }
  repoint(expected, original, launcher) { return this.call('repoint', { expected, original, launcher }); }
  release(expected, original) { return this.call('release', { expected, original }); }
  restore(expected, original) { return this.call('restore', { expected, original }); }
  launch(expected, sessionId) { return this.call('launch', { expected, sessionId }); }
}
