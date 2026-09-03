// Shared teardown for tests that spawn a bridge.
//
// `child.kill()` on Windows is TerminateProcess, so the bridge's SIGTERM handler never runs and
// every MCP server child it spawned is orphaned. One suite run leaked 24 of them; run the suite
// a few times inside the fixture's 120s self-destruct window and the machine is loaded enough
// that teardown elsewhere misses its deadline — which is how this surfaced, as an
// unrelated-looking flake in the kill-tree test.
//
// Killing the tree instead of the process leaves nothing behind.
import { execFileSync } from 'node:child_process';

export function killBridge(child) {
  if (!child) return;
  const pid = child.pid;
  if (process.platform !== 'win32' || !pid) {
    try { child.kill(); } catch { /* already gone */ }
    return;
  }
  try { execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' }); }
  catch { /* already gone */ }
  try { child.kill(); } catch { /* already gone */ }
}
