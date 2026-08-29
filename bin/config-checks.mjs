// Configuration checks shared by `mcp-pacemaker doctor` and the dashboard Health page, so the
// two cannot drift apart.

import { existsSync } from 'node:fs';
import { isAbsolute, resolve, extname } from 'node:path';

const SCRIPT_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.py', '.ps1', '.sh', '.rb', '.jar']);

// Arguments that address a file on disk, as opposed to a flag, a URL, or a package name.
// Only a script extension or an explicit `./`-style prefix counts, because package specs passed
// to a runner (`npx @scope/pkg`, `uvx tool`) also contain slashes and must not be flagged.
export function relativePathArgs(def) {
  const args = Array.isArray(def?.args) ? def.args : [];
  return args.filter((a) => {
    if (typeof a !== 'string' || !a || a.startsWith('-') || a.includes('://')) return false;
    if (isAbsolute(a)) return false;
    return SCRIPT_EXT.has(extname(a).toLowerCase()) || /^\.\.?[\\/]/.test(a);
  });
}

// A relative path is resolved against the bridge's base directory, not the directory the config
// was imported from. When a host's config assumed a project root, those paths point nowhere once
// imported: the server dies at spawn with MODULE_NOT_FOUND while `status` still lists it as
// configured, and nothing surfaces it until a client actually calls that server. Reporting it up
// front is the cheap way to catch a class of failure that is otherwise silent.
//
// Returns a check object, or null when there is nothing to report.
export function checkServerPaths(name, def, baseCwd) {
  if (!def?.command) return null; // http servers have no working directory
  const rel = relativePathArgs(def);
  if (!rel.length) return null;

  const base = def.cwd ? resolve(baseCwd, def.cwd) : baseCwd;
  const missing = rel.filter((a) => !existsSync(resolve(base, a)));
  if (missing.length) {
    return {
      name,
      status: 'bad',
      detail: def.cwd
        ? `path not found under cwd ${base}: ${missing.join(', ')}`
        : `no "cwd" set, so ${missing.join(', ')} resolves under ${base} and does not exist`,
    };
  }
  if (!def.cwd) {
    return {
      name,
      status: 'warn',
      detail: `relative path with no "cwd" — resolved from ${base}: ${rel.join(', ')}`,
    };
  }
  return null;
}
