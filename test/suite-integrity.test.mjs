// Guard: every test file must actually be in the suite.
//
// `npm test` names its files explicitly, which is portable across the Node versions in CI but
// silently drifts — two new test files were written, passed when run directly, and did not run
// under `npm test` at all. A suite that quietly skips tests is worse than one that fails, so the
// list checks itself.
//
// Also guards the port allocation table, since files that never run together in CI would not
// collide and the clash would only show up later.
import { test } from 'node:test';
import assert from 'node:assert';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const suiteFiles = () => {
  const script = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')).scripts.test;
  return script.match(/test\/[\w.-]+\.test\.mjs/g) ?? [];
};

test('every test file is listed in the npm test script', () => {
  const onDisk = readdirSync(resolve(ROOT, 'test')).filter((f) => f.endsWith('.test.mjs')).map((f) => `test/${f}`);
  const listed = suiteFiles();
  const missing = onDisk.filter((f) => !listed.includes(f));
  assert.deepEqual(missing, [], `these test files exist but never run under "npm test": ${missing.join(', ')}`);
});

test('the npm test script does not name a file that no longer exists', () => {
  const onDisk = new Set(readdirSync(resolve(ROOT, 'test')).filter((f) => f.endsWith('.test.mjs')).map((f) => `test/${f}`));
  const stale = suiteFiles().filter((f) => !onDisk.has(f));
  assert.deepEqual(stale, [], `named in "npm test" but missing from disk: ${stale.join(', ')}`);
});

test('no two test files claim the same port', () => {
  // Files run concurrently, so an overlap is a flake that only appears under load.
  //
  // Comments are stripped first: one file carries the shared allocation table listing every
  // port in the suite, and counting those would make every port look doubly claimed.
  const claims = new Map();
  for (const f of readdirSync(resolve(ROOT, 'test')).filter((x) => x.endsWith('.test.mjs'))) {
    const src = readFileSync(resolve(ROOT, 'test', f), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    for (const m of src.matchAll(/\b(88\d\d)\b/g)) {
      const port = m[1];
      if (!claims.has(port)) claims.set(port, new Set());
      claims.get(port).add(f);
    }
  }
  const shared = [...claims.entries()]
    .filter(([, files]) => files.size > 1)
    .map(([port, files]) => `${port}: ${[...files].join(' + ')}`);
  assert.deepEqual(shared, [], `ports claimed by more than one file:\n  ${shared.join('\n  ')}`);
});
