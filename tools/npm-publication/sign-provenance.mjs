import assert from 'node:assert/strict';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, sameDigests } from './policy.mjs';
import { bootstrapWorkflow, validateBootstrapContext } from './bootstrap.mjs';
import { bootstrapEnvironment } from './run.mjs';
import { npmProvenance, verifyProvenance } from './provenance.mjs';

// Private child of run.mjs, not an owner publication command. No npm registry write is implemented.
export async function signProvenance(contextPath, tarball, output) {
  const context = JSON.parse(readFileSync(contextPath, 'utf8'));
  const env = process.env;
  const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
  validateBootstrapContext({ env, event, approval: context.approval });
  bootstrapEnvironment(env, env.HOME);
  assert.deepEqual(context.workflow, bootstrapWorkflow(env));
  for (const path of [contextPath, tarball]) {
    const stat = lstatSync(path);
    assert.ok(stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.nlink === 1);
  }
  const bytes = readFileSync(tarball);
  sameDigests(digest(bytes), context.approval.artifact);
  const api = npmProvenance(env.NPM_PUBLICATION_CLI);
  const record = {
    version: '2.0.1', source: context.approval, artifact: digest(bytes), workflow: context.workflow,
  };
  const bundle = await api.generate([api.subject('mcp-pacemaker', '2.0.1', record.artifact.sha512)], {
    retry: { retries: 0 }, tufCachePath: join(env.HOME, 'tuf'),
  });
  await verifyProvenance({ record, bundle, verifyBundle: api.verifyBundle, cache: join(env.HOME, 'tuf') });
  sameDigests(digest(readFileSync(tarball)), record.artifact);
  writeFileSync(output, `${JSON.stringify(bundle)}\n`, { flag: 'wx', mode: 0o600 });
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  Promise.resolve().then(() => {
    assert.equal(process.argv.length, 5, 'Expected private context, tarball and new bundle paths');
    return signProvenance(...process.argv.slice(2));
  }).catch(() => {
    // Signing errors can contain identity tokens. Never echo the exception or child output.
    console.error('Signing stopped; outcome may be unknown. No retry. Reconcile the retained ledger.');
    process.exitCode = 1;
  });
}
