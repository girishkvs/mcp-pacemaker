import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ownedDirectory, removeOwnedDirectory } from '../compatibility/fixtures.mjs';
import { POLICY } from './policy.mjs';
import { BOOTSTRAP_FILES, CANDIDATE_FILES, exactFiles, verifyBootstrap } from './bootstrap.mjs';
import { githubReaders } from './matrix.mjs';
import { sourceAndCi, sourceLocks, cleanNpmEnvironment } from './run.mjs';
import { npmProvenance } from './provenance.mjs';
import { validateOwnerContext } from './owner-bootstrap.mjs';
import { validateLocalApproval } from './local-regression.mjs';
import { readSignedArtifact, readCandidateEvidence, readRemoteSource, readProtectedEnvironment,
  readAbsentRegistry, readOwnerRun } from './bootstrap-readers.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outside = (path, directory) => {
  const part = relative(directory, path);
  return part.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) ||
    part === '..' ||
    isAbsolute(part);
};

export function readBootstrapDirectory(directory) {
  assert.ok(isAbsolute(directory), 'Use an absolute canonical downloaded-artifact directory');
  assert.equal(fs.realpathSync.native(directory), resolve(directory), 'Artifact directory must not be an alias');
  const stat = fs.lstatSync(directory);
  assert.ok(stat.isDirectory() &&
    !stat.isSymbolicLink());
  const files = new Map();
  for (const name of fs.readdirSync(directory)) {
    const path = join(directory, name);
    const item = fs.lstatSync(path);
    assert.ok(item.isFile() &&
      !item.isSymbolicLink() &&
      item.nlink === 1 &&
      item.size <= 128 * 1024 * 1024, 'Unexpected linked, oversized or non-file artifact member');
    files.set(name, fs.readFileSync(path));
  }
  exactFiles(files, BOOTSTRAP_FILES);
  return files;
}

export function writeVerificationReceipt(output, receipt, input) {
  assert.ok(isAbsolute(output));
  assert.equal(fs.realpathSync.native(dirname(output)), resolve(dirname(output)),
    'Output parent must be an existing canonical directory');
  assert.ok(outside(output, root) &&
    outside(output, input), 'Receipt output must be outside source and signed artifact');
  fs.writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

export async function main(args) {
  assert.equal(args.length, 6, 'Expected --approval <json> --directory <artifact> --output <new receipt>');
  assert.deepEqual([args[0], args[2], args[4]], ['--approval', '--directory', '--output']);
  const [, approvalPath, , directory, , output] = args;
  for (const path of [approvalPath, directory, output]) assert.ok(isAbsolute(path));
  assert.equal(process.versions.node, POLICY.node, 'Use the reviewed verifier Node patch');
  // This never invokes npm and never reads npm account configuration.
  cleanNpmEnvironment(process.env, fs.realpathSync.native(tmpdir()));
  const approval = JSON.parse(fs.readFileSync(approvalPath, 'utf8'));
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  validateOwnerContext({ env: process.env, event, approval });
  const verifier = await createHostedBootstrapVerifier({ approval, directory });
  try {
    const receipt = await verifier.verify();
    writeVerificationReceipt(output, receipt, directory);
    console.log(JSON.stringify({ status: receipt.status, npmWrite: 'not-performed', output }));
  } finally {
    verifier.close();
  }
}

export async function createHostedBootstrapVerifier({ approval, directory, env = process.env }) {
  validateLocalApproval(approval);
  const event = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
  validateOwnerContext({ env, event, approval });
  const local = readBootstrapDirectory(directory);
  const readers = githubReaders(env);
  const signed = await readSignedArtifact(approval, readers);
  assert.deepEqual(local, signed.files, 'Downloaded signed files differ from the actual GitHub API ZIP');
  const locks = sourceLocks();
  const revalidate = async () => {
    validateOwnerContext({ env, event, approval });
    await sourceAndCi(approval);
    assert.deepEqual(sourceLocks(), locks);
    const source = await readRemoteSource(approval, readers);
    assert.equal(source.repositoryId, signed.workflow.repositoryId);
    assert.equal(source.ownerId, signed.workflow.ownerId);
    const environment = await readProtectedEnvironment(approval, signed.workflow.runId, readers);
    const publicationRun = await readOwnerRun(approval, env.GITHUB_RUN_ID, readers);
    assert.equal(publicationRun.repositoryId, env.GITHUB_REPOSITORY_ID);
    assert.equal(publicationRun.ownerId, env.GITHUB_REPOSITORY_OWNER_ID);
    const publicationEnvironment = await readProtectedEnvironment(approval, env.GITHUB_RUN_ID, readers);
    assert.equal(publicationEnvironment.id, 21922517673, 'Protected bootstrap environment was replaced');
    const candidate = await readCandidateEvidence(approval, locks, readers);
    for (const name of CANDIDATE_FILES) assert.deepEqual(candidate.files.get(name), local.get(name));
    assert.deepEqual(await readSignedArtifact(approval, readers), signed);
    assert.deepEqual(readBootstrapDirectory(directory), local);
    return { source, environment, publicationRun, publicationEnvironment,
      preparation: candidate.evidence, registry: await readAbsentRegistry() };
  };
  await revalidate();
  const cache = ownedDirectory();
  try {
    const api = npmProvenance(env.NPM_PUBLICATION_CLI);
    return {
      verify: async () => {
        const receipt = await verifyBootstrap({ approval, files: local, locks, workflow: signed.workflow,
          revalidate, verifyBundle: api.verifyBundle, cache: join(cache.dir, 'tuf') });
        assert.deepEqual(readBootstrapDirectory(directory), local);
        return receipt;
      },
      close: () => removeOwnedDirectory(cache),
    };
  } catch (error) {
    removeOwnedDirectory(cache);
    throw error;
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => {
    console.error('Bootstrap verification stopped. No publication or owner approval was performed.');
    process.exitCode = 1;
  });
}
