import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import {
  LIMITS, guarded, isolatedEnvironment, readJson, requireCondition, runBounded,
  sha256, validateBinding, workspace,
} from './core.mjs';
import { scanAdvisories } from './advisories.mjs';
import { scanPrivateContent } from './private.mjs';
import { TOOL_PINS, scanArtifact, scanSource, toolsFromEnvironment } from './secrets.mjs';

const GATES = Object.freeze({
  source: ['source-gitleaks', 'source-trufflehog', 'source-private-identifiers', 'producer-advisories'],
  artifact: ['payload-gitleaks', 'payload-trufflehog', 'payload-private-identifiers', 'consumer-advisories'],
});

function requestedGates(request) {
  const supported = Object.hasOwn(GATES, request?.phase) ? GATES[request.phase] : [];
  return supported.filter(name => Array.isArray(request?.requiredGates) && request.requiredGates.includes(name));
}

function evidence(description, value) {
  return { description, sha256: sha256(JSON.stringify(value)) };
}

function samePath(left, right) {
  return process.platform === 'win32'
    ? resolve(left).toLowerCase() === resolve(right).toLowerCase()
    : resolve(left) === resolve(right);
}

export function validatePublicationRequest(request) {
  requireCondition(request?.schemaVersion === 1 && Object.hasOwn(GATES, request.phase),
    'publication-request-schema');
  requireCondition(Array.isArray(request.requiredGates) && request.requiredGates.length > 0 &&
    request.requiredGates.every(name => typeof name === 'string') &&
    new Set(request.requiredGates).size === request.requiredGates.length, 'publication-required-gates-schema');
  validateBinding({ commit: request.commit });
  requireCondition(typeof request.sourceRoot === 'string' && isAbsolute(request.sourceRoot) &&
    typeof request.root === 'string' && isAbsolute(request.root), 'publication-absolute-roots-required');
  requireCondition(typeof request.name === 'string' && request.name.length <= 214 &&
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(request.name) &&
    typeof request.version === 'string' && request.version.length <= 128 &&
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(request.version),
  'publication-package-binding-schema');
  if (request.phase === 'source') {
    requireCondition(samePath(request.root, request.sourceRoot) && request.artifact === undefined &&
      request.consumers === undefined, 'publication-source-scope-mismatch');
  } else {
    requireCondition(typeof request.extractedRoot === 'string' && isAbsolute(request.extractedRoot) &&
      samePath(request.root, request.extractedRoot) &&
      typeof request.tarball === 'string' && isAbsolute(request.tarball), 'publication-artifact-path-schema');
    const artifact = request.artifact;
    requireCondition(artifact && /^[a-f0-9]{64}$/.test(artifact.sha256) &&
      /^[a-f0-9]{128}$/.test(artifact.sha512) &&
      artifact.integrity === `sha512-${Buffer.from(artifact.sha512, 'hex').toString('base64')}`,
    'publication-artifact-digest-schema');
    requireCondition(Array.isArray(request.consumers) && request.consumers.length === 2,
      'both-npm12-consumer-summaries-required');
    const [first, second] = request.consumers;
    requireCondition(first && second && first.node === second.node && first.npm === second.npm &&
      first.platform === second.platform && /^12\.\d+\.\d+$/.test(first.npm) &&
      new Set(request.consumers.map(item => item.installScripts)).size === 2 &&
      request.consumers.every(item => ['npm-default', 'disabled'].includes(item.installScripts)),
    'npm12-consumer-lane-mismatch');
  }
  return requestedGates(request);
}

async function checkedRoot(root) {
  const info = await lstat(root);
  requireCondition(info.isDirectory() && !info.isSymbolicLink() && samePath(root, await realpath(root)),
    'publication-root-link-or-type');
}

async function artifactDigests(path) {
  const info = await lstat(path);
  requireCondition(info.isFile() && !info.isSymbolicLink() && info.size > 0 &&
    info.size <= LIMITS.fileBytes, 'publication-tarball-input');
  const digest256 = createHash('sha256');
  const digest512 = createHash('sha512');
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    bytes += chunk.length;
    requireCondition(bytes <= LIMITS.fileBytes, 'publication-tarball-size-limit');
    digest256.update(chunk);
    digest512.update(chunk);
  }
  requireCondition(bytes === info.size, 'publication-tarball-changed');
  const sha512 = digest512.digest('hex');
  return { sha256: digest256.digest('hex'), sha512,
    integrity: `sha512-${Buffer.from(sha512, 'hex').toString('base64')}` };
}

async function verifyRequestBinding(request, tools) {
  await checkedRoot(request.sourceRoot);
  await checkedRoot(request.root);
  return workspace(async temp => {
    const context = { cwd: temp, env: isolatedEnvironment(temp), timeoutMs: 30_000 };
    const args = ['-c', 'core.hooksPath=', '-c', 'credential.helper=', '-C', request.sourceRoot,
      'rev-parse', '--show-toplevel', '--verify', 'HEAD^{commit}'];
    const result = await runBounded(tools.git ?? 'git', args, context);
    const lines = result.stdout.trim().split(/\r?\n/);
    requireCondition(result.code === 0 && result.stderr.trim() === '' && lines.length === 2 &&
      samePath(lines[0], request.sourceRoot) && lines[1] === request.commit,
    'publication-head-binding-mismatch');
    const sourceManifest = await readJson(join(request.sourceRoot, 'package.json'));
    requireCondition(sourceManifest.value.name === request.name && sourceManifest.value.version === request.version,
      'publication-source-package-mismatch');
    let payloadManifestSha256;
    if (request.phase === 'artifact') {
      const artifact = await artifactDigests(request.tarball);
      requireCondition(Object.keys(artifact).every(key => artifact[key] === request.artifact[key]),
        'publication-tarball-digest-mismatch');
      const manifest = await readJson(join(request.root, 'package.json'));
      requireCondition(manifest.value.name === request.name && manifest.value.version === request.version,
        'publication-payload-package-mismatch');
      payloadManifestSha256 = manifest.sha256;
    }
    return { sourceManifestSha256: sourceManifest.sha256,
      ...(payloadManifestSha256 ? { payloadManifestSha256 } : {}) };
  });
}

export function publicationSecretGates(result, phase, names) {
  const prefix = phase === 'source' ? 'source' : 'payload';
  const scopes = phase === 'source' ? ['working-tree', 'history'] : ['unpacked-artifact'];
  const gates = {};
  for (const tool of ['gitleaks', 'trufflehog']) {
    const name = `${prefix}-${tool}`;
    if (!names.includes(name)) continue;
    const executions = result.executions?.filter(item => item.tool?.name === tool) ?? [];
    const complete = executions.length === scopes.length &&
      scopes.every(scope => executions.filter(item => item.scope === scope).length === 1) &&
      executions.every(item => item.tool.version === TOOL_PINS[tool].version &&
        /^[a-f0-9]{64}$/.test(item.tool.sha256) && /^[a-f0-9]{64}$/.test(item.commandSha256));
    const passed = ['passed', 'findings'].includes(result.status) && complete &&
      executions.every(item => item.status === 'passed');
    gates[name] = {
      status: passed ? 'passed' : 'failed',
      evidence: [evidence(`${name}; full scanner report; online verification and automatic updates disabled`, result)],
    };
    if (complete) {
      for (const execution of executions) {
        gates[name].evidence.push(evidence(
          `${execution.scope}; ${tool} ${execution.tool.version}; binary SHA256 ${execution.tool.sha256}; ` +
            `argument-vector SHA256 ${execution.commandSha256}; redacted execution evidence`,
          execution));
      }
    }
  }
  return gates;
}

export async function scanPublicationRequest({
  request, tools = toolsFromEnvironment(), policyPath, publicPackages, publicPackagesPath,
  exemptionsPath, fetchImpl,
}) {
  const scannerDetails = {};
  const result = await guarded('publication-scanner-request', async () => {
    const names = validatePublicationRequest(request);
    const before = await verifyRequestBinding(request, tools);
    const prefix = request.phase === 'source' ? 'source' : 'payload';
    let gates = {};
    if (names.some(name => name === `${prefix}-gitleaks` ||
        name === `${prefix}-trufflehog`)) {
      const secrets = request.phase === 'source'
        ? await scanSource({ root: request.root, tools })
        : await scanArtifact({ root: request.root, tools, artifactSha256: request.artifact.sha256 });
      scannerDetails.secrets = secrets;
      gates = publicationSecretGates(secrets, request.phase, names);
    }
    const privateName = `${prefix}-private-identifiers`;
    if (names.includes(privateName)) {
      const policy = await scanPrivateContent({
        root: request.root, policyPath, source: request.phase === 'source',
        binding: { commit: request.commit, artifactSha256: request.artifact?.sha256 },
      });
      scannerDetails.privatePolicy = policy;
      gates[privateName] = {
        status: policy.status === 'passed' ? 'passed' : policy.status === 'not-run' ? 'not-run' : 'failed',
        ownerReview: 'pending',
        evidence: [evidence(`${privateName}; literal policy only; separate owner review pending`, policy)],
      };
    }
    const advisoryName = request.phase === 'source' ? 'producer-advisories' : 'consumer-advisories';
    if (names.includes(advisoryName)) {
      const input = request.phase === 'source'
        ? { locks: [
          { path: join(request.sourceRoot, 'package-lock.json'), scope: 'producer-root' },
          { path: join(request.sourceRoot, 'ui', 'package-lock.json'), scope: 'producer-ui' },
        ] }
        : { consumers: request.consumers, localArtifact: {
          name: request.name, version: request.version,
          sha256: request.artifact.sha256, integrity: request.artifact.integrity,
        } };
      const advisory = await scanAdvisories({
        ...input, publicPackages, publicPackagesPath, exemptionsPath, fetchImpl,
      });
      scannerDetails.advisories = advisory;
      gates[advisoryName] = {
        status: advisory.status === 'passed' ? 'passed' : 'failed',
        evidence: [evidence(`${advisoryName}; OSV exact supplied graphs; public coordinates only; per-run responses`,
          advisory)],
      };
    }
    const after = await verifyRequestBinding(request, tools);
    requireCondition(JSON.stringify(before) === JSON.stringify(after), 'publication-binding-changed');
    const statuses = Object.values(gates).map(gate => gate.status);
    const scannerError = Object.values(scannerDetails).some(detail => detail.status === 'error');
    return { phase: request.phase, commit: request.commit,
      ...(request.phase === 'artifact' ? { artifact: {
        sha256: request.artifact.sha256, sha512: request.artifact.sha512, integrity: request.artifact.integrity,
      } } : {}),
      status: scannerError ? 'error' : statuses.includes('failed') ? 'findings' :
        statuses.length === 0 || statuses.includes('not-run') ? 'not-run' : 'passed',
      ...(scannerError ? { error: 'publication-scanner-gate-error' } : {}),
      gates, scannerDetails, requestSha256: sha256(JSON.stringify(request)), bindingEvidence: before,
      privateContentReview: { status: 'pending', commit: request.commit,
        ...(request.artifact ? { artifactSha256: request.artifact.sha256 } : {}) },
      limits: 'Scanner gates only. HEAD plus current working bytes is not proof of a clean committed tree. ' +
        'Tarball hashes are verified; extraction identity is the calling extractor responsibility. ' +
        'No native/platform/license gates or owner approval are supplied.',
    };
  });
  if (result.status === 'error' &&
      !result.gates) {
    return { ...result,
      ...(Object.hasOwn(GATES, request?.phase) ? { phase: request.phase } : {}),
      ...(/^[a-f0-9]{40,64}$/.test(request?.commit) ? { commit: request.commit } : {}),
      ...(request?.phase === 'artifact' && /^[a-f0-9]{64}$/.test(request.artifact?.sha256) &&
        /^[a-f0-9]{128}$/.test(request.artifact?.sha512) &&
        /^sha512-[A-Za-z0-9+/]{86}==$/.test(request.artifact?.integrity) ? { artifact: {
          sha256: request.artifact.sha256, sha512: request.artifact.sha512, integrity: request.artifact.integrity,
        } } : {}),
      scannerDetails,
      gates: Object.fromEntries(requestedGates(request).map(name => [name, {
        status: name.endsWith('-private-identifiers') && !policyPath ? 'not-run' : 'failed',
        evidence: [evidence(`${name}; request, binding or scanner operation failed`, result)],
      }])),
    };
  }
  return result;
}
