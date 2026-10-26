import assert from 'node:assert/strict';
import { POLICY, exactKeys, validateApproval, validateContext } from './policy.mjs';
import { OwnerAuthEnvelope } from './owner-auth-envelope.mjs';
import { validateLocalApproval } from './local-regression.mjs';

export function validateOwnerContext({ env, event, approval, runtime = process, approvalTime = Date.now() }) {
  validateApproval(approval, 'publish-bootstrap', approvalTime);
  validateContext(env, event, approval);
  assert.equal(runtime.platform, 'linux');
  assert.equal(runtime.arch, 'x64');
  assert.equal(runtime.versions.node, POLICY.node);
  assert.equal(env.ACTUAL_RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(env.CI, 'true');
  assert.equal(env.GITHUB_JOB, 'publish-bootstrap');
  assert.equal(event.inputs?.action, 'publish-bootstrap');
  assert.deepEqual(JSON.parse(event.inputs.approval), approval);
  for (const key of ['GITHUB_RUN_ID', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID']) {
    assert.match(env[key] ?? '', /^[1-9][0-9]*$/);
  }
  assert.equal(String(event.repository.id), env.GITHUB_REPOSITORY_ID);
  assert.equal(String(event.repository.owner.id), env.GITHUB_REPOSITORY_OWNER_ID);
  assert.equal(event.repository.owner.login, POLICY.owner);
  assert.notEqual(env.GITHUB_RUN_ID, String(approval.artifact.runId));
  assert.notEqual(env.GITHUB_RUN_ID, String(approval.signedArtifact.runId));
  for (const key of Object.keys(env)) {
    const forbidden = /^(?:ACTIONS_ID_TOKEN|NPM_TOKEN$|NODE_AUTH_TOKEN$|NPM_ID_TOKEN$|SIGSTORE_ID_TOKEN$|NODE_OPTIONS$|npm_config_)/i;
    assert.ok(!forbidden.test(key) ||
      !env[key], 'Owner bootstrap forbids inherited npm configuration, credentials and OIDC');
  }
  validateOwnerKey(approval.ownerAuth);
}

export function validateOwnerKey(ownerAuth) {
  return new OwnerAuthEnvelope({ spki: ownerAuth.spki, sha256: ownerAuth.sha256 });
}

export function ownerEnvironment(env, home) {
  const keys = ['PATH', 'CI', 'GITHUB_ACTIONS', 'GITHUB_SERVER_URL', 'GITHUB_API_URL',
    'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER', 'GITHUB_REPOSITORY_OWNER_ID',
    'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'GITHUB_EVENT_PATH', 'GITHUB_ACTOR',
    'GITHUB_TRIGGERING_ACTOR', 'GITHUB_JOB', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
    'ACTUAL_RUNNER_ENVIRONMENT', 'RUNNER_TEMP', 'RUNNER_TRACKING_ID', 'NPM_PUBLICATION_CLI'];
  const child = Object.fromEntries(keys.filter(key => env[key]).map(key => [key, env[key]]));
  return { ...child, HOME: home, USERPROFILE: home, TMPDIR: home, TEMP: home, TMP: home,
    XDG_CACHE_HOME: home, XDG_CONFIG_HOME: home, NO_COLOR: '1' };
}

export function ownerBinding(approval, env) {
  return {
    repository: POLICY.repository, ref: approval.ref, commit: approval.commit,
    runId: env.GITHUB_RUN_ID, runAttempt: 1, owner: POLICY.owner, name: POLICY.name, version: '2.0.1',
    sha256: approval.artifact.sha256, keySha256: approval.ownerAuth.sha256, transaction: approval.ownerAuth.transaction,
  };
}

export function officialRegistryUrl(value) {
  assert.equal(typeof value, 'string');
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    assert.match(value, /^https:\/\/registry\.npmjs\.org(?::443)?(?:[/?]|$)/i);
  }
  const url = new URL(value, POLICY.registry);
  assert.equal(url.origin, 'https://registry.npmjs.org', 'Only the public npm registry is allowed');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  assert.ok(!/[\u0000-\u0020\\]/.test(value), 'Invalid registry URL');
  return url.href;
}

export function officialWebsiteUrl(value) {
  assert.equal(typeof value, 'string');
  assert.ok(value.length <= 2048 &&
    value.isWellFormed());
  assert.match(value, /^https:\/\/(?:www\.npmjs\.com|npmjs\.com)(?::443)?(?:[/?]|$)/i);
  const url = new URL(value);
  assert.ok(['https://www.npmjs.com', 'https://npmjs.com'].includes(url.origin),
    'Owner challenge must use the official HTTPS npm website');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  assert.ok(!/[\u0000-\u0020\\]/.test(value));
  return value;
}

export function confirmedPublicationChallenge(error) {
  const confirmed = error?.code === 'EOTP' &&
    error.statusCode === 401 &&
    error.method === 'PUT' &&
    error.uri === `${POLICY.registry}${POLICY.name}` &&
    typeof error.body?.authUrl === 'string' &&
    typeof error.body?.doneUrl === 'string';
  if (!confirmed) return null;
  return { authUrl: officialWebsiteUrl(error.body.authUrl), doneUrl: officialRegistryUrl(error.body.doneUrl) };
}

export function validateOwnerReply(message, expected) {
  exactKeys(message, ['type', 'requestId', 'binding', 'ok'], 'owner verification reply');
  assert.equal(message.type, 'verified');
  assert.equal(message.requestId, expected.requestId);
  assert.deepEqual(message.binding, expected.binding);
  assert.equal(message.ok, true, 'Fresh source/artifact verification failed');
}

// Injected SDK boundaries are unit-test seams, not crypto/server evidence.
export async function publishOwnerOnce({ approval, sdk, revalidate, record, challenge, signal }) {
  validateLocalApproval(approval);
  validateApproval(approval, 'publish-bootstrap');
  validateLocalApproval(approval);
  validateOwnerKey(approval.ownerAuth);
  let token;
  let outcome = 'not-submitted';
  let cleanup = 'not-needed';
  let attempts = 0;
  const check = async () => {
    signal?.throwIfAborted();
    validateApproval(approval, 'publish-bootstrap');
    await revalidate();
    signal?.throwIfAborted();
  };
  try {
    await check();
    await record({ phase: 'owner-login-starting' });
    cleanup = 'login-outcome-unknown';
    token = await sdk.login(url => challenge(1, 'login', officialWebsiteUrl(url)), signal);
    assert.ok(typeof token === 'string' &&
      token.length > 0 &&
      token.length <= 4096 &&
      !/[\s\u0000-\u001f]/.test(token), 'Invalid owner session');
    cleanup = 'pending';
    assert.equal(await sdk.whoami(token), POLICY.owner, 'Authenticated npm owner differs from approval');
    const profile = await sdk.profile(token);
    assert.equal(profile.name, POLICY.owner);
    assert.equal(profile.tfa?.mode, 'auth-and-writes', 'Owner account must enforce 2FA for writes');
    await record({ phase: 'owner-authenticated', owner: POLICY.owner, write2fa: 'required' });
    await check();
    const submit = async otp => {
      assert.equal(await sdk.whoami(token), POLICY.owner);
      await sdk.checkBytes();
      signal?.throwIfAborted();
      attempts++;
      outcome = 'submission-outcome-unknown';
      // Persist and fsync before handing control to the sole direct-PUT boundary.
      await record({ phase: outcome, attempt: attempts });
      const response = await sdk.publish(token, otp, signal);
      assert.ok([200, 201].includes(response?.status), 'Unrecognized publication response');
      outcome = 'published-awaiting-registry-readback';
      await record({ phase: outcome, attempt: attempts });
    };
    try {
      await submit(undefined);
    } catch (error) {
      const pair = confirmedPublicationChallenge(error);
      if (!pair) throw new Error('Publication outcome requires owner reconciliation');
      outcome = 'confirmed-publication-2fa-required';
      await record({ phase: outcome, attempt: 1 });
      const otp = await sdk.webAuth(pair, url => challenge(2, 'publish-2fa', officialWebsiteUrl(url)), signal);
      assert.ok(typeof otp === 'string' &&
        otp.length > 0 &&
        otp.length <= 4096 &&
        !/[\s\u0000-\u001f]/.test(otp), 'Invalid browser authorization response');
      await check();
      // Exactly one auth continuation, only for a confirmed rejection of this package PUT.
      await submit(otp);
    }
    await sdk.readback();
    outcome = 'published-readback-matched';
    await record({ phase: outcome, registrySignatures: 'pending-verification',
      publishedProvenance: 'pending-registry-retrieval-and-verification', freshRegistryConsumers: 'pending' });
  } catch {
    await record({ phase: 'stopped', outcome, attempts, instruction: 'No retry. Reconcile the owner release ledger.' });
  } finally {
    if (token) {
      try {
        await sdk.logout(token);
        cleanup = 'revoked';
      } catch {
        cleanup = 'revocation-failed-owner-action-required';
      }
      token = undefined;
    }
    await record({ phase: 'owner-session-cleanup', status: cleanup });
  }
  return { outcome, attempts, cleanup, success: outcome === 'published-readback-matched' &&
    cleanup === 'revoked' };
}
