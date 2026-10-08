const crypto = require('node:crypto');
const sodium = require('libsodium-wrappers');
const {
  ManagementApiVersions,
  TunnelManagementHttpClient
} = require('@microsoft/dev-tunnels-management');
const { TunnelAccessScopes } = require('@microsoft/dev-tunnels-contracts');
const { Relay } = require('./relay.cjs');

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

class DeviceLogin {
  constructor(fetcher = fetch) {
    this.fetcher = fetcher;
    this.clientId = '178c6fc778ccc68e1d6a';
  }

  async post(endpoint, values, retryable = false, intervalSeconds = 5) {
    const limit = retryable ? 4 : 1;
    for (let attempt = 0; attempt < limit; attempt++) {
      let retryDelay = Math.max(intervalSeconds, 5 * (2 ** attempt));
      try {
        const response = await this.fetcher('https://github.com/login/' + endpoint, {
          method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30000),
          headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(values)
        });
        if (response.status >= 500 ||
            response.status === 429) {
          const requested = Number(response.headers.get('retry-after'));
          if (Number.isFinite(requested)) {
            retryDelay = Math.max(retryDelay, requested);
          }
          throw new Error('AUTH_TRANSIENT_HTTP');
        }
        if (!response.ok) {
          throw new Error('AUTH_HTTP_' + response.status);
        }
        return await response.json();
      } catch (error) {
        const transient = (
          error instanceof TypeError ||
          error.name === 'TimeoutError' ||
          error.message === 'AUTH_TRANSIENT_HTTP'
        );
        if (!transient ||
            attempt + 1 === limit) {
          throw new Error('AUTH_REQUEST_FAILED');
        }
        await sleep(retryDelay * 1000);
      }
    }
  }

  async login(scope, label) {
    const device = await this.post('device/code', { client_id: this.clientId, scope });
    if (device.error) {
      throw new Error('DEVICE_CODE_REFUSED');
    }
    const deadline = Date.now() + device.expires_in * 1000;
    console.log(JSON.stringify({
      authorization: label,
      verificationUrl: device.verification_uri,
      userCode: device.user_code,
      expiresAt: new Date(deadline).toISOString(),
      account: 'girishkvs', requestedScope: scope
    }));
    let interval = device.interval || 5;
    while (Date.now() < deadline) {
      await sleep(interval * 1000);
      const result = await this.post('oauth/access_token', {
        client_id: this.clientId, device_code: device.device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      }, true, interval);
      if (result.access_token) {
        return { token: result.access_token, scopes: String(result.scope || '').split(/[,\s]+/).filter(Boolean) };
      }
      if (result.error === 'authorization_pending') {
        continue;
      }
      if (result.error === 'slow_down') {
        interval += 5;
        continue;
      }
      if (result.error === 'expired_token') {
        throw new Error('DEVICE_AUTHORIZATION_EXPIRED');
      }
      if (result.error === 'access_denied') {
        throw new Error('DEVICE_AUTHORIZATION_DENIED');
      }
      throw new Error('DEVICE_AUTHORIZATION_ENDED');
    }
    throw new Error('DEVICE_AUTHORIZATION_EXPIRED');
  }
}

class GitHubApi {
  constructor(token, audit = () => {}, fetcher = fetch) {
    this.token = token;
    this.audit = audit;
    this.fetcher = fetcher;
  }

  async request(method, endpoint, body, absent = false) {
    if (!endpoint.startsWith('/')) {
      throw new Error('INVALID_GITHUB_ENDPOINT');
    }
    const mutating = method !== 'GET';
    if (mutating) {
      this.audit({ phase: 'attempt', method, endpoint });
    }
    let response;
    const limit = mutating ? 1 : 4;
    for (let attempt = 0; attempt < limit; attempt++) {
      let delay = 5000 * (2 ** attempt);
      try {
        response = await this.fetcher('https://api.github.com' + endpoint, {
          method, redirect: 'error', signal: AbortSignal.timeout(40000),
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: 'Bearer ' + this.token,
            'X-GitHub-Api-Version': '2022-11-28',
            'Content-Type': 'application/json',
            'User-Agent': 'windows-regression-lab'
          },
          body: body === undefined ? undefined : JSON.stringify(body)
        });
        const retryable = (
          !mutating &&
          (response.status === 429 || response.status >= 500)
        );
        if (!retryable) {
          break;
        }
        const requested = Number(response.headers.get('retry-after')) * 1000;
        if (Number.isFinite(requested)) {
          delay = Math.max(delay, requested);
        }
      } catch {
        if (mutating ||
            attempt + 1 === limit) {
          throw new Error(mutating ? 'GITHUB_WRITE_OUTCOME_UNKNOWN' : 'GITHUB_READ_TRANSPORT_FAILED');
        }
      }
      if (attempt + 1 === limit) {
        throw new Error('GITHUB_READ_RETRIES_EXHAUSTED');
      }
      await sleep(delay);
    }
    if (mutating) {
      this.audit({ phase: 'response', method, endpoint, status: response.status });
    }
    if (absent &&
        method === 'GET' &&
        response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error('GITHUB_HTTP_' + response.status);
    }
    const text = response.status === 204 ? '' : await response.text();
    let value = null;
    if (text.trim().length > 0) {
      try {
        value = JSON.parse(text);
      } catch {
        throw new Error('GITHUB_RESPONSE_NOT_JSON');
      }
    }
    return { value, scopes: (response.headers.get('x-oauth-scopes') || '').split(/[,\s]+/).filter(Boolean) };
  }

  async identity() {
    const result = await this.request('GET', '/user');
    if (result.value.login !== 'girishkvs') {
      throw new Error('GITHUB_ACCOUNT_MISMATCH');
    }
    return result;
  }

  discard() {
    this.token = null;
  }
}

class RelayOwner {
  constructor() {
    this.reader = new Relay();
    this.reference = null;
    this.tokens = null;
  }

  validateIdentityScopes(scopes) {
    const expected = ['read:user', 'repo', 'workflow'];
    if (!Array.isArray(scopes) ||
        scopes.length !== expected.length ||
        !expected.every(scope => scopes.includes(scope))) {
      throw new Error('SINGLE_CODE_SCOPE_MISMATCH');
    }
  }

  diagnostics(error, secrets = []) {
    const redact = value => {
      if (typeof value !== 'string') {
        return null;
      }
      let text = value;
      for (const secret of secrets) {
        if (typeof secret === 'string' &&
            secret.length > 0) {
          text = text.split(secret).join('[redacted]');
        }
      }
      return text
        .replace(/\b(?:Bearer|github|tunnel)\s+[A-Za-z0-9._~+\/=-]{16,}/gi, '[redacted authorization]')
        .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g, '[redacted token]')
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
        .slice(0, 2048);
    };
    const data = error?.response?.data;
    const result = {
      httpStatus: Number.isInteger(error?.response?.status) ? error.response.status : null,
      errorCode: /^[A-Z0-9_]{1,64}$/.test(error?.code || '') ? error.code : null,
      localCode: /^[A-Z0-9_]{1,80}$/.test(error?.message || '') ? error.message : null
    };
    if (typeof data === 'string') {
      result.detail = redact(data);
    }
    if (typeof data === 'object' &&
        data !== null) {
      for (const key of ['title', 'detail', 'message', 'code']) {
        const value = redact(data[key]);
        if (value !== null) {
          result[key] = value;
        }
      }
      if (typeof data.errors === 'object' &&
          data.errors !== null) {
        result.validation = Object.entries(data.errors).slice(0, 10).map(([field, messages]) => ({
          field: redact(field),
          messages: (Array.isArray(messages) ? messages : [messages]).slice(0, 5).map(redact)
        }));
      }
      if (typeof data.error === 'object' &&
          data.error !== null) {
        result.providerError = {
          code: redact(data.error.code),
          message: redact(data.error.message)
        };
      }
    }
    return result;
  }

  requestedTunnel() {
    return {
      tunnelId: 'wl-' + crypto.randomBytes(12).toString('hex'),
      clusterId: 'usw2',
      customExpiration: 3600,
      ports: [{ portNumber: 2222, protocol: 'auto' }],
      accessControl: { entries: [] }
    };
  }

  async create(identityToken, audit) {
    const identity = new GitHubApi(identityToken);
    const actual = await identity.identity();
    this.validateIdentityScopes(actual.scopes);
    identity.discard();
    const manager = new TunnelManagementHttpClient(
      { name: 'windows-regression-lab', version: '0.0.0' },
      ManagementApiVersions.Version20230927preview,
      async () => 'github ' + identityToken
    );
    manager.enableEventsReporting = false;
    const requested = this.requestedTunnel();
    const reference = { tunnelId: requested.tunnelId, clusterId: requested.clusterId };
    let previous;
    try {
      previous = await this.reader.read(reference, undefined, manager);
    } catch (error) {
      audit({
        operation: 'relay-precheck', phase: 'failed',
        ...this.diagnostics(error, [identityToken])
      });
      await manager.dispose();
      throw new Error('RELAY_PRECHECK_FAILED');
    }
    if (previous !== null) {
      await manager.dispose();
      this.reference = null;
      throw new Error('GENERATED_RELAY_ID_ALREADY_EXISTS');
    }
    this.reference = reference;
    audit({ operation: 'create-relay', phase: 'attempt', ...this.reference });
    try {
      const tunnel = await manager.createTunnel(requested, {
        includePorts: true,
        includeAccessControl: true,
        tokenScopes: [TunnelAccessScopes.Host, TunnelAccessScopes.Connect, TunnelAccessScopes.Manage]
      });
      const readback = await this.reader.read(this.reference, {
        includePorts: true, includeAccessControl: true
      }, manager);
      this.reader.validate(readback, this.reference);
      this.configuration = this.reader.descriptor(readback, this.reference);
      const tokens = tunnel.accessTokens || {};
      for (const scope of ['host', 'connect', 'manage']) {
        if (typeof tokens[scope] !== 'string') {
          throw new Error('RELAY_CAPABILITY_NOT_ISSUED');
        }
      }
      this.tokens = { host: tokens.host, connect: tokens.connect, manage: tokens.manage };
      audit({ operation: 'create-relay', phase: 'verified', ...this.reference });
    } catch (error) {
      audit({
        operation: 'create-relay', phase: 'failed',
        ...this.diagnostics(error, [identityToken])
      });
      const current = await this.reader.read(this.reference, { includePorts: true, includeAccessControl: true }, manager);
      if (current !== null) {
        if (current.tunnelId !== this.reference.tunnelId ||
            current.clusterId !== this.reference.clusterId) {
          throw new Error('FAILED_RELAY_IDENTITY_MISMATCH');
        }
        audit({ operation: 'delete-failed-relay', phase: 'attempt', ...this.reference });
        await manager.deleteTunnel(this.reference);
        const remaining = await this.reader.read(this.reference, undefined, manager);
        if (remaining !== null) {
          throw new Error('FAILED_RELAY_CLEANUP_UNVERIFIED');
        }
        audit({ operation: 'delete-failed-relay', phase: 'verified', ...this.reference });
      }
      this.reference = null;
      this.tokens = null;
      throw new Error('RELAY_CREATION_FAILED');
    } finally {
      await manager.dispose();
      identityToken = null;
    }
  }

  async readVerified(identityToken) {
    if (!this.reference) {
      throw new Error('RELAY_REFERENCE_MISSING');
    }
    const manager = new TunnelManagementHttpClient(
      { name: 'windows-regression-lab', version: '0.0.0' },
      ManagementApiVersions.Version20230927preview,
      async () => 'github ' + identityToken
    );
    manager.enableEventsReporting = false;
    try {
      const tunnel = await this.reader.read(this.reference, {
        includePorts: true, includeAccessControl: true
      }, manager);
      if (tunnel === null) {
        throw new Error('RELAY_NOT_FOUND');
      }
      return this.reader.descriptor(tunnel, this.reference);
    } finally {
      await manager.dispose();
      identityToken = null;
    }
  }

  async delete(audit) {
    if (!this.reference) {
      await this.reader.close();
      return;
    }
    if (!this.tokens?.manage) {
      throw new Error('RELAY_STATE_NEEDS_OWNER_RECONCILIATION');
    }
    audit({ operation: 'delete-relay', phase: 'attempt', ...this.reference });
    await this.reader.manager.deleteTunnel(this.reference, { accessToken: this.tokens.manage });
    const existing = await this.reader.read(this.reference, {
      accessToken: this.tokens.manage
    });
    if (existing !== null) {
      throw new Error('RELAY_DELETION_NOT_VERIFIED');
    }
    audit({ operation: 'delete-relay', phase: 'verified', ...this.reference });
    this.tokens = null;
    await this.reader.close();
  }
}

async function sealSecret(value, publicKey) {
  await sodium.ready;
  const input = sodium.from_string(value);
  try {
    const key = sodium.from_base64(publicKey, sodium.base64_variants.ORIGINAL);
    if (key.length !== sodium.crypto_box_PUBLICKEYBYTES) {
      throw new Error('INVALID_SECRET_PUBLIC_KEY');
    }
    return sodium.to_base64(sodium.crypto_box_seal(input, key), sodium.base64_variants.ORIGINAL);
  } finally {
    sodium.memzero(input);
  }
}

module.exports = { DeviceLogin, GitHubApi, RelayOwner, sealSecret, sleep };
