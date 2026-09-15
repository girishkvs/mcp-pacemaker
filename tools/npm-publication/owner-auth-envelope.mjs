import {
  constants, createCipheriv, createHash, createPublicKey, publicEncrypt, randomBytes,
} from 'node:crypto';

/*
 * API: new OwnerAuthEnvelope({ spki, sha256 }).seal(context, url).
 * spki is canonical standard base64 of DER SPKI (at most 1024 DER bytes /
 * 1368 base64 characters); sha256 hashes those DER bytes. Only RSA-4096 with
 * exponent 65537 is accepted. runId is a canonical positive decimal string
 * of at most 20 digits; url is at most 2048 UTF-16 code units.
 *
 * AAD is UTF-8 JSON.stringify with no whitespace, in CONTEXT_FIELDS order,
 * followed by purpose, issuedAt, expiresAt. Dates are UTC ISO strings with
 * milliseconds; expiry is exactly 600000 ms after issue. Plaintext is UTF-8
 * JSON.stringify({ url }), preserving the validated input string.
 * All binary output fields use standard padded base64. RSA uses OAEP SHA-256
 * (including MGF1), with the default empty label. AES-256-GCM uses a fresh
 * 32-byte key, 12-byte nonce, and 16-byte tag. Decoders must use the LITERAL
 * decoded aad bytes, not reserialized JSON, and compare every context field
 * and freshness before opening the URL. AAD is limited to 1024 bytes;
 * ciphertext is at most 6154 bytes (2048 * 3 + 10 for the JSON object).
 *
 * Encryption does NOT prove artifact origin: anyone with this public key can
 * seal an envelope. Verify GitHub run/artifact provenance separately. The
 * caller must generate transaction with a CSPRNG, enforce sequence/replay
 * checks, and keep URL/error logging outside this module secret-free.
 */

const CONTEXT_FIELDS = Object.freeze([
  'repository', 'ref', 'commit', 'runId', 'runAttempt', 'owner', 'name', 'version',
  'sha256', 'keySha256', 'transaction', 'sequence', 'kind',
]);
const MAX_DER_BYTES = 1024;
const MAX_SPKI_CHARACTERS = 1368;
const MAX_URL_CHARACTERS = 2048;
const MAX_AAD_BYTES = 1024;
const MAX_PLAINTEXT_BYTES = MAX_URL_CHARACTERS * 3 + 10;

export class OwnerAuthEnvelope {
  #publicKey;
  #keySha256;

  constructor(options) {
    try {
      const { spki, sha256 } = this.#readFields(options, ['spki', 'sha256']);
      const hasBoundedEncoding = typeof spki === 'string' &&
        spki.length > 0 &&
        spki.length <= MAX_SPKI_CHARACTERS &&
        spki.length % 4 === 0;
      if (!hasBoundedEncoding ||
          !this.#isLowerHex(sha256, 64)) {
        throw new Error('Invalid key encoding.');
      }

      const der = Buffer.from(spki, 'base64');
      const isCanonicalEncoding = der.length > 0 &&
        der.length <= MAX_DER_BYTES &&
        der.toString('base64') === spki;
      if (!isCanonicalEncoding ||
          createHash('sha256').update(der).digest('hex') !== sha256) {
        throw new Error('Invalid key encoding.');
      }

      const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
      const details = publicKey.asymmetricKeyDetails;
      const isAllowedKey = publicKey.asymmetricKeyType === 'rsa' &&
        details?.modulusLength === 4096 &&
        details?.publicExponent === 65537n;
      if (!isAllowedKey ||
          !publicKey.export({ format: 'der', type: 'spki' }).equals(der)) {
        throw new Error('Invalid key parameters.');
      }

      this.#publicKey = publicKey;
      this.#keySha256 = sha256;
    } catch {
      throw new Error('Invalid owner auth public key.');
    }
  }

  seal(context, url) {
    let aesKey;
    let plaintext;
    try {
      const validatedContext = this.#validateContext(context);
      this.#validateUrl(url);
      const issuedAt = new Date();
      const aad = Buffer.from(JSON.stringify({
        ...validatedContext,
        purpose: 'mcp-pacemaker-npm-owner-auth',
        issuedAt: issuedAt.toISOString(),
        expiresAt: new Date(issuedAt.getTime() + 600000).toISOString(),
      }), 'utf8');
      plaintext = Buffer.from(JSON.stringify({ url }), 'utf8');
      if (aad.length > MAX_AAD_BYTES ||
          plaintext.length > MAX_PLAINTEXT_BYTES) {
        throw new Error('Invalid envelope size.');
      }

      aesKey = randomBytes(32);
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const wrappedKey = publicEncrypt({
        key: this.#publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      }, aesKey);

      return {
        schemaVersion: 1,
        algorithm: 'RSA-OAEP-256+A256GCM',
        aad: aad.toString('base64'),
        wrappedKey: wrappedKey.toString('base64'),
        nonce: nonce.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
      };
    } catch {
      throw new Error('Unable to seal owner auth envelope.');
    } finally {
      aesKey?.fill(0);
      plaintext?.fill(0);
    }
  }

  #readFields(input, fields) {
    if (input === null ||
        typeof input !== 'object') {
      throw new Error('Invalid fields.');
    }
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype &&
        prototype !== null) {
      throw new Error('Invalid fields.');
    }
    if (Reflect.ownKeys(input).length !== fields.length) {
      throw new Error('Invalid fields.');
    }

    const result = Object.create(null);
    for (const field of fields) {
      const descriptor = Object.getOwnPropertyDescriptor(input, field);
      if (!descriptor?.enumerable ||
          !Object.hasOwn(descriptor, 'value')) {
        throw new Error('Invalid fields.');
      }
      result[field] = descriptor.value;
    }
    return result;
  }

  #isLowerHex(value, length) {
    return typeof value === 'string' &&
      value.length === length &&
      !/[^0-9a-f]/.test(value);
  }

  #validateContext(context) {
    const value = this.#readFields(context, CONTEXT_FIELDS);
    const hasExpectedPackage = value.repository === 'girishkvs/mcp-pacemaker' &&
      value.owner === 'girishkvs' &&
      value.name === 'mcp-pacemaker' &&
      value.version === '2.0.1';
    const hasAllowedRef = value.ref === 'refs/tags/npm/v2.0.1' ||
      value.ref === 'refs/tags/v2.0.1';
    const hasAllowedRun = typeof value.runId === 'string' &&
      value.runId.length > 0 &&
      value.runId.length <= 20 &&
      value.runId[0] !== '0' &&
      !/[^0-9]/.test(value.runId) &&
      value.runAttempt === 1;
    const hasValidBinding = this.#isLowerHex(value.commit, 40) &&
      this.#isLowerHex(value.sha256, 64) &&
      this.#isLowerHex(value.keySha256, 64) &&
      value.keySha256 === this.#keySha256 &&
      this.#isLowerHex(value.transaction, 32);
    const isLogin = value.sequence === 1 &&
      value.kind === 'login';
    const isPublish = value.sequence === 2 &&
      value.kind === 'publish-2fa';
    const isAllowedContext = hasExpectedPackage &&
      hasAllowedRef &&
      hasAllowedRun &&
      hasValidBinding &&
      (isLogin || isPublish);
    if (!isAllowedContext) {
      throw new Error('Invalid context.');
    }
    return value;
  }

  #validateUrl(url) {
    if (typeof url !== 'string' ||
        url.length === 0 ||
        url.length > MAX_URL_CHARACTERS) {
      throw new Error('Invalid URL.');
    }
    // Check the raw authority too: URL parsing otherwise normalizes credentials,
    // backslashes, whitespace, and encoded or Unicode hostnames.
    const hasAllowedSpelling = url.isWellFormed() &&
      !/[\u0000-\u0020\u007f\\#]/.test(url) &&
      /^https:\/\/(?:www\.npmjs\.com|npmjs\.com)(?::443)?(?:[/?]|$)/i.test(url);
    if (!hasAllowedSpelling) {
      throw new Error('Invalid URL.');
    }
    const parsed = new URL(url);
    const hasAllowedOrigin = parsed.protocol === 'https:' &&
      (parsed.hostname === 'www.npmjs.com' || parsed.hostname === 'npmjs.com') &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.port === '' &&
      parsed.hash === '';
    if (!hasAllowedOrigin) {
      throw new Error('Invalid URL.');
    }
  }
}
