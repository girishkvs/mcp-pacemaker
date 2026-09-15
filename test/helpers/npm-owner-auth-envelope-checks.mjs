// Imported by the explicitly registered npm-publication-proof.test.mjs suite.
import assert from 'node:assert/strict';
import {
  constants, createDecipheriv, createHash, createPublicKey, generateKeyPairSync,
  privateDecrypt, randomBytes,
} from 'node:crypto';
import { before, test } from 'node:test';
import * as envelopeModule from '../../tools/npm-publication/owner-auth-envelope.mjs';

const { OwnerAuthEnvelope } = envelopeModule;
const CONTEXT_FIELDS = [
  'repository', 'ref', 'commit', 'runId', 'runAttempt', 'owner', 'name', 'version',
  'sha256', 'keySha256', 'transaction', 'sequence', 'kind',
];
const OUTPUT_FIELDS = [
  'schemaVersion', 'algorithm', 'aad', 'wrappedKey', 'nonce', 'ciphertext', 'tag',
];

class Fixture {
  constructor() {
    const pair = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 });
    this.privateKey = pair.privateKey;
    this.der = pair.publicKey.export({ type: 'spki', format: 'der' });
    this.keyOptions = this.options(this.der);
    this.envelope = new OwnerAuthEnvelope(this.keyOptions);
    // Synthetic values only. No browser, registry, network, disk, or real tokens.
    this.url = 'https://www.npmjs.com/login?sessionToken=synthetic-session-value' +
      '&doneUrl=https%3A%2F%2Fnpmjs.com%2Fsynthetic-done&otp=synthetic-otp';
  }

  options(der) {
    return {
      spki: der.toString('base64'),
      sha256: createHash('sha256').update(der).digest('hex'),
    };
  }

  context(overrides = {}) {
    return {
      repository: 'girishkvs/mcp-pacemaker',
      ref: 'refs/tags/npm/v2.0.1',
      commit: 'a'.repeat(40),
      runId: '123456789',
      runAttempt: 1,
      owner: 'girishkvs',
      name: 'mcp-pacemaker',
      version: '2.0.1',
      sha256: 'b'.repeat(64),
      keySha256: this.keyOptions.sha256,
      transaction: randomBytes(16).toString('hex'),
      sequence: 1,
      kind: 'login',
      ...overrides,
    };
  }

  unwrap(envelope, privateKey = this.privateKey) {
    return privateDecrypt({
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, Buffer.from(envelope.wrappedKey, 'base64'));
  }

  decrypt(envelope, privateKey = this.privateKey) {
    const aesKey = this.unwrap(envelope, privateKey);
    const plaintextBuffers = [];
    try {
      assert.equal(aesKey.length, 32);
      const aadBytes = Buffer.from(envelope.aad, 'base64');
      const decipher = createDecipheriv('aes-256-gcm', aesKey,
        Buffer.from(envelope.nonce, 'base64'), { authTagLength: 16 });
      decipher.setAAD(aadBytes);
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      plaintextBuffers.push(decipher.update(Buffer.from(envelope.ciphertext, 'base64')));
      plaintextBuffers.push(decipher.final());
      const plaintext = Buffer.concat(plaintextBuffers);
      plaintextBuffers.push(plaintext);
      const rawPlaintext = plaintext.toString('utf8');
      return { aadBytes, aad: JSON.parse(aadBytes.toString('utf8')),
        payload: JSON.parse(rawPlaintext), rawPlaintext };
    } finally {
      aesKey.fill(0);
      for (const buffer of plaintextBuffers) buffer.fill(0);
    }
  }

  flip(encoded) {
    const bytes = Buffer.from(encoded, 'base64');
    bytes[0] ^= 1;
    return bytes.toString('base64');
  }

  rejects(callback, message) {
    assert.throws(callback, error => {
      assert.equal(error.constructor, Error);
      assert.equal(error.message, message);
      assert.deepEqual(Object.getOwnPropertyNames(error).sort(), ['message', 'stack']);
      for (const secret of [
        this.url, 'synthetic-session-value', 'synthetic-done', 'synthetic-otp',
        'synthetic-sensitive-error', this.keyOptions.spki,
      ]) {
        assert.equal(error.stack.includes(secret), false);
      }
      return true;
    });
  }

  rejectsKey(options) {
    this.rejects(() => new OwnerAuthEnvelope(options), 'Invalid owner auth public key.');
  }

  rejectsSeal(context, url = this.url) {
    this.rejects(() => this.envelope.seal(context, url), 'Unable to seal owner auth envelope.');
  }
}

let fixture;
before(() => { fixture = new Fixture(); });

test('exports only the encryption class, with no production decrypt helper', () => {
  assert.deepEqual(Object.keys(envelopeModule), ['OwnerAuthEnvelope']);
  assert.deepEqual(Object.getOwnPropertyNames(OwnerAuthEnvelope.prototype), ['constructor', 'seal']);
  assert.deepEqual(Object.keys(fixture.envelope), []);
});

test('roundtrips exact URL and ordered context using literal AAD and empty OAEP label', () => {
  const context = fixture.context();
  const original = structuredClone(context);
  const beforeSeal = Date.now();
  const envelope = fixture.envelope.seal(Object.freeze(context), fixture.url);
  const afterSeal = Date.now();
  const result = fixture.decrypt(envelope);
  assert.deepEqual(context, original);
  assert.deepEqual(result.payload, { url: fixture.url });
  assert.equal(result.rawPlaintext, JSON.stringify({ url: fixture.url }));
  assert.deepEqual(Object.keys(result.aad), [...CONTEXT_FIELDS, 'purpose', 'issuedAt', 'expiresAt']);
  assert.deepEqual(Object.fromEntries(CONTEXT_FIELDS.map(key => [key, result.aad[key]])), context);
  assert.equal(result.aad.purpose, 'mcp-pacemaker-npm-owner-auth');
  const issued = Date.parse(result.aad.issuedAt);
  assert.ok(issued >= beforeSeal);
  assert.ok(issued <= afterSeal);
  assert.equal(new Date(issued).toISOString(), result.aad.issuedAt);
  assert.equal(result.aad.expiresAt, new Date(issued + 600000).toISOString());
  assert.equal(result.aadBytes.toString('utf8'), JSON.stringify({
    ...context, purpose: 'mcp-pacemaker-npm-owner-auth',
    issuedAt: result.aad.issuedAt, expiresAt: result.aad.expiresAt,
  }));
});

test('supports allowed refs and both exact sequence-kind pairs', () => {
  for (const ref of ['refs/tags/npm/v2.0.1', 'refs/tags/v2.0.1',
    'refs/tags/npm-r2/v2.0.1', 'refs/tags/npm-r3/v2.0.1']) {
    for (const [sequence, kind] of [[1, 'login'], [2, 'publish-2fa']]) {
      const context = fixture.context({ ref, sequence, kind });
      const result = fixture.decrypt(fixture.envelope.seal(context, fixture.url));
      assert.deepEqual(Object.fromEntries(CONTEXT_FIELDS.map(key => [key, result.aad[key]])), context);
    }
  }
});

test('serializes context in fixed field order regardless of input insertion order', () => {
  const context = fixture.context();
  const reversed = Object.fromEntries(Object.entries(context).reverse());
  const result = fixture.decrypt(fixture.envelope.seal(reversed, fixture.url));
  assert.deepEqual(Object.keys(result.aad), [...CONTEXT_FIELDS, 'purpose', 'issuedAt', 'expiresAt']);
  const nullPrototype = Object.assign(Object.create(null), context);
  assert.deepEqual(fixture.decrypt(fixture.envelope.seal(nullPrototype, fixture.url)).payload,
    { url: fixture.url });
});

test('uses a fresh AES key, nonce, ciphertext, and OAEP wrapping on every seal', () => {
  const context = fixture.context();
  const first = fixture.envelope.seal(context, fixture.url);
  const second = fixture.envelope.seal(context, fixture.url);
  for (const field of ['nonce', 'ciphertext', 'wrappedKey', 'tag']) {
    assert.notEqual(first[field], second[field]);
  }
  const firstKey = fixture.unwrap(first);
  const secondKey = fixture.unwrap(second);
  try {
    assert.equal(firstKey.equals(secondKey), false);
  } finally {
    firstKey.fill(0);
    secondKey.fill(0);
  }
  assert.deepEqual(fixture.decrypt(first).payload, fixture.decrypt(second).payload);
});

for (const field of ['aad', 'ciphertext', 'tag', 'wrappedKey', 'nonce']) {
  test(`authentication negative control rejects tampered ${field}`, () => {
    const envelope = fixture.envelope.seal(fixture.context(), fixture.url);
    assert.deepEqual(fixture.decrypt(envelope).payload, { url: fixture.url });
    assert.throws(() => fixture.decrypt({ ...envelope, [field]: fixture.flip(envelope[field]) }));
  });
}

test('authentication rejects parseable AAD edits and equivalent JSON with different literal bytes', () => {
  const envelope = fixture.envelope.seal(fixture.context(), fixture.url);
  const aad = JSON.parse(Buffer.from(envelope.aad, 'base64'));
  const changedContext = Buffer.from(JSON.stringify({ ...aad, runId: '987654321' })).toString('base64');
  assert.throws(() => fixture.decrypt({ ...envelope, aad: changedContext }));
  const reserialized = Buffer.from(JSON.stringify(aad, null, 2)).toString('base64');
  assert.throws(() => fixture.decrypt({ ...envelope, aad: reserialized }));
});

test('decryption fails with a different ephemeral RSA-4096 private key', () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 });
  const envelope = fixture.envelope.seal(fixture.context(), fixture.url);
  assert.throws(() => fixture.decrypt(envelope, other.privateKey));
});

test('rejects RSA keys with the wrong modulus size or exponent and non-RSA keys', () => {
  const small = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  fixture.rejectsKey(fixture.options(small.publicKey.export({ type: 'spki', format: 'der' })));
  const wrongExponent = createPublicKey({
    key: { ...createPublicKey(fixture.privateKey).export({ format: 'jwk' }), e: 'Aw' },
    format: 'jwk',
  });
  fixture.rejectsKey(fixture.options(wrongExponent.export({ type: 'spki', format: 'der' })));
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  fixture.rejectsKey(fixture.options(ec.publicKey.export({ type: 'spki', format: 'der' })));
});

test('rejects missing, extra, non-data, and incorrectly typed constructor inputs', () => {
  for (const options of [
    undefined, null, [], 'synthetic-sensitive-error', {}, { spki: fixture.keyOptions.spki },
    { ...fixture.keyOptions, extra: 'synthetic-sensitive-error' },
    { ...fixture.keyOptions, spki: Buffer.from(fixture.der) },
    { ...fixture.keyOptions, spki: { toString() { throw new Error('synthetic-sensitive-error'); } } },
    Object.create(fixture.keyOptions),
  ]) {
    fixture.rejectsKey(options);
  }
  const accessor = { ...fixture.keyOptions };
  Object.defineProperty(accessor, 'spki', {
    enumerable: true, get() { throw new Error('synthetic-sensitive-error'); },
  });
  fixture.rejectsKey(accessor);
});

test('requires lowercase SHA-256 of the exact public DER bytes', () => {
  for (const sha256 of [
    '0'.repeat(64), fixture.keyOptions.sha256.toUpperCase(),
    fixture.keyOptions.sha256.slice(1), `${fixture.keyOptions.sha256}\n`,
    `${'a'.repeat(63)}\n`, 'g'.repeat(64), 1, null, undefined, 'a'.repeat(10000),
  ]) {
    fixture.rejectsKey({ ...fixture.keyOptions, sha256 });
  }
});

test('rejects noncanonical or oversized base64, malformed DER, and trailing DER data', () => {
  const { spki } = fixture.keyOptions;
  for (const encoded of [
    '', `${spki}\n`, ` ${spki}`, spki.replace(/=+$/, ''), `${spki}=`,
    spki.replace(/\+/g, '-').replace(/\//g, '_'), `${spki.slice(0, 20)}!${spki.slice(21)}`,
    'A'.repeat(1372), 'A'.repeat(100000),
  ]) {
    fixture.rejectsKey({ ...fixture.keyOptions, spki: encoded });
  }
  assert.ok(spki.endsWith('=='));
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lastIndex = spki.length - 3;
  const nonzeroPadBits = spki.slice(0, lastIndex) +
    alphabet[alphabet.indexOf(spki[lastIndex]) + 1] + '==';
  assert.deepEqual(Buffer.from(nonzeroPadBits, 'base64'), fixture.der);
  fixture.rejectsKey({ ...fixture.keyOptions, spki: nonzeroPadBits });
  for (const der of [
    Buffer.from('synthetic-sensitive-error'), Buffer.alloc(1025),
    fixture.der.subarray(0, fixture.der.length - 1),
    Buffer.concat([fixture.der, Buffer.from([0])]),
  ]) {
    fixture.rejectsKey(fixture.options(der));
  }
  const pkcs1 = createPublicKey(fixture.privateKey).export({ type: 'pkcs1', format: 'der' });
  fixture.rejectsKey(fixture.options(pkcs1));
});

for (const field of CONTEXT_FIELDS) {
  test(`rejects missing or malformed context field ${field}`, () => {
    const missing = fixture.context();
    delete missing[field];
    fixture.rejectsSeal(missing);
    for (const value of [undefined, null, {}, [], true, '', 'synthetic-sensitive-error']) {
      fixture.rejectsSeal(fixture.context({ [field]: value }));
    }
  });
}

test('rejects extra, inherited, symbol, non-enumerable, and accessor context fields', () => {
  for (const extra of ['url', 'doneUrl', 'sessionToken', 'otp', 'purpose', 'issuedAt', 'expiresAt']) {
    fixture.rejectsSeal({ ...fixture.context(), [extra]: 'synthetic-sensitive-error' });
  }
  fixture.rejectsSeal({ ...fixture.context(), [Symbol('extra')]: 'synthetic-sensitive-error' });
  fixture.rejectsSeal(Object.create(fixture.context()));
  for (const invalid of [undefined, null, [], 'synthetic-sensitive-error']) fixture.rejectsSeal(invalid);
  const hiddenExtra = fixture.context();
  Object.defineProperty(hiddenExtra, 'extra', { value: 'synthetic-sensitive-error' });
  fixture.rejectsSeal(hiddenExtra);
  const hiddenRequired = fixture.context();
  Object.defineProperty(hiddenRequired, 'commit', { enumerable: false });
  fixture.rejectsSeal(hiddenRequired);
  const accessor = fixture.context();
  let invoked = false;
  Object.defineProperty(accessor, 'commit', { enumerable: true, get() {
    invoked = true;
    throw new Error('synthetic-sensitive-error');
  } });
  fixture.rejectsSeal(accessor);
  assert.equal(invoked, false);
});

test('rejects wrong package, ref, version, run, sequence-kind, and key binding', () => {
  const changes = [
    { repository: 'other/mcp-pacemaker' }, { owner: 'other' }, { name: 'other' },
    { version: '2.0.0' }, { version: '2.0.1\n' },
    ...['refs/heads/main', 'refs/tags/v2.0.0', 'refs/tags/npm/v2.0.1\n',
      'v2.0.1', 'refs/tags/npm/v2.0.10', 'refs/tags/npm-r2/v1.3.1',
      'refs/tags/npm-r2/v2.0.1-extra', 'refs/tags/npm-r3/v1.3.1',
      'refs/tags/npm-r3/v2.0.1-extra', 'refs/tags/npm-r4/v2.0.1',
      'x'.repeat(10000)].map(ref => ({ ref })),
    ...['0', '01', '-1', '+1', '1.0', '1e3', '1\n', ' 1', '1 ', '１２',
      '1'.repeat(21), 1, 1n].map(runId => ({ runId })),
    ...[0, 2, '1', 1n].map(runAttempt => ({ runAttempt })),
    ...[0, 3, '1', '2', 1n].map(sequence => ({ sequence })),
    { sequence: 1, kind: 'publish-2fa' }, { sequence: 2, kind: 'login' },
    { kind: 'publish' }, { kind: 'login\n' },
    { keySha256: '0'.repeat(64) },
  ];
  for (const changeset of changes) fixture.rejectsSeal(fixture.context(changeset));
});

test('rejects non-lowercase, wrong-length, non-hex, and line-terminated context hashes', () => {
  for (const [field, length] of [['commit', 40], ['sha256', 64], ['keySha256', 64], ['transaction', 32]]) {
    for (const value of [
      'A'.repeat(length), 'g'.repeat(length), 'a'.repeat(length - 1), 'a'.repeat(length + 1),
      `${'a'.repeat(length - 1)}\n`, `${'a'.repeat(length)}\n`, 'a'.repeat(10000),
    ]) {
      fixture.rejectsSeal(fixture.context({ [field]: value }));
    }
  }
});

test('accepts canonical runId bounds without converting IDs to a JS number', () => {
  for (const runId of ['1', '18446744073709551615']) {
    const result = fixture.decrypt(fixture.envelope.seal(fixture.context({ runId }), fixture.url));
    assert.equal(result.aad.runId, runId);
  }
});

test('accepts only the two npm HTTPS website origins and preserves valid URL spelling', () => {
  for (const url of [
    'https://www.npmjs.com', 'https://npmjs.com/', 'https://npmjs.com:443/login',
    'https://www.npmjs.com:443/login?value=%23%40%2F',
    'HTTPS://WWW.NPMJS.COM/login', 'https://npmjs.com/login?value=漢字😀',
    'https://npmjs.com/login?value="synthetic"',
  ]) {
    assert.deepEqual(fixture.decrypt(fixture.envelope.seal(fixture.context(), url)).payload, { url });
  }
});

test('rejects HTTP, credentials, ports, fragments, other hosts, and authority normalization tricks', () => {
  const credentials = new URL('https://npmjs.com/login');
  credentials.username = 'synthetic-user';
  credentials.password = 'synthetic-password';
  for (const url of [
    'http://www.npmjs.com/login', 'https://user@www.npmjs.com/login',
    credentials.href, 'https://@npmjs.com/login',
    'https://:@npmjs.com/login', 'https://npmjs.com:80/login', 'https://npmjs.com:444/login',
    'https://npmjs.com:/login', 'https://npmjs.com/login#fragment', 'https://npmjs.com/login#',
    'https://registry.npmjs.org/login', 'https://evil.example/login',
    'https://npmjs.com.evil.example/login', 'https://evil.example@npmjs.com/login',
    'https://npmjs.com@evil.example/login', 'https://npmjs.com./login',
    'https://%6epmjs.com/login', 'https://ｎｐｍｊｓ.com/login',
    'https://npmjs.com\\@evil.example/login', 'https:\\\\npmjs.com\\login',
    '//npmjs.com/login', 'https:npmjs.com/login', 'https:///npmjs.com/login',
    ' https://npmjs.com/login', 'https://npmjs.com/login ', 'https://npmjs.com/lo\ngin',
    'https://npmjs.com/\tlogin', 'https://npmjs.com/\rlogin', 'https://npmjs.com/\0login',
    'https://npmjs.com/\u007f', 'https://npmjs.com/\ud800',
    'javascript:synthetic-sensitive-error', '',
  ]) {
    fixture.rejectsSeal(fixture.context(), url);
  }
  for (const url of [null, 1, {}, { url: fixture.url }, new URL(fixture.url), new String(fixture.url)]) {
    fixture.rejectsSeal(fixture.context(), url);
  }
  fixture.rejects(() => fixture.envelope.seal(fixture.context()), 'Unable to seal owner auth envelope.');
});

test('enforces exact output shape, canonical base64, binary sizes, and URL/output caps', () => {
  const prefix = 'https://www.npmjs.com/';
  for (const character of ['a', '漢', '"']) {
    const url = prefix + character.repeat(2048 - prefix.length);
    const envelope = fixture.envelope.seal(fixture.context(), url);
    assert.deepEqual(Object.keys(envelope), OUTPUT_FIELDS);
    assert.equal(envelope.schemaVersion, 1);
    assert.equal(envelope.algorithm, 'RSA-OAEP-256+A256GCM');
    for (const field of OUTPUT_FIELDS.slice(2)) {
      assert.equal(typeof envelope[field], 'string');
      assert.equal(Buffer.from(envelope[field], 'base64').toString('base64'), envelope[field]);
    }
    assert.equal(Buffer.from(envelope.wrappedKey, 'base64').length, 512);
    assert.equal(Buffer.from(envelope.nonce, 'base64').length, 12);
    assert.equal(Buffer.from(envelope.tag, 'base64').length, 16);
    assert.ok(Buffer.from(envelope.aad, 'base64').length <= 1024);
    assert.ok(Buffer.from(envelope.ciphertext, 'base64').length <= 6154);
    assert.ok(envelope.aad.length <= 1368);
    assert.equal(envelope.wrappedKey.length, 684);
    assert.equal(envelope.nonce.length, 16);
    assert.equal(envelope.tag.length, 24);
    assert.ok(envelope.ciphertext.length <= 8208);
    assert.ok(Buffer.byteLength(JSON.stringify(envelope)) < 11 * 1024);
    assert.deepEqual(fixture.decrypt(envelope).payload, { url });
    fixture.rejectsSeal(fixture.context(), `${url}a`);
  }
});

test('never exposes plaintext URL, session, done URL, OTP, AES key, or caller objects in output', () => {
  const envelope = fixture.envelope.seal(fixture.context(), fixture.url);
  const aad = JSON.parse(Buffer.from(envelope.aad, 'base64'));
  const serialized = JSON.stringify(envelope);
  for (const secret of [fixture.url, 'synthetic-session-value', 'synthetic-done', 'synthetic-otp']) {
    assert.equal(serialized.includes(secret), false);
    assert.equal(JSON.stringify(aad).includes(secret), false);
  }
  for (const field of ['url', 'loginUrl', 'doneUrl', 'sessionToken', 'otp', 'aesKey', 'context']) {
    assert.equal(Object.hasOwn(envelope, field), false);
    assert.equal(Object.hasOwn(aad, field), false);
  }
});

test('sanitizes thrown input errors without retaining a cause, crypto details, or secret values', () => {
  const throwing = new Proxy({}, {
    getPrototypeOf() { throw new Error('synthetic-sensitive-error'); },
  });
  fixture.rejectsKey(throwing);
  fixture.rejectsSeal(throwing);
  fixture.rejectsKey(fixture.options(Buffer.from('synthetic-sensitive-error')));
  fixture.rejectsSeal(fixture.context(), 'https://synthetic-sensitive-error@npmjs.com/');
});
