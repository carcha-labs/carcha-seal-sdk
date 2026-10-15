import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import {
  decryptFeature,
  deviceFeatureWrapKey,
  devicePublicKey,
  featureWrapKeyForDevice,
  decryptForFeature,
  encryptForFeature,
  FeatureCryptoError,
  featureWrapKey,
  generateFeatureKey,
  unwrapFeatureKey,
  wrapFeatureKey,
  generateSigningKeys,
  signLease,
  verifyLease,
  decodeLease,
  keyId,
  publicJwk,
  hashFingerprint,
  generateLicenseKey,
  normalizeLicenseKey,
  hashLicenseKey,
  legacyLicenseKeyHash,
  LeaseClaims,
  LEASE_ALGORITHM,
  LEASE_TYPE,
  LEASE_ISSUER,
} from './index';

const keys = generateSigningKeys();
const fp = hashFingerprint('machine-123', 'demo');
const now = 1_800_000_000;

function claims(over: Partial<LeaseClaims> = {}): LeaseClaims {
  return {
    iss: LEASE_ISSUER,
    sub: 'lic_1',
    aud: 'demo',
    jti: 'lease_1',
    iat: now,
    nbf: now,
    exp: now + 3600,
    rev: now + 600,
    fp,
    feat: ['pro'],
    cus: 'Acme',
    ...over,
  };
}

const opts = { keys: [keys.publicKeyPem], product: 'demo', fingerprintHash: fp, now };

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

function reason(token: string, over: Partial<typeof opts> & Record<string, unknown> = {}) {
  const r = verifyLease(token, { ...opts, ...over });
  return r.ok ? 'ok' : r.reason;
}

test('keyId is the RFC 7638 thumbprint of the Ed25519 JWK (RFC 8037 A.3 vector)', () => {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }, format: 'jwk' });
  assert.equal(keyId(key), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('a lease is a compact JWS with the Ed25519 alg, explicit type and key id', () => {
  const token = signLease(claims(), keys.privateKeyPem);
  assert.equal(token.split('.').length, 3);
  const decoded = decodeLease(token);
  assert.deepEqual(decoded?.header, { alg: LEASE_ALGORITHM, typ: LEASE_TYPE, kid: keyId(keys.publicKeyPem) });
  assert.equal(LEASE_ALGORITHM, 'Ed25519');
  assert.equal(LEASE_TYPE, 'licensekit-lease+jwt');
  assert.deepEqual(decoded?.claims, claims());
});

test('a valid lease verifies offline against the key set', () => {
  const r = verifyLease(signLease(claims(), keys.privateKeyPem), opts);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.claims.sub, 'lic_1');
});

test('the key set accepts leases from every listed key and rejects unknown key ids', () => {
  const next = generateSigningKeys();
  const set = [keys.publicKeyPem, next.publicKeyPem];
  assert.equal(reason(signLease(claims(), keys.privateKeyPem), { keys: set }), 'ok');
  assert.equal(reason(signLease(claims(), next.privateKeyPem), { keys: set }), 'ok');
  assert.equal(reason(signLease(claims(), next.privateKeyPem)), 'unknown_key');
});

test('a changed payload or a signature under a reused key id fails the signature check', () => {
  const [h, , s] = signLease(claims(), keys.privateKeyPem).split('.');
  assert.equal(reason(`${h}.${b64({ ...claims(), feat: ['pro', 'enterprise'] })}.${s}`), 'bad_signature');
  const other = generateSigningKeys();
  const [, p2, s2] = signLease(claims(), other.privateKeyPem).split('.');
  assert.equal(reason(`${h}.${p2}.${s2}`), 'bad_signature');
});

test('the header algorithm and type are checked before the key is used', () => {
  const [, p, s] = signLease(claims(), keys.privateKeyPem).split('.');
  const kid = keyId(keys.publicKeyPem);
  assert.equal(reason(`${b64({ alg: 'none', typ: LEASE_TYPE, kid })}.${p}.${s}`), 'unsupported_algorithm');
  assert.equal(reason(`${b64({ alg: 'EdDSA', typ: LEASE_TYPE, kid })}.${p}.${s}`), 'unsupported_algorithm');
  assert.equal(reason(`${b64({ alg: 'HS256', typ: LEASE_TYPE, kid })}.${p}.${s}`), 'unsupported_algorithm');
  assert.equal(reason(`${b64({ alg: LEASE_ALGORITHM, typ: 'JWT', kid })}.${p}.${s}`), 'wrong_type');
  assert.equal(reason(`${b64({ alg: LEASE_ALGORITHM, typ: LEASE_TYPE })}.${p}.${s}`), 'unknown_key');
});

test('issuer, product and device are bound', () => {
  const token = signLease(claims(), keys.privateKeyPem);
  assert.equal(reason(token, { issuer: 'someone-else' }), 'wrong_issuer');
  assert.equal(reason(signLease(claims({ iss: 'someone-else' }), keys.privateKeyPem)), 'wrong_issuer');
  assert.equal(reason(token, { product: 'other' }), 'wrong_product');
  assert.equal(reason(token, { fingerprintHash: hashFingerprint('other', 'demo') }), 'wrong_device');
});

test('not before allows five minutes of clock skew by default', () => {
  const token = signLease(claims({ nbf: now + 600 }), keys.privateKeyPem);
  assert.equal(reason(token), 'not_yet_valid');
  assert.equal(reason(token, { now: now + 300 }), 'ok');
  assert.equal(reason(token, { now: now + 299 }), 'not_yet_valid');
});

test('expiry allows the same five minutes of clock skew', () => {
  const token = signLease(claims({ rev: now + 10_000 }), keys.privateKeyPem);
  assert.equal(reason(token, { now: now + 3600 + 299 }), 'ok');
  assert.equal(reason(token, { now: now + 3600 + 300 }), 'expired');
  assert.equal(reason(token, { now: now + 3600, leewaySeconds: 0 }), 'expired');
});

test('a header with crit is rejected, even when correctly signed (RFC 7515 4.1.11)', () => {
  const kid = keyId(keys.publicKeyPem);
  const signWith = (header: Record<string, unknown>) => {
    const input = `${b64(header)}.${b64(claims())}`;
    return `${input}.${sign(null, Buffer.from(input, 'ascii'), createPrivateKey(keys.privateKeyPem)).toString('base64url')}`;
  };
  assert.equal(reason(signWith({ alg: LEASE_ALGORITHM, typ: LEASE_TYPE, kid })), 'ok', 'the helper signs a valid lease');
  assert.equal(reason(signWith({ alg: LEASE_ALGORITHM, typ: LEASE_TYPE, kid, crit: ['exp'] })), 'malformed');
  assert.equal(reason(signWith({ alg: LEASE_ALGORITHM, typ: LEASE_TYPE, kid, crit: ['x-anything'], 'x-anything': 1 })), 'malformed');
});

test('expiry, revalidation window and grace', () => {
  const token = signLease(claims(), keys.privateKeyPem);
  assert.equal(reason(token, { now: now + 3600 + 300 }), 'expired');
  assert.equal(reason(token, { now: now + 700 }), 'revalidation_required');
  assert.equal(reason(token, { now: now + 700, graceSeconds: 200 }), 'ok');
});

test('a perpetual license has no exp claim', () => {
  const perpetual = claims({ rev: now + 10_000_000 });
  delete perpetual.exp;
  const token = signLease(perpetual, keys.privateKeyPem);
  assert.equal(decodeLease(token)?.claims.exp, undefined);
  assert.equal(reason(token, { now: now + 9_000_000 }), 'ok');
});

test('malformed leases', () => {
  const [h, p, s] = signLease(claims(), keys.privateKeyPem).split('.');
  assert.equal(reason(''), 'malformed');
  assert.equal(reason('abc'), 'malformed');
  assert.equal(reason(`${p}.${s}`), 'malformed');
  assert.equal(reason(`${h}.${p}.${s}.x`), 'malformed');
  assert.equal(reason(`not-json.${p}.${s}`), 'malformed');
  assert.equal(decodeLease('abc'), null);
  assert.equal(reason(`${h}..${s}`), 'malformed');
});

test('a well-signed payload with the wrong claim shapes is malformed', () => {
  const broken = { ...claims(), feat: 'pro' } as unknown as LeaseClaims;
  assert.equal(reason(signLease(broken, keys.privateKeyPem)), 'malformed');
});

test('license keys carry at least 128 random bits: seven Crockford Base32 groups of four', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const key = generateLicenseKey();
    assert.match(key, /^LK(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    assert.ok(key.replace(/^LK-|-/g, '').length * 5 >= 128);
    assert.equal(normalizeLicenseKey(key), key);
    seen.add(key);
  }
  assert.equal(seen.size, 200);
});

test('keys issued in the earlier four-group format still hash as they did', () => {
  const old = 'LK-7Q2M-9XPA-K4TD-W8NE';
  assert.equal(hashLicenseKey(old), createHash('sha256').update(old).digest('hex'));
  assert.equal(hashLicenseKey('lk7q2m9xpak4tdw8ne'), hashLicenseKey(old));
});

test('key input ignores case, spaces and hyphens and maps I, L to 1 and O to 0', () => {
  assert.equal(normalizeLicenseKey(' lk-7q2m-9xpa-k4td-w8ne '), 'LK-7Q2M-9XPA-K4TD-W8NE');
  assert.equal(normalizeLicenseKey('LK7Q2M9XPAK4TDW8NE'), 'LK-7Q2M-9XPA-K4TD-W8NE');
  assert.equal(normalizeLicenseKey('7q2m 9xpa k4td w8ne'), 'LK-7Q2M-9XPA-K4TD-W8NE');
  assert.equal(normalizeLicenseKey('LK-I0Ol-0000-1111-2222'), 'LK-1001-0000-1111-2222');
  const key = generateLicenseKey();
  assert.equal(hashLicenseKey(key), hashLicenseKey(key.toLowerCase().replace(/-/g, '')));
  assert.equal(hashLicenseKey(key), createHash('sha256').update(key).digest('hex'));
});

test('keys issued before the Crockford alphabet still match through the legacy hash', () => {
  const old = 'LK-ABLC-UVWX-2345-6789';
  const stored = createHash('sha256').update(old).digest('hex');
  assert.equal(legacyLicenseKeyHash(` ${old.toLowerCase()} `), stored);
  assert.notEqual(hashLicenseKey(old), stored);
});

test('grace and maintenance travel in the lease as optional numeric claims', () => {
  const token = signLease(claims({ grc: 7 * 86400, mnt: now + 30 * 86400 }), keys.privateKeyPem);
  const r = verifyLease(token, opts);
  assert.equal(r.ok && r.claims.grc, 7 * 86400);
  assert.equal(r.ok && r.claims.mnt, now + 30 * 86400);
  const broken = { ...claims(), grc: '7d' } as unknown as LeaseClaims;
  assert.equal(reason(signLease(broken, keys.privateKeyPem)), 'malformed');
  const negative = claims({ grc: -1 });
  assert.equal(reason(signLease(negative, keys.privateKeyPem)), 'malformed');
});

test('a JWK for the key set carries kid, alg and use', () => {
  const jwk = publicJwk(keys.publicKeyPem);
  assert.equal(jwk.kty, 'OKP');
  assert.equal(jwk.crv, 'Ed25519');
  assert.equal(jwk.alg, 'Ed25519');
  assert.equal(jwk.use, 'sig');
  assert.equal(jwk.kid, keyId(keys.publicKeyPem));
  assert.equal(keyId(createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' })), jwk.kid);
});

test('the lease vectors the Rust verifier is tested with (packages/lease/tests/vectors.json) are this library\'s results', async () => {
  const { readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const file = JSON.parse(readFileSync(join(__dirname, '..', '..', 'lease', 'tests', 'vectors.json'), 'utf8'));
  assert.equal(keyId(file.publicKey), file.kid);
  assert.ok(file.vectors.length >= 40);
  for (const v of file.vectors) {
    const r = verifyLease(v.token, { keys: [file.publicKey], ...v.check });
    assert.deepEqual(r.ok ? { ok: true, kid: r.header.kid } : { ok: false, reason: r.reason }, v.expected, v.name);
  }
  for (const v of file.features.normalize) assert.equal(normalizeLicenseKey(v.input), v.expected);
  for (const v of file.features.wrapKeys) assert.equal(featureWrapKey(v.licenseKey, v.product, v.fingerprintHash, v.leaseId).toString('hex'), v.expected);
  for (const v of file.features.decrypts) {
    const secret = v.deviceSecret ? Buffer.from(v.deviceSecret, 'hex') : undefined;
    const r = decryptFeature(v.token, { keys: [file.publicKey], ...v.check }, v.licenseKey, v.feature, Buffer.from(v.data, 'base64'), secret);
    assert.deepEqual(r.ok ? { ok: true, data: r.data.toString('base64') } : { ok: false, reason: r.reason }, v.expected, v.name);
  }
});

test('device public keys and device wrapping match the vectors and refuse other devices', () => {
  const file = JSON.parse(require('node:fs').readFileSync(require('node:path').join(__dirname, '..', '..', 'lease', 'tests', 'vectors.json'), 'utf8'));
  for (const v of file.features.devicePublicKeys) assert.equal(devicePublicKey(Buffer.from(v.secret, 'hex')).toString('base64url'), v.expected);
  const secret = Buffer.alloc(32, 7);
  const { wrapKey, epk } = featureWrapKeyForDevice('LK-AAAA', 'studio', 'fp', 'lease-1', devicePublicKey(secret));
  assert.deepEqual(deviceFeatureWrapKey('lk-aaaa', 'studio', 'fp', 'lease-1', secret, epk), wrapKey);
  assert.notDeepEqual(deviceFeatureWrapKey('LK-AAAA', 'studio', 'fp', 'lease-1', Buffer.alloc(32, 8), epk), wrapKey);
  assert.notDeepEqual(featureWrapKeyForDevice('LK-AAAA', 'studio', 'fp', 'lease-1', devicePublicKey(secret)).epk, epk, 'a new one-off key each time');
  assert.throws(() => featureWrapKeyForDevice('LK-AAAA', 'studio', 'fp', 'lease-1', Buffer.alloc(32)), FeatureCryptoError, 'low-order device key');
});

test('feature data: only the right content key and feature open it, and any change is detected', () => {
  const key = generateFeatureKey();
  const data = Buffer.from('premium');
  const sealed = encryptForFeature(key, 'pro', data);
  assert.deepEqual(sealed.subarray(0, 4), Buffer.from('LKE1'));
  assert.notDeepEqual(encryptForFeature(key, 'pro', data), sealed, 'a fresh nonce each time');
  assert.deepEqual(decryptForFeature(key, 'pro', sealed), data);
  assert.throws(() => decryptForFeature(key, 'export', sealed), FeatureCryptoError);
  assert.throws(() => decryptForFeature(generateFeatureKey(), 'pro', sealed), FeatureCryptoError);
  const changed = Buffer.from(sealed);
  changed[10] ^= 1;
  assert.throws(() => decryptForFeature(key, 'pro', changed), FeatureCryptoError);
  assert.throws(() => encryptForFeature(Buffer.alloc(16), 'pro', data), FeatureCryptoError);
});

test('a wrapped feature key opens only with the same license key, product, device and lease id', () => {
  const content = generateFeatureKey();
  const wrapKey = featureWrapKey('LK-AAAA-BBBB', 'studio', 'fp', 'lease-1');
  const wrapped = wrapFeatureKey(content, wrapKey, 'pro');
  assert.deepEqual(unwrapFeatureKey(wrapped, featureWrapKey('lk-aaaa-bbbb', 'studio', 'fp', 'lease-1'), 'pro'), content);
  for (const other of [
    featureWrapKey('LK-AAAA-BBBC', 'studio', 'fp', 'lease-1'),
    featureWrapKey('LK-AAAA-BBBB', 'other', 'fp', 'lease-1'),
    featureWrapKey('LK-AAAA-BBBB', 'studio', 'fp2', 'lease-1'),
    featureWrapKey('LK-AAAA-BBBB', 'studio', 'fp', 'lease-2'),
  ]) {
    assert.throws(() => unwrapFeatureKey(wrapped, other, 'pro'), FeatureCryptoError);
  }
  assert.throws(() => unwrapFeatureKey(wrapped, wrapKey, 'export'), FeatureCryptoError, 'bound to its feature');
});

test('licensekit-encrypt writes data that decryptForFeature opens; the key never comes from the command line', async () => {
  const { mkdtempSync, writeFileSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { runEncrypt } = await import('./encrypt-cli');
  const dir = mkdtempSync(join(tmpdir(), 'lke-'));
  const key = generateFeatureKey();
  writeFileSync(join(dir, 'in.js'), 'module.exports = 42;');
  const lines: string[] = [];
  const io = { out: (s: string) => lines.push(s), err: (s: string) => lines.push(s) };
  assert.equal(runEncrypt(['--feature', 'pro', join(dir, 'in.js'), join(dir, 'out.lke')], { LICENSEKIT_FEATURE_KEY: key.toString('base64url') }, io), 0);
  assert.equal(decryptForFeature(key, 'pro', readFileSync(join(dir, 'out.lke'))).toString(), 'module.exports = 42;');
  writeFileSync(join(dir, 'key.txt'), key.toString('base64url') + '\n');
  assert.equal(runEncrypt(['--feature', 'pro', '--key-file', join(dir, 'key.txt'), join(dir, 'in.js'), join(dir, 'out2.lke')], {}, io), 0);
  assert.equal(decryptForFeature(key, 'pro', readFileSync(join(dir, 'out2.lke'))).toString(), 'module.exports = 42;');
  assert.equal(runEncrypt(['--feature', 'pro', join(dir, 'in.js'), join(dir, 'x')], {}, io), 2, 'no key');
  assert.equal(runEncrypt(['--feature', 'pro', join(dir, 'in.js'), join(dir, 'x')], { LICENSEKIT_FEATURE_KEY: 'short' }, io), 2);
  assert.equal(runEncrypt([join(dir, 'in.js'), join(dir, 'x')], { LICENSEKIT_FEATURE_KEY: key.toString('base64url') }, io), 2, 'no feature');
});

test('licensekit-encrypt encrypts every file in a folder to the same paths with .lke', async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { runEncrypt } = await import('./encrypt-cli');
  const dir = mkdtempSync(join(tmpdir(), 'lke-dir-'));
  const key = generateFeatureKey();
  mkdirSync(join(dir, 'premium', 'lib'), { recursive: true });
  writeFileSync(join(dir, 'premium', 'index.js'), 'module.exports = require("./lib/math");');
  writeFileSync(join(dir, 'premium', 'lib', 'math.js'), 'module.exports = { add: (a, b) => a + b };');
  const lines: string[] = [];
  const io = { out: (s: string) => lines.push(s), err: (s: string) => lines.push(s) };
  assert.equal(runEncrypt(['--feature', 'pro', join(dir, 'premium'), join(dir, 'out')], { LICENSEKIT_FEATURE_KEY: key.toString('base64url') }, io), 0);
  assert.match(lines.at(-1)!, /Encrypted 2 file/);
  assert.equal(decryptForFeature(key, 'pro', readFileSync(join(dir, 'out', 'index.js.lke'))).toString(), 'module.exports = require("./lib/math");');
  assert.ok(existsSync(join(dir, 'out', 'lib', 'math.js.lke')));
  assert.equal(existsSync(join(dir, 'out', 'index.js')), false, 'no plain copy');
});
