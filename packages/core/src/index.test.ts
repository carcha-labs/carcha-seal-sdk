import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import {
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

test('expiry, revalidation window and grace', () => {
  const token = signLease(claims(), keys.privateKeyPem);
  assert.equal(reason(token, { now: now + 3600 }), 'expired');
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

test('license keys use the Crockford Base32 alphabet in four groups of four', () => {
  for (let i = 0; i < 200; i++) {
    assert.match(generateLicenseKey(), /^LK-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  }
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
