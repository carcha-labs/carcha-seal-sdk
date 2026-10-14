'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, createPublicKey } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const hwid = require('..');

const vectors = JSON.parse(readFileSync(path.join(__dirname, '..', '..', 'lease', 'tests', 'vectors.json'), 'utf8'));

/** keyId as @carchalabs/licensekit-core computes it. */
const keyId = (pem) => {
  const x = createPublicKey(pem).export({ format: 'jwk' }).x;
  return createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
};

test('the default build trusts the hosted service keys, current and next', () => {
  const dir = path.join(__dirname, '..', '..', 'quickstart', 'public-keys');
  const expected = ['current.pem', 'next.pem'].map((f) => keyId(readFileSync(path.join(dir, f), 'utf8')));
  assert.deepEqual(hwid.leaseKeyIds(), expected);
});

test('a lease signed by a key the build does not trust is refused, whatever it says', () => {
  const valid = vectors.vectors.find((v) => v.name === 'valid');
  assert.deepEqual(hwid.verifyLease(valid.token, valid.check), { ok: false, reason: 'unknown_key' });
});

// A build made with LICENSEKIT_LEASE_PUBLIC_KEYS set to the vectors' test key (CI builds one):
// every vector must give the result the core library gives.
const testAddon = process.env.LICENSEKIT_LEASE_TEST_ADDON;
test('every lease vector gives the core library result', { skip: !testAddon && 'set LICENSEKIT_LEASE_TEST_ADDON' }, () => {
  const addon = require(path.resolve(testAddon));
  assert.deepEqual(addon.leaseKeyIds(), [vectors.kid]);
  for (const v of vectors.vectors) {
    const r = addon.verifyLease(v.token, v.check);
    assert.deepEqual(r.ok ? { ok: true, kid: r.kid } : { ok: false, reason: r.reason }, v.expected, v.name);
  }
});

test('feature data is decrypted only through a lease the build trusts', () => {
  const v = vectors.features.decrypts.find((x) => x.name === 'decrypts for a licensed feature');
  const r = hwid.decryptFeature(v.token, v.check, v.licenseKey, v.feature, Buffer.from(v.data, 'base64'));
  assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: 'unknown_key' });
  assert.equal(r.data, undefined);
});

test('every feature vector gives the core library result', { skip: !testAddon && 'set LICENSEKIT_LEASE_TEST_ADDON' }, () => {
  const addon = require(path.resolve(testAddon));
  // The test build takes a device secret as a sixth argument (feature test-device-secret).
  for (const v of vectors.features.decrypts) {
    const secret = v.deviceSecret ? Buffer.from(v.deviceSecret, 'hex') : undefined;
    const r = addon.decryptFeature(v.token, v.check, v.licenseKey, v.feature, Buffer.from(v.data, 'base64'), secret);
    assert.deepEqual(r.ok ? { ok: true, data: r.data.toString('base64') } : { ok: false, reason: r.reason }, v.expected, v.name);
  }
});

test('the device key comes from this machine: stable, per product, and it opens what was wrapped for it', () => {
  const key = hwid.devicePublicKey('licensekit:studio');
  if (key === null) return; // a machine that reports none of uuid, board, disk, os (rare)
  assert.match(key, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(hwid.devicePublicKey('licensekit:studio'), key);
  assert.equal(hwid.devicePublicKey(Buffer.from('licensekit:studio')), key);
  assert.notEqual(hwid.devicePublicKey('licensekit:other'), key);
  assert.throws(() => hwid.devicePublicKey(''), /key must not be empty/);
});

test('a lease wrapped for this machine\'s device key opens here; one wrapped for another key does not', { skip: !testAddon && 'set LICENSEKIT_LEASE_TEST_ADDON' }, () => {
  const addon = require(path.resolve(testAddon));
  const { createPrivateKey, createPublicKey: pub, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign, createCipheriv } = require('node:crypto');
  const device = addon.devicePublicKey('licensekit:studio');
  if (device === null) return;
  // Independent of licensekit-core: the construction as documented, with Node's crypto.
  const b64 = (b) => Buffer.from(b).toString('base64url');
  const LICENSE = 'LK-7K2M-QX9P-4RTV-8WNB-3HCJ-6DFG-YZ5S';
  const FP = 'f'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const content = randomBytes(32);
  const seal = (key, plain, aad) => {
    const nonce = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, nonce);
    c.setAAD(Buffer.from(aad));
    return Buffer.concat([nonce, c.update(plain), c.final(), c.getAuthTag()]);
  };
  const leaseFor = (devicePublic) => {
    const eph = generateKeyPairSync('x25519');
    const epk = pub(eph.privateKey).export({ format: 'der', type: 'spki' }).subarray(12);
    const devKey = pub({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(devicePublic, 'base64url')]), format: 'der', type: 'spki' });
    const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: devKey });
    const jti = 'lease-hw';
    const info = `studio\n${FP}\n${jti}\n${b64(epk)}\n${devicePublic}`;
    const wrapKey = Buffer.from(hkdfSync('sha256', Buffer.concat([shared, Buffer.from(LICENSE)]), Buffer.from('licensekit feature key v2 device'), Buffer.from(info), 32));
    const claims = { iss: 'licensekit', sub: 'lic', aud: 'studio', jti, iat: now - 10, nbf: now - 10, rev: now + 3600, fp: FP, feat: ['pro'], fk: { pro: b64(seal(wrapKey, content, 'fk:pro')) }, epk: b64(epk) };
    const header = { alg: 'Ed25519', typ: 'licensekit-lease+jwt', kid: vectors.kid };
    const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
    return `${input}.${b64(sign(null, Buffer.from(input), createPrivateKey(vectors.testOnlyPrivateKey)))}`;
  };
  const data = Buffer.concat([Buffer.from('LKE1'), seal(content, Buffer.from('hardware-bound'), 'LKE1:pro')]);
  const check = { product: 'studio', fingerprintHash: FP };
  const here = addon.decryptFeature(leaseFor(device), check, LICENSE, 'pro', data);
  assert.equal(here.ok, true, here.reason);
  assert.equal(here.data.toString(), 'hardware-bound');
  const elsewhere = generateKeyPairSync('x25519');
  const otherPublic = b64(pub(elsewhere.privateKey).export({ format: 'der', type: 'spki' }).subarray(12));
  assert.deepEqual(addon.decryptFeature(leaseFor(otherPublic), check, LICENSE, 'pro', data).reason, 'decrypt_failed');
});
