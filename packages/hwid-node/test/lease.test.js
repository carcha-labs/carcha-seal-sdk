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
