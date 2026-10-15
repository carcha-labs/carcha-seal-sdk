// Writes vectors.json: leases signed by @carchalabs/seal-core with a throwaway test
// key (its private half is in the file as testOnlyPrivateKey, so tests can sign more; no build
// trusts it except the CI test build), each with the result core's verifyLease gives. The Rust crate must give the same
// result for every vector (tests/conformance.rs); test/vectors.test.js in hwid-node re-checks
// the expected results against core, so the file cannot drift from it.
// Run from the repository root after building core: node packages/lease/tests/make-vectors.js
'use strict';
const { writeFileSync } = require('node:fs');
const path = require('node:path');
const { generateKeyPairSync, sign } = require('node:crypto');
const core = require('../../core');

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const kid = core.keyId(publicKey);

const NOW = 1_800_000_000;
const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const claims = (over = {}) => ({
  iss: 'licensekit', sub: 'lic_1', aud: 'studio', jti: 'j1', iat: NOW - 60, nbf: NOW - 60, exp: NOW + 86400,
  rev: NOW + 3600, fp: 'f'.repeat(64), feat: ['pro'], cus: 'Acme', grc: 604800, ...over,
});
const header = (over = {}) => ({ alg: 'Ed25519', typ: 'licensekit-lease+jwt', kid, ...over });
/** Signs any header and claims (raw segments allowed) with the test key, as core does. */
const signed = (h, c, key = privateKey) => {
  const input = `${typeof h === 'string' ? h : b64(h)}.${typeof c === 'string' ? c : b64(c)}`;
  return `${input}.${sign(null, Buffer.from(input, 'ascii'), key).toString('base64url')}`;
};
const good = core.signLease(claims(), privateKey);
const [gh, gc, gs] = good.split('.');
const without = (name) => { const c = claims(); delete c[name]; return c; };

const base = { product: 'studio', fingerprintHash: 'f'.repeat(64), now: NOW };
const cases = [
  ['valid', good],
  ['valid without exp', core.signLease(without('exp'), privateKey)],
  ['valid without optional cus, grc, mnt', core.signLease((({ cus, grc, ...c }) => c)(claims()), privateKey)],
  ['two parts', `${gh}.${gc}`],
  ['four parts', `${good}.x`],
  ['empty signature', `${gh}.${gc}.`],
  ['header not base64url', `${gh}=.${gc}.${gs}`],
  ['header not JSON', signed(b64('not json'), claims())],
  ['header is an array', signed(b64('[1]'), claims())],
  ['alg none', signed(header({ alg: 'none' }), claims())],
  ['alg missing', signed((({ alg, ...h }) => h)(header()), claims())],
  ['alg lowercase', signed(header({ alg: 'ed25519' }), claims())],
  ['typ JWT', signed(header({ typ: 'JWT' }), claims())],
  ['crit present', signed(header({ crit: ['exp'] }), claims())],
  ['kid unknown', signed(header({ kid: 'nope' }), claims())],
  ['kid not a string', signed(header({ kid: 1 }), claims())],
  ['signature not base64url', `${gh}.${gc}.${gs.slice(0, -1)}+`],
  ['signature by another key', signed(header(), claims(), other.privateKey)],
  ['claims changed after signing', `${gh}.${b64(claims({ feat: ['pro', 'enterprise'] }))}.${gs}`],
  ['signature truncated', `${gh}.${gc}.${gs.slice(0, 40)}`],
  ['claims not JSON', signed(header(), b64('nope'))],
  ['claims missing fp', signed(header(), without('fp'))],
  ['claims iat a string', signed(header(), claims({ iat: '1' }))],
  ['claims exp null', signed(header(), claims({ exp: null }))],
  ['claims feat not strings', signed(header(), claims({ feat: [1] }))],
  ['claims cus null', signed(header(), claims({ cus: null }))],
  ['claims grc negative', signed(header(), claims({ grc: -1 }))],
  ['claims mnt zero', signed(header(), claims({ mnt: 0 }))],
  ['wrong issuer', core.signLease(claims({ iss: 'someone' }), privateKey)],
  ['wrong product', core.signLease(claims({ aud: 'other' }), privateKey)],
  ['wrong device', core.signLease(claims({ fp: 'e'.repeat(64) }), privateKey)],
  ['not yet valid beyond leeway', core.signLease(claims({ nbf: NOW + 301 }), privateKey)],
  ['nbf within leeway', core.signLease(claims({ nbf: NOW + 300 }), privateKey)],
  ['expired at leeway edge', core.signLease(claims({ exp: NOW - 300 }), privateKey)],
  ['exp within leeway', core.signLease(claims({ exp: NOW - 299 }), privateKey)],
  ['revalidation due', core.signLease(claims({ rev: NOW }), privateKey)],
  ['revalidation one second left', core.signLease(claims({ rev: NOW + 1 }), privateKey)],
];
const vectors = cases.map(([name, token]) => ({ name, token, check: base }));
// Options the SDK passes: grace for the lenient check, another issuer, a fractional clock.
vectors.push({ name: 'revalidation due, inside grace', token: core.signLease(claims({ rev: NOW - 10 }), privateKey), check: { ...base, graceSeconds: 11 } });
vectors.push({ name: 'revalidation due, grace used up', token: core.signLease(claims({ rev: NOW - 10 }), privateKey), check: { ...base, graceSeconds: 10 } });
vectors.push({ name: 'custom issuer', token: core.signLease(claims({ iss: 'acme' }), privateKey), check: { ...base, issuer: 'acme' } });
vectors.push({ name: 'leeway zero', token: core.signLease(claims({ nbf: NOW + 1 }), privateKey), check: { ...base, leewaySeconds: 0 } });

// Feature keys in the claims: an object of strings, or absent.
vectors.push({ name: 'fk with a wrapped key', token: core.signLease(claims({ fk: { pro: 'AAAA' } }), privateKey), check: base });
vectors.push({ name: 'fk not an object', token: signed(header(), claims({ fk: ['AAAA'] })), check: base });
vectors.push({ name: 'fk value not a string', token: signed(header(), claims({ fk: { pro: 1 } })), check: base });
vectors.push({ name: 'epk a string', token: core.signLease(claims({ fk: {}, epk: 'AAAA' }), privateKey), check: base });
vectors.push({ name: 'epk not a string', token: signed(header(), claims({ epk: 1 })), check: base });

for (const v of vectors) {
  const r = core.verifyLease(v.token, { keys: [pem], ...v.check });
  v.expected = r.ok ? { ok: true, kid } : { ok: false, reason: r.reason };
}

// ---- Feature keys ----
const normalize = ['lk-abcd-efgh-ijkl', ' LK ABCD efgh ', 'abcdoil0', 'LKLK-1234', 'lk--', '', 'ABCDEFGHIJ'].map((input) => ({ input, expected: core.normalizeLicenseKey(input) }));

const LICENSE = 'LK-7K2M-QX9P-4RTV-8WNB-3HCJ-6DFG-YZ5S';
const FP = 'f'.repeat(64);
const contentKeys = { pro: core.generateFeatureKey(), export: core.generateFeatureKey() };
/** A lease granting `feat`, with the content keys of `wrapFor` wrapped for this license key, device and lease id. */
const featureLease = ({ jti = 'lease-1', feat = ['pro', 'export'], wrapFor = feat, license = LICENSE, fp = FP } = {}) => {
  const wrapKey = core.featureWrapKey(license, 'studio', fp, jti);
  const fk = Object.fromEntries(wrapFor.map((f) => [f, core.wrapFeatureKey(contentKeys[f], wrapKey, f)]));
  return core.signLease(claims({ jti, feat, fk, fp }), privateKey);
};
const plaintext = Buffer.from('premium module: export(){ return 42 }', 'utf8');
const forPro = core.encryptForFeature(contentKeys.pro, 'pro', plaintext);
const tampered = Buffer.from(forPro);
tampered[tampered.length - 1] ^= 1;
const decrypts = [
  ['decrypts for a licensed feature', featureLease(), LICENSE, 'pro', forPro],
  ['license key typed differently (normalized)', featureLease(), ' lk-7k2m-qx9p-4rtv-8wnb-3hcj-6dfg-yz5s ', 'pro', forPro],
  ['data for another feature', featureLease(), LICENSE, 'export', forPro],
  ['feature not in the lease', featureLease({ feat: ['export'] }), LICENSE, 'pro', forPro],
  ['feature granted but no key in the lease', featureLease({ wrapFor: ['export'] }), LICENSE, 'pro', forPro],
  ['another license key', featureLease(), 'LK-0000-0000-0000-0000-0000-0000-0000', 'pro', forPro],
  ['keys wrapped for another device', featureLease({ fp: 'e'.repeat(64) }), LICENSE, 'pro', forPro],
  ['data modified', featureLease(), LICENSE, 'pro', tampered],
  ['not data encrypted for Carcha Seal', featureLease(), LICENSE, 'pro', plaintext],
  ['data too short', featureLease(), LICENSE, 'pro', Buffer.from('LKE1')],
  ['lease refused (signed by another key)', signed(header(), claims({ fk: {} }), other.privateKey), LICENSE, 'pro', forPro],
];

// Device keys: feature keys wrapped for a device's X25519 public key (claim epk).
const deviceSecret = Buffer.from('11'.repeat(32), 'hex');
const otherDevice = Buffer.from('22'.repeat(32), 'hex');
const deviceLease = ({ jti = 'lease-d', epkOverride } = {}) => {
  const { wrapKey, epk } = core.featureWrapKeyForDevice(LICENSE, 'studio', FP, jti, core.devicePublicKey(deviceSecret));
  const fk = { pro: core.wrapFeatureKey(contentKeys.pro, wrapKey, 'pro') };
  return core.signLease(claims({ jti, feat: ['pro'], fk, epk: epkOverride ?? epk }), privateKey);
};
decrypts.push(
  ['device: decrypts with the device secret', deviceLease(), LICENSE, 'pro', forPro, deviceSecret],
  ['device: another device\'s secret', deviceLease(), LICENSE, 'pro', forPro, otherDevice],
  ['device: no device secret', deviceLease(), LICENSE, 'pro', forPro],
  ['device: wrong license key', deviceLease(), 'LK-0000-0000-0000-0000-0000-0000-0000', 'pro', forPro, deviceSecret],
  ['device: low-order epk (all zero)', deviceLease({ epkOverride: Buffer.alloc(32).toString('base64url') }), LICENSE, 'pro', forPro, deviceSecret],
  ['device: epk not 32 bytes', deviceLease({ epkOverride: 'AAAA' }), LICENSE, 'pro', forPro, deviceSecret],
  ['device: secret given, lease not wrapped for a device', featureLease(), LICENSE, 'pro', forPro, deviceSecret],
);
const decryptVectors = decrypts.map(([name, token, licenseKey, feature, data, secret]) => {
  const r = core.decryptFeature(token, { keys: [pem], ...base }, licenseKey, feature, data, secret);
  return {
    name, token, check: base, licenseKey, feature, data: data.toString('base64'), ...(secret ? { deviceSecret: secret.toString('hex') } : {}),
    expected: r.ok ? { ok: true, data: r.data.toString('base64') } : { ok: false, reason: r.reason },
  };
});
const devicePublicKeys = [deviceSecret, otherDevice, Buffer.from('ff'.repeat(32), 'hex')].map((secret) => ({ secret: secret.toString('hex'), expected: core.devicePublicKey(secret).toString('base64url') }));
// The wrap key itself, so a different derivation shows up directly.
const wrapKeys = [[LICENSE, 'studio', FP, 'lease-1'], ['lk-abcd', 'p', 'x', '']].map(([licenseKey, product, fingerprintHash, leaseId]) => ({
  licenseKey, product, fingerprintHash, leaseId, expected: core.featureWrapKey(licenseKey, product, fingerprintHash, leaseId).toString('hex'),
}));

writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify({ publicKey: pem, kid, testOnlyPrivateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), vectors, features: { normalize, wrapKeys, decrypts: decryptVectors, devicePublicKeys } }, null, 2) + '\n');
console.log(`${vectors.length} lease vectors, ${normalize.length + wrapKeys.length + decryptVectors.length + devicePublicKeys.length} feature vectors`);
