// Writes vectors.json: leases signed by @carchalabs/licensekit-core with a throwaway test
// key, each with the result core's verifyLease gives. The Rust crate must give the same
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

for (const v of vectors) {
  const r = core.verifyLease(v.token, { keys: [pem], ...v.check });
  v.expected = r.ok ? { ok: true, kid } : { ok: false, reason: r.reason };
}
writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify({ publicKey: pem, kid, vectors }, null, 2) + '\n');
console.log(`${vectors.length} vectors`);
