// Writes vectors.json: client scenarios run through @carchalabs/seal-electron (the reference SDK) with a scripted
// license server and a set clock, with what the SDK sent and returned at every step. The native client (Rust, used by
// the C++, C# and Java SDKs) must give the same requests and results for every scenario; client-vectors.test.ts in
// sdk-electron re-runs the file against the SDK, so it cannot drift from it.
// Leases are signed with the lease vectors' throwaway test key (../../lease/tests/vectors.json).
// Run from the repository root after `npm run build`: node packages/client/tests/make-vectors.js
'use strict';
const { readFileSync, writeFileSync } = require('node:fs');
const path = require('node:path');
const core = require('../../core');
const { runScenario } = require('../../sdk-electron/dist/scenario-runner.test.js');

const leaseVectors = JSON.parse(readFileSync(path.join(__dirname, '../../lease/tests/vectors.json'), 'utf8'));
const privateKey = leaseVectors.testOnlyPrivateKey;
const publicKey = leaseVectors.publicKey;

const S = 1_800_000_000; // seconds
const H = 3600;
const D = 86400;
const ms = (seconds) => seconds * 1000;
const PRODUCT = 'studio';
const MACHINE = 'linux:0123456789abcdef0123456789abcdef';
const FP = core.hashFingerprint(MACHINE, PRODUCT);
const KEY = 'LK-7K2M-QX9P-4RTV-8WNB-3HCJ-6DFG-YZ5S';

let leaseNumber = 0;
/** A lease as the server issues it, at server time `at` (seconds). */
function lease(at, over = {}) {
  const claims = {
    iss: 'licensekit', sub: 'lic_1', aud: PRODUCT, jti: `lease-${++leaseNumber}`, iat: at, nbf: at,
    exp: at + 365 * D, rev: at + 72 * H, fp: FP, feat: ['pro'], cus: 'Acme', ...over,
  };
  for (const name of Object.keys(claims)) if (claims[name] === undefined) delete claims[name];
  return core.signLease(claims, privateKey);
}
const ok = (token, extra = {}) => ({ status: 200, body: { token, ...extra } });
const refusal = (status, error, message) => ({ status, body: { error, message } });
const NETWORK = { network: true };

const contentKey = Buffer.alloc(32, 7);
const previousKey = Buffer.alloc(32, 9);
const plain = Buffer.from('feature data for pro');
const older = Buffer.from('data encrypted before the key was replaced');
/** A lease whose fk carries the pro feature's content key (and optionally its previous one), wrapped for KEY. */
function leaseWithKeys(at, { previous = false } = {}) {
  const jti = `lease-${++leaseNumber}`;
  const wrapKey = core.featureWrapKey(KEY, PRODUCT, FP, jti);
  const fk = { pro: core.wrapFeatureKey(contentKey, wrapKey, 'pro') };
  if (previous) fk['pro~previous'] = core.wrapFeatureKey(previousKey, wrapKey, 'pro~previous');
  return lease(at, { jti, feat: ['pro', 'export'], fk });
}

const options = (over = {}) => ({ product: PRODUCT, publicKey: [publicKey], appVersion: '2.4.0', ...over });
const scenario = (name, steps, over = {}) => ({ name, options: options(over.options), machineId: over.machineId === undefined ? MACHINE : over.machineId, steps });
const at = (seconds, call, args, response) => ({ call, ...(args ? { args } : {}), nowMs: ms(seconds), ...(response ? { response } : {}) });

const scenarios = [
  scenario('nothing activated', [at(S, 'check')]),
  scenario('activate, then check in online', [
    at(S, 'activate', ['  lk-7k2m-qx9p-4rtv-8wnb-3hcj-6dfg-yz5s ', 'Design PC'], ok(lease(S))),
    at(S + H, 'check', null, ok(lease(S + H), { notices: [{ code: 'sdk_update_recommended', minimum: '0.6.0', requiredFrom: null }] })),
    at(S + 2 * H, 'check', null, NETWORK),
  ]),
  scenario('activate without a machine name, a long name is cut', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S, 'deactivate', null, { status: 200, body: { ok: true } }),
    at(S, 'activate', [KEY, 'x'.repeat(100)], ok(lease(S))),
  ]),
  scenario('activation refused: all seats used', [
    at(S, 'activate', [KEY], refusal(409, 'activation_limit', 'All 2 seat(s) are in use.')),
    at(S, 'check'),
  ]),
  scenario('activation: server error page, no JSON', [at(S, 'activate', [KEY], { status: 502, raw: '<html>Bad gateway</html>' })]),
  scenario('activation: no connection', [at(S, 'activate', [KEY], NETWORK)]),
  scenario('activation: lease for another device or product', [
    at(S, 'activate', [KEY], ok(lease(S, { fp: 'e'.repeat(64) }))),
    at(S, 'activate', [KEY], ok(lease(S, { aud: 'other' }))),
    at(S, 'check'),
  ]),
  scenario('activation: lease from the future (device clock behind)', [at(S - 2 * D, 'activate', [KEY], ok(lease(S)))]),
  scenario('offline within the revalidation time', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + 71 * H, 'check', null, NETWORK),
  ]),
  scenario('offline grace from the app option, then over', [
    at(S, 'activate', [KEY], ok(lease(S, { grc: undefined }))),
    at(S + 80 * H, 'check', null, NETWORK),
    at(S + 72 * H + 3 * D + 1, 'check', null, NETWORK),
  ], { options: { graceDays: 3 } }),
  scenario('offline grace from the lease, capped by expiry', [
    at(S, 'activate', [KEY], ok(lease(S, { grc: D, exp: S + 72 * H + 6 * H }))),
    at(S + 74 * H, 'check', null, NETWORK),
    at(S + 72 * H + D + 1, 'check', null, NETWORK),
  ], { options: { graceDays: 7 } }),
  scenario('default grace of 7 days', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + 72 * H + 6 * D, 'check', null, NETWORK),
    at(S + 72 * H + 7 * D, 'check', null, NETWORK),
  ]),
  scenario('device clock set back', [
    at(S, 'activate', [KEY], ok(lease(S, { rev: S + 30 * D }))),
    at(S + 10 * D, 'check', null, ok(lease(S + 10 * D, { rev: S + 40 * D }))),
    at(S + 9 * D, 'check', null, NETWORK),
    at(S + 8 * D, 'check', null, NETWORK),
  ]),
  scenario('server lease from the future at check-in', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, ok(lease(S + 2 * D))),
  ]),
  scenario('suspended: kept offline, restored online', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, refusal(403, 'license_suspended', 'This license is suspended.')),
    at(S + 2 * H, 'check', null, NETWORK),
    at(S + 3 * H, 'check', null, ok(lease(S + 3 * H))),
  ]),
  scenario('revoked: the key is forgotten', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, refusal(403, 'license_revoked', 'This license was revoked.')),
    at(S + 2 * H, 'check'),
  ]),
  scenario('invalid key: forgotten', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, refusal(404, 'invalid_key', 'Unknown license key.')),
    at(S + 2 * H, 'check'),
  ]),
  scenario('other definitive refusals', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, refusal(403, 'sdk_update_required', 'Update the app to keep using it.')),
    at(S + 2 * H, 'check', null, refusal(403, 'license_expired', 'This license has expired.')),
    at(S + 3 * H, 'check', null, refusal(404, 'not_activated', 'This device is not activated for this license')),
    at(S + 4 * H, 'check', null, refusal(403, 'vm_not_allowed', 'Virtual machines are not allowed.')),
    at(S + 5 * H, 'check', null, NETWORK),
  ]),
  scenario('server error at check-in: the saved lease is used', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, refusal(500, 'internal', 'Something went wrong.')),
    at(S + 2 * H, 'check', null, refusal(429, 'rate_limited', 'Too many requests.')),
    at(S + 3 * H, 'check', null, { status: 503, raw: 'unavailable' }),
  ]),
  scenario('expired lease offline', [
    at(S, 'activate', [KEY], ok(lease(S, { exp: S + D, rev: S + 3 * D }))),
    at(S + D + 200, 'check', null, NETWORK),
    at(S + D + 301, 'check', null, NETWORK),
  ]),
  scenario('perpetual license with maintenance', [
    at(S, 'activate', [KEY], ok(lease(S, { exp: undefined, mnt: S + 365 * D, cus: undefined, feat: [] }))),
  ]),
  scenario('lease signed with an unknown key or changed', [
    at(S, 'activate', [KEY], ok(core.signLease({ iss: 'licensekit', sub: 'l', aud: PRODUCT, jti: 'x', iat: S, nbf: S, rev: S + H, fp: FP, feat: [] }, core.generateSigningKeys().privateKeyPem))),
    at(S, 'activate', [KEY], ok(lease(S).slice(0, -2) + 'AA')),
  ]),
  scenario('deactivate', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'deactivate', null, { status: 200, body: { ok: true } }),
    at(S + 2 * H, 'check'),
    at(S + 2 * H, 'deactivate'),
  ]),
  scenario('deactivate when the server no longer knows the device', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'deactivate', null, refusal(404, 'not_activated', 'This device is not activated for this license')),
    at(S + 2 * H, 'check'),
  ]),
  scenario('deactivate without a connection keeps the license', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'deactivate', null, NETWORK),
    at(S + 2 * H, 'check', null, NETWORK),
  ]),
  scenario('offline activation by file', (() => {
    const token = lease(S, { rev: S + 30 * D, grc: 14 * D });
    const file = JSON.stringify({ format: 'licensekit-offline-license', version: 1, product: PRODUCT, licenseKey: KEY.toLowerCase(), token, customer: 'Acme', revalidateBy: new Date(ms(S + 30 * D)).toISOString() });
    return [
      at(S, 'offlineRequest', [` ${KEY.toLowerCase()} `]),
      at(S, 'offlineRequest', [KEY, 'Lab PC']),
      at(S + H, 'activateOffline', [file]),
      at(S + 2 * D, 'check'),
      at(S + 35 * D, 'check'),
      at(S + 45 * D, 'check'),
      at(S + 45 * D, 'deactivateOffline'),
      at(S + 45 * D, 'check'),
      at(S + 45 * D, 'deactivateOffline'),
    ];
  })()),
  scenario('offline license files that are refused', (() => {
    const good = { format: 'licensekit-offline-license', version: 1, product: PRODUCT, licenseKey: KEY };
    return [
      at(S, 'activateOffline', ['not json']),
      at(S, 'activateOffline', [JSON.stringify({ ...good, format: 'other', token: lease(S) })]),
      at(S, 'activateOffline', [JSON.stringify({ ...good, version: 2, token: lease(S) })]),
      at(S, 'activateOffline', [JSON.stringify({ ...good })]),
      at(S, 'activateOffline', [JSON.stringify({ ...good, product: 'other', token: lease(S) })]),
      at(S, 'activateOffline', [JSON.stringify({ ...good, token: lease(S, { fp: 'e'.repeat(64) }) })]),
      at(S, 'activateOffline', [JSON.stringify({ ...good, token: lease(S + 2 * D) })]),
      at(S, 'check'),
    ];
  })()),
  scenario('decrypt feature data', [
    at(S, 'decrypt', ['pro', core.encryptForFeature(contentKey, 'pro', plain).toString('base64')]),
    at(S, 'activate', [KEY], ok(leaseWithKeys(S, { previous: true }))),
    at(S + H, 'decrypt', ['pro', core.encryptForFeature(contentKey, 'pro', plain).toString('base64')]),
    at(S + H, 'decrypt', ['pro', core.encryptForFeature(previousKey, 'pro', older).toString('base64')]),
    at(S + H, 'decrypt', ['export', core.encryptForFeature(contentKey, 'export', plain).toString('base64')]),
    at(S + H, 'decrypt', ['other', core.encryptForFeature(contentKey, 'other', plain).toString('base64')]),
    at(S + H, 'decrypt', ['pro', core.encryptForFeature(Buffer.alloc(32, 1), 'pro', plain).toString('base64')]),
    at(S + 72 * H + D, 'decrypt', ['pro', core.encryptForFeature(contentKey, 'pro', plain).toString('base64')]),
    at(S + 72 * H + 8 * D, 'decrypt', ['pro', core.encryptForFeature(contentKey, 'pro', plain).toString('base64')]),
  ]),
  scenario('machine id cannot be read', [
    at(S, 'check'),
    at(S, 'activate', [KEY]),
  ], { machineId: null }),
  // A TLS-inspecting proxy or captive portal answering 200 with its own page: no lease from this server for this
  // device, so it counts as no answer and the saved lease stays (it used to replace it and lock the device out).
  scenario('a 2xx without a lease for this device is no answer: the saved lease is kept', [
    at(S, 'activate', [KEY], ok(lease(S))),
    at(S + H, 'check', null, { status: 200, raw: '<html>Blocked by your network administrator</html>' }),
    at(S + 2 * H, 'check', null, { status: 200, body: {} }),
    at(S + 3 * H, 'check', null, ok('not-a-lease')),
    at(S + 4 * H, 'check', null, ok(lease(S + 4 * H, { fp: core.hashFingerprint('linux:another-machine', PRODUCT) }))),
    at(S + 5 * H, 'check', null, NETWORK),
    at(S + 6 * H, 'check', null, ok(lease(S + 6 * H))),
  ]),
];

async function main() {
  const out = [];
  for (const s of scenarios) out.push({ ...s, outcomes: await runScenario(s) });
  const file = { publicKey, server: 'https://seal.example.com', scenarios: out };
  writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify(file, null, 2) + '\n');
  const steps = out.reduce((n, s) => n + s.steps.length, 0);
  console.log(`${out.length} scenarios, ${steps} steps`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
