import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readMachineId } from './fingerprint';
import { generateSigningKeys } from '@carchalabs/licensekit-core';
import { LicenseKit } from './index';

test('an unusable public key is rejected when the SDK is created', () => {
  assert.throws(() => new LicenseKit({ serverUrl: 'http://x', product: 'a', publicKey: '', storageDir: '/tmp' }));
});

test('machine id is stable across calls', async () => {
  const a = await readMachineId();
  const b = await readMachineId();
  assert.ok(a.length > 8);
  assert.equal(a, b);
});

test('fingerprint is a per-product sha256, never the raw id', async () => {
  const opts = { serverUrl: 'http://x', publicKey: generateSigningKeys().publicKeyPem, storageDir: '/tmp', machineId: async () => 'raw-id' };
  const f1 = await new LicenseKit({ ...opts, product: 'a' }).fingerprint();
  const f2 = await new LicenseKit({ ...opts, product: 'b' }).fingerprint();
  assert.match(f1, /^[a-f0-9]{64}$/);
  assert.notEqual(f1, f2);
  assert.equal(f1.includes('raw-id'), false);
});
