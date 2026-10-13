import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IOREG, MachineIdUnavailableError, readMachineId, REG_EXE } from './fingerprint';
import { generateSigningKeys } from '@carchalabs/licensekit-core';
import { LicenseError, LicenseKit } from './index';

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

test('the OS tools are run by absolute path, so a fake ioreg or reg first in PATH is never used', async () => {
  const calls: string[] = [];
  const mac = await readMachineId({
    platform: 'darwin',
    run: async (file) => (calls.push(file), { stdout: '  "IOPlatformUUID" = "ABC-123"' }),
  });
  assert.equal(mac, 'mac:ABC-123');
  const win = await readMachineId({
    platform: 'win32',
    run: async (file, args) => (calls.push(file), assert.ok(args.includes('/reg:64')), { stdout: '    MachineGuid    REG_SZ    1234-abcd' }),
  });
  assert.equal(win, 'win:1234-abcd');
  assert.deepEqual(calls, [IOREG, REG_EXE[0]]);
  assert.equal(IOREG, '/usr/sbin/ioreg');
  for (const file of [IOREG, ...REG_EXE]) assert.ok(file.startsWith('/') || /^[A-Z]:\\/i.test(file), file);
});

test('on Windows every reg.exe location is tried, each by absolute path, when one cannot run', async () => {
  const calls: string[] = [];
  await assert.rejects(
    readMachineId({
      platform: 'win32',
      attempts: 1,
      run: async (file) => {
        calls.push(file);
        throw new Error('ENOENT');
      },
    }),
    MachineIdUnavailableError,
  );
  assert.deepEqual(calls, REG_EXE);
});

test('a failed OS id read is retried before giving up', async () => {
  let calls = 0;
  const id = await readMachineId({
    platform: 'darwin',
    delayMs: 1,
    run: async () => (++calls < 3 ? { stdout: '' } : { stdout: '"IOPlatformUUID" = "LATE-1"' }),
  });
  assert.deepEqual([id, calls], ['mac:LATE-1', 3]);
});

test('without the OS id there is no silent fallback: an error unless the vendor allows hardware traits', async () => {
  const failing = { platform: 'darwin' as const, delayMs: 1, run: async () => ({ stdout: '' }) };
  await assert.rejects(readMachineId(failing), (e: any) => e instanceof MachineIdUnavailableError && e.code === 'machine_id_unavailable');
  assert.match(await readMachineId({ ...failing, allowFallback: true }), /^fallback:/);
});

test('the SDK reports machine_id_unavailable instead of activating with a different fingerprint', async () => {
  const kit = new LicenseKit({
    serverUrl: 'http://127.0.0.1:9',
    product: 'a',
    publicKey: generateSigningKeys().publicKeyPem,
    storageDir: '/tmp/lk-no-id',
    machineId: async () => {
      throw new MachineIdUnavailableError();
    },
  });
  const state = await kit.check();
  assert.deepEqual([state.status, state.reason], ['invalid', 'machine_id_unavailable']);
  await assert.rejects(kit.activate('LK-AAAA'), (e: any) => e instanceof LicenseError && e.code === 'machine_id_unavailable');
});
