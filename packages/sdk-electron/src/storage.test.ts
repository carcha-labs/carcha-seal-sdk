// license.dat is replaced whole (written to license.dat.tmp, then renamed), so a crash or a full disk mid-write
// leaves the previous record instead of a cut-off file that would read as "unlicensed".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSigningKeys } from '@carchalabs/seal-core';
import { Seal } from './index';

test('license.dat is replaced whole, owner-only, and a failed write keeps the saved record', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'seal-store-'));
  const seal = new Seal({ serverUrl: 'https://x', product: 'p', publicKey: generateSigningKeys().publicKeyPem, storageDir: dir, machineId: async () => 'm', hardware: false });
  const save = (stored: object) => (seal as any).save(stored) as Promise<void>;
  const file = join(dir, 'license.dat');

  await save({ licenseKey: 'LK-A' });
  await save({ licenseKey: 'LK-B' });
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), { licenseKey: 'LK-B' });
  assert.equal(existsSync(file + '.tmp'), false, 'no temporary file left');
  if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);

  mkdirSync(file + '.tmp'); // the temporary file cannot be written
  await assert.rejects(save({ licenseKey: 'LK-C' }));
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), { licenseKey: 'LK-B' });
  rmdirSync(file + '.tmp');
});
