// No computer name by default (D6 finding P2): host names often hold a person's name, so activate() and
// offlineRequest() send a machine name only when the app passes one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSigningKeys } from '@carchalabs/seal-core';
import { Seal } from './index';

const publicKey = generateSigningKeys().publicKeyPem;
const seal = (serverUrl: string) =>
  new Seal({ serverUrl, product: 'p', publicKey, storageDir: mkdtempSync(join(tmpdir(), 'seal-name-')), machineId: async () => 'm', hardware: false });

test('activate sends a machine name only when the app gives one', async () => {
  const bodies: any[] = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      bodies.push(JSON.parse(body));
      res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'invalid_key', message: 'no' }));
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await seal(url).activate('LK-AAAA-BBBB').catch(() => undefined);
    await seal(url).activate('LK-AAAA-BBBB', 'Studio iMac').catch(() => undefined);
  } finally {
    server.close();
  }
  assert.equal(bodies.length, 2);
  assert.ok(!('machineName' in bodies[0]) || bodies[0].machineName === undefined, 'nothing sent by default');
  assert.ok(!JSON.stringify(bodies[0]).includes(hostname()), "the computer's name is not sent");
  assert.equal(bodies[1].machineName, 'Studio iMac');
});

test('an offline request holds a machine name only when the app gives one', async () => {
  const without = JSON.parse(await seal('https://seal.example.com').offlineRequest('LK-AAAA-BBBB')).activation;
  const withName = JSON.parse(await seal('https://seal.example.com').offlineRequest('LK-AAAA-BBBB', 'Lab PC')).activation;
  assert.equal(without.machineName, undefined);
  assert.equal(withName.machineName, 'Lab PC');
});
