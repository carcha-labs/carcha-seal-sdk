// The license server is reached over https only, and a redirect is never followed (OWASP ASVS 4.1.2): a request
// carries the license key and the device's fingerprint.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSigningKeys } from '@carchalabs/seal-core';
import { LicenseError, Seal } from './index';

const publicKey = generateSigningKeys().publicKeyPem;
const seal = (serverUrl: string, extra: Partial<ConstructorParameters<typeof Seal>[0]> = {}) =>
  new Seal({ serverUrl, product: 'p', publicKey, storageDir: mkdtempSync(join(tmpdir(), 'seal-url-')), machineId: async () => 'm', hardware: false, ...extra });

const refused = (code: string) => (e: unknown) => e instanceof LicenseError && e.code === code;

test('https is accepted; http only for this computer', () => {
  for (const url of ['https://seal.carchalabs.com', 'https://licenses.example.com:8443/base/', 'http://localhost:4000', 'http://127.0.0.1:4000', 'http://127.8.9.10', 'http://[::1]:4000']) {
    assert.doesNotThrow(() => seal(url), url);
  }
});

test('plain http to another host, or another scheme, is refused when the SDK is created', () => {
  for (const url of ['http://seal.carchalabs.com', 'http://192.168.1.10:4000', 'http://localhost.example.com', 'http://127.0.0.1.example.com', 'ftp://seal.carchalabs.com', 'ws://localhost']) {
    assert.throws(() => seal(url), refused('insecure_server_url'), url);
  }
  assert.throws(() => seal('seal.carchalabs.com'), refused('invalid_server_url'), 'no scheme');
});

const listen = (server: Server) => new Promise<string>((done) => server.listen(0, '127.0.0.1', () => done(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));

test('a redirect is not followed: the request never reaches the other address', async () => {
  let reached = 0;
  const target = createServer((_req, res) => {
    reached++;
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  const targetUrl = await listen(target);
  const redirecting = createServer((_req, res) => res.writeHead(307, { location: `${targetUrl}/v1/activate` }).end());
  const url = await listen(redirecting);
  try {
    await assert.rejects(seal(url).activate('LK-TEST', 'pc'), refused('network'));
    assert.equal(reached, 0);
  } finally {
    redirecting.close();
    target.close();
  }
});

test('every request asks fetch not to follow redirects', async () => {
  const inits: RequestInit[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    inits.push(init);
    return new Response('{}', { status: 500 });
  }) as typeof fetch;
  await assert.rejects(seal('https://seal.carchalabs.com', { fetchImpl }).activate('LK-TEST', 'pc'));
  assert.equal(inits[0]?.redirect, 'error');
});
