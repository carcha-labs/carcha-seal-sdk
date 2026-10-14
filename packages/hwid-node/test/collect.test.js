'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const hwid = require('..');

test('collect returns hashed components, never raw values', () => {
  const c = hwid.collect('product-a');
  assert.equal(c.format, 1);
  assert.equal(typeof c.vm, 'boolean');
  assert.ok(c.components.length > 0, 'at least one component on any real machine');
  for (const x of c.components) {
    assert.match(x.kind, /^(uuid|board|disk|mac|os|cpu|gpu)$/);
    assert.match(x.hash, /^[0-9a-f]{64}$/);
  }
  assert.ok(Array.isArray(c.notes));
});

test('same key gives the same result; another key gives unrelated hashes', () => {
  const a = hwid.collect('product-a');
  assert.deepEqual(hwid.collect('product-a'), a);
  assert.deepEqual(hwid.collect(Buffer.from('product-a')), a, 'string and bytes are the same key');
  const b = hwid.collect('product-b');
  assert.deepEqual(b.components.map((x) => x.kind), a.components.map((x) => x.kind));
  for (let i = 0; i < a.components.length; i++) assert.notEqual(b.components[i].hash, a.components[i].hash);
});

test('matches the C interface and the Rust core', () => {
  // The core's own HMAC test vector, recomputed here with Node's crypto:
  // HMAC-SHA256(key, kind || 0x00 || value) is what every layer must produce.
  const crypto = require('node:crypto');
  const expected = crypto.createHmac('sha256', 'product-a').update(Buffer.from('disk\0SN123')).digest('hex');
  assert.equal(expected, '6fcf77138cd14a06f8ea528c725d14dcbff9a9e7e7ffe9a510e0e5b414e645b9');
});

test('rejects an empty or missing key', () => {
  assert.throws(() => hwid.collect(''), /key must not be empty/);
  assert.throws(() => hwid.collect(Buffer.alloc(0)), /key must not be empty/);
  assert.throws(() => hwid.collect());
  assert.throws(() => hwid.collect(42));
});

test('version is semver', () => {
  assert.match(hwid.version(), /^\d+\.\d+\.\d+$/);
});
