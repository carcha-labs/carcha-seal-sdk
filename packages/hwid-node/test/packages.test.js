'use strict';
// The published layout (napi-rs convention): the main package lists one platform package per
// target as an exact-version optional dependency; each declares os/cpu (and libc on Linux), so
// npm installs only the one for the machine.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { target, TARGETS } = require('../target');

const root = path.join(__dirname, '..');
const main = require(path.join(root, 'package.json'));

test('every target has a platform package at the main version, listed with that exact version', () => {
  assert.deepEqual(Object.keys(main.optionalDependencies).sort(), TARGETS.map((t) => `@carchalabs/seal-hwid-${t}`).sort());
  for (const t of TARGETS) {
    const pkg = require(path.join(root, 'npm', t, 'package.json'));
    assert.equal(pkg.name, `@carchalabs/seal-hwid-${t}`);
    assert.equal(pkg.version, main.version, t);
    assert.equal(main.optionalDependencies[pkg.name], main.version, t);
    assert.equal(pkg.main, `seal-hwid.${t}.node`);
    assert.deepEqual(pkg.files, [pkg.main]);
    assert.equal(pkg.os.length, 1);
    assert.equal(pkg.cpu.length, 1);
    assert.equal(target(pkg.os[0], pkg.cpu[0], false), t, `${t} os/cpu map back to it`);
    assert.deepEqual(pkg.libc, pkg.os[0] === 'linux' ? ['glibc'] : undefined);
  }
});

test('platforms without a prebuilt module get no target', () => {
  assert.equal(target('linux', 'x64', true), null, 'musl');
  assert.equal(target('linux', 'arm64', false), null);
  assert.equal(target('win32', 'arm64', false), null);
  assert.equal(target('freebsd', 'x64', false), null);
});

test('the main package ships the loader, types and target map, not binaries', () => {
  assert.deepEqual(main.files, ['index.js', 'index.d.ts', 'target.js']);
});
