'use strict';
// Loads the prebuilt addon for this platform: a local build next to this file (development),
// otherwise the platform package npm installed (@carchalabs/licensekit-hwid-<target>, one of
// the optionalDependencies). Fails loudly when there is none: the SDK then sends no components
// rather than a weaker fingerprint.
const path = require('node:path');
const { existsSync } = require('node:fs');
const { target } = require('./target');

function unavailable(detail) {
  const err = new Error(`@carchalabs/licensekit-hwid: no native module for ${process.platform}-${process.arch}: ${detail}`);
  err.code = 'HWID_UNAVAILABLE';
  return err;
}

const name = target();
if (!name) throw unavailable('this platform has no prebuilt module');
const local = path.join(__dirname, `licensekit-hwid.${name}.node`);
let addon;
try {
  addon = existsSync(local) ? require(local) : require(`@carchalabs/licensekit-hwid-${name}`);
} catch (e) {
  throw unavailable(e.message);
}

module.exports = { collect: addon.collect, verifyLease: addon.verifyLease, leaseKeyIds: addon.leaseKeyIds, version: addon.version };
