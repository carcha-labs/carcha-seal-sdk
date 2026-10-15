# @carchalabs/seal-core

The lease format used by [Carcha Seal](https://seal.carchalabs.com) (formerly LicenseKit). A lease is a compact JSON Web Signature (RFC 7515) signed with Ed25519 (RFC 9864), with the header `typ: licensekit-lease+jwt` and a `kid` that is the RFC 7638 thumbprint of the signing key.

Apps normally use [`@carchalabs/seal-electron`](https://www.npmjs.com/package/@carchalabs/seal-electron), which uses this package. Use it directly to sign leases on a server or to verify them in another runtime.

```js
const { generateSigningKeys, signLease, verifyLease, keySet } = require('@carchalabs/seal-core');

const { privateKeyPem, publicKeyPem } = generateSigningKeys();
const token = signLease(claims, privateKeyPem);
const result = verifyLease(token, { keys: keySet([publicKeyPem]), product: 'my-app', fingerprintHash, now: Math.floor(Date.now() / 1000) });
if (!result.ok) console.log(result.reason);
```

`verifyLease` accepts only Ed25519, selects the key by `kid`, and checks issuer, product, device, `nbf`, `exp` and the check-in deadline. Failure reasons are listed in the [documentation](https://seal.carchalabs.com/docs/#lease).

Other exports: `keyId`, `publicJwk`, `publicKeyFromPrivate`, `decodeLease`, `hashFingerprint`, `generateLicenseKey`, `normalizeLicenseKey`, `hashLicenseKey`, and the feature encryption functions (`encryptForFeature`, `decryptForFeature`, `decryptFeature`).

`seal-encrypt` encrypts a file, or every file in a folder, for a feature at build time, with the key from `SEAL_FEATURE_KEY` or `--key-file`:

```bash
npx -p @carchalabs/seal-core seal-encrypt --feature pro dist/pro.js dist/pro.js.lke
npx -p @carchalabs/seal-core seal-encrypt --feature pro dist/premium dist/premium   # each file gets .lke
```

Requires Node 22.13 or later. MIT License.
