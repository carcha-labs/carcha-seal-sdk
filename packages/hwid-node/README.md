# @carchalabs/licensekit-hwid

Node-API layer over the `licensekit_hwid` native core (`../hwid`), for Node.js and Electron. One `.node` file per platform; Node-API is ABI-stable, and napi-rs looks up the Node-API functions in the host process at load time, so the same file loads in Node and in Electron.

```js
const { collect, version } = require('@carchalabs/licensekit-hwid');
const { vm, components, notes } = collect('your-product-key');
// components: [{ kind: 'uuid' | 'board' | 'disk' | 'mac' | 'os' | 'cpu' | 'gpu', hash: '<64 hex>' }]
```

Only kinds, hashes, the VM flag and diagnostic notes reach JavaScript, never raw serials. If no native module exists for the platform, `require` throws (`code: 'HWID_UNAVAILABLE'`) instead of falling back.

## Lease verification

The module also verifies LicenseKit leases (`../lease`, the `licensekit_lease` crate) with the same rules, order and failure reasons as `verifyLease` in `@carchalabs/licensekit-core`. The Ed25519 public keys it trusts are compiled in, so a lease signed with another key cannot be made to pass by changing a file or a setting.

```js
const { verifyLease, leaseKeyIds } = require('@carchalabs/licensekit-hwid');
verifyLease(token, { product, fingerprintHash, now, graceSeconds }); // { ok, reason?, kid? }
leaseKeyIds(); // ids of the compiled-in keys (keyId in licensekit-core)
```

The published build trusts the hosted service's current and next keys (`../quickstart/public-keys`). A self-hosted server's operator builds with their own: `LICENSEKIT_LEASE_PUBLIC_KEYS=<base64 SPKI>,<base64 SPKI> npm run build` (the PEM bodies, comma-separated). The Electron SDK uses this verifier next to its JavaScript one when the compiled-in keys include every key the app was given; a different answer from the two is treated as a modified license.

Both verifiers are tested against the same vectors: `../lease/tests/vectors.json`, leases signed by licensekit-core with a throwaway key and the result core gives for each (`node ../lease/tests/make-vectors.js` regenerates them). The Rust crate (`cargo test` in `../lease`), core's own tests and this module (a build that trusts the vectors' key, in CI) must all give those results.

## Packages

Published as napi-rs lays out prebuilt modules: the main package holds the loader, and each target is its own package listed as an exact-version optional dependency, with `os`/`cpu` (and `libc`) so npm installs only the one for the machine. Nothing is compiled or downloaded at install time.

| Target | Package | Built on |
| --- | --- | --- |
| macOS arm64 | `@carchalabs/licensekit-hwid-darwin-arm64` | `macos-latest` |
| macOS x64 | `@carchalabs/licensekit-hwid-darwin-x64` | `macos-15-intel` (GitHub's Intel macOS runners end in fall 2027) |
| Windows x64 | `@carchalabs/licensekit-hwid-win32-x64-msvc` | `windows-latest` |
| Linux x64 (glibc) | `@carchalabs/licensekit-hwid-linux-x64-gnu` | `ubuntu-22.04` |

Other platforms (Linux musl or arm64, Windows arm64) have no module yet: `require` throws `HWID_UNAVAILABLE`. CI (`.github/workflows/hwid-node.yml`) builds each target on its own runner, runs the tests there, installs the main and platform package from tarballs the way users get them, and uploads the platform package.

In Electron the `.node` file must sit outside the app's asar archive (Electron loads native modules with `process.dlopen`); electron-builder unpacks native modules automatically.

```
npm run build   # cargo build --release, then licensekit-hwid.<target>.node next to index.js (loaded first)
npm test        # Node tests
node scripts/build.js --npm   # also copies it into npm/<target>/ (CI)
npx electron test/electron-check.js   # loads it in Electron (with electron installed)
```
