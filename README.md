# LicenseKit SDK

The npm packages of [LicenseKit](https://licensekit.carchalabs.com), a licensing kit for desktop software. Leases are Ed25519-signed compact JWS tokens that the app verifies offline.

| Package | What it does |
| --- | --- |
| [`@carchalabs/licensekit-core`](packages/core) | Lease format: signing, verification, key sets and license keys |
| [`@carchalabs/licensekit-electron`](packages/sdk-electron) | SDK for the Electron main process and Node: activation, offline checks, grace period |
| [`@carchalabs/licensekit-quickstart`](packages/quickstart) | Try LicenseKit from a terminal with `npx` |
| [`@carchalabs/licensekit-hwid`](packages/hwid-node) | Reads hardware components and returns one keyed hash each, for Node and Electron (prebuilt per platform) |

[`packages/hwid`](packages/hwid) is the native core of the hardware module, in Rust, with a C interface for other languages.

The license server and admin console are not part of this repository.

## Development

Requires Node 22.13 or later.

```
npm ci
npm test
```

The hardware module needs a Rust toolchain: `cargo test` in `packages/hwid`, `npm run build && npm test` in `packages/hwid-node`.

## Releases

Publishing runs from GitHub Actions with npm trusted publishing when a GitHub release is published. The hardware module's native file is built and tested on each platform first. Each package is published only if its version is not on npm yet, in dependency order: the four hardware platform packages, the hardware module, core, electron, quickstart.

## License

MIT. See [LICENSE](LICENSE).
