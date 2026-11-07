# Carcha Seal SDK

The npm packages of [Carcha Seal](https://seal.carchalabs.com), licensing for desktop software: a license server, an Electron SDK and an admin console. Leases are Ed25519-signed compact JWS tokens that the app verifies offline.

Carcha Seal was previously named LicenseKit, and these packages were `@carchalabs/licensekit-*` (now deprecated; same code as the last release under the old names). The SDK class is `Seal`; `LicenseKit` stays exported as an alias. License keys keep their `LK-` prefix, and leases, device hashes and offline files keep their format, so existing apps, keys and activations keep working. It is not related to licensekit.dev or to Kankoda's LicenseKit.

| Package | What it does |
| --- | --- |
| [`@carchalabs/seal-core`](packages/core) | Lease format: signing, verification, key sets and license keys |
| [`@carchalabs/seal-electron`](packages/sdk-electron) | SDK for the Electron main process and Node: activation, offline checks, grace period |
| [`@carchalabs/seal-quickstart`](packages/quickstart) | Try Carcha Seal from a terminal with `npx` |
| [`@carchalabs/seal-hwid`](packages/hwid-node) | Reads hardware components and returns one keyed hash each, for Node and Electron (prebuilt per platform) |

[`packages/hwid`](packages/hwid) is the native core of the hardware module, in Rust, with a C interface for other languages.

For apps in other languages: [`packages/client`](packages/client) is the license client in Rust (the Electron SDK's behaviour, checked against scenarios recorded from it), [`packages/native`](packages/native) its C interface (`seal.h`), and [`packages/cpp`](packages/cpp) the C++ SDK over it. C# and Java SDKs are in progress.

The license server and admin console are not part of this repository.

For the EU Cyber Resilience Act: what Carcha Labs provides for Seal and what stays with you as the maker of your app, in [CRA.md](CRA.md). Security reports, the support period and SBOMs: [SECURITY.md](SECURITY.md).

What the SDK reads on your users' computers, what it sends and keeps, and wording for your privacy notice: [PRIVACY.md](PRIVACY.md).

## Development

Requires Node 22.13 or later.

```
npm ci
npm test
```

The hardware module needs a Rust toolchain: `cargo test` in `packages/hwid`, `npm run build && npm test` in `packages/hwid-node`.

## Releases

Publishing runs from GitHub Actions with npm trusted publishing when a GitHub release is published. The hardware module's native file is built and tested on each platform first. Each package is published only if its version is not on npm yet, in dependency order: the four hardware platform packages, the hardware module, core, electron, quickstart. A package that is not on npm yet is staged instead (`npm stage publish`) and goes public after a maintainer approves it with 2FA on npmjs.com; trusted publishing is then set up for it.

Each version published after 15 October 2026 has a provenance statement that links it to the workflow run that built it, and so does each native file of the hardware module (a GitHub build attestation). The first version of each package, staged on 15 October 2026, has neither. To check them in an app that uses the packages:

```
npm audit signatures
gh attestation verify node_modules/@carchalabs/seal-hwid-darwin-arm64/seal-hwid.darwin-arm64.node -R carcha-labs/carcha-seal-sdk
```

## License

MIT. See [LICENSE](LICENSE).
