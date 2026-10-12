# LicenseKit SDK

The npm packages of [LicenseKit](https://licensekit.carchalabs.com), a licensing kit for desktop software. Leases are Ed25519-signed compact JWS tokens that the app verifies offline.

| Package | What it does |
| --- | --- |
| [`@carchalabs/licensekit-core`](packages/core) | Lease format: signing, verification, key sets and license keys |
| [`@carchalabs/licensekit-electron`](packages/sdk-electron) | SDK for the Electron main process and Node: activation, offline checks, grace period |
| [`@carchalabs/licensekit-quickstart`](packages/quickstart) | Try LicenseKit from a terminal with `npx` |

The license server and admin console are not part of this repository.

## Development

Requires Node 22.13 or later.

```
npm ci
npm test
```

## Releases

Publishing runs from GitHub Actions with npm trusted publishing when a GitHub release is published. Each package is published only if its version is not on npm yet, in dependency order: core, electron, quickstart.

## License

MIT. See [LICENSE](LICENSE).
