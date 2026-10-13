# @carchalabs/licensekit-electron

The [LicenseKit](https://licensekit.carchalabs.com) SDK. It runs in the Electron main process or in plain Node. It activates a license key on this device, saves the signed lease, and verifies it offline with your public keys.

```js
const { LicenseKit } = require('@carchalabs/licensekit-electron');

const kit = new LicenseKit({
  serverUrl: 'https://licenses.example.com',
  product: 'example-studio',
  publicKey: [currentKeyPem, nextKeyPem],
  storageDir: app.getPath('userData'),
  secureStore: {
    encrypt: (s) => safeStorage.encryptString(s),
    decrypt: (b) => safeStorage.decryptString(b),
  },
});

const state = await kit.check();
if (state.status === 'unlicensed') await kit.activate(userEnteredKey);
if (LicenseKit.hasFeature(state, 'export-pdf')) exportPdf();
```

`check()` returns one of `valid`, `grace`, `invalid`, `unlicensed` or `clock_suspect`, with `offline` and `storageProtected` flags. A refusal from the server (suspended, expired, device removed, update required) is kept while offline and cleared by the next successful check-in. `notices` carries what the server asks your app to act on, such as `sdk_update_recommended` or `app_update_recommended` with a `minimum` version and a `requiredFrom` date; the SDK shows nothing itself. `activate(key, machineName)` sends the device name you pass; the default is the computer's host name. `deactivate()` releases the seat.

The SDK sends the license key, a per-product SHA-256 hash of the operating system's machine ID, the device name, the platform, your app version and its own version. The raw machine ID does not leave the computer.

Full reference: [licensekit.carchalabs.com/docs](https://licensekit.carchalabs.com/docs/#sdk). Requires Node 22.13 or later. MIT License.
