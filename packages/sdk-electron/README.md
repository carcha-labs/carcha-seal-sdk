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

Code can be protected the same way (Envelope): encrypt a CommonJS module or a folder of them with `licensekit-encrypt --feature pro dist/premium dist/premium`, and load it with `await kit.requireEncrypted('pro', path.join(__dirname, 'premium/index.js.lke'))`. Without the feature in the license the code cannot be read; a licensed user can still read it from memory.

Computers that never reach the server use offline activation: `offlineRequest(key)` returns a request file, the license server turns it into a license file (its `/offline` page, `POST /v1/offline/activate` or the console), and `activateOffline(file)` loads it; it works only on that computer, for the policy's offline days. `deactivateOffline()` removes the license and returns a deactivation file the vendor uploads to free the seat. See the [documentation](https://licensekit.carchalabs.com/docs/#concepts).

The SDK sends the license key, a per-product SHA-256 hash of the operating system's machine ID, the device name, the platform, your app version and its own version. The raw machine ID does not leave the computer.

**Feature data.** `await kit.decrypt('pro', data)` returns data you encrypted for a feature (`encryptForFeature` in `@carchalabs/licensekit-core`, with the feature's content key from the console). It works offline from the stored lease and only on a device whose license includes the feature; without a license the data stays encrypted, so removing a license check from your app does not unlock it. With `@carchalabs/licensekit-hwid` 0.2 the native module does the decryption and the key never reaches JavaScript.

**Hardware components.** When `@carchalabs/licensekit-hwid` is installed, the SDK also sends one keyed hash per hardware part (motherboard, disk, network card, OS install, CPU and graphics models) and whether the computer is a virtual machine. The license server then recognises the computer after a new disk, network card or operating system install, and refuses a copied disk or system image on other hardware. Raw serial numbers never leave the computer. Without the package, or on a platform it has no module for, nothing extra is sent. `hardware: false` turns it off. Bundlers must leave the package to Node (mark it external); electron-builder unpacks its native module from the asar archive.

Integration guide (activate once, check at start, put feature code behind `decrypt`, ship the native module, harden the app): [licensekit.carchalabs.com/docs/#integration](https://licensekit.carchalabs.com/docs/#integration). Full reference: [licensekit.carchalabs.com/docs](https://licensekit.carchalabs.com/docs/#sdk). Requires Node 22.13 or later. MIT License.
