# Changelog

## Unreleased

- With `@carchalabs/licensekit-hwid` 0.2 installed, every saved lease is verified twice: by the JavaScript verifier and by the native module, whose trusted keys are compiled in. The two follow the same rules, so a different answer is treated as a modified license (`bad_signature`). Apps given keys the native build does not trust (a self-hosted server with the default build) keep the JavaScript check alone.

## 0.2.0

Upgrade from 0.1.2; no code changes needed.

- The SDK now sends hardware components: one keyed hash per part (motherboard, disk, network card, OS install, CPU and graphics models) and whether the computer is a virtual machine, read with `@carchalabs/licensekit-hwid` (installed with the SDK as an optional dependency, prebuilt for macOS arm64 and x64, Windows x64 and Linux x64). The license server then recognises the computer after a new disk, network card or operating system install, so it keeps its seat, and refuses a copied disk or system image on other hardware. Raw serial numbers never leave the computer.
- Where the module is not available (other platforms, or not installed), nothing extra is sent and the SDK works as before. `hardware: false` turns it off; `hardware: () => report` supplies your own.
- Bundlers must leave `@carchalabs/licensekit-hwid` to Node (mark it external); electron-builder unpacks its native module from the asar archive.
- `vm_not_allowed` (a license whose policy does not allow virtual machines) is kept while offline like the other refusals.
- Requires a license server with hardware matching (LicenseKit server from 2026-10-14); older servers reject the new fields.

## 0.1.2

Security update. Upgrade from 0.1.1. Uses `@carchalabs/licensekit-core` 0.1.1.

- A lease whose header lists critical extensions (`crit`) is rejected as malformed. LicenseKit leases use none (RFC 7515 4.1.11).
- Lease expiry allows the same five minutes of clock skew as the start time, so a computer clock that runs a few minutes fast no longer ends a valid lease early.
- License keys issued by the server now have seven groups of four characters (140 random bits). Keys in the earlier four-group format keep working.

## 0.1.1

Security update. Upgrade from 0.1.0.

- A refusal from the license server (license suspended, revoked or expired, device removed) is now kept on the device. Before, an app that went offline after a refusal could keep working from its previous lease until that lease ran out.
- The machine id is read with `/usr/sbin/ioreg` and `C:\Windows\System32\reg.exe` by absolute path instead of through `PATH`, and the 64-bit registry view is used on Windows.
- When the machine id cannot be read, it is retried; if it still fails, the state is `invalid` with reason `machine_id_unavailable` instead of falling back to a different fingerprint. `allowFallbackFingerprint: true` restores the previous fallback.
- The SDK sends its own version (`sdkVersion`). `sdk_update_required` and `app_update_required` are kept like other refusals, and `state.notices` reports recommended updates with their dates.
- Requires a license server that accepts `sdkVersion` (LicenseKit server from 2026-10-12).

## 0.1.0

First release.
