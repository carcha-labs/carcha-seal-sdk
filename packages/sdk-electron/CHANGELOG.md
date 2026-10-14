# Changelog

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
