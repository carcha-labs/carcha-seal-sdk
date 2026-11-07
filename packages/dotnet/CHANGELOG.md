# Changelog

`CarchaLabs.Seal`, `CarchaLabs.Seal.Runtime` and `CarchaLabs.Seal.NetFramework` are released together, with one
version. Security fixes are marked **Security** and released as patch versions, apart from functional changes where
technically feasible.

## 0.1.0

The first release.

- `SealClient`: activation, check-ins online and from the saved lease offline, offline grace, clock checks,
  refusals kept offline, offline activation files and feature decryption, with the same behaviour as the Electron
  SDK (the client scenarios recorded from it pass through these packages).
- .NET 10 (source-generated `LibraryImport`, trimming and Native AOT), .NET Standard 2.0 and .NET Framework 4.6.2+
  (AnyCPU, x86, x64, ARM64; PackageReference or packages.config).
- The native library for Windows x86, x64 and ARM64 (no Visual C++ runtime needed), macOS 11+ (x64, ARM64) and
  Linux x64 and ARM64 (glibc 2.34+: Ubuntu 22.04, Debian 12, RHEL 9 and later).
- Requests go through `HttpClient`, so the app's proxy and certificate settings apply; https only (http:// for this
  computer), redirects never followed, also through an `HttpClient` the app passes.
- `license.dat` is replaced whole on each save; one operation runs at a time on a client.
