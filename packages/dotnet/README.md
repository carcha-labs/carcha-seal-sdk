# Carcha Seal for .NET

Licensing for .NET desktop apps that keeps working offline: activation, check-ins, offline grace, clock checks, offline license files and feature decryption, with the same behaviour as the Electron SDK. `CarchaLabs.Seal` is a thin layer over the native library's C interface ([`packages/native`](https://github.com/carcha-labs/carcha-seal-sdk/tree/main/packages/native)), where the client logic, lease verification and decryption run. Requests go through .NET's `HttpClient`, so your app's proxy and certificate settings apply.

Targets: `net10.0` (source-generated `LibraryImport`, trimming and Native AOT), `netstandard2.0` and `net462` (`DllImport`, for .NET Framework WinForms and WPF apps).

```csharp
using CarchaLabs.Seal;

using var seal = new SealClient(new SealOptions
{
    Product = "studio",
    ServerUrl = "https://seal.carchalabs.com/<your slug>",   // https://, or http:// on this computer only
    PublicKeys = PublicKeys,                                 // the PEM from the console, in your code, not read from a file
    StorageDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Studio"),
    AppVersion = "2.4.0",
});

try
{
    await seal.ActivateAsync(keyTheUserTyped);
}
catch (LicenseException e)
{
    Show(e.Message);                 // e.Code: "activation_limit", "invalid_key", "network", ...
}

LicenseState state = await seal.CheckAsync();   // at every start: online when the server answers, else offline grace
if (state.HasFeature("pro")) { /* ... */ }
byte[] model = seal.Decrypt("pro", encryptedModel);   // data you encrypted for the feature
```

| Member | What it does |
| --- | --- |
| `ActivateAsync(key, machineName)` | Activates this device; no machine name is sent unless you pass one |
| `CheckAsync()` | The license state; offline from the saved lease, with its grace period and clock checks |
| `DeactivateAsync()` | Releases this device's seat |
| `OfflineRequest(key)`, `ActivateOffline(file)`, `DeactivateOffline()` | Offline activation by file |
| `Decrypt(feature, data)` | Decrypts data encrypted for a feature; the content key stays in the native library |

`SealOptions.HttpClient` takes your own `HttpClient`; turn off automatic redirects on its handler (`AllowAutoRedirect = false`), as the library's own does: a redirect is never followed. One operation runs at a time on a `SealClient`; concurrent calls wait for each other.

## Packages

Not on nuget.org yet. `pack/` builds three packages, the layout Microsoft recommends for a native library used from both .NET and .NET Framework ("Native files in .NET packages"):

| Package | For | Holds |
| --- | --- | --- |
| `CarchaLabs.Seal` | What apps install | No files: it depends on one of the two below, chosen by the app's target framework |
| `CarchaLabs.Seal.Runtime` | .NET 5+ (and other .NET Standard 2.0 hosts) | The library under `ref/` and `runtimes/any/lib/` (net10.0, netstandard2.0), the native library under `runtimes/<rid>/native/` |
| `CarchaLabs.Seal.NetFramework` | .NET Framework 4.6.2+: AnyCPU, x86, x64, ARM64; PackageReference or packages.config | The library (net462), the native library for each Windows CPU, and build targets that copy them to `carcha-seal\<cpu>\` next to the app; the library loads the one that matches the process |

Put the native libraries (`cargo build --release --manifest-path ../native/Cargo.toml`, no features) in `artifacts/native/<rid>/`: `seal_native.dll` for `win-x86`, `win-x64`, `win-arm64`; `libseal_native.dylib` for `osx-x64`, `osx-arm64`; `libseal_native.so` for `linux-x64`, `linux-arm64`. Then:

```
dotnet pack pack/CarchaLabs.Seal.Runtime
dotnet pack pack/CarchaLabs.Seal.NetFramework
dotnet pack pack/CarchaLabs.Seal
```

The packages are written to `artifacts/packages/`. A platform with no file in `artifacts/native/` is left out of them.

CI (`.github/workflows/dotnet-packages.yml`) builds the native library for all seven platforms: on Windows with the C runtime linked in (`-C target-feature=+crt-static`), so the DLL needs no Visual C++ redistributable; on macOS for macOS 11 and later; on Linux on Ubuntu 22.04, so it needs no newer glibc than 22.04's. It packs them, checks every file in the packages, and runs `tests/Consumer`, an app that installs the packages: .NET 10 on Windows (x64, ARM64), macOS (Apple Silicon, Intel) and Linux (x64, ARM64; Ubuntu 22.04 and 24.04), and .NET Framework built for x86, x64, AnyCPU and ARM64 through PackageReference and packages.config, each checking that it loaded the copy for its CPU.

## Tests

Needs the .NET 10 SDK and a Rust toolchain (the tests build `../native` with cargo).

```
dotnet test --project tests/CarchaLabs.Seal.Tests -c Release              # against the net10.0 build
dotnet test --project tests/CarchaLabs.Seal.Tests.NetStandard -c Release  # against the netstandard2.0 build
```

Both run every client scenario recorded from the Electron SDK (`../client/tests/vectors.json`) and the HTTP client against a local server.
