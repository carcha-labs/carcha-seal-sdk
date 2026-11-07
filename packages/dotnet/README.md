# Carcha Seal for .NET

Licensing for .NET desktop apps that keeps working offline: activation, check-ins, offline grace, clock checks, offline license files and feature decryption, with the same behaviour as the Electron SDK. `CarchaLabs.Seal` is a thin layer over the native library's C interface ([`../native`](../native)), where the client logic, lease verification and decryption run. Requests go through .NET's `HttpClient`, so your app's proxy and certificate settings apply.

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

The NuGet package (with the native library for each platform, and the .NET Framework build targets) is not published yet.

## Tests

Needs the .NET 10 SDK and a Rust toolchain (the tests build `../native` with cargo).

```
dotnet test --project tests/CarchaLabs.Seal.Tests -c Release              # against the net10.0 build
dotnet test --project tests/CarchaLabs.Seal.Tests.NetStandard -c Release  # against the netstandard2.0 build
```

Both run every client scenario recorded from the Electron SDK (`../client/tests/vectors.json`) and the HTTP client against a local server.
