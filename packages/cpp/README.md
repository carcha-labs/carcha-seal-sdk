# Carcha Seal for C++

Licensing for C++ desktop apps that keeps working offline: activation, check-ins, offline grace, clock checks, offline license files and feature decryption, with the same behaviour as the Electron SDK. `include/carcha/seal.hpp` is a header-only C++17 layer over the native library's C interface ([`../native`](../native)), where the client logic, lease verification and decryption run.

## Build

Needs CMake 3.16+, a C++17 compiler and a Rust toolchain (`cargo`). The CMake project builds the native library as a static library and links the system libraries it needs on each platform (as `rustc --print native-static-libs` reports them).

```cmake
add_subdirectory(carcha-seal-sdk/packages/cpp)
target_link_libraries(my_app PRIVATE CarchaSeal::seal)
```

`CARCHA_SEAL_HTTP` (default `ON`) builds in the HTTP client: certificates checked by the OS, the proxy from `HTTPS_PROXY` / `ALL_PROXY` (on Windows also the user's proxy setting; not PAC scripts), redirects not followed. Turn it off when your app passes its own transport.

## Use

```cpp
#include <carcha/seal.hpp>
namespace seal = carcha::seal;

seal::Options options;
options.product = "studio";
options.server_url = "https://seal.carchalabs.com/<your slug>";   // https://, or http:// on this computer only
options.public_keys = kPublicKeys;      // the PEM from the console, in your code, not read from a file
options.storage_dir = app_data_dir;     // license.dat is kept here
options.app_version = "2.4.0";
seal::Client client(options);           // throws std::invalid_argument naming a bad option

try {
  seal::State state = client.activate(key_the_user_typed);
} catch (const seal::LicenseError& e) {
  show(e.what());                       // e.code(): "activation_limit", "invalid_key", "network", ...
}

seal::State state = client.check();     // at every start: online when the server answers, else offline grace
if (state.has_feature("pro")) { /* ... */ }
std::vector<uint8_t> model = client.decrypt("pro", encrypted_model);   // data you encrypted for the feature
```

| Method | What it does |
| --- | --- |
| `activate(key, machine_name)` | Activates this device; no machine name is sent unless you pass one |
| `check()` | The license state; offline from the saved lease, with its grace period and clock checks |
| `deactivate()` | Releases this device's seat |
| `offline_request(key)`, `activate_offline(file)`, `deactivate_offline()` | Offline activation by file |
| `decrypt(feature, data)` | Decrypts data encrypted for a feature; the content key stays in the native library |

To send requests through your own HTTP stack (Qt, libcurl, WinHTTP), set `options.transport`: POST `request.body` to `request.url` with `Content-Type: application/json` and `request.user_agent`, refuse redirects, use a timeout, and return status 0 when there was no answer.

One call at a time runs on a `Client`; calls from several threads wait for each other.

## Tests

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

`tests/scenarios.cpp` runs every client scenario recorded from the Electron SDK (`../client/tests/vectors.json`) through `seal.hpp`, with a scripted server: the requests sent, and the states, errors, files and data returned. `examples/seal_cli.cpp` is a small command-line app to try a real server.
