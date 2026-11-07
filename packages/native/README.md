# seal_native

The C interface of Carcha Seal (`include/seal.h`), for apps written in C, C++, C# and Java: the license client, lease verification, decryption of data encrypted for a feature, this device's public key and its hashed hardware components. It wraps [`../client`](../client), [`../lease`](../lease) and [`../hwid`](../hwid): the client behaves as the Electron SDK's `Seal` class, and verification gives the same results, in the same order and with the same failure reasons, as `verifyLease` and `decryptFeature` in `@carchalabs/seal-core`.

Built as a static library (`libseal_native.a`, `seal_native.lib`) for native apps to link, and a shared library (`.dll`, `.dylib`, `.so`) for .NET and the JVM. The C++, C# and Java SDKs are built on it.

The app passes the Ed25519 public keys it trusts to `seal_keys_new`, from its own code, so one build works for every vendor, hosted or self-hosted. The device secret and the feature content keys never leave the library.

## License client

The client does no network I/O. An operation that needs the server returns a result of kind `SEAL_RESULT_SEND`: POST its body to `seal_result_request_url` with `Content-Type: application/json`, `User-Agent: seal_client_user_agent(client)`, redirects refused and a timeout, then pass the status (0 when there was no answer) and body to the matching `*_finish` function. Use your own HTTP stack (so your app's proxy and certificate settings apply), or `seal_http_post` in builds with the `http` feature.

The server URL must be `https://`; `http://` is accepted for this computer only (localhost, 127.x.x.x, `[::1]`), as in the Electron SDK. `seal_client_options_error` names what is wrong with the options.

```c
seal_client_options options;
seal_client_options_init(&options);
options.product = "studio";
options.server_url = "https://seal.carchalabs.com/<your slug>";
options.public_keys = VENDOR_PUBLIC_KEYS_PEM;            /* compiled into your app */
options.storage_dir = app_data_folder;                   /* license.dat is kept here */
options.sdk_name = "cpp";
seal_client *client = seal_client_new(&options);

seal_result *r = seal_client_check_begin(client, now_ms);
if (seal_result_kind(r) == SEAL_RESULT_SEND) {
    int status = seal_http_post(seal_result_request_url(r), seal_client_user_agent(client),
                                seal_result_request_body(r), 8000, &body, &len);
    seal_result_free(r);
    r = seal_client_check_finish(client, status, body, len, now_ms);
    seal_bytes_free(body, len);
}
if (seal_state_has_feature(r, "pro")) { /* ... */ }
seal_result_free(r);
```

| Function | What it does |
| --- | --- |
| `seal_client_activate_begin` / `_finish` | Activates this device with a license key |
| `seal_client_check_begin` / `_finish` | Checks in; without an answer, the saved lease with its offline grace |
| `seal_client_deactivate_begin` / `_finish` | Releases this device's seat |
| `seal_client_offline_request`, `seal_client_activate_offline`, `seal_client_deactivate_offline` | Offline activation by file |
| `seal_client_decrypt` | Decrypts data encrypted for a feature, offline |
| `seal_result_*`, `seal_state_*` | The request to send, the error, the license state, a file text or decrypted data |
| `seal_http_post`, `seal_bytes_free` | The built-in HTTP client (feature `http`): OS certificate check, `HTTPS_PROXY` / `ALL_PROXY` and the Windows user proxy setting (not PAC scripts), redirects not followed |

Every request carries `sdkVersion` = this library's version (the client logic is here, so it is the version that matters for a minimum-SDK rule) and the User-Agent `carcha-seal-native/<version> (<sdk_name>)`. The device fingerprint is computed from the same OS machine id as the Electron SDK's.

## Lease verification

```c
seal_keys *keys = seal_keys_new(VENDOR_PUBLIC_KEYS_PEM);   /* compiled into your app */
seal_check check;
seal_check_init(&check);
check.product = "studio";
check.fingerprint_hash = fingerprint_hash;
check.now = (double)time(NULL);
int32_t r = seal_verify_lease(keys, lease, &check, NULL, 0);
if (r != SEAL_OK) printf("refused: %s\n", seal_result_name(r));
seal_keys_free(keys);
```

| Function | What it does |
| --- | --- |
| `seal_keys_new`, `seal_keys_free`, `seal_keys_count`, `seal_keys_id` | The trusted key set: PEM blocks or base64 bodies; NULL if any key is not Ed25519 |
| `seal_check_init` | A check with the defaults (no issuer, no grace, 300 s leeway) |
| `seal_verify_lease` | `SEAL_OK` or the reason (`seal_result_name` gives the SDK's string) |
| `seal_decrypt_feature` | Verifies the lease and decrypts `LKE1` data for a feature, with this device's key |
| `seal_device_public_key` | This machine's X25519 public key for the product (base64url) |
| `seal_hardware` | This machine's components, one HMAC-SHA256 each, as JSON |

```
cargo test --features "test-device-secret http"   # unit tests, every lease and decrypt vector, every client scenario through the C functions, the HTTP client against a local server
tests/c/run.sh                             # C programs linked against the static library: every lease vector, and the client
```

The `test-device-secret` feature exports `seal_test_decrypt_feature_with_secret` so the shared decrypt vectors can run through the C interface. Published builds never have it.
