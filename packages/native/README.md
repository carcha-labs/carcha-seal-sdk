# seal_native

The C interface of Carcha Seal (`include/seal.h`), for apps written in C, C++, C# and Java: lease verification, decryption of data encrypted for a feature, this device's public key and its hashed hardware components. It wraps [`../lease`](../lease) and [`../hwid`](../hwid), so it gives the same results, in the same order and with the same failure reasons, as `verifyLease` and `decryptFeature` in `@carchalabs/seal-core`.

Built as a static library (`libseal_native.a`, `seal_native.lib`) for native apps to link, and a shared library (`.dll`, `.dylib`, `.so`) for .NET and the JVM. The C++, C# and Java SDKs are built on it.

The app passes the Ed25519 public keys it trusts to `seal_keys_new`, from its own code, so one build works for every vendor, hosted or self-hosted. The device secret and the feature content keys never leave the library.

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
cargo test --features test-device-secret   # unit tests + every lease and decrypt vector through the C functions
tests/c/run.sh                             # a C program linked against the static library, over every lease vector
```

The `test-device-secret` feature exports `seal_test_decrypt_feature_with_secret` so the shared decrypt vectors can run through the C interface. Published builds never have it.
