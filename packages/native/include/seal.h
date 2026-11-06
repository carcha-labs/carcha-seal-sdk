/*
 * Carcha Seal native library: lease verification, feature decryption, this
 * device's public key and hardware components, for apps written in C, C++,
 * C# and Java. The same rules, order and failure reasons as verifyLease and
 * decryptFeature in @carchalabs/seal-core.
 *
 * Link the static library (seal_native.lib / libseal_native.a) into native
 * apps, or load the shared one (seal_native.dll / libseal_native.dylib /
 * libseal_native.so).
 *
 * Strings are UTF-8 and NUL-terminated. Every function is safe to call from
 * several threads at once. No function unwinds into the caller.
 */
#ifndef SEAL_H
#define SEAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Results. 0 is success; positive values are why a lease or a decryption was
 * refused (seal_result_name gives the SDK's reason string); negative values
 * are errors in the call itself. */
#define SEAL_OK 0
#define SEAL_MALFORMED 1
#define SEAL_UNSUPPORTED_ALGORITHM 2
#define SEAL_WRONG_TYPE 3
#define SEAL_UNKNOWN_KEY 4
#define SEAL_BAD_SIGNATURE 5
#define SEAL_WRONG_ISSUER 6
#define SEAL_WRONG_PRODUCT 7
#define SEAL_WRONG_DEVICE 8
#define SEAL_NOT_YET_VALID 9
#define SEAL_EXPIRED 10
#define SEAL_REVALIDATION_REQUIRED 11
/* The verified lease does not grant the feature or carries no key for it. */
#define SEAL_NOT_LICENSED 12
/* The key or the data did not authenticate (another license key or device, or modified data). */
#define SEAL_DECRYPT_FAILED 13

/* An argument is NULL, not UTF-8, or out of range. */
#define SEAL_E_ARGS (-1)
/* Internal error; nothing was written. */
#define SEAL_E_INTERNAL (-2)
/* The output buffer is too small; the needed size was reported and nothing was written. */
#define SEAL_E_BUFFER (-3)
/* This machine reports none of the parts a device key is made from. */
#define SEAL_E_NO_DEVICE_KEY (-4)

/* Library version, e.g. "0.1.0". Static string; do not free. */
const char *seal_version(void);

/* The reason string for a result ("malformed", "not_licensed", ...), "ok" for
 * SEAL_OK, "error" for negative results and "unknown" otherwise. Static. */
const char *seal_result_name(int32_t result);

/* ---- Trusted keys ------------------------------------------------------- */

/* The Ed25519 public keys your app trusts for leases. Opaque and immutable. */
typedef struct seal_keys seal_keys;

/*
 * Parses one or more Ed25519 public keys: PEM "PUBLIC KEY" blocks (SPKI) one
 * after another, as the console and GET /v1/public-key give them, or their
 * base64 bodies separated by commas or whitespace. Put them in your app's code,
 * not in a file or a setting someone can replace. Returns NULL when there is no
 * key or one of them is not an Ed25519 key. Free with seal_keys_free.
 */
seal_keys *seal_keys_new(const char *pem);
void seal_keys_free(seal_keys *keys);
/* Number of keys in the set. */
size_t seal_keys_count(const seal_keys *keys);
/* Copies the id (kid) of key `index` plus a NUL into out. Returns SEAL_OK,
 * SEAL_E_ARGS, or SEAL_E_BUFFER with *needed set to the bytes required. */
int32_t seal_keys_id(const seal_keys *keys, size_t index, char *out, size_t out_len, size_t *needed);

/* ---- Lease checks ------------------------------------------------------- */

typedef struct seal_check {
    /* Your product code, as the lease's "aud". */
    const char *product;
    /* This device's fingerprint hash, as the lease's "fp". */
    const char *fingerprint_hash;
    /* Expected issuer; NULL for the default ("licensekit"). */
    const char *issuer;
    /* Seconds since the Unix epoch. */
    double now;
    /* Offline grace after the revalidation time; 0 for none. */
    double grace_seconds;
    /* Clock-skew leeway for nbf and exp; seal_check_init sets 300. */
    double leeway_seconds;
} seal_check;

/* Sets the defaults: no issuer, now 0, no grace, 300 s leeway. Set product,
 * fingerprint_hash and now yourself. */
void seal_check_init(seal_check *check);

/*
 * Verifies a lease (compact JWS) against the trusted keys and the check.
 * Returns SEAL_OK or the reason (SEAL_MALFORMED ... SEAL_REVALIDATION_REQUIRED).
 * kid_out may be NULL; otherwise the id of the key that signed it is written
 * there on SEAL_OK (a key id is 43 characters; 64 bytes is enough).
 */
int32_t seal_verify_lease(const seal_keys *keys, const char *token, const seal_check *check, char *kid_out, size_t kid_out_len);

/*
 * Verifies the lease, unwraps the feature's content key for this license key
 * and this device, and decrypts data the vendor encrypted for the feature
 * ("LKE1" format). The content key and this device's secret never leave the
 * library. The plaintext is data_len - 32 bytes: *out_len is set to that, and
 * when out_cap is smaller SEAL_E_BUFFER is returned before anything is
 * decrypted. Returns SEAL_OK, a lease reason, SEAL_NOT_LICENSED or
 * SEAL_DECRYPT_FAILED.
 */
int32_t seal_decrypt_feature(const seal_keys *keys, const char *token, const seal_check *check, const char *license_key,
                             const char *feature, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_cap,
                             size_t *out_len);

/* ---- This device -------------------------------------------------------- */

/*
 * This machine's X25519 public key for the product (base64url, 43 characters
 * plus a NUL), derived from its hardware. Send it with activation so the
 * server wraps feature keys for this device only. Returns SEAL_OK,
 * SEAL_E_NO_DEVICE_KEY, or SEAL_E_BUFFER (out_len below 44).
 */
int32_t seal_device_public_key(const char *product, char *out, size_t out_len);

/*
 * This machine's hardware components, one HMAC-SHA256 each keyed by the
 * product, as UTF-8 JSON plus a NUL:
 *   {"format":1,"vm":false,"components":[{"kind":"disk","hash":"<64 hex>"},...]}
 * Returns SEAL_OK, or SEAL_E_BUFFER with *needed set to the bytes required
 * (pass out = NULL, out_len = 0 to ask). Hardware is read on each call.
 */
int32_t seal_hardware(const char *product, char *out, size_t out_len, size_t *needed);

#ifdef __cplusplus
}
#endif

#endif /* SEAL_H */
