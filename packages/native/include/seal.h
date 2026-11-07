/*
 * Carcha Seal native library, for apps written in C, C++, C# and Java: the
 * license client (the Electron SDK's behaviour, with the HTTP request left to
 * the app), lease verification, feature decryption, this device's public key
 * and hardware components. The same rules, order and failure reasons as
 * verifyLease and decryptFeature in @carchalabs/seal-core.
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

/* ---- License client ----------------------------------------------------
 *
 * The same behaviour as the Electron SDK's Seal class: activation, check-ins,
 * offline grace, clock checks, refusals kept offline, offline license files
 * and feature decryption. The library does no network I/O: an operation that
 * needs the server returns a result of kind SEAL_RESULT_SEND; POST its body
 * (Content-Type: application/json, User-Agent: seal_client_user_agent) to the
 * server URL + seal_result_request_path, refusing redirects, with a timeout,
 * then pass the status and body to the matching *_finish function (status 0
 * when there was no answer). Every function returns a result to free with
 * seal_result_free, or NULL when an argument is invalid.
 *
 *   seal_result *r = seal_client_check_begin(client, now_ms);
 *   if (seal_result_kind(r) == SEAL_RESULT_SEND) {
 *       int status = post(url, seal_result_request_path(r), seal_result_request_body(r), &body, &len);
 *       seal_result_free(r);
 *       r = seal_client_check_finish(client, status, body, len, now_ms);
 *   }
 *   if (seal_state_status(r) == SEAL_STATUS_VALID) ...
 *   seal_result_free(r);
 */

typedef struct seal_client seal_client;
typedef struct seal_result seal_result;

typedef struct seal_client_options {
    /* Your product code. */
    const char *product;
    /* The Ed25519 public keys you trust, as for seal_keys_new. */
    const char *public_keys;
    /* The folder that keeps license.dat (created when needed). */
    const char *storage_dir;
    /* Your app's version, sent so you can require a minimum; NULL: not sent. */
    const char *app_version;
    /* Offline grace when the lease has none; below 0 (the default): 7 days. */
    double grace_days;
    /* Lowercase name of the SDK for the User-Agent ("cpp", "dotnet", "java"); NULL: "c". */
    const char *sdk_name;
    /* The raw machine id; NULL (the default): this machine's OS id, as the Electron SDK reads it. */
    const char *machine_id;
    /* 1 (the default): send hashed hardware components and this device's public key; 0: none. */
    int32_t hardware;
} seal_client_options;

/* Sets the defaults (see above). Set product, public_keys and storage_dir yourself. */
void seal_client_options_init(seal_client_options *options);
/* A client; NULL when product, public_keys or storage_dir is missing or invalid. One call at a time
 * runs on a client; concurrent calls wait. Free with seal_client_free. */
seal_client *seal_client_new(const seal_client_options *options);
void seal_client_free(seal_client *client);
/* The User-Agent to send with every request, e.g. "carcha-seal-native/0.2.0 (cpp)". Lives as long as the client. */
const char *seal_client_user_agent(const seal_client *client);

/* machine_name: the name to show the vendor, or NULL to send none (a host name often holds a person's name). */
seal_result *seal_client_activate_begin(seal_client *client, const char *license_key, const char *machine_name);
seal_result *seal_client_activate_finish(seal_client *client, int32_t http_status, const uint8_t *body, size_t body_len, double now_ms);
seal_result *seal_client_check_begin(seal_client *client, double now_ms);
seal_result *seal_client_check_finish(seal_client *client, int32_t http_status, const uint8_t *body, size_t body_len, double now_ms);
seal_result *seal_client_deactivate_begin(seal_client *client);
seal_result *seal_client_deactivate_finish(seal_client *client, int32_t http_status, const uint8_t *body, size_t body_len);
/* Offline activation: the request file for this machine (seal_result_text), the license file the
 * server issued for it, and the deactivation file that gives the seat back (seal_result_text). */
seal_result *seal_client_offline_request(seal_client *client, const char *license_key, const char *machine_name);
seal_result *seal_client_activate_offline(seal_client *client, const char *license_file, double now_ms);
seal_result *seal_client_deactivate_offline(seal_client *client);
/* Decrypts data encrypted for a feature with the saved lease, offline (seal_result_data). */
seal_result *seal_client_decrypt(seal_client *client, const char *feature, const uint8_t *data, size_t data_len, double now_ms);

/* Result kinds. */
#define SEAL_RESULT_SEND 1  /* send the request, then call *_finish */
#define SEAL_RESULT_DONE 2  /* finished: a state, a file text, data, or nothing */
#define SEAL_RESULT_ERROR 3 /* refused or failed: seal_result_error_code and _message */

/* License statuses. */
#define SEAL_STATUS_VALID 1
#define SEAL_STATUS_GRACE 2
#define SEAL_STATUS_INVALID 3
#define SEAL_STATUS_UNLICENSED 4
#define SEAL_STATUS_CLOCK_SUSPECT 5

/* State flags. */
#define SEAL_FLAG_OFFLINE 1
#define SEAL_FLAG_STORAGE_PROTECTED 2
#define SEAL_FLAG_OFFLINE_ACTIVATED 3

/* State text fields; dates are ISO 8601 UTC. */
#define SEAL_FIELD_REASON 1
#define SEAL_FIELD_MESSAGE 2
#define SEAL_FIELD_CUSTOMER 3
#define SEAL_FIELD_EXPIRES_AT 4
#define SEAL_FIELD_MAINTENANCE_UNTIL 5
#define SEAL_FIELD_REVALIDATE_BY 6
#define SEAL_FIELD_KEY_HINT 7
#define SEAL_FIELD_NOTICES_JSON 8 /* the server's notices as a JSON array */

void seal_result_free(seal_result *result);
/* SEAL_RESULT_SEND, _DONE or _ERROR. */
int32_t seal_result_kind(const seal_result *result);
/* The whole result as JSON: {"send":{"path","body"}}, {"ok":true,"value":...} or {"ok":false,"error":{"code","message"}}. */
const char *seal_result_json(const seal_result *result);
const char *seal_result_request_path(const seal_result *result);
const char *seal_result_request_body(const seal_result *result);
const char *seal_result_error_code(const seal_result *result);
const char *seal_result_error_message(const seal_result *result);
const char *seal_result_text(const seal_result *result);
/* Decrypted data; overwritten when the result is freed. */
const uint8_t *seal_result_data(const seal_result *result, size_t *len);
/* The state of activate, check and activate_offline: SEAL_STATUS_*, or 0 when the result holds none. */
int32_t seal_state_status(const seal_result *result);
/* 1 or 0; -1 when the result holds no state. */
int32_t seal_state_flag(const seal_result *result, int32_t flag);
/* NULL when the field is absent. */
const char *seal_state_text(const seal_result *result, int32_t field);
size_t seal_state_feature_count(const seal_result *result);
const char *seal_state_feature(const seal_result *result, size_t index);
/* 1 when the state is valid or in grace and grants the feature. */
int32_t seal_state_has_feature(const seal_result *result, const char *feature);
/* Strings returned by seal_result_* and seal_state_* live as long as the result. */

#ifdef __cplusplus
}
#endif

#endif /* SEAL_H */
