//! C interface of the Carcha Seal native library (include/seal.h): lease
//! verification, feature decryption, the device public key and hardware
//! components, over `seal_lease` and `seal_hwid`. The C++, C# and Java SDKs
//! go through these functions.
//!
//! Unlike the Node-API module, the trusted keys are passed in by the app
//! (seal_keys_new), so a vendor with its own signing key (hosted or
//! self-hosted) uses the same build.

use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod client;
pub use client::*;

use seal_lease::{DEFAULT_LEEWAY_SECONDS, DecryptError, Failure, Options, TrustedKey};

pub const SEAL_OK: i32 = 0;
pub const SEAL_NOT_LICENSED: i32 = 12;
pub const SEAL_DECRYPT_FAILED: i32 = 13;
pub const SEAL_E_ARGS: i32 = -1;
pub const SEAL_E_INTERNAL: i32 = -2;
pub const SEAL_E_BUFFER: i32 = -3;
pub const SEAL_E_NO_DEVICE_KEY: i32 = -4;

/// "LKE1" (4) + nonce (12) + tag (16): the bytes encrypted data has beyond its plaintext.
const ENCRYPTED_OVERHEAD: usize = 32;

/// The result code of a lease failure; the order is the header's.
fn failure_code(failure: Failure) -> i32 {
    match failure {
        Failure::Malformed => 1,
        Failure::UnsupportedAlgorithm => 2,
        Failure::WrongType => 3,
        Failure::UnknownKey => 4,
        Failure::BadSignature => 5,
        Failure::WrongIssuer => 6,
        Failure::WrongProduct => 7,
        Failure::WrongDevice => 8,
        Failure::NotYetValid => 9,
        Failure::Expired => 10,
        Failure::RevalidationRequired => 11,
    }
}

fn decrypt_code(error: &DecryptError) -> i32 {
    match error {
        DecryptError::Lease(failure) => failure_code(*failure),
        DecryptError::NotLicensed => SEAL_NOT_LICENSED,
        DecryptError::Failed => SEAL_DECRYPT_FAILED,
    }
}

/// Runs `f`, turning a panic into SEAL_E_INTERNAL so it never unwinds into C.
fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(SEAL_E_INTERNAL)
}

/// A UTF-8 string argument; None when NULL or not UTF-8.
///
/// # Safety
/// `ptr`, when not NULL, must point to a NUL-terminated string.
unsafe fn text<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null and NUL-terminated per the caller's contract.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Writes `value` plus a NUL into `out` when it fits.
///
/// # Safety
/// `out`, when not NULL, must point to `out_len` writable bytes.
unsafe fn write_text(value: &str, out: *mut c_char, out_len: usize) -> bool {
    if out.is_null() || value.len() >= out_len {
        return false;
    }
    // SAFETY: value.len() + 1 <= out_len writable bytes at `out`.
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), out.cast::<u8>(), value.len());
        *out.add(value.len()) = 0;
    }
    true
}

/// Library version as a NUL-terminated string. Static; do not free.
#[unsafe(no_mangle)]
pub extern "C" fn seal_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// The SDK's reason string for a result code. Static; do not free.
#[unsafe(no_mangle)]
pub extern "C" fn seal_result_name(result: i32) -> *const c_char {
    let name: &'static str = match result {
        0 => "ok\0",
        1 => "malformed\0",
        2 => "unsupported_algorithm\0",
        3 => "wrong_type\0",
        4 => "unknown_key\0",
        5 => "bad_signature\0",
        6 => "wrong_issuer\0",
        7 => "wrong_product\0",
        8 => "wrong_device\0",
        9 => "not_yet_valid\0",
        10 => "expired\0",
        11 => "revalidation_required\0",
        12 => "not_licensed\0",
        13 => "decrypt_failed\0",
        r if r < 0 => "error\0",
        _ => "unknown\0",
    };
    name.as_ptr().cast()
}

// ---- Trusted keys ---------------------------------------------------------------------------

/// The trusted key set behind a `seal_keys *`.
pub struct SealKeys {
    keys: Vec<TrustedKey>,
}

/// Splits PEM blocks and bare base64 bodies (separated by commas or whitespace) into one
/// base64 body per key. None for a PEM block with no END line.
fn key_bodies(input: &str) -> Option<Vec<String>> {
    let mut bodies = Vec::new();
    let mut block: Option<String> = None;
    for line in input.lines().map(str::trim) {
        if line.starts_with("-----BEGIN") {
            block = Some(String::new());
        } else if line.starts_with("-----END") {
            if let Some(body) = block.take() {
                bodies.push(body);
            }
        } else if let Some(body) = block.as_mut() {
            body.push_str(line);
        } else {
            bodies.extend(line.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).map(String::from));
        }
    }
    if block.is_some() {
        return None;
    }
    Some(bodies)
}

fn parse_keys(input: &str) -> Option<SealKeys> {
    let bodies = key_bodies(input)?;
    if bodies.is_empty() {
        return None;
    }
    let keys = bodies.iter().map(|body| TrustedKey::from_spki_pem(body)).collect::<Option<Vec<_>>>()?;
    Some(SealKeys { keys })
}

/// Parses the trusted keys; NULL when there is none or one is not an Ed25519 SPKI key.
///
/// # Safety
/// `pem` must be NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_keys_new(pem: *const c_char) -> *mut SealKeys {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per this function's contract.
        let Some(input) = (unsafe { text(pem) }) else { return std::ptr::null_mut() };
        parse_keys(input).map_or(std::ptr::null_mut(), |keys| Box::into_raw(Box::new(keys)))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Frees a key set from seal_keys_new; NULL is ignored.
///
/// # Safety
/// `keys` must be NULL or a pointer from seal_keys_new not freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_keys_free(keys: *mut SealKeys) {
    if !keys.is_null() {
        // SAFETY: from Box::into_raw in seal_keys_new, freed once per the contract.
        drop(unsafe { Box::from_raw(keys) });
    }
}

/// Number of keys; 0 for NULL.
///
/// # Safety
/// `keys` must be NULL or a live pointer from seal_keys_new.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_keys_count(keys: *const SealKeys) -> usize {
    // SAFETY: per this function's contract.
    unsafe { keys.as_ref() }.map_or(0, |k| k.keys.len())
}

/// Copies key `index`'s id plus a NUL into `out`.
///
/// # Safety
/// `keys` must be NULL or a live pointer from seal_keys_new; `out`, when not NULL, must point
/// to `out_len` writable bytes; `needed` must be NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_keys_id(keys: *const SealKeys, index: usize, out: *mut c_char, out_len: usize, needed: *mut usize) -> i32 {
    guard(|| {
        // SAFETY: per this function's contract.
        let Some(key) = (unsafe { keys.as_ref() }).and_then(|k| k.keys.get(index)) else { return SEAL_E_ARGS };
        if !needed.is_null() {
            // SAFETY: non-null and writable per the contract.
            unsafe { *needed = key.kid.len() + 1 };
        }
        // SAFETY: per this function's contract.
        if unsafe { write_text(&key.kid, out, out_len) } { SEAL_OK } else { SEAL_E_BUFFER }
    })
}

// ---- Lease checks ---------------------------------------------------------------------------

/// The `seal_check` struct of the header.
#[repr(C)]
pub struct SealCheck {
    pub product: *const c_char,
    pub fingerprint_hash: *const c_char,
    pub issuer: *const c_char,
    pub now: f64,
    pub grace_seconds: f64,
    pub leeway_seconds: f64,
}

/// Sets a check's defaults.
///
/// # Safety
/// `check` must be NULL or point to a writable seal_check.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_check_init(check: *mut SealCheck) {
    if !check.is_null() {
        let defaults = SealCheck {
            product: std::ptr::null(),
            fingerprint_hash: std::ptr::null(),
            issuer: std::ptr::null(),
            now: 0.0,
            grace_seconds: 0.0,
            leeway_seconds: DEFAULT_LEEWAY_SECONDS,
        };
        // SAFETY: non-null and writable per the contract.
        unsafe { check.write(defaults) };
    }
}

/// The verifier's options from a C check; None when a field is missing or invalid.
///
/// # Safety
/// The check's string fields must be NULL or NUL-terminated strings.
unsafe fn options<'a>(keys: &'a SealKeys, check: &'a SealCheck) -> Option<Options<'a>> {
    let finite = |n: f64| n.is_finite().then_some(n);
    // SAFETY: per this function's contract.
    let (product, fingerprint_hash) = unsafe { (text(check.product)?, text(check.fingerprint_hash)?) };
    let issuer = if check.issuer.is_null() {
        None
    } else {
        // SAFETY: per this function's contract.
        Some(unsafe { text(check.issuer) }?)
    };
    Some(Options {
        keys: &keys.keys,
        product,
        fingerprint_hash,
        issuer,
        now: finite(check.now)?,
        grace_seconds: finite(check.grace_seconds).filter(|g| *g >= 0.0)?,
        leeway_seconds: finite(check.leeway_seconds).filter(|l| *l >= 0.0)?,
    })
}

/// Verifies a lease. See seal.h.
///
/// # Safety
/// `keys` must be a live pointer from seal_keys_new; `token` and the check's strings
/// NUL-terminated; `kid_out`, when not NULL, `kid_out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_verify_lease(keys: *const SealKeys, token: *const c_char, check: *const SealCheck, kid_out: *mut c_char, kid_out_len: usize) -> i32 {
    guard(|| {
        // SAFETY: per this function's contract.
        let (Some(keys), Some(check), Some(token)) = (unsafe { keys.as_ref() }, unsafe { check.as_ref() }, unsafe { text(token) }) else {
            return SEAL_E_ARGS;
        };
        // SAFETY: per this function's contract.
        let Some(options) = (unsafe { options(keys, check) }) else { return SEAL_E_ARGS };
        match seal_lease::verify(token, &options) {
            Ok(verified) => {
                if !kid_out.is_null() {
                    // SAFETY: per this function's contract.
                    if !unsafe { write_text(&verified.kid, kid_out, kid_out_len) } {
                        return SEAL_E_BUFFER;
                    }
                }
                SEAL_OK
            }
            Err((failure, _)) => failure_code(failure),
        }
    })
}

/// The product key the SDK derives hardware hashes and the device secret with.
fn product_key(product: &str) -> String {
    format!("licensekit:{product}")
}

/// Decrypts feature data. See seal.h.
///
/// # Safety
/// `keys` must be a live pointer from seal_keys_new; the strings NUL-terminated; `data`
/// `data_len` readable bytes; `out`, when not NULL, `out_cap` writable bytes; `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_decrypt_feature(
    keys: *const SealKeys,
    token: *const c_char,
    check: *const SealCheck,
    license_key: *const c_char,
    feature: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the device secret comes from this machine's hardware.
    unsafe { decrypt(keys, token, check, license_key, feature, data, data_len, out, out_cap, out_len, None) }
}

/// Test builds only: decrypts with a given device secret (32 bytes), so the shared vectors can be
/// run through the C interface. Published builds always derive it from the hardware.
///
/// # Safety
/// As seal_decrypt_feature; `secret` must point to 32 readable bytes.
#[cfg(feature = "test-device-secret")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_test_decrypt_feature_with_secret(
    keys: *const SealKeys,
    token: *const c_char,
    check: *const SealCheck,
    license_key: *const c_char,
    feature: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    secret: *const u8,
) -> i32 {
    if secret.is_null() {
        return SEAL_E_ARGS;
    }
    // SAFETY: 32 readable bytes per the contract.
    let secret: [u8; 32] = unsafe { std::slice::from_raw_parts(secret, 32) }.try_into().expect("32 bytes");
    // SAFETY: per this function's contract.
    unsafe { decrypt(keys, token, check, license_key, feature, data, data_len, out, out_cap, out_len, Some(secret)) }
}

#[allow(clippy::too_many_arguments)]
unsafe fn decrypt(
    keys: *const SealKeys,
    token: *const c_char,
    check: *const SealCheck,
    license_key: *const c_char,
    feature: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    given_secret: Option<[u8; 32]>,
) -> i32 {
    guard(|| {
        // SAFETY: per the callers' contracts.
        let (Some(keys), Some(check), Some(token), Some(license_key), Some(feature)) =
            (unsafe { keys.as_ref() }, unsafe { check.as_ref() }, unsafe { text(token) }, unsafe { text(license_key) }, unsafe { text(feature) })
        else {
            return SEAL_E_ARGS;
        };
        if out_len.is_null() || (data.is_null() && data_len != 0) || (out.is_null() && out_cap != 0) {
            return SEAL_E_ARGS;
        }
        // SAFETY: per the callers' contracts.
        let Some(options) = (unsafe { options(keys, check) }) else { return SEAL_E_ARGS };
        let plain_len = data_len.saturating_sub(ENCRYPTED_OVERHEAD);
        // SAFETY: out_len is non-null and writable.
        unsafe { *out_len = plain_len };
        if out_cap < plain_len {
            return SEAL_E_BUFFER;
        }
        let data: &[u8] = if data_len == 0 {
            &[]
        } else {
            // SAFETY: non-null with data_len readable bytes.
            unsafe { std::slice::from_raw_parts(data, data_len) }
        };
        let secret = given_secret.or_else(|| seal_hwid::device_secret(product_key(options.product).as_bytes()));
        match seal_lease::decrypt_feature(token, &options, license_key, feature, data, secret.as_ref()) {
            Ok(plain) if plain.len() == plain_len => {
                if plain_len > 0 {
                    // SAFETY: out has out_cap >= plain_len writable bytes.
                    unsafe { std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain_len) };
                }
                SEAL_OK
            }
            Ok(_) => SEAL_E_INTERNAL,
            Err(e) => decrypt_code(&e),
        }
    })
}

// ---- This device ----------------------------------------------------------------------------

/// This machine's device public key for the product. See seal.h.
///
/// # Safety
/// `product` must be a NUL-terminated string; `out`, when not NULL, `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_device_public_key(product: *const c_char, out: *mut c_char, out_len: usize) -> i32 {
    guard(|| {
        // SAFETY: per this function's contract.
        let Some(product) = (unsafe { text(product) }) else { return SEAL_E_ARGS };
        let Some(secret) = seal_hwid::device_secret(product_key(product).as_bytes()) else { return SEAL_E_NO_DEVICE_KEY };
        use base64::Engine;
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seal_lease::device_public_key(&secret));
        // SAFETY: per this function's contract.
        if unsafe { write_text(&public, out, out_len) } { SEAL_OK } else { SEAL_E_BUFFER }
    })
}

/// The components as the C interface of seal_hwid writes them (same JSON shape).
fn hardware_json(product: &str) -> String {
    let collected = seal_hwid::collect(product_key(product).as_bytes());
    let items: Vec<String> = collected
        .components
        .iter()
        .map(|c| format!(r#"{{"kind":"{}","hash":"{}"}}"#, c.kind.as_str(), c.hash))
        .collect();
    format!(r#"{{"format":{},"vm":{},"components":[{}]}}"#, seal_hwid::LK_HWID_FORMAT, collected.vm, items.join(","))
}

/// This machine's hashed hardware components for the product. See seal.h.
///
/// # Safety
/// `product` must be a NUL-terminated string; `out`, when not NULL, `out_len` writable bytes;
/// `needed` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_hardware(product: *const c_char, out: *mut c_char, out_len: usize, needed: *mut usize) -> i32 {
    guard(|| {
        // SAFETY: per this function's contract.
        let Some(product) = (unsafe { text(product) }) else { return SEAL_E_ARGS };
        if out.is_null() && out_len != 0 {
            return SEAL_E_ARGS;
        }
        let json = hardware_json(product);
        if !needed.is_null() {
            // SAFETY: non-null and writable per the contract.
            unsafe { *needed = json.len() + 1 };
        }
        // SAFETY: per this function's contract.
        if unsafe { write_text(&json, out, out_len) } { SEAL_OK } else { SEAL_E_BUFFER }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: &str = "MCowBQYDK2VwAyEALiAdmTkGG9jtE74LHZzjfNugnNT9bIvVBRm0onTDGgQ=";
    const NEXT: &str = "MCowBQYDK2VwAyEA71j+vfBUoOPZ2QfmhzjZQv/Aj600Wni1Vv7y5A/r/xg=";

    #[test]
    fn keys_from_pem_blocks_and_bare_bodies() {
        let pem = |b: &str| format!("-----BEGIN PUBLIC KEY-----\n{b}\n-----END PUBLIC KEY-----\n");
        assert_eq!(parse_keys(&format!("{}{}", pem(CURRENT), pem(NEXT))).unwrap().keys.len(), 2);
        assert_eq!(parse_keys(&format!("{CURRENT},{NEXT}")).unwrap().keys.len(), 2);
        assert_eq!(parse_keys(&format!(" {CURRENT}\n{NEXT} ")).unwrap().keys.len(), 2);
        assert_eq!(parse_keys(&pem(CURRENT)).unwrap().keys[0].kid, parse_keys(CURRENT).unwrap().keys[0].kid);
    }

    #[test]
    fn no_key_or_a_bad_key_gives_no_set() {
        assert!(parse_keys("").is_none());
        assert!(parse_keys(" \n,").is_none());
        assert!(parse_keys(&format!("{CURRENT},MCowBQYDK2VwAyEA")).is_none(), "one bad key refuses the whole set");
        assert!(parse_keys(&format!("-----BEGIN PUBLIC KEY-----\n{CURRENT}\n")).is_none(), "unterminated block");
    }

    #[test]
    fn result_names_match_the_core_reasons() {
        let name = |r| unsafe { CStr::from_ptr(seal_result_name(r)) }.to_str().unwrap();
        for failure in [
            Failure::Malformed,
            Failure::UnsupportedAlgorithm,
            Failure::WrongType,
            Failure::UnknownKey,
            Failure::BadSignature,
            Failure::WrongIssuer,
            Failure::WrongProduct,
            Failure::WrongDevice,
            Failure::NotYetValid,
            Failure::Expired,
            Failure::RevalidationRequired,
        ] {
            assert_eq!(name(failure_code(failure)), failure.as_str());
        }
        assert_eq!(name(SEAL_NOT_LICENSED), DecryptError::NotLicensed.as_str());
        assert_eq!(name(SEAL_DECRYPT_FAILED), DecryptError::Failed.as_str());
        assert_eq!(name(0), "ok");
        assert_eq!(name(SEAL_E_BUFFER), "error");
        assert_eq!(name(99), "unknown");
    }
}
