//! Node-API layer over `licensekit_hwid` and `licensekit_lease` for Node.js and
//! Electron.
//!
//! Exposes `collect(key)`, `verifyLease(token, options)`, `leaseKeyIds()` and
//! `version()`. Only kinds, hashes, the VM flag and diagnostic notes cross into
//! JavaScript, never raw serials.

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct Component {
    /// uuid, board, disk, mac, os, cpu or gpu.
    pub kind: String,
    /// Lowercase hex HMAC-SHA256 of the component, keyed by the product.
    pub hash: String,
}

#[napi(object)]
pub struct Collected {
    /// Version of the result shape (same as the C interface's "format").
    pub format: u32,
    pub vm: bool,
    pub components: Vec<Component>,
    /// Why kinds are missing: the failing call and its error code, never a value.
    pub notes: Vec<String>,
}

/// Reads this machine's components and hashes each with `key` (the product
/// key as a string or bytes). Synchronous: a read takes a few milliseconds.
#[napi]
pub fn collect(key: Either<String, Buffer>) -> Result<Collected> {
    let bytes: Vec<u8> = match key {
        Either::A(s) => s.into_bytes(),
        Either::B(b) => b.to_vec(),
    };
    if bytes.is_empty() {
        return Err(Error::new(Status::InvalidArg, "key must not be empty"));
    }
    let (c, notes) = licensekit_hwid::collect_with_notes(&bytes);
    Ok(Collected {
        format: licensekit_hwid::LK_HWID_FORMAT,
        vm: c.vm,
        components: c
            .components
            .into_iter()
            .map(|x| Component { kind: x.kind.as_str().to_string(), hash: x.hash })
            .collect(),
        notes,
    })
}

/// Version of the native core, e.g. "0.1.0".
#[napi]
pub fn version() -> String {
    // SAFETY: lk_hwid_version returns a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(licensekit_hwid::lk_hwid_version()) }
        .to_string_lossy()
        .into_owned()
}

/// Public keys this build trusts for leases, compiled in: SPKI PEM bodies
/// (base64), comma-separated, from LICENSEKIT_LEASE_PUBLIC_KEYS at build time.
/// The default is the hosted service's current and next signing keys
/// (packages/quickstart/public-keys). Compiled in, so a lease signed with
/// another key cannot be made to pass by changing a file or a setting.
const LEASE_PUBLIC_KEYS: &str = match option_env!("LICENSEKIT_LEASE_PUBLIC_KEYS") {
    Some(keys) => keys,
    None => concat!(
        "MCowBQYDK2VwAyEALiAdmTkGG9jtE74LHZzjfNugnNT9bIvVBRm0onTDGgQ=,",
        "MCowBQYDK2VwAyEA71j+vfBUoOPZ2QfmhzjZQv/Aj600Wni1Vv7y5A/r/xg=",
    ),
};

fn trusted_keys() -> &'static [licensekit_lease::TrustedKey] {
    static KEYS: std::sync::OnceLock<Vec<licensekit_lease::TrustedKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        LEASE_PUBLIC_KEYS
            .split(',')
            .map(|key| licensekit_lease::TrustedKey::from_spki_pem(key).expect("LICENSEKIT_LEASE_PUBLIC_KEYS: not an Ed25519 SPKI key"))
            .collect()
    })
}

#[napi(object)]
pub struct LeaseCheck {
    pub product: String,
    pub fingerprint_hash: String,
    /// Seconds since the Unix epoch; default: now.
    pub now: Option<f64>,
    pub grace_seconds: Option<f64>,
    pub leeway_seconds: Option<f64>,
    pub issuer: Option<String>,
}

#[napi(object)]
pub struct LeaseVerdict {
    pub ok: bool,
    /// The failure reason (the core library's names); absent when ok.
    pub reason: Option<String>,
    /// Id of the key that signed the lease; present when ok.
    pub kid: Option<String>,
}

/// Verifies a lease with the compiled-in keys and the same rules, order and
/// reasons as verifyLease in @carchalabs/licensekit-core.
#[napi]
pub fn verify_lease(token: String, check: LeaseCheck) -> LeaseVerdict {
    let now = check.now.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as f64).unwrap_or(0.0)
    });
    let options = licensekit_lease::Options {
        keys: trusted_keys(),
        product: &check.product,
        fingerprint_hash: &check.fingerprint_hash,
        issuer: check.issuer.as_deref(),
        now,
        grace_seconds: check.grace_seconds.unwrap_or(0.0),
        leeway_seconds: check.leeway_seconds.unwrap_or(licensekit_lease::DEFAULT_LEEWAY_SECONDS),
    };
    match licensekit_lease::verify(&token, &options) {
        Ok(verified) => LeaseVerdict { ok: true, reason: None, kid: Some(verified.kid) },
        Err((failure, _)) => LeaseVerdict { ok: false, reason: Some(failure.as_str().to_string()), kid: None },
    }
}

/// Ids of the keys this build trusts (same ids as keyId in the core library).
#[napi]
pub fn lease_key_ids() -> Vec<String> {
    trusted_keys().iter().map(|key| key.kid.clone()).collect()
}
