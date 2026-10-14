//! Node-API layer over `licensekit_hwid` for Node.js and Electron.
//!
//! Exposes `collect(key)` and `version()`. Only kinds, hashes, the VM flag and
//! diagnostic notes cross into JavaScript, never raw serials.

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
