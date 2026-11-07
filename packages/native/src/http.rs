//! The built-in HTTP client (cargo feature `http`, in the builds for C++): POSTs a request of the license client
//! with the OS's certificate verification, the proxy from HTTPS_PROXY / ALL_PROXY (and on Windows the user's
//! proxy setting), redirects refused and a timeout. C#, Java and apps with their own HTTP stack do not need it.

use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

use crate::{SEAL_E_ARGS, text};

/// The largest answer read; a lease and its notices are a few kilobytes.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

fn post(url: &str, user_agent: &str, body: &str, timeout_ms: u32) -> Option<(u16, Vec<u8>)> {
    let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .http_status_as_error(false)
        // A redirect could take the license key to another address or to http:// (ASVS 4.1.2): never followed.
        .max_redirects(0)
        .timeout_global(Some(Duration::from_millis(u64::from(timeout_ms))))
        .user_agent(user_agent)
        .build()
        .into();
    let mut response = agent.post(url).header("Content-Type", "application/json").send(body).ok()?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return None;
    }
    let bytes = response.body_mut().with_config().limit(MAX_RESPONSE_BYTES).read_to_vec().ok()?;
    Some((status, bytes))
}

/// POSTs `body` (JSON) to `url` and returns the HTTP status, 0 when there was no answer (no connection, timeout, TLS
/// failure, a redirect, an answer over 1 MB) or SEAL_E_ARGS. The answer's body goes to `*response` /
/// `*response_len`; free it with seal_bytes_free. See seal.h.
///
/// # Safety
/// `url`, `user_agent` and `body` must be NUL-terminated; `response` and `response_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_http_post(url: *const c_char, user_agent: *const c_char, body: *const c_char, timeout_ms: u32, response: *mut *mut u8, response_len: *mut usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per this function's contract.
        let (Some(url), Some(user_agent), Some(body)) = (unsafe { text(url) }, unsafe { text(user_agent) }, unsafe { text(body) }) else {
            return SEAL_E_ARGS;
        };
        if response.is_null() || response_len.is_null() || timeout_ms == 0 || seal_client::check_server_url(url).is_err() {
            return SEAL_E_ARGS;
        }
        // SAFETY: writable per the contract.
        unsafe {
            *response = std::ptr::null_mut();
            *response_len = 0;
        }
        let Some((status, bytes)) = post(url, user_agent, body, timeout_ms) else { return 0 };
        let len = bytes.len();
        let raw = Box::into_raw(bytes.into_boxed_slice()).cast::<u8>();
        // SAFETY: writable per the contract.
        unsafe {
            *response = raw;
            *response_len = len;
        }
        i32::from(status)
    }))
    .unwrap_or(0)
}

/// Frees an answer body from seal_http_post; NULL is ignored.
///
/// # Safety
/// `bytes` and `len` must be NULL / any, or exactly what seal_http_post wrote, not freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_bytes_free(bytes: *mut u8, len: usize) {
    if !bytes.is_null() {
        // SAFETY: from Box::into_raw of a boxed slice of `len` bytes in seal_http_post.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(bytes, len)) });
    }
}
