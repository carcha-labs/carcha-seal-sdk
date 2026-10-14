//! C interface. Every binding (native apps, .NET P/Invoke, the Node-API
//! layer) goes through these two functions; see include/licensekit_hwid.h.

use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::{Collected, collect};

/// Interface version; bumped when the JSON shape changes incompatibly.
pub const LK_HWID_FORMAT: u32 = 1;

/// `key` or `out` arguments are invalid.
pub const LK_HWID_E_ARGS: isize = -1;
/// An internal error (a panic) was caught; nothing was written.
pub const LK_HWID_E_INTERNAL: isize = -2;

/// Library version as a NUL-terminated string, e.g. "0.1.0". Static; do not free.
#[unsafe(no_mangle)]
pub extern "C" fn lk_hwid_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Reads the machine's components, hashes each with `key`, and writes them as
/// UTF-8 JSON plus a NUL terminator into `out`:
///
/// `{"format":1,"vm":false,"components":[{"kind":"disk","hash":"<64 hex>"},…]}`
///
/// Returns the JSON length in bytes, without the terminator. When that is
/// `>= out_len` nothing usable was written: call again with a buffer of at
/// least the returned length + 1 (`out` may be NULL with `out_len` 0 to ask
/// for the size). Hardware is read on every call, so the second call can in
/// rare cases need more room; repeat until the result fits.
///
/// Returns `LK_HWID_E_ARGS` when `key` is NULL or `key_len` is 0, or `out` is
/// NULL with a non-zero `out_len`; `LK_HWID_E_INTERNAL` on an internal error.
/// Never unwinds into the caller.
///
/// # Safety
/// `key` must point to `key_len` readable bytes; `out`, when not NULL, to
/// `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lk_hwid_collect(key: *const u8, key_len: usize, out: *mut u8, out_len: usize) -> isize {
    if key.is_null() || key_len == 0 || (out.is_null() && out_len != 0) {
        return LK_HWID_E_ARGS;
    }
    // SAFETY: checked non-null; the caller guarantees `key_len` readable bytes.
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let json = match catch_unwind(AssertUnwindSafe(|| to_json(&collect(key)))) {
        Ok(json) => json,
        Err(_) => return LK_HWID_E_INTERNAL,
    };
    let len = json.len();
    if len < out_len {
        // SAFETY: `out` is non-null here (out_len > len >= 0) and the caller
        // guarantees `out_len` writable bytes; we write len + 1 <= out_len.
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), out, len);
            *out.add(len) = 0;
        }
    }
    len as isize
}

/// Kinds and hashes are fixed ASCII (lowercase words, hex), so no escaping is needed.
pub(crate) fn to_json(c: &Collected) -> String {
    let items: Vec<String> = c
        .components
        .iter()
        .map(|x| format!(r#"{{"kind":"{}","hash":"{}"}}"#, x.kind.as_str(), x.hash))
        .collect();
    format!(r#"{{"format":{LK_HWID_FORMAT},"vm":{},"components":[{}]}}"#, c.vm, items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Component, Kind};
    use std::ffi::CStr;

    #[test]
    fn json_shape() {
        let c = Collected {
            components: vec![Component { kind: Kind::Disk, hash: "ab".repeat(32) }],
            vm: true,
        };
        assert_eq!(
            to_json(&c),
            format!(r#"{{"format":1,"vm":true,"components":[{{"kind":"disk","hash":"{}"}}]}}"#, "ab".repeat(32))
        );
    }

    #[test]
    fn size_query_then_fill() {
        let key = b"product-a";
        let n = unsafe { lk_hwid_collect(key.as_ptr(), key.len(), std::ptr::null_mut(), 0) };
        assert!(n > 0);
        let mut buf = vec![0xAAu8; n as usize + 1];
        let m = unsafe { lk_hwid_collect(key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len()) };
        assert_eq!(m, n);
        let s = CStr::from_bytes_with_nul(&buf).unwrap().to_str().unwrap();
        assert!(s.starts_with(r#"{"format":1,"#), "{s}");
    }

    #[test]
    fn too_small_buffer_is_left_untouched() {
        let key = b"k";
        let mut buf = [0xAAu8; 8];
        let n = unsafe { lk_hwid_collect(key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 8);
        assert_eq!(buf, [0xAA; 8]);
    }

    #[test]
    fn bad_arguments_are_refused() {
        let mut buf = [0u8; 4];
        assert_eq!(unsafe { lk_hwid_collect(std::ptr::null(), 1, buf.as_mut_ptr(), 4) }, LK_HWID_E_ARGS);
        assert_eq!(unsafe { lk_hwid_collect(b"k".as_ptr(), 0, buf.as_mut_ptr(), 4) }, LK_HWID_E_ARGS);
        assert_eq!(unsafe { lk_hwid_collect(b"k".as_ptr(), 1, std::ptr::null_mut(), 4) }, LK_HWID_E_ARGS);
    }

    #[test]
    fn version_is_the_crate_version() {
        let v = unsafe { CStr::from_ptr(lk_hwid_version()) }.to_str().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }
}
