//! Runs every vector in ../lease/tests/vectors.json (made with the core library) through the C
//! interface: the same result codes as core's reasons, through seal_keys_new, seal_check and the
//! output buffers a C, C# or Java caller uses.

use std::ffi::{CStr, CString, c_char};

use seal_native::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../lease/tests/vectors.json")).unwrap()
}

fn name(result: i32) -> String {
    unsafe { CStr::from_ptr(seal_result_name(result)) }.to_str().unwrap().to_string()
}

/// The strings a check points to, kept alive while it is used.
struct Check {
    product: CString,
    fingerprint: CString,
    issuer: Option<CString>,
    now: f64,
    grace: f64,
    leeway: Option<f64>,
}

impl Check {
    fn from(v: &Value) -> Check {
        Check {
            product: CString::new(v["product"].as_str().unwrap()).unwrap(),
            fingerprint: CString::new(v["fingerprintHash"].as_str().unwrap()).unwrap(),
            issuer: v["issuer"].as_str().map(|s| CString::new(s).unwrap()),
            now: v["now"].as_f64().unwrap(),
            grace: v["graceSeconds"].as_f64().unwrap_or(0.0),
            leeway: v["leewaySeconds"].as_f64(),
        }
    }

    fn c(&self) -> SealCheck {
        let mut check = std::mem::MaybeUninit::<SealCheck>::uninit();
        unsafe { seal_check_init(check.as_mut_ptr()) };
        let mut check = unsafe { check.assume_init() };
        check.product = self.product.as_ptr();
        check.fingerprint_hash = self.fingerprint.as_ptr();
        check.issuer = self.issuer.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        check.now = self.now;
        check.grace_seconds = self.grace;
        if let Some(leeway) = self.leeway {
            check.leeway_seconds = leeway;
        }
        check
    }
}

fn keys(file: &Value) -> *mut SealKeys {
    let pem = CString::new(file["publicKey"].as_str().unwrap()).unwrap();
    let keys = unsafe { seal_keys_new(pem.as_ptr()) };
    assert!(!keys.is_null());
    keys
}

#[test]
fn every_lease_vector_gives_core_result() {
    let file = vectors();
    let keys = keys(&file);
    assert_eq!(unsafe { seal_keys_count(keys) }, 1);
    let mut kid = [0 as c_char; 64];
    let mut needed = 0usize;
    assert_eq!(unsafe { seal_keys_id(keys, 0, kid.as_mut_ptr(), kid.len(), &mut needed) }, SEAL_OK);
    assert_eq!(unsafe { CStr::from_ptr(kid.as_ptr()) }.to_str().unwrap(), file["kid"].as_str().unwrap());
    assert_eq!(needed, 44);

    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 40);
    for v in vectors {
        let label = v["name"].as_str().unwrap();
        let token = CString::new(v["token"].as_str().unwrap()).unwrap();
        let check = Check::from(&v["check"]);
        let mut kid = [0 as c_char; 64];
        let result = unsafe { seal_verify_lease(keys, token.as_ptr(), &check.c(), kid.as_mut_ptr(), kid.len()) };
        let got = if result == SEAL_OK {
            serde_json::json!({ "ok": true, "kid": unsafe { CStr::from_ptr(kid.as_ptr()) }.to_str().unwrap() })
        } else {
            assert!(result > 0, "{label}: call error {result}");
            serde_json::json!({ "ok": false, "reason": name(result) })
        };
        assert_eq!(got, v["expected"], "{label}");
    }
    unsafe { seal_keys_free(keys) };
}

#[cfg(feature = "test-device-secret")]
#[test]
fn every_decrypt_vector_gives_core_result() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let file = vectors();
    let keys = keys(&file);
    let decrypts = file["features"]["decrypts"].as_array().unwrap();
    assert!(decrypts.len() >= 10);
    for v in decrypts {
        let label = v["name"].as_str().unwrap();
        let token = CString::new(v["token"].as_str().unwrap()).unwrap();
        let license_key = CString::new(v["licenseKey"].as_str().unwrap()).unwrap();
        let feature = CString::new(v["feature"].as_str().unwrap()).unwrap();
        let data = b64.decode(v["data"].as_str().unwrap()).unwrap();
        let check = Check::from(&v["check"]);
        // A vector without a device secret gets an all-zero one: unused when the lease has no epk,
        // and when it has one, the wrong secret must fail as core fails without one (decrypt_failed).
        let secret: [u8; 32] = match v["deviceSecret"].as_str() {
            Some(hex) => (0..64).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap(),
            None => [0u8; 32],
        };
        let mut out = vec![0u8; data.len()];
        let mut out_len = 0usize;
        let result = unsafe {
            seal_test_decrypt_feature_with_secret(
                keys,
                token.as_ptr(),
                &check.c(),
                license_key.as_ptr(),
                feature.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                secret.as_ptr(),
            )
        };
        let got = if result == SEAL_OK {
            serde_json::json!({ "ok": true, "data": b64.encode(&out[..out_len]) })
        } else {
            assert!(result > 0, "{label}: call error {result}");
            serde_json::json!({ "ok": false, "reason": name(result) })
        };
        assert_eq!(got, v["expected"], "{label}");
    }
    unsafe { seal_keys_free(keys) };
}

#[test]
fn small_buffers_are_reported_and_left_untouched() {
    let file = vectors();
    let keys = keys(&file);
    let v = &file["vectors"][0];
    assert_eq!(v["expected"]["ok"], true);
    let token = CString::new(v["token"].as_str().unwrap()).unwrap();
    let check = Check::from(&v["check"]);
    let mut kid = [0x55 as c_char; 8];
    assert_eq!(unsafe { seal_verify_lease(keys, token.as_ptr(), &check.c(), kid.as_mut_ptr(), kid.len()) }, SEAL_E_BUFFER);
    assert!(kid.iter().all(|&b| b == 0x55));

    let mut needed = 0usize;
    assert_eq!(unsafe { seal_keys_id(keys, 0, std::ptr::null_mut(), 0, &mut needed) }, SEAL_E_BUFFER);
    assert_eq!(needed, 44);
    assert_eq!(unsafe { seal_keys_id(keys, 1, std::ptr::null_mut(), 0, &mut needed) }, SEAL_E_ARGS, "no key 1");

    // Decrypt reports the plaintext size and decrypts nothing when out is too small.
    let license = CString::new("LK-AAAA").unwrap();
    let feature = CString::new("pro").unwrap();
    let data = [0u8; 40];
    let mut out_len = 0usize;
    let result = unsafe {
        seal_decrypt_feature(keys, token.as_ptr(), &check.c(), license.as_ptr(), feature.as_ptr(), data.as_ptr(), data.len(), std::ptr::null_mut(), 0, &mut out_len)
    };
    assert_eq!((result, out_len), (SEAL_E_BUFFER, 8));
    unsafe { seal_keys_free(keys) };
}

#[test]
fn bad_arguments_are_refused() {
    let file = vectors();
    let keys = keys(&file);
    let token = CString::new("a.b.c").unwrap();
    let check = Check::from(&file["vectors"][0]["check"]);
    assert_eq!(unsafe { seal_verify_lease(std::ptr::null(), token.as_ptr(), &check.c(), std::ptr::null_mut(), 0) }, SEAL_E_ARGS);
    assert_eq!(unsafe { seal_verify_lease(keys, std::ptr::null(), &check.c(), std::ptr::null_mut(), 0) }, SEAL_E_ARGS);
    assert_eq!(unsafe { seal_verify_lease(keys, token.as_ptr(), std::ptr::null(), std::ptr::null_mut(), 0) }, SEAL_E_ARGS);
    let mut c = check.c();
    c.product = std::ptr::null();
    assert_eq!(unsafe { seal_verify_lease(keys, token.as_ptr(), &c, std::ptr::null_mut(), 0) }, SEAL_E_ARGS, "no product");
    let mut c = check.c();
    c.now = f64::NAN;
    assert_eq!(unsafe { seal_verify_lease(keys, token.as_ptr(), &c, std::ptr::null_mut(), 0) }, SEAL_E_ARGS, "now is NaN");
    let mut c = check.c();
    c.grace_seconds = -1.0;
    assert_eq!(unsafe { seal_verify_lease(keys, token.as_ptr(), &c, std::ptr::null_mut(), 0) }, SEAL_E_ARGS, "negative grace");
    let bad_utf8 = [0xffu8, 0xfe, 0];
    assert_eq!(unsafe { seal_verify_lease(keys, bad_utf8.as_ptr().cast(), &check.c(), std::ptr::null_mut(), 0) }, SEAL_E_ARGS, "token not UTF-8");
    assert!(unsafe { seal_keys_new(std::ptr::null()) }.is_null());
    let empty = CString::new("").unwrap();
    assert!(unsafe { seal_keys_new(empty.as_ptr()) }.is_null());
    assert_eq!(unsafe { seal_keys_count(std::ptr::null()) }, 0);
    unsafe { seal_keys_free(std::ptr::null_mut()) };
    unsafe { seal_keys_free(keys) };
}

#[test]
fn this_machine_device_key_and_hardware() {
    let product = CString::new("studio").unwrap();
    let mut out = [0 as c_char; 44];
    match unsafe { seal_device_public_key(product.as_ptr(), out.as_mut_ptr(), out.len()) } {
        SEAL_OK => assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()) }.to_bytes().len(), 43),
        SEAL_E_NO_DEVICE_KEY => eprintln!("this machine reports no device-key parts"),
        other => panic!("seal_device_public_key: {other}"),
    }
    let mut small = [0 as c_char; 43];
    let r = unsafe { seal_device_public_key(product.as_ptr(), small.as_mut_ptr(), small.len()) };
    assert!(r == SEAL_E_BUFFER || r == SEAL_E_NO_DEVICE_KEY);

    let mut needed = 0usize;
    assert_eq!(unsafe { seal_hardware(product.as_ptr(), std::ptr::null_mut(), 0, &mut needed) }, SEAL_E_BUFFER);
    let mut buf = vec![0 as c_char; needed + 64];
    assert_eq!(unsafe { seal_hardware(product.as_ptr(), buf.as_mut_ptr(), buf.len(), &mut needed) }, SEAL_OK);
    let json: Value = serde_json::from_str(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap()).unwrap();
    assert_eq!(json["format"], 1);
    assert!(json["components"].as_array().unwrap().iter().all(|c| c["hash"].as_str().unwrap().len() == 64));
}

#[test]
fn version_is_the_crate_version() {
    assert_eq!(unsafe { CStr::from_ptr(seal_version()) }.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}
