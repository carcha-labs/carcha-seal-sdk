//! Every vector in vectors.json (made by make-vectors.js with the core library)
//! must give the same result here as in core's verifyLease.

use licensekit_lease::{DEFAULT_LEEWAY_SECONDS, Options, TrustedKey, verify};
use serde_json::Value;

#[test]
fn same_result_as_the_core_library_for_every_vector() {
    let file: Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let key = TrustedKey::from_spki_pem(file["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!(key.kid, file["kid"].as_str().unwrap(), "key id computed as core computes it");
    let keys = [key];
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 40);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let check = &v["check"];
        let options = Options {
            keys: &keys,
            product: check["product"].as_str().unwrap(),
            fingerprint_hash: check["fingerprintHash"].as_str().unwrap(),
            issuer: check["issuer"].as_str(),
            now: check["now"].as_f64().unwrap(),
            grace_seconds: check["graceSeconds"].as_f64().unwrap_or(0.0),
            leeway_seconds: check["leewaySeconds"].as_f64().unwrap_or(DEFAULT_LEEWAY_SECONDS),
        };
        let got = match verify(v["token"].as_str().unwrap(), &options) {
            Ok(verified) => serde_json::json!({ "ok": true, "kid": verified.kid }),
            Err((failure, _)) => serde_json::json!({ "ok": false, "reason": failure.as_str() }),
        };
        assert_eq!(got, v["expected"], "{name}");
    }
}

fn options<'a>(keys: &'a [TrustedKey], check: &'a Value) -> Options<'a> {
    Options {
        keys,
        product: check["product"].as_str().unwrap(),
        fingerprint_hash: check["fingerprintHash"].as_str().unwrap(),
        issuer: check["issuer"].as_str(),
        now: check["now"].as_f64().unwrap(),
        grace_seconds: check["graceSeconds"].as_f64().unwrap_or(0.0),
        leeway_seconds: check["leewaySeconds"].as_f64().unwrap_or(DEFAULT_LEEWAY_SECONDS),
    }
}

#[test]
fn feature_keys_work_as_in_the_core_library() {
    use base64::Engine;
    use licensekit_lease::{decrypt_feature, feature_wrap_key, normalize_license_key};
    let b64 = base64::engine::general_purpose::STANDARD;
    let file: Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let keys = [TrustedKey::from_spki_pem(file["publicKey"].as_str().unwrap()).unwrap()];
    let features = &file["features"];

    for v in features["normalize"].as_array().unwrap() {
        assert_eq!(normalize_license_key(v["input"].as_str().unwrap()), v["expected"].as_str().unwrap(), "{}", v["input"]);
    }
    for v in features["wrapKeys"].as_array().unwrap() {
        let s = |name: &str| v[name].as_str().unwrap();
        let key = feature_wrap_key(s("licenseKey"), s("product"), s("fingerprintHash"), s("leaseId"));
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, s("expected"));
    }
    let decrypts = features["decrypts"].as_array().unwrap();
    assert!(decrypts.len() >= 10);
    for v in decrypts {
        let name = v["name"].as_str().unwrap();
        let data = b64.decode(v["data"].as_str().unwrap()).unwrap();
        let got = match decrypt_feature(
            v["token"].as_str().unwrap(),
            &options(&keys, &v["check"]),
            v["licenseKey"].as_str().unwrap(),
            v["feature"].as_str().unwrap(),
            &data,
        ) {
            Ok(plain) => serde_json::json!({ "ok": true, "data": b64.encode(plain) }),
            Err(e) => serde_json::json!({ "ok": false, "reason": e.as_str() }),
        };
        assert_eq!(got, v["expected"], "{name}");
    }
}
