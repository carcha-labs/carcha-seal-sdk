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
