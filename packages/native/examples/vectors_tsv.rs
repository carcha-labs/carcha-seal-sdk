//! Writes the lease vectors of ../lease/tests/vectors.json as tab-separated lines for the C test
//! (tests/c/verify.c), which has no JSON parser:
//! name, token, product, fingerprint hash, issuer or "-", now, grace or "-", leeway or "-",
//! expected ("ok:<kid>" or the reason). The first line is the public key PEM with "\n" escaped.

use serde_json::Value;

fn main() {
    let file: Value = serde_json::from_str(include_str!("../../lease/tests/vectors.json")).unwrap();
    println!("{}", file["publicKey"].as_str().unwrap().replace('\n', "\\n"));
    for v in file["vectors"].as_array().unwrap() {
        let c = &v["check"];
        let text = |value: &Value| value.as_str().map_or("-".to_string(), str::to_string);
        let number = |value: &Value| value.as_f64().map_or("-".to_string(), |n| n.to_string());
        let expected = match v["expected"]["ok"].as_bool() {
            Some(true) => format!("ok:{}", v["expected"]["kid"].as_str().unwrap()),
            _ => v["expected"]["reason"].as_str().unwrap().to_string(),
        };
        let fields = [
            text(&v["name"]),
            text(&v["token"]),
            text(&c["product"]),
            text(&c["fingerprintHash"]),
            text(&c["issuer"]),
            number(&c["now"]),
            number(&c["graceSeconds"]),
            number(&c["leewaySeconds"]),
            expected,
        ];
        assert!(fields.iter().all(|f| !f.contains('\t') && !f.contains('\n')));
        println!("{}", fields.join("\t"));
    }
}
