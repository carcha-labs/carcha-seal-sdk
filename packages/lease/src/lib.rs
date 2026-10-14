//! Verifies LicenseKit leases: compact JWS tokens signed with Ed25519
//! (`header.claims.signature`, base64url). The rules, their order and the
//! failure reasons are the same as `verifyLease` in @carchalabs/licensekit-core,
//! so both verifiers give the same answer for the same lease (the conformance
//! test in packages/hwid-node checks this).

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const LEASE_ALGORITHM: &str = "Ed25519";
pub const LEASE_TYPE: &str = "licensekit-lease+jwt";
pub const LEASE_ISSUER: &str = "licensekit";
pub const DEFAULT_LEEWAY_SECONDS: f64 = 300.0;

/// Why a lease was refused. The names are the core library's reason strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Malformed,
    UnsupportedAlgorithm,
    WrongType,
    UnknownKey,
    BadSignature,
    WrongIssuer,
    WrongProduct,
    WrongDevice,
    NotYetValid,
    Expired,
    RevalidationRequired,
}

impl Failure {
    pub fn as_str(self) -> &'static str {
        match self {
            Failure::Malformed => "malformed",
            Failure::UnsupportedAlgorithm => "unsupported_algorithm",
            Failure::WrongType => "wrong_type",
            Failure::UnknownKey => "unknown_key",
            Failure::BadSignature => "bad_signature",
            Failure::WrongIssuer => "wrong_issuer",
            Failure::WrongProduct => "wrong_product",
            Failure::WrongDevice => "wrong_device",
            Failure::NotYetValid => "not_yet_valid",
            Failure::Expired => "expired",
            Failure::RevalidationRequired => "revalidation_required",
        }
    }
}

/// A trusted Ed25519 public key and its key id: base64url(SHA-256 of
/// `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`), as the core library computes it.
#[derive(Clone)]
pub struct TrustedKey {
    pub kid: String,
    key: VerifyingKey,
}

/// The 12-byte DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

impl TrustedKey {
    pub fn from_raw(raw: [u8; 32]) -> Option<TrustedKey> {
        let key = VerifyingKey::from_bytes(&raw).ok()?;
        let x = b64().encode(raw);
        let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        let kid = b64().encode(Sha256::digest(canonical.as_bytes()));
        Some(TrustedKey { kid, key })
    }

    /// From a PEM `PUBLIC KEY` (SPKI) or just its base64 body.
    pub fn from_spki_pem(pem: &str) -> Option<TrustedKey> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD.decode(body).ok()?;
        if der.len() != 44 || der[..12] != SPKI_PREFIX {
            return None;
        }
        TrustedKey::from_raw(der[12..].try_into().ok()?)
    }
}

pub struct Options<'a> {
    pub keys: &'a [TrustedKey],
    pub product: &'a str,
    pub fingerprint_hash: &'a str,
    pub issuer: Option<&'a str>,
    /// Seconds since the Unix epoch.
    pub now: f64,
    pub grace_seconds: f64,
    pub leeway_seconds: f64,
}

#[derive(Debug, PartialEq)]
pub struct Verified {
    pub kid: String,
    /// The validated claims object.
    pub claims: Map<String, Value>,
}

/// The refusal reason, with the claims when the signature was already proven
/// (the core library returns them for the same reasons).
pub type Refused = (Failure, Option<Map<String, Value>>);

/// base64url as Node's Buffer.from(_, 'base64url') reads it: padding optional,
/// unused trailing bits ignored.
fn b64() -> GeneralPurpose {
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

fn is_base64url(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_segment(segment: &str) -> Option<Value> {
    if !is_base64url(segment) {
        return None;
    }
    let bytes = b64().decode(segment).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn finite(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64).filter(|n| n.is_finite())
}

/// The same shape check as the core library's isLeaseClaims.
fn valid_claims(claims: &Map<String, Value>) -> bool {
    let strings = ["iss", "sub", "aud", "jti", "fp"].iter().all(|name| claims.get(*name).is_some_and(Value::is_string));
    let numbers = ["iat", "nbf", "rev"].iter().all(|name| finite(claims.get(*name)).is_some());
    let expiry = claims.get("exp").is_none_or(|v| finite(Some(v)).is_some());
    let features = claims.get("feat").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string));
    let customer = claims.get("cus").is_none_or(Value::is_string);
    let optional_times = ["grc", "mnt"].iter().all(|name| claims.get(*name).is_none_or(|v| finite(Some(v)).is_some_and(|n| n >= 0.0)));
    strings && numbers && expiry && features && customer && optional_times
}

pub fn verify(token: &str, options: &Options) -> Result<Verified, Refused> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err((Failure::Malformed, None));
    }
    let (encoded_header, encoded_claims, encoded_signature) = (parts[0], parts[1], parts[2]);

    let Some(Value::Object(header)) = parse_segment(encoded_header) else {
        return Err((Failure::Malformed, None));
    };
    if header.get("alg").and_then(Value::as_str) != Some(LEASE_ALGORITHM) {
        return Err((Failure::UnsupportedAlgorithm, None));
    }
    if header.get("typ").and_then(Value::as_str) != Some(LEASE_TYPE) {
        return Err((Failure::WrongType, None));
    }
    // RFC 7515 4.1.11: leases use no critical extensions, so any "crit" is refused.
    if header.contains_key("crit") {
        return Err((Failure::Malformed, None));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let Some(trusted) = kid.and_then(|kid| options.keys.iter().find(|k| k.kid == kid)) else {
        return Err((Failure::UnknownKey, None));
    };

    if !is_base64url(encoded_signature) {
        return Err((Failure::Malformed, None));
    }
    let signature_ok = b64()
        .decode(encoded_signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .is_some_and(|signature| {
            let message = format!("{encoded_header}.{encoded_claims}");
            trusted.key.verify_strict(message.as_bytes(), &signature).is_ok()
        });
    if !signature_ok {
        return Err((Failure::BadSignature, None));
    }

    let claims = match parse_segment(encoded_claims) {
        Some(Value::Object(claims)) if valid_claims(&claims) => claims,
        _ => return Err((Failure::Malformed, None)),
    };
    let text = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or_default();
    if text("iss") != options.issuer.unwrap_or(LEASE_ISSUER) {
        return Err((Failure::WrongIssuer, Some(claims)));
    }
    if text("aud") != options.product {
        return Err((Failure::WrongProduct, Some(claims)));
    }
    if text("fp") != options.fingerprint_hash {
        return Err((Failure::WrongDevice, Some(claims)));
    }

    // The same clock-skew leeway on both ends (RFC 7519 4.1.4, 4.1.5).
    let (now, leeway) = (options.now, options.leeway_seconds);
    let nbf = finite(claims.get("nbf")).unwrap_or_default();
    let rev = finite(claims.get("rev")).unwrap_or_default();
    if now + leeway < nbf {
        return Err((Failure::NotYetValid, Some(claims)));
    }
    if let Some(exp) = finite(claims.get("exp")) {
        if now - leeway >= exp {
            return Err((Failure::Expired, Some(claims)));
        }
    }
    if now >= rev + options.grace_seconds {
        return Err((Failure::RevalidationRequired, Some(claims)));
    }
    Ok(Verified { kid: trusted.kid.clone(), claims })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The hosted service's current key (packages/quickstart/public-keys/current.pem).
    const CURRENT: &str = "MCowBQYDK2VwAyEALiAdmTkGG9jtE74LHZzjfNugnNT9bIvVBRm0onTDGgQ=";

    #[test]
    fn spki_keys_parse_and_others_do_not() {
        assert!(TrustedKey::from_spki_pem(CURRENT).is_some());
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{CURRENT}\n-----END PUBLIC KEY-----\n");
        assert_eq!(TrustedKey::from_spki_pem(&pem).unwrap().kid, TrustedKey::from_spki_pem(CURRENT).unwrap().kid);
        assert!(TrustedKey::from_spki_pem("MCowBQYDK2VwAyEA").is_none());
        assert!(TrustedKey::from_spki_pem("not base64!").is_none());
    }

    #[test]
    fn structural_failures() {
        let keys = [TrustedKey::from_spki_pem(CURRENT).unwrap()];
        let o = Options { keys: &keys, product: "p", fingerprint_hash: "f", issuer: None, now: 0.0, grace_seconds: 0.0, leeway_seconds: DEFAULT_LEEWAY_SECONDS };
        assert_eq!(verify("a.b", &o).unwrap_err().0, Failure::Malformed);
        assert_eq!(verify("a..c", &o).unwrap_err().0, Failure::Malformed);
        let header = |json: &str| b64().encode(json);
        assert_eq!(verify(&format!("{}.e30.c2ln", header(r#"{"alg":"none"}"#)), &o).unwrap_err().0, Failure::UnsupportedAlgorithm);
        assert_eq!(verify(&format!("{}.e30.c2ln", header(r#"{"alg":"Ed25519","typ":"JWT"}"#)), &o).unwrap_err().0, Failure::WrongType);
        assert_eq!(
            verify(&format!("{}.e30.c2ln", header(r#"{"alg":"Ed25519","typ":"licensekit-lease+jwt","crit":["x"]}"#)), &o).unwrap_err().0,
            Failure::Malformed
        );
        assert_eq!(
            verify(&format!("{}.e30.c2ln", header(r#"{"alg":"Ed25519","typ":"licensekit-lease+jwt","kid":"nope"}"#)), &o).unwrap_err().0,
            Failure::UnknownKey
        );
    }
}
