//! Verifies Carcha Seal leases: compact JWS tokens signed with Ed25519
//! (`header.claims.signature`, base64url). The rules, their order and the
//! failure reasons are the same as `verifyLease` in @carchalabs/seal-core,
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
    let feature_keys = claims.get("fk").is_none_or(|v| v.as_object().is_some_and(|m| m.values().all(Value::is_string)));
    let ephemeral = claims.get("epk").is_none_or(Value::is_string);
    strings && numbers && expiry && features && customer && optional_times && feature_keys && ephemeral
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

// ---- Feature keys (same construction as the core library) ----------------------------------

const FEATURE_WRAP_SALT: &[u8] = b"licensekit feature key v1";
const ENCRYPTED_MAGIC: &[u8] = b"LKE1";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// The core library's normalizeLicenseKey: upper case, no spaces or dashes, no "LK" prefix,
/// I and L read as 1 and O as 0, then "LK-" and groups of four. License keys are ASCII.
pub fn normalize_license_key(input: &str) -> String {
    let mut body: String = input.to_uppercase().chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if let Some(rest) = body.strip_prefix("LK") {
        body = rest.to_string();
    }
    let body: Vec<char> = body.chars().map(|c| match c {
        'I' | 'L' => '1',
        'O' => '0',
        c => c,
    }).collect();
    let mut out = String::from("LK");
    for group in body.chunks(4) {
        out.push('-');
        out.extend(group);
    }
    out
}

/// HKDF-SHA256 (RFC 5869) over the normalized license key; info = product, fingerprint, lease id.
pub fn feature_wrap_key(license_key: &str, product: &str, fingerprint_hash: &str, lease_id: &str) -> [u8; 32] {
    let ikm = normalize_license_key(license_key);
    let info = format!("{product}\n{fingerprint_hash}\n{lease_id}");
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(FEATURE_WRAP_SALT), ikm.as_bytes())
        .expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

// ---- Device keys (X25519, RFC 7748; same construction as the core library) -------------------

const DEVICE_WRAP_SALT: &[u8] = b"licensekit feature key v2 device";

/// The X25519 public key of a device secret.
pub fn device_public_key(device_secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*device_secret)).to_bytes()
}

/// The wrap key for a lease whose feature keys the server wrapped for this device (claim epk).
/// None for an epk that is not 32 base64url bytes, or a low-order one (all-zero shared secret).
pub fn device_feature_wrap_key(license_key: &str, product: &str, fingerprint_hash: &str, lease_id: &str, device_secret: &[u8; 32], epk: &str) -> Option<[u8; 32]> {
    if !is_base64url(epk) {
        return None;
    }
    let epk_raw: [u8; 32] = b64().decode(epk).ok()?.try_into().ok()?;
    let shared = x25519_dalek::StaticSecret::from(*device_secret).diffie_hellman(&x25519_dalek::PublicKey::from(epk_raw));
    if !shared.was_contributory() {
        return None;
    }
    let mut ikm = shared.as_bytes().to_vec();
    ikm.extend_from_slice(normalize_license_key(license_key).as_bytes());
    let info = format!(
        "{product}\n{fingerprint_hash}\n{lease_id}\n{}\n{}",
        b64().encode(epk_raw),
        b64().encode(device_public_key(device_secret))
    );
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(DEVICE_WRAP_SALT), &ikm)
        .expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Some(okm)
}

/// AES-256-GCM open of nonce || ciphertext || tag with associated data.
fn open(key: &[u8; 32], sealed: &[u8], aad: &str) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return None;
    }
    let (nonce, body) = sealed.split_at(NONCE_BYTES);
    aes_gcm::Aes256Gcm::new(key.into())
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: body, aad: aad.as_bytes() })
        .ok()
}

/// A lease's wrapped content key for `feature` (claims.fk[feature], base64url) opened with the wrap key.
pub fn unwrap_feature_key(wrapped: &str, wrap_key: &[u8; 32], feature: &str) -> Option<[u8; 32]> {
    if !is_base64url(wrapped) {
        return None;
    }
    let sealed = b64().decode(wrapped).ok()?;
    open(wrap_key, &sealed, &format!("fk:{feature}"))?.try_into().ok()
}

/// Data encrypted for a feature: "LKE1" || nonce || ciphertext || tag, the feature as associated data.
pub fn decrypt_for_feature(content_key: &[u8; 32], feature: &str, encrypted: &[u8]) -> Option<Vec<u8>> {
    let sealed = encrypted.strip_prefix(ENCRYPTED_MAGIC)?;
    open(content_key, sealed, &format!("LKE1:{feature}"))
}

/// Why feature data could not be decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The lease itself was refused (same reasons as verify).
    Lease(Failure),
    /// The verified lease does not grant this feature or carries no key for it.
    NotLicensed,
    /// The key or the data did not authenticate (wrong license key or device, or modified data).
    Failed,
}

impl DecryptError {
    /// The core library's reason names (decryptFeature).
    pub fn as_str(&self) -> &'static str {
        match self {
            DecryptError::Lease(failure) => failure.as_str(),
            DecryptError::NotLicensed => "not_licensed",
            DecryptError::Failed => "decrypt_failed",
        }
    }
}

/// Verifies the lease, then unwraps the feature's content key for this license key and device and
/// decrypts `encrypted` with it. A lease wrapped for a device key (claim epk) needs that device's
/// secret. The content key never leaves this function.
pub fn decrypt_feature(
    token: &str,
    options: &Options,
    license_key: &str,
    feature: &str,
    encrypted: &[u8],
    device_secret: Option<&[u8; 32]>,
) -> Result<Vec<u8>, DecryptError> {
    let verified = verify(token, options).map_err(|(failure, _)| DecryptError::Lease(failure))?;
    let claims = &verified.claims;
    let licensed = claims.get("feat").and_then(Value::as_array).is_some_and(|f| f.iter().any(|x| x.as_str() == Some(feature)));
    let wrapped = claims.get("fk").and_then(|fk| fk.get(feature)).and_then(Value::as_str);
    let (true, Some(wrapped)) = (licensed, wrapped) else {
        return Err(DecryptError::NotLicensed);
    };
    let lease_id = claims.get("jti").and_then(Value::as_str).unwrap_or_default();
    let wrap_key = match claims.get("epk").and_then(Value::as_str) {
        Some(epk) => device_secret
            .and_then(|secret| device_feature_wrap_key(license_key, options.product, options.fingerprint_hash, lease_id, secret, epk))
            .ok_or(DecryptError::Failed)?,
        None => feature_wrap_key(license_key, options.product, options.fingerprint_hash, lease_id),
    };
    let content_key = unwrap_feature_key(wrapped, &wrap_key, feature).ok_or(DecryptError::Failed)?;
    decrypt_for_feature(&content_key, feature, encrypted).ok_or(DecryptError::Failed)
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
