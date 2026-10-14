//! One HMAC-SHA256 per component, keyed by the product.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::normalize::normalize;
use crate::{Component, Kind, Raw};

/// Normalizes, drops junk and duplicates, hashes. The output is sorted by
/// kind then hash, so the same machine always yields the same list.
pub(crate) fn hash_all(key: &[u8], raws: Vec<Raw>) -> Vec<Component> {
    let mut kept: Vec<Raw> = raws
        .into_iter()
        .filter_map(|r| {
            normalize(r.kind, &r.value).map(|value| Raw { kind: r.kind, value })
        })
        .collect();
    kept.sort();
    kept.dedup();

    let mut out: Vec<Component> = kept
        .into_iter()
        .map(|r| Component { kind: r.kind, hash: hmac_hex(key, r.kind.as_str(), &r.value) })
        .collect();
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.hash.cmp(&b.hash)));
    out
}

/// Kinds whose raw values make the device secret: identifiers with enough entropy that the
/// server's keyed hashes cannot be reversed to them. MAC addresses are left out (24 bits after the
/// vendor prefix), as are CPU and graphics models (shared by many machines).
const DEVICE_SECRET_KINDS: [Kind; 4] = [Kind::Uuid, Kind::Board, Kind::Disk, Kind::Os];
const DEVICE_SECRET_SALT: &[u8] = b"licensekit device key v1";

/// The device secret: HKDF-SHA256 (RFC 5869) over the normalized raw values of the
/// DEVICE_SECRET_KINDS (sorted, each as kind || 0x00 || value || 0x00), with `key` (the product
/// key) as info. None when the machine reports none of those kinds. It changes when one of those
/// parts changes (a new disk, motherboard or OS install).
pub(crate) fn device_secret(key: &[u8], raws: Vec<Raw>) -> Option<[u8; 32]> {
    let mut kept: Vec<Raw> = raws
        .into_iter()
        .filter(|r| DEVICE_SECRET_KINDS.contains(&r.kind))
        .filter_map(|r| normalize(r.kind, &r.value).map(|value| Raw { kind: r.kind, value }))
        .collect();
    kept.sort();
    kept.dedup();
    if kept.is_empty() {
        return None;
    }
    let mut ikm = Vec::new();
    for r in &kept {
        ikm.extend_from_slice(r.kind.as_str().as_bytes());
        ikm.push(0);
        ikm.extend_from_slice(r.value.as_bytes());
        ikm.push(0);
    }
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(DEVICE_SECRET_SALT), &ikm)
        .expand(key, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Some(okm)
}

/// HMAC-SHA256(key, kind || 0x00 || value). The kind is part of the message,
/// so the same string read as two kinds gives two unrelated hashes.
fn hmac_hex(key: &[u8], kind: &str, value: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(kind.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(kind: Kind, value: &str) -> Raw {
        Raw { kind, value: value.into() }
    }

    #[test]
    fn matches_a_known_hmac_sha256() {
        // HMAC-SHA256(key="product-a", msg="disk\0SN123"), computed independently
        // with: printf 'disk\0SN123' | openssl dgst -sha256 -hmac product-a
        assert_eq!(
            hmac_hex(b"product-a", "disk", "SN123"),
            include_str!("../tests/fixtures/hmac-disk-sn123.txt").trim()
        );
    }

    #[test]
    fn device_secret_from_strong_parts_only() {
        let parts = vec![raw(Kind::Uuid, "4C4C4544-0042-3510-8051-B4C04F4A4E32"), raw(Kind::Disk, "S4EWNX0R123456"), raw(Kind::Os, "0f9e8d7c6b5a49382716051423324150")];
        let a = device_secret(b"product-a", parts.clone()).unwrap();
        assert_eq!(device_secret(b"product-a", parts.iter().rev().cloned().collect()), Some(a), "order does not matter");
        assert_ne!(device_secret(b"product-b", parts.clone()), Some(a), "another product, another secret");
        let mut with_extras = parts.clone();
        with_extras.extend([raw(Kind::Mac, "00:1A:2B:3C:4D:5E"), raw(Kind::Cpu, "Intel Core i7"), raw(Kind::Gpu, "10de:2484")]);
        assert_eq!(device_secret(b"product-a", with_extras), Some(a), "MAC, CPU and GPU do not count");
        let mut new_disk = parts.clone();
        new_disk[1] = raw(Kind::Disk, "S4EWNX0R999999");
        assert_ne!(device_secret(b"product-a", new_disk), Some(a), "a new disk is a new secret");
        assert_eq!(device_secret(b"product-a", vec![raw(Kind::Mac, "00:1A:2B:3C:4D:5E")]), None);
        assert_eq!(device_secret(b"product-a", vec![raw(Kind::Board, "To be filled by O.E.M.")]), None, "placeholders are dropped");
    }

    #[test]
    fn device_secret_matches_its_definition() {
        // HKDF-SHA256(salt "licensekit device key v1", ikm "disk\0SN1234\0os\0<id>\0", info "p").
        let got = device_secret(b"p", vec![raw(Kind::Os, "0f9e8d7c6b5a49382716051423324150"), raw(Kind::Disk, "SN1234")]).unwrap();
        let mut ikm = Vec::new();
        for (k, v) in [("disk", "SN1234"), ("os", "0f9e8d7c6b5a49382716051423324150")] {
            ikm.extend_from_slice(k.as_bytes());
            ikm.push(0);
            ikm.extend_from_slice(v.as_bytes());
            ikm.push(0);
        }
        let mut want = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(Some(b"licensekit device key v1"), &ikm).expand(b"p", &mut want).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn different_products_get_unrelated_hashes() {
        let a = hash_all(b"product-a", vec![raw(Kind::Disk, "SN123456")]);
        let b = hash_all(b"product-b", vec![raw(Kind::Disk, "SN123456")]);
        assert_ne!(a[0].hash, b[0].hash);
    }

    #[test]
    fn same_value_as_two_kinds_gives_two_hashes() {
        let out = hash_all(b"k", vec![raw(Kind::Disk, "ABCD1234"), raw(Kind::Board, "ABCD1234")]);
        assert_eq!(out.len(), 2);
        assert_ne!(out[0].hash, out[1].hash);
    }

    #[test]
    fn junk_and_duplicates_are_dropped_and_order_is_stable() {
        let input = vec![
            raw(Kind::Mac, "3c:22:fb:12:34:56"),
            raw(Kind::Board, "Default string"),
            raw(Kind::Disk, "S4EWNX0R123456"),
            raw(Kind::Mac, "3C-22-FB-12-34-56"),
            raw(Kind::Mac, "02:42:ac:11:00:02"),
        ];
        let mut reversed = input.clone();
        reversed.reverse();
        let out = hash_all(b"k", input);
        assert_eq!(out.iter().map(|c| c.kind).collect::<Vec<_>>(), vec![Kind::Disk, Kind::Mac]);
        assert_eq!(out, hash_all(b"k", reversed));
    }
}
