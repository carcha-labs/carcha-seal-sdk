//! One HMAC-SHA256 per component, keyed by the product.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::normalize::normalize;
use crate::{Component, Raw};

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
    use crate::Kind;

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
