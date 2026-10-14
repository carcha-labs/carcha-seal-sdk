//! Turns a value as read into the form that is hashed, or drops it when it
//! identifies nothing.

use crate::Kind;

/// Placeholder strings firmware vendors leave in SMBIOS and disk fields.
/// Compared after trimming and uppercasing.
const PLACEHOLDERS: &[&str] = &[
    "TO BE FILLED BY O.E.M.",
    "TO BE FILLED BY OEM",
    "DEFAULT STRING",
    "SYSTEM SERIAL NUMBER",
    "SYSTEM PRODUCT NAME",
    "BASE BOARD SERIAL NUMBER",
    "CHASSIS SERIAL NUMBER",
    "NOT SPECIFIED",
    "NOT APPLICABLE",
    "NOT AVAILABLE",
    "N/A",
    "NONE",
    "NULL",
    "UNKNOWN",
    "INVALID",
    "OEM",
    "O.E.M.",
    "SERIAL",
    "0123456789",
    "123456789",
    "1234567890",
];

/// Returns the value to hash, or `None` when it must be dropped.
pub(crate) fn normalize(kind: Kind, value: &str) -> Option<String> {
    match kind {
        Kind::Mac => mac(value),
        Kind::Uuid => uuid(value),
        Kind::Os => os_id(value),
        Kind::Board | Kind::Disk => serial(value),
        Kind::Cpu | Kind::Gpu => model(value),
    }
}

/// Collapses runs of whitespace, trims, uppercases.
fn clean(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

/// True when every character is the same one (all '0', all 'F', all ' ', …),
/// ignoring separators.
fn one_repeated_char(value: &str) -> bool {
    let mut chars = value.chars().filter(|c| !matches!(c, '-' | ':' | ' ' | '.'));
    match chars.next() {
        None => true,
        Some(first) => chars.all(|c| c == first),
    }
}

fn serial(value: &str) -> Option<String> {
    let v = clean(value);
    if v.len() < 4 || one_repeated_char(&v) || PLACEHOLDERS.contains(&v.as_str()) {
        return None;
    }
    Some(v)
}

fn model(value: &str) -> Option<String> {
    let v = clean(value);
    if v.is_empty() || PLACEHOLDERS.contains(&v.as_str()) {
        return None;
    }
    Some(v)
}

/// SMBIOS UUID. All 0x00 or all 0xFF means "not set" (DMTF DSP0134).
fn uuid(value: &str) -> Option<String> {
    let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 || one_repeated_char(&hex.to_uppercase()) {
        return None;
    }
    Some(hex.to_uppercase())
}

/// OS install id (machine-id is 32 lowercase hex; MachineGuid is a GUID).
fn os_id(value: &str) -> Option<String> {
    let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 || one_repeated_char(&hex.to_uppercase()) {
        return None;
    }
    Some(hex.to_lowercase())
}

/// Factory MAC address. Dropped when it is all-zero, broadcast, multicast or
/// locally administered (bit 0x02 of the first octet, which is how randomized
/// and virtual addresses are marked under IEEE 802).
fn mac(value: &str) -> Option<String> {
    let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let first = u8::from_str_radix(&hex[0..2], 16).ok()?;
    if first & 0x02 != 0 || first & 0x01 != 0 || one_repeated_char(&hex.to_uppercase()) {
        return None;
    }
    let lower = hex.to_lowercase();
    let octets: Vec<&str> = (0..6).map(|i| &lower[i * 2..i * 2 + 2]).collect();
    Some(octets.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_and_repeated_values_are_dropped() {
        for v in ["", "   ", "To be filled by O.E.M.", "Default string", "0000000000", "FFFFFFFF", "0123456789", "None"] {
            assert_eq!(normalize(Kind::Board, v), None, "{v:?}");
        }
        assert_eq!(normalize(Kind::Board, "  pf3abc12 \n"), Some("PF3ABC12".into()));
    }

    #[test]
    fn unset_uuids_are_dropped() {
        assert_eq!(normalize(Kind::Uuid, "00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(normalize(Kind::Uuid, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), None);
        assert_eq!(normalize(Kind::Uuid, "1234"), None);
        assert_eq!(
            normalize(Kind::Uuid, "4c4c4544-0042-3510-8051-b4c04f4e3332"),
            Some("4C4C4544004235108051B4C04F4E3332".into())
        );
    }

    #[test]
    fn randomized_and_special_macs_are_dropped() {
        assert_eq!(normalize(Kind::Mac, "00:00:00:00:00:00"), None);
        assert_eq!(normalize(Kind::Mac, "ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize(Kind::Mac, "02:42:ac:11:00:02"), None, "locally administered (Docker)");
        assert_eq!(normalize(Kind::Mac, "da:a1:19:00:00:01"), None, "locally administered (randomized)");
        assert_eq!(normalize(Kind::Mac, "01:00:5e:00:00:01"), None, "multicast");
        assert_eq!(normalize(Kind::Mac, "3C-22-FB-12-34-56"), Some("3c:22:fb:12:34:56".into()));
    }

    #[test]
    fn os_ids_are_32_hex_digits() {
        assert_eq!(normalize(Kind::Os, "0123456789abcdef0123456789abcdef\n"), Some("0123456789abcdef0123456789abcdef".into()));
        assert_eq!(normalize(Kind::Os, "uninitialized"), None);
        assert_eq!(normalize(Kind::Os, "00000000000000000000000000000000"), None);
    }
}
