//! Reads the real machine the tests run on. Only checks which kinds are
//! found, never values, so it holds on any machine of that OS.

use licensekit_hwid::{Kind, collect};

fn kinds() -> Vec<Kind> {
    collect(b"licensekit-test").components.iter().map(|c| c.kind).collect()
}

#[test]
fn hashes_are_64_hex_and_stable() {
    let a = collect(b"licensekit-test");
    let b = collect(b"licensekit-test");
    assert_eq!(a, b, "two reads of the same machine must agree");
    for c in &a.components {
        assert_eq!(c.hash.len(), 64);
        assert!(c.hash.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_reads_the_os_id_and_cpu() {
    let k = kinds();
    assert!(k.contains(&Kind::Os) && k.contains(&Kind::Cpu), "{k:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_reads_the_platform_uuid_and_cpu() {
    let k = kinds();
    assert!(k.contains(&Kind::Uuid) && k.contains(&Kind::Cpu), "{k:?}");
}

#[cfg(windows)]
#[test]
fn windows_reads_the_smbios_uuid_os_id_and_cpu() {
    let k = kinds();
    assert!(k.contains(&Kind::Uuid) && k.contains(&Kind::Os) && k.contains(&Kind::Cpu), "{k:?}");
}
