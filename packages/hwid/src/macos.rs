//! macOS reader. Every value comes from the I/O Registry or sysctl, readable
//! by a normal user.
//!
//! - `uuid`: `IOPlatformUUID` of `IOPlatformExpertDevice` (xnu IOKitKeys.h).
//! - `board`: `IOPlatformSerialNumber` of the same node (Apple TN1103). Apple
//!   warns it can be lost after a repair; it is then simply missing.
//! - `mac`: `IOMACAddress` of the built-in `en0`, else built-in `en1`, else
//!   `en0` — the lookup Apple's receipt validation sample uses.
//! - `cpu`: `machdep.cpu.brand_string`.
//! - VM: `kern.hv_vmm_present` ("running on a vmm", xnu hvg_sysctl.c).
//!
//! Internal disk serial and GPU are not read: Apple documents no property for
//! them, and on Apple silicon the disk sits on the logic board with the UUID
//! and serial anyway.

use crate::{Kind, Raw};

/// What the reader needs from the system. The real one is IOKit + sysctl
/// (`iokit.rs`); tests use a fake, so this logic is tested on every OS.
pub(crate) trait Source {
    fn platform_uuid(&self) -> Option<String>;
    fn platform_serial(&self) -> Option<String>;
    /// IOMACAddress bytes of the BSD interface `name`, if it exists and its
    /// `IOBuiltin` flag equals `built_in`.
    fn mac_address(&self, name: &str, built_in: bool) -> Option<Vec<u8>>;
    fn sysctl_string(&self, name: &str) -> Option<String>;
    fn sysctl_int(&self, name: &str) -> Option<i64>;
}

pub(crate) fn read(src: &impl Source) -> (Vec<Raw>, bool) {
    let mut out = Vec::new();
    if let Some(v) = src.platform_uuid() {
        out.push(Raw { kind: Kind::Uuid, value: v });
    }
    if let Some(v) = src.platform_serial() {
        out.push(Raw { kind: Kind::Board, value: v });
    }
    let mac = src
        .mac_address("en0", true)
        .or_else(|| src.mac_address("en1", true))
        .or_else(|| src.mac_address("en0", false));
    if let Some(bytes) = mac {
        let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        out.push(Raw { kind: Kind::Mac, value: hex.join(":") });
    }
    if let Some(v) = src.sysctl_string("machdep.cpu.brand_string") {
        out.push(Raw { kind: Kind::Cpu, value: v });
    }
    let vm = src.sysctl_int("kern.hv_vmm_present") == Some(1);
    (out, vm)
}

#[cfg(target_os = "macos")]
pub(crate) mod iokit;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        uuid: Option<String>,
        serial: Option<String>,
        macs: HashMap<(&'static str, bool), Vec<u8>>,
        strings: HashMap<&'static str, String>,
        ints: HashMap<&'static str, i64>,
    }

    impl Source for Fake {
        fn platform_uuid(&self) -> Option<String> {
            self.uuid.clone()
        }
        fn platform_serial(&self) -> Option<String> {
            self.serial.clone()
        }
        fn mac_address(&self, name: &str, built_in: bool) -> Option<Vec<u8>> {
            self.macs.iter().find(|((n, b), _)| *n == name && *b == built_in).map(|(_, v)| v.clone())
        }
        fn sysctl_string(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }
        fn sysctl_int(&self, name: &str) -> Option<i64> {
            self.ints.get(name).copied()
        }
    }

    fn values(raws: &[Raw], kind: Kind) -> Vec<String> {
        raws.iter().filter(|r| r.kind == kind).map(|r| r.value.clone()).collect()
    }

    #[test]
    fn reads_an_apple_silicon_mac() {
        let mut f = Fake {
            uuid: Some("4C4C4544-0042-3510-8051-B4C04F4E3332".into()),
            serial: Some("C02XK0AAJGH5".into()),
            ..Default::default()
        };
        f.macs.insert(("en0", true), vec![0x3c, 0x22, 0xfb, 0x12, 0x34, 0x56]);
        f.strings.insert("machdep.cpu.brand_string", "Apple M2".into());
        f.ints.insert("kern.hv_vmm_present", 0);

        let (raws, vm) = read(&f);
        assert_eq!(values(&raws, Kind::Uuid), vec!["4C4C4544-0042-3510-8051-B4C04F4E3332"]);
        assert_eq!(values(&raws, Kind::Board), vec!["C02XK0AAJGH5"]);
        assert_eq!(values(&raws, Kind::Mac), vec!["3c:22:fb:12:34:56"]);
        assert_eq!(values(&raws, Kind::Cpu), vec!["Apple M2"]);
        assert!(!vm);
    }

    #[test]
    fn mac_prefers_built_in_en0_then_built_in_en1_then_any_en0() {
        let mut f = Fake::default();
        f.macs.insert(("en0", false), vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.macs.insert(("en1", true), vec![0x3c, 0x22, 0xfb, 0x00, 0x00, 0x01]);
        assert_eq!(values(&read(&f).0, Kind::Mac), vec!["3c:22:fb:00:00:01"]);

        f.macs.insert(("en0", true), vec![0x3c, 0x22, 0xfb, 0x00, 0x00, 0x02]);
        assert_eq!(values(&read(&f).0, Kind::Mac), vec!["3c:22:fb:00:00:02"]);

        let mut only_external = Fake::default();
        only_external.macs.insert(("en0", false), vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(values(&read(&only_external).0, Kind::Mac), vec!["00:11:22:33:44:55"]);
    }

    #[test]
    fn hypervisor_flag_marks_a_vm() {
        let mut f = Fake::default();
        f.ints.insert("kern.hv_vmm_present", 1);
        assert!(read(&f).1);
    }

    #[test]
    fn a_mac_that_lost_its_serial_still_reads_the_rest() {
        let f = Fake { uuid: Some("4C4C4544-0042-3510-8051-B4C04F4E3332".into()), ..Default::default() };
        let (raws, _) = read(&f);
        assert_eq!(raws.len(), 1);
        assert!(values(&raws, Kind::Board).is_empty());
    }
}
