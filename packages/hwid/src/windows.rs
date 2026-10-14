//! Windows reader. Plain Win32 calls, no WMI (`wmic` is being removed from
//! Windows 11) and no administrator rights expected.
//!
//! - `uuid`, `board`: raw SMBIOS from `GetSystemFirmwareTable('RSMB')`;
//!   System Information (type 1) UUID at 08h and Baseboard (type 2) serial at
//!   07h, falling back to the type 1 serial (DMTF DSP0134 7.2, 7.3).
//! - `disk`: serial of the physical disk holding the Windows directory,
//!   `IOCTL_STORAGE_GET_DEVICE_NUMBER` then `IOCTL_STORAGE_QUERY_PROPERTY`.
//!   Microsoft says direct disk access needs administrator rights; the handle
//!   is opened with no access rights, which CreateFile documents for
//!   querying device attributes. Whether a normal user gets the serial this
//!   way still has to be measured; if not, `disk` is simply missing.
//! - `mac`: `PermanentPhysicalAddress` of hardware Ethernet / Wi-Fi
//!   interfaces with a connector, from `GetIfTable2` (MIB_IF_ROW2).
//! - `os`: `MachineGuid` (64-bit registry view). Not documented by Microsoft.
//! - `cpu`: CPUID brand string on x86_64, `ProcessorNameString` on Arm.
//! - `gpu`: PCI vendor:device of display adapters from SetupAPI.
//! - VM: CPUID (see `cpuid.rs`), then the SMBIOS manufacturer / product.

use crate::normalize::normalize;
use crate::{Kind, Raw, Reading};

/// One network interface as GetIfTable2 reports it.
pub(crate) struct Adapter {
    pub hardware: bool,
    pub filter: bool,
    pub connector: bool,
    /// IANA ifType: 6 Ethernet, 71 IEEE 802.11.
    pub if_type: u32,
    pub permanent: Vec<u8>,
}

/// What the reader needs from the system; `win32.rs` is the real one,
/// tests use a fake.
pub(crate) trait Source {
    /// The whole RawSMBIOSData buffer returned for 'RSMB'. Errors carry the
    /// failing call and its error code, never a value.
    fn smbios(&self) -> Result<Vec<u8>, String>;
    fn system_disk_serial(&self) -> Result<String, String>;
    fn adapters(&self) -> Vec<Adapter>;
    fn machine_guid(&self) -> Option<String>;
    fn cpu_name(&self) -> Option<String>;
    /// First hardware id of each present display adapter, e.g.
    /// `PCI\VEN_10DE&DEV_2484&SUBSYS_...`.
    fn display_hardware_ids(&self) -> Vec<String>;
    fn in_guest(&self) -> bool;
}

pub(crate) fn read(src: &impl Source) -> Reading {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let smbios = match src.smbios() {
        Ok(raw) => parse_smbios(&raw),
        Err(e) => {
            notes.push(format!("uuid, board: {e}"));
            Smbios::default()
        }
    };

    if let Some(v) = &smbios.uuid {
        out.push(Raw { kind: Kind::Uuid, value: v.clone() });
    }
    let board = [&smbios.board_serial, &smbios.system_serial]
        .into_iter()
        .flatten()
        .find(|v| normalize(Kind::Board, v).is_some());
    if let Some(v) = board {
        out.push(Raw { kind: Kind::Board, value: v.clone() });
    }
    match src.system_disk_serial() {
        Ok(v) => out.push(Raw { kind: Kind::Disk, value: v }),
        Err(e) => notes.push(format!("disk: {e}")),
    }
    let adapters = src.adapters();
    let before = out.len();
    for a in &adapters {
        if a.hardware && a.connector && !a.filter && matches!(a.if_type, 6 | 71) && a.permanent.len() == 6 {
            let hex: Vec<String> = a.permanent.iter().map(|b| format!("{b:02x}")).collect();
            out.push(Raw { kind: Kind::Mac, value: hex.join(":") });
        }
    }
    if out.len() == before {
        notes.push(format!("mac: no hardware Ethernet / Wi-Fi interface with a permanent address among {} interfaces", adapters.len()));
    }
    match src.machine_guid() {
        Some(v) => out.push(Raw { kind: Kind::Os, value: v }),
        None => notes.push("os: MachineGuid not readable".into()),
    }
    match src.cpu_name() {
        Some(v) => out.push(Raw { kind: Kind::Cpu, value: v }),
        None => notes.push("cpu: no CPU name".into()),
    }
    let ids = src.display_hardware_ids();
    let before = out.len();
    for id in &ids {
        if let Some(v) = pci_vendor_device(id) {
            out.push(Raw { kind: Kind::Gpu, value: v });
        }
    }
    if out.len() == before {
        // Only the bus prefix (PCI, VMBUS, ROOT...), never the full id.
        let buses: Vec<&str> = ids.iter().filter_map(|i| i.split('\\').next()).collect();
        notes.push(format!("gpu: no PCI display adapter (buses seen: {buses:?})"));
    }

    let firmware = format!(
        "{} {}",
        smbios.manufacturer.as_deref().unwrap_or(""),
        smbios.product.as_deref().unwrap_or("")
    );
    let vm = src.in_guest() || crate::vm::names_a_hypervisor(&firmware);
    Reading { raws: out, vm, notes }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Smbios {
    pub uuid: Option<String>,
    pub system_serial: Option<String>,
    pub board_serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

/// Parses the RawSMBIOSData buffer: an 8-byte header (calling method,
/// major, minor, DMI revision, u32 table length), then the structure table.
pub(crate) fn parse_smbios(raw: &[u8]) -> Smbios {
    let mut out = Smbios::default();
    if raw.len() < 8 {
        return out;
    }
    let len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let table = &raw[8..raw.len().min(8 + len)];

    let mut pos = 0;
    while pos + 4 <= table.len() {
        let kind = table[pos];
        let formatted_len = table[pos + 1] as usize;
        if formatted_len < 4 || pos + formatted_len > table.len() {
            break;
        }
        let formatted = &table[pos..pos + formatted_len];
        // Strings follow the formatted area; the set ends with a double NUL.
        let strings_start = pos + formatted_len;
        let mut end = strings_start;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        let strings: Vec<&[u8]> = table[strings_start..end].split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
        let string = |offset: usize| -> Option<String> {
            let index = *formatted.get(offset)? as usize;
            if index == 0 {
                return None;
            }
            let s = String::from_utf8_lossy(strings.get(index - 1)?).trim().to_string();
            (!s.is_empty()).then_some(s)
        };

        match kind {
            1 => {
                out.manufacturer = string(0x04);
                out.product = string(0x05);
                out.system_serial = string(0x07);
                if formatted_len >= 0x18 {
                    out.uuid = Some(smbios_uuid(&formatted[0x08..0x18]));
                }
            }
            2 => out.board_serial = string(0x07),
            127 => break,
            _ => {}
        }
        pos = end + 2;
    }
    out
}

/// SMBIOS 2.6+ stores the first three UUID fields little-endian (DSP0134
/// 7.2.1); print it in the usual text form.
fn smbios_uuid(b: &[u8]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// `PCI\VEN_10DE&DEV_2484&...` → `10de:2484` (the Linux reader's form).
/// Non-PCI adapters (e.g. Microsoft Basic Display) give `None`.
fn pci_vendor_device(id: &str) -> Option<String> {
    let upper = id.to_uppercase();
    let rest = upper.strip_prefix("PCI\\")?;
    let field = |name: &str| {
        rest.split('&')
            .find_map(|p| p.strip_prefix(name))
            .filter(|v| v.len() == 4 && v.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|v| v.to_lowercase())
    };
    Some(format!("{}:{}", field("VEN_")?, field("DEV_")?))
}

#[cfg(windows)]
pub(crate) mod win32;

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one SMBIOS structure: formatted area + strings + double NUL.
    fn structure(kind: u8, formatted_rest: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut s = vec![kind, (4 + formatted_rest.len()) as u8, 0, 0];
        s.extend_from_slice(formatted_rest);
        if strings.is_empty() {
            s.extend_from_slice(&[0, 0]);
        } else {
            for st in strings {
                s.extend_from_slice(st.as_bytes());
                s.push(0);
            }
            s.push(0);
        }
        s
    }

    fn raw_smbios(structures: &[Vec<u8>]) -> Vec<u8> {
        let table: Vec<u8> = structures.concat();
        let mut raw = vec![0, 3, 4, 0];
        raw.extend_from_slice(&(table.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table);
        raw
    }

    fn type1(uuid: [u8; 16], serial_index: u8) -> Vec<u8> {
        // offsets 04h manufacturer=1, 05h product=2, 06h version=0, 07h serial
        let mut rest = vec![1, 2, 0, serial_index];
        rest.extend_from_slice(&uuid);
        rest.extend_from_slice(&[6, 0, 0]); // wake-up type, SKU, family
        rest
    }

    const UUID_BYTES: [u8; 16] = [0x44, 0x45, 0x4c, 0x4c, 0x42, 0x00, 0x10, 0x35, 0x80, 0x51, 0xb4, 0xc0, 0x4f, 0x4e, 0x33, 0x32];

    #[test]
    fn parses_system_and_baseboard() {
        let raw = raw_smbios(&[
            structure(0, &[1, 2, 0, 0], &["American Megatrends", "1.0"]),
            structure(1, &type1(UUID_BYTES, 3), &["LENOVO", "20XW", "PF3ABC12"]),
            structure(2, &[1, 2, 0, 3], &["LENOVO", "20XWCTO1WW", "L1HF2AB0123"]),
            structure(127, &[], &[]),
        ]);
        let s = parse_smbios(&raw);
        assert_eq!(s.uuid.as_deref(), Some("4C4C4544-0042-3510-8051-B4C04F4E3332"));
        assert_eq!(s.system_serial.as_deref(), Some("PF3ABC12"));
        assert_eq!(s.board_serial.as_deref(), Some("L1HF2AB0123"));
        assert_eq!(s.manufacturer.as_deref(), Some("LENOVO"));
        assert_eq!(s.product.as_deref(), Some("20XW"));
    }

    #[test]
    fn truncated_or_empty_tables_do_not_panic() {
        assert_eq!(parse_smbios(&[]), Smbios::default());
        assert_eq!(parse_smbios(&[0, 3, 4, 0, 200, 0, 0, 0, 1, 50]), Smbios::default());
        let mut raw = raw_smbios(&[structure(1, &type1(UUID_BYTES, 3), &["A", "B", "C"])]);
        raw.truncate(raw.len() - 5);
        let _ = parse_smbios(&raw);
    }

    #[test]
    fn pci_ids() {
        assert_eq!(pci_vendor_device("PCI\\VEN_10DE&DEV_2484&SUBSYS_146B10DE&REV_A1").as_deref(), Some("10de:2484"));
        assert_eq!(pci_vendor_device("ROOT\\BasicDisplay"), None);
        assert_eq!(pci_vendor_device("PCI\\VEN_10DE"), None);
    }

    struct Fake {
        smbios: Option<Vec<u8>>,
        disk: Option<String>,
        adapters: Vec<(bool, bool, bool, u32, Vec<u8>)>,
        guest: bool,
    }

    impl Source for Fake {
        fn smbios(&self) -> Result<Vec<u8>, String> {
            self.smbios.clone().ok_or_else(|| "GetSystemFirmwareTable('RSMB') failed, error 1".into())
        }
        fn system_disk_serial(&self) -> Result<String, String> {
            self.disk.clone().ok_or_else(|| "opening \\\\.\\C: failed, error 5".into())
        }
        fn adapters(&self) -> Vec<Adapter> {
            self.adapters
                .iter()
                .map(|(hardware, filter, connector, if_type, permanent)| Adapter {
                    hardware: *hardware,
                    filter: *filter,
                    connector: *connector,
                    if_type: *if_type,
                    permanent: permanent.clone(),
                })
                .collect()
        }
        fn machine_guid(&self) -> Option<String> {
            Some("2d5c1e6a-6f0e-4b8a-9b1e-0c7d3f9a1b2c".into())
        }
        fn cpu_name(&self) -> Option<String> {
            Some("11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz".into())
        }
        fn display_hardware_ids(&self) -> Vec<String> {
            vec!["PCI\\VEN_8086&DEV_9A49&SUBSYS_22D817AA&REV_01".into(), "ROOT\\BasicDisplay".into()]
        }
        fn in_guest(&self) -> bool {
            self.guest
        }
    }

    fn values(raws: &[Raw], kind: Kind) -> Vec<String> {
        raws.iter().filter(|r| r.kind == kind).map(|r| r.value.clone()).collect()
    }

    fn laptop() -> Fake {
        Fake {
            smbios: Some(raw_smbios(&[
                structure(1, &type1(UUID_BYTES, 3), &["LENOVO", "20XW", "PF3ABC12"]),
                structure(2, &[1, 2, 0, 3], &["LENOVO", "20XWCTO1WW", "L1HF2AB0123"]),
            ])),
            disk: Some("S4EWNX0R123456".into()),
            adapters: vec![
                (true, false, true, 6, vec![0x3c, 0x22, 0xfb, 0x12, 0x34, 0x56]), // built-in Ethernet
                (true, true, true, 6, vec![0x3c, 0x22, 0xfb, 0x12, 0x34, 0x56]),  // its filter: skipped
                (false, false, false, 6, vec![0x00, 0x15, 0x5d, 0x00, 0x00, 0x01]), // Hyper-V vEthernet: skipped
                (true, false, true, 24, vec![]),                                  // loopback: skipped
            ],
            guest: false,
        }
    }

    #[test]
    fn reads_a_typical_laptop() {
        let Reading { raws, vm, notes } = read(&laptop());
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(values(&raws, Kind::Uuid), vec!["4C4C4544-0042-3510-8051-B4C04F4E3332"]);
        assert_eq!(values(&raws, Kind::Board), vec!["L1HF2AB0123"]);
        assert_eq!(values(&raws, Kind::Disk), vec!["S4EWNX0R123456"]);
        assert_eq!(values(&raws, Kind::Mac), vec!["3c:22:fb:12:34:56"]);
        assert_eq!(values(&raws, Kind::Os), vec!["2d5c1e6a-6f0e-4b8a-9b1e-0c7d3f9a1b2c"]);
        assert_eq!(values(&raws, Kind::Gpu), vec!["8086:9a49"]);
        assert_eq!(values(&raws, Kind::Cpu).len(), 1);
        assert!(!vm);
    }

    #[test]
    fn placeholder_board_serial_falls_back_to_the_system_serial() {
        let mut f = laptop();
        f.smbios = Some(raw_smbios(&[
            structure(1, &type1(UUID_BYTES, 3), &["LENOVO", "20XW", "PF3ABC12"]),
            structure(2, &[1, 2, 0, 3], &["ASUS", "PRIME", "Default string"]),
        ]));
        assert_eq!(values(&read(&f).raws, Kind::Board), vec!["PF3ABC12"]);
    }

    #[test]
    fn vm_from_cpuid_or_firmware_strings() {
        let mut f = laptop();
        f.guest = true;
        assert!(read(&f).vm);

        let mut f = laptop();
        f.smbios = Some(raw_smbios(&[structure(1, &type1(UUID_BYTES, 3), &["Microsoft Corporation", "Virtual Machine", "0000-0001"])]));
        assert!(read(&f).vm);
    }

    #[test]
    fn missing_disk_and_smbios_still_read_the_rest() {
        let mut f = laptop();
        f.smbios = None;
        f.disk = None;
        let r = read(&f);
        assert!(values(&r.raws, Kind::Uuid).is_empty() && values(&r.raws, Kind::Disk).is_empty());
        assert_eq!(values(&r.raws, Kind::Mac).len(), 1);
        assert_eq!(
            r.notes,
            vec!["uuid, board: GetSystemFirmwareTable('RSMB') failed, error 1", "disk: opening \\\\.\\C: failed, error 5"]
        );
    }
}
