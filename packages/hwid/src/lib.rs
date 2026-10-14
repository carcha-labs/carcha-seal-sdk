//! Reads a machine's hardware components and returns one keyed hash per
//! component. Raw serials never leave this library: each value is hashed with
//! HMAC-SHA256 under a product key, so two products see unrelated hashes for
//! the same machine (as systemd's `sd_id128_get_machine_app_specific` does).
//!
//! The matching rule (how many components must still match) lives on the
//! license server; this library only collects.

#[cfg(any(target_os = "linux", windows))]
mod cpuid;
mod ffi;
mod hash;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
mod normalize;
#[cfg(any(target_os = "linux", windows, test))]
mod vm;
#[cfg(any(windows, test))]
mod windows;

pub use ffi::*;

/// What a component is. The server weighs components by kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// SMBIOS system UUID (Windows, macOS IOPlatformUUID).
    Uuid,
    /// Motherboard / system serial number.
    Board,
    /// Serial of an internal disk.
    Disk,
    /// Factory (permanent) MAC address of a built-in network adapter.
    Mac,
    /// OS installation id (Linux machine-id, Windows MachineGuid).
    Os,
    /// CPU model. Shared by every CPU of the same model.
    Cpu,
    /// Graphics adapter model (PCI vendor:device). Shared by the same model.
    Gpu,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Uuid => "uuid",
            Kind::Board => "board",
            Kind::Disk => "disk",
            Kind::Mac => "mac",
            Kind::Os => "os",
            Kind::Cpu => "cpu",
            Kind::Gpu => "gpu",
        }
    }
}

/// One component value as read, before hashing. Never leaves the library.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Raw {
    pub kind: Kind,
    pub value: String,
}

/// What a platform reader returns: raw values, the VM flag, and why kinds
/// are missing (failing call + error code, never a value).
pub(crate) struct Reading {
    pub raws: Vec<Raw>,
    pub vm: bool,
    pub notes: Vec<String>,
}

/// One hashed component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub kind: Kind,
    /// Lowercase hex HMAC-SHA256.
    pub hash: String,
}

/// Result of a collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collected {
    pub components: Vec<Component>,
    /// True when a hypervisor was detected. Best effort; the server catches
    /// clones by seeing the same component set under two activations.
    pub vm: bool,
}

/// Reads this machine's components and hashes each with `key`.
///
/// Values that identify nothing (empty, all-zero, OEM placeholders,
/// randomized MACs) are dropped before hashing, so a placeholder can never
/// make two machines look alike.
pub fn collect(key: &[u8]) -> Collected {
    collect_with_notes(key).0
}

/// Like [`collect`], plus notes on why kinds are missing: the failing call
/// and its error code, or that a value was read but dropped as junk. Notes
/// never contain a value; they are for diagnostics tools such as the probe.
pub fn collect_with_notes(key: &[u8]) -> (Collected, Vec<String>) {
    let Reading { raws, vm, mut notes } = read_platform();
    for r in &raws {
        if normalize::normalize(r.kind, &r.value).is_none() {
            notes.push(format!("{}: value read but dropped (empty, placeholder or randomized)", r.kind.as_str()));
        }
    }
    (Collected { components: hash::hash_all(key, raws), vm }, notes)
}

#[cfg(target_os = "linux")]
fn read_platform() -> Reading {
    let (raws, vm) = linux::read(&linux::Fs::system());
    Reading { raws, vm, notes: Vec::new() }
}

#[cfg(target_os = "macos")]
fn read_platform() -> Reading {
    let (raws, vm) = macos::read(&macos::iokit::IoKit);
    Reading { raws, vm, notes: Vec::new() }
}

#[cfg(windows)]
fn read_platform() -> Reading {
    windows::read(&windows::win32::Win32)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_platform() -> Reading {
    Reading { raws: Vec::new(), vm: false, notes: Vec::new() }
}
