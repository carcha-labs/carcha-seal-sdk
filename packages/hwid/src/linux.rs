//! Linux reader. Everything here is readable by a normal user.
//!
//! The SMBIOS system UUID and board/system serials (`/sys/class/dmi/id/
//! product_uuid`, `board_serial`, `product_serial`) are root-only, so they are
//! not read: reading them only when the app happens to run as root would give
//! the same machine two different component sets.

use std::fs;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use crate::{Kind, Raw};

/// File-system root, so tests can point the reader at a fake `/sys` tree.
pub(crate) struct Fs {
    root: PathBuf,
}

impl Fs {
    pub(crate) fn system() -> Self {
        Fs { root: PathBuf::from("/") }
    }

    #[cfg(test)]
    pub(crate) fn at(root: &Path) -> Self {
        Fs { root: root.to_path_buf() }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn read(&self, p: &str) -> Option<String> {
        fs::read_to_string(self.path(p)).ok().map(|s| s.trim().to_string())
    }

    fn exists(&self, p: &str) -> bool {
        self.path(p).exists()
    }

    /// Entry names in a directory, sorted.
    fn list(&self, p: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.path(p))
            .map(|rd| rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Last path segment of a symlink's target.
    fn link_name(&self, p: &str) -> Option<String> {
        let target = fs::read_link(self.path(p)).ok()?;
        Some(target.file_name()?.to_string_lossy().into_owned())
    }
}

pub(crate) fn read(fs: &Fs) -> (Vec<Raw>, bool) {
    let mut out = Vec::new();
    os_id(fs, &mut out);
    macs(fs, &mut out);
    disks(fs, &mut out);
    cpu(fs, &mut out);
    gpus(fs, &mut out);
    (out, is_vm(fs))
}

fn push(out: &mut Vec<Raw>, kind: Kind, value: String) {
    out.push(Raw { kind, value });
}

/// systemd/D-Bus machine id (man 5 machine-id). Follows a cloned image, so the
/// server never counts it as a hardware anchor.
fn os_id(fs: &Fs, out: &mut Vec<Raw>) {
    if let Some(v) = fs.read("/etc/machine-id").or_else(|| fs.read("/var/lib/dbus/machine-id")) {
        push(out, Kind::Os, v);
    }
}

/// Factory MAC of each physical, non-USB network interface.
///
/// Kernel ABI (sysfs-class-net): `addr_assign_type` 0 means the address is
/// permanent; 1 random, 2 stolen, 3 set by the user. Interfaces without a
/// `device` link are virtual (bridges, tunnels, Docker, VPN).
fn macs(fs: &Fs, out: &mut Vec<Raw>) {
    for name in fs.list("/sys/class/net") {
        let base = format!("/sys/class/net/{name}");
        if !fs.exists(&format!("{base}/device")) {
            continue;
        }
        if fs.link_name(&format!("{base}/device/subsystem")).as_deref() == Some("usb") {
            continue;
        }
        if fs.read(&format!("{base}/addr_assign_type")).as_deref() != Some("0") {
            continue;
        }
        if let Some(addr) = fs.read(&format!("{base}/address")) {
            push(out, Kind::Mac, addr);
        }
    }
}

/// Serial of each NVMe controller on PCIe (kernel ABI sysfs-nvme). Fabrics
/// (`tcp`, `rdma`, `fc`) and USB enclosures are skipped.
fn disks(fs: &Fs, out: &mut Vec<Raw>) {
    for name in fs.list("/sys/class/nvme") {
        let base = format!("/sys/class/nvme/{name}");
        if fs.read(&format!("{base}/transport")).as_deref() != Some("pcie") {
            continue;
        }
        if let Some(serial) = fs.read(&format!("{base}/serial")) {
            push(out, Kind::Disk, serial);
        }
    }
}

/// CPU model from /proc/cpuinfo: `model name` on x86, implementer + part on Arm.
fn cpu(fs: &Fs, out: &mut Vec<Raw>) {
    let Some(info) = fs.read("/proc/cpuinfo") else { return };
    let field = |key: &str| {
        info.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    if let Some(model) = field("model name") {
        push(out, Kind::Cpu, model);
    } else if let (Some(imp), Some(part)) = (field("CPU implementer"), field("CPU part")) {
        push(out, Kind::Cpu, format!("{imp}:{part}"));
    }
}

/// PCI display controllers (class 0x03xxxx) as vendor:device ids.
fn gpus(fs: &Fs, out: &mut Vec<Raw>) {
    for name in fs.list("/sys/bus/pci/devices") {
        let base = format!("/sys/bus/pci/devices/{name}");
        let Some(class) = fs.read(&format!("{base}/class")) else { continue };
        if !class.starts_with("0x03") {
            continue;
        }
        if let (Some(v), Some(d)) = (fs.read(&format!("{base}/vendor")), fs.read(&format!("{base}/device"))) {
            push(out, Kind::Gpu, format!("{}:{}", v.trim_start_matches("0x"), d.trim_start_matches("0x")));
        }
    }
}

/// Best-effort hypervisor detection: CPUID (see `cpuid.rs`), then
/// `/sys/hypervisor/type` and the DMI vendor strings (readable by any user,
/// but changeable by the VM owner, so only supporting evidence).
fn is_vm(fs: &Fs) -> bool {
    if crate::cpuid::in_guest() {
        return true;
    }
    if fs.read("/sys/hypervisor/type").is_some_and(|t| !t.is_empty()) {
        return true;
    }
    let dmi = ["sys_vendor", "product_name", "board_vendor"]
        .iter()
        .filter_map(|f| fs.read(&format!("/sys/class/dmi/id/{f}")))
        .collect::<Vec<_>>()
        .join(" ");
    crate::vm::names_a_hypervisor(&dmi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A throwaway fake root under the system temp dir.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("lk-hwid-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Tree(dir)
        }
        fn file(&self, p: &str, content: &str) -> &Self {
            let path = self.0.join(p.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
            self
        }
        fn dir(&self, p: &str) -> &Self {
            fs::create_dir_all(self.0.join(p.trim_start_matches('/'))).unwrap();
            self
        }
        fn link(&self, p: &str, target: &str) -> &Self {
            let path = self.0.join(p.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(target, path).unwrap();
            self
        }
        fn fs(&self) -> Fs {
            Fs::at(&self.0)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn values(raws: &[Raw], kind: Kind) -> Vec<String> {
        raws.iter().filter(|r| r.kind == kind).map(|r| r.value.clone()).collect()
    }

    #[test]
    fn reads_a_typical_laptop() {
        let t = Tree::new("laptop");
        t.file("/etc/machine-id", "0123456789abcdef0123456789abcdef\n")
            // built-in Ethernet: permanent
            .dir("/sys/class/net/enp3s0/device")
            .file("/sys/class/net/enp3s0/addr_assign_type", "0\n")
            .file("/sys/class/net/enp3s0/address", "3c:22:fb:12:34:56\n")
            // Wi-Fi with a randomized address: skipped
            .dir("/sys/class/net/wlp2s0/device")
            .file("/sys/class/net/wlp2s0/addr_assign_type", "1\n")
            .file("/sys/class/net/wlp2s0/address", "da:a1:19:00:00:01\n")
            // USB dongle: skipped
            .dir("/sys/class/net/enx001122/device")
            .link("/sys/class/net/enx001122/device/subsystem", "../../../../bus/usb")
            .file("/sys/class/net/enx001122/addr_assign_type", "0\n")
            .file("/sys/class/net/enx001122/address", "00:11:22:33:44:55\n")
            // Docker bridge: no device link, skipped
            .file("/sys/class/net/docker0/addr_assign_type", "3\n")
            .file("/sys/class/net/docker0/address", "02:42:ac:11:00:01\n")
            .file("/sys/class/nvme/nvme0/transport", "pcie\n")
            .file("/sys/class/nvme/nvme0/serial", "S4EWNX0R123456      \n")
            .file("/sys/class/nvme/nvme1/transport", "tcp\n")
            .file("/sys/class/nvme/nvme1/serial", "REMOTE-TARGET-1\n")
            .file("/proc/cpuinfo", "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i7-1165G7 @ 2.80GHz\n")
            .file("/sys/bus/pci/devices/0000:00:02.0/class", "0x030000\n")
            .file("/sys/bus/pci/devices/0000:00:02.0/vendor", "0x8086\n")
            .file("/sys/bus/pci/devices/0000:00:02.0/device", "0x9a49\n")
            .file("/sys/bus/pci/devices/0000:00:14.0/class", "0x0c0330\n")
            .file("/sys/bus/pci/devices/0000:00:14.0/vendor", "0x8086\n")
            .file("/sys/bus/pci/devices/0000:00:14.0/device", "0xa0ed\n")
            .file("/sys/class/dmi/id/sys_vendor", "LENOVO\n");

        let (raws, _vm) = read(&t.fs());
        assert_eq!(values(&raws, Kind::Os), vec!["0123456789abcdef0123456789abcdef"]);
        assert_eq!(values(&raws, Kind::Mac), vec!["3c:22:fb:12:34:56"]);
        assert_eq!(values(&raws, Kind::Disk), vec!["S4EWNX0R123456"]);
        assert_eq!(values(&raws, Kind::Cpu), vec!["Intel(R) Core(TM) i7-1165G7 @ 2.80GHz"]);
        assert_eq!(values(&raws, Kind::Gpu), vec!["8086:9a49"]);
        assert!(values(&raws, Kind::Uuid).is_empty() && values(&raws, Kind::Board).is_empty());
    }

    #[test]
    fn arm_cpu_uses_implementer_and_part() {
        let t = Tree::new("arm");
        t.file("/proc/cpuinfo", "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n");
        let (raws, _) = read(&t.fs());
        assert_eq!(values(&raws, Kind::Cpu), vec!["0x41:0xd0c"]);
    }

    #[test]
    fn machine_id_falls_back_to_dbus() {
        let t = Tree::new("dbus");
        t.file("/var/lib/dbus/machine-id", "fedcba9876543210fedcba9876543210\n");
        let (raws, _) = read(&t.fs());
        assert_eq!(values(&raws, Kind::Os), vec!["fedcba9876543210fedcba9876543210"]);
    }

    #[test]
    fn dmi_vendor_and_hypervisor_type_mark_a_vm() {
        let t = Tree::new("vm-dmi");
        t.file("/sys/class/dmi/id/sys_vendor", "QEMU\n");
        assert!(is_vm(&t.fs()));
        let t = Tree::new("vm-xen");
        t.file("/sys/hypervisor/type", "xen\n");
        assert!(is_vm(&t.fs()));
    }

    #[test]
    fn an_empty_system_reads_nothing() {
        let t = Tree::new("empty");
        let (raws, _) = read(&t.fs());
        assert!(raws.is_empty());
    }
}
