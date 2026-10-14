//! Firmware vendor / product strings that name a hypervisor. They are only
//! supporting evidence: a VM owner can change them (VirtualBox manual,
//! "Configuring the BIOS DMI information").

const NAMES: &[&str] = &[
    "VMWARE",
    "QEMU",
    "VIRTUALBOX",
    "INNOTEK",
    "XEN",
    "KVM",
    "VIRTUAL MACHINE", // Hyper-V guests: "Microsoft Corporation" / "Virtual Machine"
    "PARALLELS",
    "BOCHS",
    "AMAZON EC2",
    "GOOGLE COMPUTE ENGINE",
];

pub(crate) fn names_a_hypervisor(strings: &str) -> bool {
    let upper = strings.to_uppercase();
    NAMES.iter().any(|n| upper.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hypervisors_are_named() {
        assert!(names_a_hypervisor("QEMU Standard PC (Q35 + ICH9, 2009)"));
        assert!(names_a_hypervisor("Microsoft Corporation Virtual Machine"));
        assert!(names_a_hypervisor("VMware, Inc. VMware20,1"));
        assert!(!names_a_hypervisor("LENOVO 20XW"));
        assert!(!names_a_hypervisor("Microsoft Corporation Surface Laptop 5"));
    }
}
