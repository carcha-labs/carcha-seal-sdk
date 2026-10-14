//! x86_64 CPUID helpers shared by the Linux and Windows readers.
//!
//! Hypervisor detection follows Microsoft's Hypervisor Top-Level
//! Functional Specification (feature discovery):
//! - leaf 1, ECX bit 31: a hypervisor is present;
//! - leaf 0x40000000: vendor signature ("Microsoft Hv" for Hyper-V);
//! - leaf 0x40000003: the partition privilege mask, EAX = bits 0-31,
//!   EBX = bits 32-63. Bit 32 is CreatePartitions, which only the root
//!   (parent) partition has: "A root partition creates child partitions
//!   using the hypercall API" (Hyper-V architecture).
//!
//! Windows 11 with virtualization-based security runs on the hypervisor even
//! on a physical PC, as the root partition, so "hypervisor present" alone
//! would call every such PC a VM. The root partition is not a guest.

#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    // SAFETY: CPUID exists on every x86_64 CPU. (`__cpuid` is a safe fn on
    // newer toolchains, hence the allow.)
    #[allow(unused_unsafe)]
    let r = unsafe { std::arch::x86_64::__cpuid(leaf) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// True when running as a guest of a hypervisor (not as Hyper-V's root).
#[cfg(target_arch = "x86_64")]
pub(crate) fn in_guest() -> bool {
    let (_, _, ecx, _) = cpuid(1);
    if ecx & (1 << 31) == 0 {
        return false;
    }
    let (max_leaf, b, c, d) = cpuid(0x4000_0000);
    let vendor: Vec<u8> = [b, c, d].iter().flat_map(|r| r.to_le_bytes()).collect();
    if vendor == *b"Microsoft Hv" && max_leaf >= 0x4000_0003 {
        let (_, privileges_high, _, _) = cpuid(0x4000_0003);
        let create_partitions = privileges_high & 1 != 0; // bit 32 of the mask
        return !create_partitions;
    }
    true
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn in_guest() -> bool {
    false
}

/// Processor brand string, CPUID leaves 0x80000002-0x80000004.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn brand_string() -> Option<String> {
    let (max_ext, _, _, _) = cpuid(0x8000_0000);
    if max_ext < 0x8000_0004 {
        return None;
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004u32 {
        let (a, b, c, d) = cpuid(leaf);
        for r in [a, b, c, d] {
            bytes.extend_from_slice(&r.to_le_bytes());
        }
    }
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}
