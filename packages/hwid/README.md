# licensekit_hwid

Native core that reads a machine's hardware components and returns one HMAC-SHA256 per component, keyed by the product. Raw serials never leave the library. The license server decides how many components must still match.

One Rust library with a C interface (`include/licensekit_hwid.h`), built as a static library (native apps link it), a shared library (.NET P/Invoke and other loaders) and, later, a Node-API layer for Node.js and Electron.

| Kind | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `uuid` | not readable without root | `IOPlatformUUID` | SMBIOS type 1 UUID via `GetSystemFirmwareTable('RSMB')` |
| `board` | not readable without root | `IOPlatformSerialNumber` | SMBIOS baseboard serial, else system serial |
| `disk` | NVMe serial on PCIe | not read (no documented property; on Apple silicon it is on the logic board) | serial of the disk holding Windows (`IOCTL_STORAGE_QUERY_PROPERTY`); normal-user access to be measured |
| `mac` | permanent MAC of physical, non-USB interfaces | `IOMACAddress` of built-in `en0` / `en1`, as Apple's receipt sample | `PermanentPhysicalAddress` of hardware Ethernet / Wi-Fi (`GetIfTable2`) |
| `os` | `/etc/machine-id` | — | `MachineGuid` |
| `cpu` | model | `machdep.cpu.brand_string` | CPUID brand string (Arm: `ProcessorNameString`) |
| `gpu` | PCI vendor:device | not read | PCI vendor:device of display adapters (SetupAPI) |
| VM flag | CPUID guest check, `/sys/hypervisor`, DMI vendor | `kern.hv_vmm_present` | CPUID guest check (Hyper-V root is not a guest), SMBIOS vendor |

Empty values, all-zero / all-FF values, firmware placeholders ("To be filled by O.E.M.") and locally administered or multicast MACs are dropped before hashing.

```
cargo test                                   # unit tests (fake /sys trees, IOKit, Win32) + a read of this machine
tests/c/run.sh                               # links a C program against the static library
cargo run --release --example probe          # kinds, hashes, read time and why kinds are missing
```
