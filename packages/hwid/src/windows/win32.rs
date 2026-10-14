//! The real Windows source: Win32 through Microsoft's `windows-sys` crate.

use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_PRESENT, GUID_DEVCLASS_DISPLAY, SP_DEVINFO_DATA, SPDRP_HARDWAREID, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_NUMBER, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, GetSystemWindowsDirectoryW, RSMB};

use super::{Adapter, Source};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A device handle, closed on drop.
struct Handle(HANDLE);

impl Handle {
    /// Opens a device with no access rights: enough to query attributes.
    fn open_device(path: &str) -> Result<Handle, String> {
        let p = wide(path);
        // SAFETY: valid NUL-terminated path; all other arguments are plain values.
        let h = unsafe {
            CreateFileW(p.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut())
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(format!("opening {path} failed, {}", last_error()));
        }
        Ok(Handle(h))
    }

    /// DeviceIoControl into `out`; returns the bytes written.
    fn ioctl(&self, code: u32, name: &str, input: &[u8], out: &mut [u8]) -> Result<usize, String> {
        let mut returned = 0u32;
        // SAFETY: the buffers are valid for the lengths passed.
        let ok = unsafe {
            DeviceIoControl(
                self.0,
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("{name} failed, {}", last_error()));
        }
        Ok(returned as usize)
    }
}

/// "error N" from GetLastError, for diagnostics (no values, only the code).
fn last_error() -> String {
    // SAFETY: reads the calling thread's last-error value.
    format!("error {}", unsafe { GetLastError() })
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn as_bytes<T>(v: &T) -> &[u8] {
    // SAFETY: plain-old-data structs from windows-sys, read as bytes.
    unsafe { std::slice::from_raw_parts((v as *const T).cast(), size_of::<T>()) }
}

fn registry_string(subkey: &str, value: &str) -> Option<String> {
    let (subkey, value) = (wide(subkey), wide(value));
    let mut buf = [0u16; 256];
    let mut bytes = (buf.len() * 2) as u32;
    // SAFETY: buffer of `bytes` bytes; RRF_RT_REG_SZ guarantees a terminated string.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let chars = (bytes as usize / 2).min(buf.len());
    let end = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
    String::from_utf16(&buf[..end]).ok()
}

pub(crate) struct Win32;

impl Source for Win32 {
    fn smbios(&self) -> Result<Vec<u8>, String> {
        // SAFETY: first call asks for the size, second fills a buffer of it.
        unsafe {
            let size = GetSystemFirmwareTable(RSMB, 0, null_mut(), 0);
            if size == 0 {
                return Err(format!("GetSystemFirmwareTable('RSMB') failed, {}", last_error()));
            }
            let mut buf = vec![0u8; size as usize];
            let got = GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), size);
            if got == 0 || got > size {
                return Err(format!("GetSystemFirmwareTable('RSMB') returned {got} of {size} bytes, {}", last_error()));
            }
            buf.truncate(got as usize);
            Ok(buf)
        }
    }

    fn system_disk_serial(&self) -> Result<String, String> {
        // The volume holding the Windows directory, e.g. "C:".
        let mut dir = [0u16; 260];
        // SAFETY: buffer of 260 UTF-16 units.
        let n = unsafe { GetSystemWindowsDirectoryW(dir.as_mut_ptr(), dir.len() as u32) } as usize;
        if n < 2 || n >= dir.len() || dir[1] != u16::from(b':') {
            return Err(format!("GetSystemWindowsDirectoryW gave no drive letter, {}", last_error()));
        }
        let drive = char::from_u32(u32::from(dir[0])).ok_or("Windows directory has no drive letter")?;
        let volume = Handle::open_device(&format!("\\\\.\\{drive}:"))?;

        let mut number = [0u8; size_of::<STORAGE_DEVICE_NUMBER>()];
        let got = volume.ioctl(IOCTL_STORAGE_GET_DEVICE_NUMBER, "IOCTL_STORAGE_GET_DEVICE_NUMBER", &[], &mut number)?;
        if got < number.len() {
            return Err(format!("IOCTL_STORAGE_GET_DEVICE_NUMBER returned {got} bytes"));
        }
        // SAFETY: the buffer holds a full STORAGE_DEVICE_NUMBER.
        let number: STORAGE_DEVICE_NUMBER = unsafe { std::ptr::read_unaligned(number.as_ptr().cast()) };
        let disk = Handle::open_device(&format!("\\\\.\\PhysicalDrive{}", number.DeviceNumber))?;

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        const QUERY: &str = "IOCTL_STORAGE_QUERY_PROPERTY";
        let mut buf = vec![0u8; 1024];
        let mut returned = disk.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, QUERY, as_bytes(&query), &mut buf)?;
        if returned < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            return Err(format!("{QUERY} returned {returned} bytes"));
        }
        // SAFETY: at least one full descriptor header was returned.
        let mut desc: STORAGE_DEVICE_DESCRIPTOR = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        if desc.Size as usize > buf.len() {
            buf = vec![0u8; desc.Size as usize];
            returned = disk.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, QUERY, as_bytes(&query), &mut buf)?;
            // SAFETY: as above.
            desc = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        }
        let offset = desc.SerialNumberOffset as usize;
        if offset == 0 || offset >= returned {
            return Err(format!("PhysicalDrive{} reports no serial number (bus type {})", number.DeviceNumber, desc.BusType));
        }
        let bytes = &buf[offset..returned];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let serial = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
        if serial.is_empty() {
            return Err(format!("PhysicalDrive{} reports an empty serial number (bus type {})", number.DeviceNumber, desc.BusType));
        }
        Ok(serial)
    }

    fn adapters(&self) -> Vec<Adapter> {
        let mut table: *mut MIB_IF_TABLE2 = null_mut();
        // SAFETY: GetIfTable2 allocates the table; we free it with FreeMibTable.
        if unsafe { GetIfTable2(&mut table) } != NO_ERROR || table.is_null() {
            return Vec::new();
        }
        // SAFETY: the table holds NumEntries rows starting at `Table`.
        let rows: &[MIB_IF_ROW2] = unsafe {
            let n = (*table).NumEntries as usize;
            std::slice::from_raw_parts(std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(), n)
        };
        let out = rows
            .iter()
            .map(|r| {
                // MIB_IF_ROW2 InterfaceAndOperStatusFlags, in declaration order:
                // HardwareInterface, FilterInterface, ConnectorPresent, ...
                let flags = r.InterfaceAndOperStatusFlags._bitfield;
                let len = (r.PhysicalAddressLength as usize).min(r.PermanentPhysicalAddress.len());
                Adapter {
                    hardware: flags & 0b001 != 0,
                    filter: flags & 0b010 != 0,
                    connector: flags & 0b100 != 0,
                    if_type: r.Type,
                    permanent: r.PermanentPhysicalAddress[..len].to_vec(),
                }
            })
            .collect();
        // SAFETY: allocated by GetIfTable2; `rows` is not used after this.
        unsafe { FreeMibTable(table as *const core::ffi::c_void) };
        out
    }

    fn machine_guid(&self) -> Option<String> {
        registry_string("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid")
    }

    fn cpu_name(&self) -> Option<String> {
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(name) = crate::cpuid::brand_string() {
                return Some(name);
            }
        }
        registry_string("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString")
    }

    fn display_hardware_ids(&self) -> Vec<String> {
        let mut out = Vec::new();
        // SAFETY: SetupAPI enumeration; the set is destroyed at the end and
        // every buffer passed is valid for the size given.
        unsafe {
            let set = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, null(), null_mut(), DIGCF_PRESENT);
            if set == INVALID_HANDLE_VALUE as isize {
                return out;
            }
            let mut index = 0;
            loop {
                let mut data = SP_DEVINFO_DATA { cbSize: size_of::<SP_DEVINFO_DATA>() as u32, ..Default::default() };
                if SetupDiEnumDeviceInfo(set, index, &mut data) == 0 {
                    break;
                }
                index += 1;
                let mut buf = [0u8; 2048];
                let mut required = 0u32;
                if SetupDiGetDeviceRegistryPropertyW(
                    set,
                    &data,
                    SPDRP_HARDWAREID,
                    null_mut(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut required,
                ) == 0
                {
                    continue;
                }
                // REG_MULTI_SZ: take the first string.
                let units: Vec<u16> = buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
                if let Ok(id) = String::from_utf16(&units[..end]) {
                    out.push(id);
                }
            }
            SetupDiDestroyDeviceInfoList(set);
        }
        out
    }

    fn in_guest(&self) -> bool {
        crate::cpuid::in_guest()
    }
}
