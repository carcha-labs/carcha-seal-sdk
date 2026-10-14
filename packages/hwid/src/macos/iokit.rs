//! The real macOS source: IOKit, CoreFoundation and sysctl, declared by hand
//! (a dozen functions) instead of pulling in binding crates.

use std::ffi::{CString, c_char, c_void};

use super::Source;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFTypeID = usize;
type Boolean = u8;
type MachPort = u32;
type IoObject = u32;
type KernReturn = i32;

const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// kIOMainPortDefault / kIOMasterPortDefault is MACH_PORT_NULL.
const MAIN_PORT_DEFAULT: MachPort = 0;
const KIO_REGISTRY_ITERATE_RECURSIVELY: u32 = 0x1;
const KIO_REGISTRY_ITERATE_PARENTS: u32 = 0x2;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> *mut c_void;
    /// Consumes one reference to `matching`.
    fn IOServiceGetMatchingService(main: MachPort, matching: *mut c_void) -> IoObject;
    fn IOBSDNameMatching(main: MachPort, options: u32, bsd_name: *const c_char) -> *mut c_void;
    /// Consumes one reference to `matching`.
    fn IOServiceGetMatchingServices(main: MachPort, matching: *mut c_void, existing: *mut IoObject) -> KernReturn;
    fn IOIteratorNext(iterator: IoObject) -> IoObject;
    fn IOObjectRelease(object: IoObject) -> KernReturn;
    fn IORegistryEntryCreateCFProperty(entry: IoObject, key: CFTypeRef, allocator: CFTypeRef, options: u32) -> CFTypeRef;
    fn IORegistryEntrySearchCFProperty(
        entry: IoObject,
        plane: *const c_char,
        key: CFTypeRef,
        allocator: CFTypeRef,
        options: u32,
    ) -> CFTypeRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: CFTypeRef, c_str: *const c_char, encoding: u32) -> CFTypeRef;
    fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(s: CFTypeRef, buffer: *mut c_char, size: CFIndex, encoding: u32) -> Boolean;
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFDataGetTypeID() -> CFTypeID;
    fn CFBooleanGetTypeID() -> CFTypeID;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> Boolean;
    fn CFRelease(cf: CFTypeRef);
}

unsafe extern "C" {
    fn sysctlbyname(name: *const c_char, oldp: *mut c_void, oldlenp: *mut usize, newp: *mut c_void, newlen: usize) -> i32;
}

/// An owned CoreFoundation object, released on drop.
struct Cf(CFTypeRef);

impl Cf {
    fn string(s: &str) -> Option<Cf> {
        let c = CString::new(s).ok()?;
        // SAFETY: valid NUL-terminated string; NULL allocator = default.
        let r = unsafe { CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), KCF_STRING_ENCODING_UTF8) };
        (!r.is_null()).then_some(Cf(r))
    }

    fn type_is(&self, id: CFTypeID) -> bool {
        // SAFETY: self.0 is a live CF object.
        unsafe { CFGetTypeID(self.0) == id }
    }

    fn to_string(&self) -> Option<String> {
        // SAFETY: CF calls on a live object, checked to be a CFString; the
        // buffer is sized with CFStringGetMaximumSizeForEncoding + 1.
        unsafe {
            if !self.type_is(CFStringGetTypeID()) {
                return None;
            }
            let max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(self.0), KCF_STRING_ENCODING_UTF8) + 1;
            let mut buf = vec![0u8; usize::try_from(max).ok()?];
            if CFStringGetCString(self.0, buf.as_mut_ptr().cast(), max, KCF_STRING_ENCODING_UTF8) == 0 {
                return None;
            }
            let end = buf.iter().position(|&b| b == 0)?;
            String::from_utf8(buf[..end].to_vec()).ok()
        }
    }

    fn to_bytes(&self) -> Option<Vec<u8>> {
        // SAFETY: checked to be CFData; the pointer is valid for the length
        // while the object lives, and we copy out before drop.
        unsafe {
            if !self.type_is(CFDataGetTypeID()) {
                return None;
            }
            let len = usize::try_from(CFDataGetLength(self.0)).ok()?;
            let ptr = CFDataGetBytePtr(self.0);
            if ptr.is_null() {
                return None;
            }
            Some(std::slice::from_raw_parts(ptr, len).to_vec())
        }
    }

    fn to_bool(&self) -> Option<bool> {
        // SAFETY: checked to be a CFBoolean.
        unsafe { self.type_is(CFBooleanGetTypeID()).then(|| CFBooleanGetValue(self.0) != 0) }
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: we own one reference.
        unsafe { CFRelease(self.0) }
    }
}

/// An owned IOKit object, released on drop.
struct Io(IoObject);

impl Io {
    fn property(&self, key: &str) -> Option<Cf> {
        let key = Cf::string(key)?;
        // SAFETY: live registry entry and key; the result is +1 or NULL.
        let r = unsafe { IORegistryEntryCreateCFProperty(self.0, key.0, std::ptr::null(), 0) };
        (!r.is_null()).then_some(Cf(r))
    }

    /// Searches this entry and its parents in the IOService plane.
    fn search_property(&self, key: &str) -> Option<Cf> {
        let key = Cf::string(key)?;
        let plane = CString::new("IOService").ok()?;
        // SAFETY: as above; the plane name is a valid C string.
        let r = unsafe {
            IORegistryEntrySearchCFProperty(
                self.0,
                plane.as_ptr(),
                key.0,
                std::ptr::null(),
                KIO_REGISTRY_ITERATE_RECURSIVELY | KIO_REGISTRY_ITERATE_PARENTS,
            )
        };
        (!r.is_null()).then_some(Cf(r))
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        // SAFETY: we own one reference.
        unsafe {
            IOObjectRelease(self.0);
        }
    }
}

fn platform_expert() -> Option<Io> {
    let name = CString::new("IOPlatformExpertDevice").ok()?;
    // SAFETY: IOServiceMatching returns a +1 dictionary (or NULL) that
    // IOServiceGetMatchingService consumes.
    let service = unsafe {
        let matching = IOServiceMatching(name.as_ptr());
        if matching.is_null() {
            return None;
        }
        IOServiceGetMatchingService(MAIN_PORT_DEFAULT, matching)
    };
    (service != 0).then_some(Io(service))
}

pub(crate) struct IoKit;

impl Source for IoKit {
    fn platform_uuid(&self) -> Option<String> {
        platform_expert()?.property("IOPlatformUUID")?.to_string()
    }

    fn platform_serial(&self) -> Option<String> {
        platform_expert()?.property("IOPlatformSerialNumber")?.to_string()
    }

    fn mac_address(&self, name: &str, built_in: bool) -> Option<Vec<u8>> {
        let bsd = CString::new(name).ok()?;
        let mut iterator: IoObject = 0;
        // SAFETY: IOBSDNameMatching returns a +1 dictionary that
        // IOServiceGetMatchingServices consumes; the iterator is ours.
        unsafe {
            let matching = IOBSDNameMatching(MAIN_PORT_DEFAULT, 0, bsd.as_ptr());
            if matching.is_null() || IOServiceGetMatchingServices(MAIN_PORT_DEFAULT, matching, &mut iterator) != 0 {
                return None;
            }
        }
        let iterator = Io(iterator);
        loop {
            // SAFETY: live iterator; each returned object is +1.
            let candidate = unsafe { IOIteratorNext(iterator.0) };
            if candidate == 0 {
                return None;
            }
            let candidate = Io(candidate);
            if candidate.property("IOBuiltin").and_then(|b| b.to_bool()) == Some(built_in) {
                return candidate.search_property("IOMACAddress")?.to_bytes();
            }
        }
    }

    fn sysctl_string(&self, name: &str) -> Option<String> {
        let name = CString::new(name).ok()?;
        let mut len = 0usize;
        // SAFETY: first call asks for the size; second fills a buffer of that size.
        unsafe {
            if sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 || len == 0 {
                return None;
            }
            let mut buf = vec![0u8; len];
            if sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 {
                return None;
            }
            buf.truncate(len);
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8(buf[..end].to_vec()).ok()
        }
    }

    fn sysctl_int(&self, name: &str) -> Option<i64> {
        let name = CString::new(name).ok()?;
        let mut buf = [0u8; 8];
        let mut len = buf.len();
        // SAFETY: buffer of `len` bytes; the kernel writes at most `len`.
        if unsafe { sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
            return None;
        }
        match len {
            4 => Some(i32::from_ne_bytes(buf[..4].try_into().ok()?) as i64),
            8 => Some(i64::from_ne_bytes(buf)),
            _ => None,
        }
    }
}
