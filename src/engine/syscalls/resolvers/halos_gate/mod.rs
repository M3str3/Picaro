//! Halo's Gate SSN resolver: derives a hooked stub's SSN from its neighbours
//!
//! Operator reference: `README.md` (rendered into
//! `docs/features/ref/syscalls/halos_gate.md`).

use crate::techniques::Stability;

use super::ResolverDef;

pub const DEF: ResolverDef = ResolverDef {
    name: "halos_gate",
    phase: "6d",
    attck: &["T1106"],
    // The packer-side logic is unit-tested; the generated stub's neighbour walk
    // has not been measured on the lab host yet.
    stability: Stability::Experimental,
    doc_path: "src/engine/syscalls/resolvers/halos_gate/README.md",
    readme: include_str!("README.md"),
};

/// Halo's Gate resolver: reads the SSN from the live stub when its prologue is
/// intact and, when an EDR hooked it, derives it from the nearest intact
/// neighbour in the live export table (the stubs are 32 bytes apart and ordered
/// by SSN). Falls back to a clean on-disk copy when no neighbour is usable.
/// `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$FILE_PE_HELPERS$` are
/// filled by `resolvers::render_body`.
pub(crate) const FRAGMENT: &str = r#"    /// Halo's Gate: resolves every SSN from the live module, walking its export
    /// table directly (no `GetProcAddress`) and using the neighbours of a
    /// hooked stub instead of failing.
    fn resolve_ssns() -> Result<(SsnTable, usize), SyscallError> {
        let ntdll =
            std::ffi::CString::new($NTDLL_DEF$).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;

        let mut table = SsnTable {
$SSN_INIT$
        };
$SSN_RESOLVE$

        let gadget = find_gadget(module)?;
        Ok((table, gadget))
    }

    /// Resolves one function: its own prologue when intact, its neighbours when
    /// hooked, a clean on-disk copy as the last resort.
    fn resolve_ssn_with_fallback(module: HMODULE, name: &str) -> Result<u32, SyscallError> {
        let base = module.0 as usize;
        let Some(target) = live_export_address(base, name) else {
            crate::tech_dbg!(
                "syscalls",
                "{name}: the live export walk failed, falling back to the clean copy"
            );
            let file = read_clean_ntdll(&$NTDLL_DEF$)?;
            return resolve_ssn_from_file(&file, name);
        };
        if let Some(ssn) = read_live_ssn(target) {
            crate::tech_dbg!("syscalls", "{name} -> SSN {ssn}");
            return Ok(ssn);
        }

        if let Some(ssn) = neighbour_ssn(base, target) {
            crate::tech_dbg!("syscalls", "{name} -> SSN {ssn} (neighbour)");
            return Ok(ssn);
        }

        crate::tech_dbg!(
            "syscalls",
            "{name}: no live neighbour yields an SSN, falling back to the clean copy"
        );
        let file = read_clean_ntdll(&$NTDLL_DEF$)?;
        resolve_ssn_from_file(&file, name)
    }

    /// Returns the live export's address by walking the module's own export
    /// directory. Avoiding `GetProcAddress` keeps the resolver off a hookable
    /// resolution path.
    fn live_export_address(base: usize, name: &str) -> Option<usize> {
        let (functions, names, ordinals, count) = live_export_tables(base)?;
        for index in 0..count {
            let Some((candidate, address)) = live_export_at(base, functions, names, ordinals, index)
            else {
                continue;
            };
            if cstr_eq(candidate, name) {
                return Some(address);
            }
        }
        None
    }

    /// Reads the canonical SSN from a live stub, if its prologue is intact.
    fn read_live_ssn(address: usize) -> Option<u32> {
        let prologue = unsafe { std::slice::from_raw_parts(address as *const u8, 8) };
        parse_ssn(prologue)
    }

    /// Derives the target's SSN from the nearest intact export whose distance
    /// is a whole number of 32-byte syscall stubs.
    ///
    /// The `Nt*` exports are ordered by SSN in the address space, so a neighbour
    /// that is `n * 32` bytes away is exactly `n` SSNs away. Both directions are
    /// tried and the closest consistent answer wins.
    fn neighbour_ssn(base: usize, target: usize) -> Option<u32> {
        let (functions, names, ordinals, count) = live_export_tables(base)?;
        let mut anchors: Vec<(usize, u32)> = Vec::new();
        for index in 0..count {
            let Some((_, address)) = live_export_at(base, functions, names, ordinals, index) else {
                continue;
            };
            if let Some(ssn) = read_live_ssn(address) {
                anchors.push((address, ssn));
            }
        }
        // The `Zw*` aliases share an address with their `Nt*` twin.
        anchors.sort_unstable_by_key(|(address, _)| *address);
        anchors.dedup_by_key(|(address, _)| *address);

        let mut best: Option<(usize, u32)> = None;
        for (address, ssn) in &anchors {
            let distance = target.abs_diff(*address);
            if distance == 0 || distance > 0x8000 || distance % 32 != 0 {
                continue;
            }
            let delta = (distance / 32) as u32;
            let candidate = if *address < target {
                ssn.checked_add(delta)
            } else {
                ssn.checked_sub(delta)
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if candidate >= 0x1000 {
                continue;
            }
            if best.map_or(true, |(best_distance, _)| distance < best_distance) {
                best = Some((distance, candidate));
            }
        }
        best.map(|(_, ssn)| ssn)
    }

    /// Returns the export directory's three RVAs and its name count, read from
    /// the live mapped image.
    fn live_export_tables(base: usize) -> Option<(usize, usize, usize, usize)> {
        let e_lfanew = pe_u32(base, 0x3C)? as usize;
        if pe_u32(base, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let opt = e_lfanew.checked_add(4 + 20)?;
        let magic = pe_u16(base, opt)?;
        // The data directory starts at optional-header offset 112 (PE32+) or
        // 96 (PE32); ntdll on x64 is PE32+, but keep both for the port.
        let dir = if magic == 0x20b {
            opt.checked_add(112)?
        } else {
            opt.checked_add(96)?
        };
        let export_rva = pe_u32(base, dir)? as usize;
        if export_rva == 0 {
            return None;
        }
        // `pe_u16`/`pe_u32` take an offset from `base`, so the export
        // directory stays an RVA here.
        let count = pe_u32(base, export_rva.checked_add(24)?)? as usize;
        let functions = pe_u32(base, export_rva.checked_add(28)?)? as usize;
        let names = pe_u32(base, export_rva.checked_add(32)?)? as usize;
        let ordinals = pe_u32(base, export_rva.checked_add(36)?)? as usize;
        Some((functions, names, ordinals, count))
    }

    /// Resolves one export-table entry to `(name pointer, function address)`.
    fn live_export_at(
        base: usize,
        functions: usize,
        names: usize,
        ordinals: usize,
        index: usize,
    ) -> Option<(usize, usize)> {
        let name_rva = pe_u32(base, names.checked_add(index.checked_mul(4)?)?)? as usize;
        let name = base.checked_add(name_rva)?;
        let ordinal = pe_u16(base, ordinals.checked_add(index.checked_mul(2)?)?)? as usize;
        let function_rva =
            pe_u32(base, functions.checked_add(ordinal.checked_mul(4)?)?)? as usize;
        if function_rva == 0 {
            return None;
        }
        Some((name, base.checked_add(function_rva)?))
    }

    /// Compares a NUL-terminated export name in the live image with `name`.
    fn cstr_eq(address: usize, name: &str) -> bool {
        let wanted = name.as_bytes();
        let bytes = unsafe { std::slice::from_raw_parts(address as *const u8, wanted.len() + 1) };
        &bytes[..wanted.len()] == wanted && bytes[wanted.len()] == 0
    }

    /// Reads an SSN from a clean on-disk copy of ntdll (the last resort), the
    /// same walk Tartarus Gate uses.
    fn resolve_ssn_from_file(file: &[u8], name: &str) -> Result<u32, SyscallError> {
        let rva = export_rva(file, name)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        let offset = rva_to_offset(file, rva as usize)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        let Some(end) = offset.checked_add(8) else {
            return Err(SyscallError::FunctionNotFound(name.to_string()));
        };
        let prologue = file
            .get(offset..end)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        parse_ssn(prologue).ok_or_else(|| SyscallError::PatternMismatch(name.to_string()))
    }

$FILE_PE_HELPERS$
"#;

#[cfg(test)]
mod tests {
    use super::DEF;
    use crate::techniques::Stability;

    /// Mirrors the generated stub's `neighbour_ssn` arithmetic so the formula is
    /// unit-tested by the packer instead of only on a live ntdll. `anchors` are
    /// the live `(address, SSN)` pairs of intact exports.
    fn neighbour_ssn(target: usize, anchors: &[(usize, u32)]) -> Option<u32> {
        let mut best: Option<(usize, u32)> = None;
        for &(address, ssn) in anchors {
            let distance = target.abs_diff(address);
            if distance == 0 || distance > 0x8000 || distance % 32 != 0 {
                continue;
            }
            let delta = (distance / 32) as u32;
            let candidate = if address < target {
                ssn.checked_add(delta)
            } else {
                ssn.checked_sub(delta)
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if candidate >= 0x1000 {
                continue;
            }
            if best.is_none_or(|(best_distance, _)| distance < best_distance) {
                best = Some((distance, candidate));
            }
        }
        best.map(|(_, ssn)| ssn)
    }

    #[test]
    fn def_is_well_formed() {
        assert_eq!(DEF.name, "halos_gate");
        assert_eq!(DEF.phase, "6d");
        assert_eq!(DEF.stability, Stability::Experimental);
        assert!(!DEF.attck.is_empty());
        assert!(DEF.readme.starts_with("# "));
    }

    #[test]
    fn derives_the_ssn_from_a_lower_anchor() {
        // The target is one 32-byte stub above an intact anchor.
        assert_eq!(neighbour_ssn(0x1020, &[(0x1000, 0x10)]), Some(0x11));
    }

    #[test]
    fn derives_the_ssn_from_an_upper_anchor() {
        // Two stubs below an intact anchor: 0x20 - 2 = 0x1e.
        assert_eq!(neighbour_ssn(0x1020, &[(0x1060, 0x20)]), Some(0x1e));
    }

    #[test]
    fn prefers_the_closest_anchor() {
        // 0x20 away (one stub) beats 0x80 away (four stubs).
        assert_eq!(
            neighbour_ssn(0x1020, &[(0x1000, 0x10), (0x10a0, 0x20)]),
            Some(0x11)
        );
    }

    #[test]
    fn ignores_an_anchor_that_is_not_stub_aligned() {
        assert_eq!(neighbour_ssn(0x1020, &[(0x1010, 0x10)]), None);
    }

    #[test]
    fn rejects_a_result_outside_the_plausible_ssn_range() {
        // 0xffe + 2 = 0x1000, the first value the resolver refuses.
        assert_eq!(neighbour_ssn(0x1040, &[(0x1000, 0xffe)]), None);
    }

    #[test]
    fn ignores_an_anchor_beyond_the_search_window() {
        assert_eq!(neighbour_ssn(0x10020, &[(0x1000, 0x10)]), None);
    }
}
