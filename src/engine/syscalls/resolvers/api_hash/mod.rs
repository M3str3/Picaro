//! API-hashing SSN resolver: matches each export by a precomputed FNV-1a
//!
//! Operator reference: `README.md` (rendered into
//! `docs/features/ref/syscalls/api_hash.md`).

use crate::techniques::Stability;

use super::ResolverDef;

pub const DEF: ResolverDef = ResolverDef {
    name: "api_hash",
    phase: "6c",
    attck: &["T1106"],
    stability: Stability::Stable,
    doc_path: "src/engine/syscalls/resolvers/api_hash/README.md",
    readme: include_str!("README.md"),
};

/// API-hashing resolver: walks a clean copy of ntdll read from disk and matches
/// each required function by a precomputed FNV-1a hash of its name, so neither
/// `GetProcAddress` nor any function-name string is needed. The SSN is read
/// from the clean prologue; the gadget still comes from the live ntdll.
/// `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$FILE_PE_HELPERS$` are
/// filled by `resolvers::render_body`.
pub(crate) const FRAGMENT: &str = r#"    /// API hashing: resolves each SSN by a precomputed FNV-1a hash of its
    /// name, walking a clean copy of ntdll read from disk. No GetProcAddress
    /// and no function-name strings are involved.
    fn resolve_ssns() -> Result<(SsnTable, usize), SyscallError> {
        let file = read_clean_ntdll(&$NTDLL_DEF$)?;

        let mut table = SsnTable {
$SSN_INIT$
        };
$SSN_RESOLVE$

        let ntdll =
            std::ffi::CString::new($NTDLL_DEF$).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;
        let gadget = find_gadget(module)?;
        Ok((table, gadget))
    }

    /// Per-build FNV-1a offset basis, emitted by the packer so the hash
    /// constants vary between artifacts (a fixed basis is a static signature).
    const API_HASH_SEED: u64 = $API_HASH_SEED$;

    /// FNV-1a 64-bit hash of a function name, over the per-build basis.
    fn api_hash(name: &[u8]) -> u64 {
        let mut hash: u64 = API_HASH_SEED;
        for &byte in name {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Resolves one function by hash and reads its SSN from the clean file.
    fn resolve_ssn(file: &[u8], hash: u64) -> Result<u32, SyscallError> {
        let rva = export_rva_by_hash(file, hash)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        let offset = rva_to_offset(file, rva as usize)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        let Some(end) = offset.checked_add(8) else {
            return Err(SyscallError::FunctionNotFound(format!("0x{hash:016x}")));
        };
        let prologue = file
            .get(offset..end)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        match parse_ssn(prologue) {
            Some(ssn) => {
                crate::tech_dbg!("syscalls", "0x{hash:016x} -> SSN {ssn}");
                Ok(ssn)
            }
            None => {
                crate::tech_dbg!(
                    "syscalls",
                    "0x{hash:016x}: export prologue is not in the expected form"
                );
                Err(SyscallError::PatternMismatch(format!("0x{hash:016x}")))
            }
        }
    }

    /// Finds a function's RVA by matching its hashed export name against
    /// `hash` — the shared walk with a hash predicate.
    fn export_rva_by_hash(file: &[u8], hash: u64) -> Option<u32> {
        export_rva_where(file, |candidate| api_hash(candidate) == hash)
    }

$FILE_PE_HELPERS$
"#;

/// The canonical FNV-1a 64-bit offset basis. The generated stub uses a
/// per-build seed instead; this is the reference value the tests pin.
#[cfg(test)]
pub(crate) const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit hash of a function name with an explicit offset `basis`.
///
/// The API-hashing resolver embeds these hashes as numeric constants instead of
/// the (obfuscated) Nt* names, so it needs neither `GetProcAddress` nor a name
/// string. The packer and the generated stub (whose `api_hash` uses the seeded
/// `API_HASH_SEED`) must stay in sync — the reference-value tests guard it.
pub(crate) fn api_hash_with(name: &[u8], basis: u64) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = basis;
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
