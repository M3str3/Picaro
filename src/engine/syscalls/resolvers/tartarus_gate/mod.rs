//! Tartarus Gate SSN resolver: reads each SSN from a clean on-disk copy
//!
//! Operator reference: `README.md` (rendered into
//! `docs/features/ref/syscalls/tartarus_gate.md`).

use crate::techniques::Stability;

use super::ResolverDef;

pub const DEF: ResolverDef = ResolverDef {
    name: "tartarus_gate",
    phase: "6b",
    attck: &["T1106"],
    stability: Stability::Stable,
    doc_path: "src/engine/syscalls/resolvers/tartarus_gate/README.md",
    readme: include_str!("README.md"),
};

/// Tartarus Gate resolver: reads SSNs from a clean copy of ntdll read from
/// disk. `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$FILE_PE_HELPERS$`
/// are filled by `resolvers::render_body`.
pub(crate) const FRAGMENT: &str = r#"    /// Tartarus Gate: reads each SSN from a clean copy of ntdll read from
    /// disk, so EDR hooks in the live export stubs cannot hide the SSN. The
    /// gadget still comes from the live ntdll (its `.text` is not hooked).
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

    /// Resolves one function and reads its SSN from the clean file image.
    fn resolve_ssn(file: &[u8], name: &str) -> Result<u32, SyscallError> {
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

    /// The export-directory walk and the clean-copy reader are provided by the
    /// shared PE-file helpers injected below.
$FILE_PE_HELPERS$
"#;
