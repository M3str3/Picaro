//! Position-independent shellcode output (`build.output.kind: shellcode`).
//!
//! Shellcode is not a new compile shape: the packed DLL is compiled exactly as
//! for `kind: dll`, then handed to sRDI (`ConvertToShellcode.py`), which prepends
//! a reflective PE loader and emits raw, position-independent bytes. A host that
//! can run shellcode (a `msbuild` inline task, a JVM through the FFM API, …) maps
//! those bytes and jumps to them; the loader then maps the DLL into memory,
//! resolves its imports and calls the plain export, so the chain runs without a
//! PE ever touching the disk or the image loader.
//!
//! sRDI is vendored under `vendor/srdi/` (C source + `build_blob.py`, which
//! compiles the reflective loader blob and emits the corrected
//! `ShellcodeRDI.py`). The converter is a Python 3 script, so it runs on the
//! Linux Docker image exactly like the rest of the toolchain; the Dockerfile
//! builds the blob at image time and points `PICARO_SRDI` at the result. Locate
//! it with `PICARO_SRDI` (a path to `ConvertToShellcode.py` or to a directory
//! that contains it) and have `python`/`python3` on `PATH`.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{BuildError, Result};

/// Environment variable that points at the sRDI converter.
const SRDI_ENV: &str = "PICARO_SRDI";

/// The converter script inside the sRDI repository.
const SRDI_SCRIPT: &str = "ConvertToShellcode.py";

/// Resolves the sRDI converter script from the `PICARO_SRDI` override.
///
/// The value may be the script itself, or a directory that contains it (either
/// at the top level or under a `Python/` subdirectory, the layout of the
/// upstream repository). A missing override is a build error with the install
/// instructions in the message.
pub fn find_srdi() -> Result<PathBuf> {
    let Some(raw) = std::env::var_os(SRDI_ENV).filter(|v| !v.is_empty()) else {
        return Err(BuildError::ShellcodeConverterNotFound(format!(
            "set {SRDI_ENV} to the path of `{SRDI_SCRIPT}` (or its directory); the \
             Docker image builds it from `vendor/srdi/`"
        )));
    };

    let path = PathBuf::from(raw);
    if path.is_file() {
        return Ok(path);
    }
    if path.is_dir() {
        for candidate in converter_candidates(&path) {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        return Err(BuildError::ShellcodeConverterNotFound(format!(
            "`{SRDI_ENV}` points at '{}', which has no `{SRDI_SCRIPT}`",
            path.display()
        )));
    }

    Err(BuildError::ShellcodeConverterNotFound(format!(
        "`{SRDI_ENV}` points at '{}', which is neither a file nor a directory",
        path.display()
    )))
}

/// Candidate converter paths inside a directory, most specific first.
fn converter_candidates(dir: &Path) -> Vec<PathBuf> {
    vec![dir.join(SRDI_SCRIPT), dir.join("Python").join(SRDI_SCRIPT)]
}

/// Resolves a Python 3 interpreter for the converter script.
///
/// Windows exposes the launcher as `python`; Linux containers often only ship
/// `python3`. The first candidate that runs `--version` cleanly wins.
fn find_python() -> Option<&'static str> {
    ["python", "python3"].into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

/// Converts a packed DLL into position-independent shellcode with sRDI.
///
/// The reflective loader calls the named plain export (`Run`, or the name from
/// `build.output.entry: export:<name>`) after `DllMain`, so `export` must be the
/// chain-runner export the entry block emitted. The result is the raw shellcode
/// bytes; the build writes them straight to `build.output.path`.
pub fn convert(dll: &Path, export: &str) -> Result<Vec<u8>> {
    let converter = find_srdi()?;
    let python = find_python().ok_or_else(|| {
        BuildError::ShellcodeConverterNotFound(
            "a Python 3 interpreter is not available on PATH (sRDI's converter is a Python script)"
                .to_string(),
        )
    })?;

    let output = Command::new(python)
        .arg(&converter)
        .arg(dll)
        .arg("-f")
        .arg(export)
        .arg("-of")
        .arg("raw")
        .output()
        .map_err(|e| {
            BuildError::ShellcodeConversionFailed(format!(
                "could not run '{}': {e}",
                converter.display()
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BuildError::ShellcodeConversionFailed(stderr.to_string()));
    }

    // sRDI writes the shellcode next to the DLL it converts, but the name is not
    // a plain extension swap: `ConvertToShellcode.py` computes
    // `input_dll.replace('.dll', '.bin')` (the *first* `.dll` over the whole path
    // string). Mirror it exactly, or a stem that itself contains `.dll` makes the
    // converter and the packer disagree on the file name and the build reads the
    // wrong file.
    let bin = converted_path(dll);
    let bytes = std::fs::read(&bin).map_err(|e| {
        BuildError::ShellcodeConversionFailed(format!(
            "the converter did not write '{}': {e}",
            bin.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(BuildError::ShellcodeConversionFailed(format!(
            "'{}' is empty",
            bin.display()
        )));
    }
    Ok(bytes)
}

/// The path `ConvertToShellcode.py` writes, from the DLL path it is handed.
///
/// The converter does `output_bin = input_dll.replace('.dll', '.bin')` on the
/// whole path string, and Python's `str.replace` swaps *every* occurrence — not
/// just the final extension. Mirroring it keeps the packer and the converter in
/// agreement (a stem like `a.dll.picaro` would otherwise diverge). The fallback
/// covers a path with no `.dll` at all, which the intermediate never is.
fn converted_path(dll: &Path) -> PathBuf {
    let text = dll.to_string_lossy();
    if !text.contains(".dll") {
        return dll.with_extension("bin");
    }
    PathBuf::from(text.replace(".dll", ".bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_converter_candidates_cover_both_repo_layouts() {
        let candidates = converter_candidates(Path::new("/opt/srdi"));
        assert_eq!(
            candidates[0],
            PathBuf::from("/opt/srdi/ConvertToShellcode.py")
        );
        assert_eq!(
            candidates[1],
            PathBuf::from("/opt/srdi/Python/ConvertToShellcode.py")
        );
    }

    #[test]
    fn a_python_interpreter_is_required() {
        // `python --version` runs without a converter; it only checks the
        // interpreter is present, never executes shellcode.
        assert!(
            find_python().is_some(),
            "expected a Python interpreter on PATH"
        );
    }

    #[test]
    fn the_converted_path_mirrors_the_converter() {
        // The common case: an ordinary stem and a final `.dll`.
        assert_eq!(
            converted_path(Path::new("/tmp/build/loader.dll")),
            PathBuf::from("/tmp/build/loader.bin")
        );
        // A stem that itself contains `.dll`: Python's `str.replace` swaps every
        // occurrence, and so must the packer, or it reads the wrong file.
        assert_eq!(
            converted_path(Path::new("/tmp/build/a.dll.picaro.dll")),
            PathBuf::from("/tmp/build/a.bin.picaro.bin")
        );
    }
}
