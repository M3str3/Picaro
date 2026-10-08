//! Per-output advisory lock for concurrent builds.
//!
//! Two `picaro build` runs that target the same output path race on three
//! writes: the artifact copy, the Authenticode signing (which rewrites the
//! artifact in place) and the provenance manifest written next to it. A unique
//! scratch directory already isolates each run's *intermediate* files, but the
//! final output path is shared by design — two runs for the same YAML both want
//! `dist/out.exe`. [`OutputLock`] serializes that last section so the loser of
//! the race waits instead of interleaving its copy/sign/manifest into the other
//! run's artifact.
//!
//! The lock is dependency-free: a lock file (`<output>.lock`) is created with
//! `create_new(true)`, which atomically fails if it already exists. A stale
//! lock (an owner that died without releasing it) is reclaimed after a
//! threshold; the holder is not expected to hold the lock longer than a build.
//!
//! The guard releases the lock in [`Drop`], so it is also released when the
//! build returns early with an error.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

/// How long the lock is considered abandoned and may be reclaimed.
const STALE_AFTER: Duration = Duration::from_secs(60);

/// How long a build waits for a *live* lock before giving up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to sleep between attempts while the lock is held elsewhere.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Error acquiring the per-output build lock.
#[derive(Debug, thiserror::Error)]
pub enum BuildLockError {
    /// The lock could not be acquired within the bounded timeout.
    #[error(
        "could not acquire the output lock '{path}' within {timeout_ms} ms: \
         another build appears to be writing the same output"
    )]
    Timeout { path: PathBuf, timeout_ms: u64 },

    /// The output's parent directory could not be created.
    #[error("could not create the output directory '{path}': {source}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The lock file could not be created.
    #[error("could not create the output lock file '{path}': {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A stale lock file could not be removed.
    #[error("could not remove the stale output lock file '{path}': {source}")]
    RemoveStale {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// An exclusive, RAII-guarded lock keyed on an output file path.
///
/// Acquire it before the copy-to-output / sign / manifest section of a build;
/// it is released (the lock file is deleted) when the guard drops, including
/// on an early `?` return.
#[derive(Debug)]
pub struct OutputLock {
    path: PathBuf,
}

impl OutputLock {
    /// Acquires the lock for `output`, creating `<output>.lock` next to it.
    ///
    /// Retries against a live lock for a bounded time, reclaiming a lock older
    /// than [`STALE_AFTER`] as abandoned.
    pub fn acquire(output: &Path) -> Result<Self, BuildLockError> {
        Self::acquire_with(output, LOCK_TIMEOUT, STALE_AFTER, RETRY_INTERVAL)
    }

    /// [`Self::acquire`] with the timing knobs exposed for tests.
    fn acquire_with(
        output: &Path,
        timeout: Duration,
        stale_after: Duration,
        retry: Duration,
    ) -> Result<Self, BuildLockError> {
        let path = lock_path(output);

        // The lock file shares the output's parent, so that directory must
        // exist first. Creating a directory is idempotent and safe under
        // concurrency; only the artifact and its siblings are guarded here.
        if let Some(parent) = output.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|source| BuildLockError::CreateParent {
                    path: path.clone(),
                    source,
                })?;
            }
        }

        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_file) => return Ok(OutputLock { path }),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    if stale_after > Duration::ZERO && is_stale(&path, stale_after) {
                        match std::fs::remove_file(&path) {
                            Ok(()) => continue,
                            // Someone else reclaimed it first; retry the create.
                            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                                continue
                            }
                            Err(source) => {
                                return Err(BuildLockError::RemoveStale { path, source })
                            }
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(BuildLockError::Timeout {
                            path,
                            timeout_ms: timeout.as_millis() as u64,
                        });
                    }
                    sleep(retry);
                }
                Err(source) => return Err(BuildLockError::Create { path, source }),
            }
        }
    }
}

impl Drop for OutputLock {
    fn drop(&mut self) {
        // Best-effort: a lingering lock file is only a temporary inconvenience
        // (it is reclaimed once stale), so removal failures are ignored here.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The lock file that guards `output`: `<output>.lock`, next to the artifact.
fn lock_path(output: &Path) -> PathBuf {
    let mut os = output.as_os_str().to_owned();
    os.push(".lock");
    PathBuf::from(os)
}

/// Whether `path` has not been modified for `stale_after`, i.e. its owner is
/// presumed dead and the lock may be reclaimed.
fn is_stale(path: &Path, stale_after: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .map(|age| age > stale_after)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private, unique directory that tests can create files in.
    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "picaro-lock-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn lock_path_appends_a_lock_suffix_next_to_the_output() {
        assert_eq!(
            lock_path(Path::new("dist/out.exe")),
            Path::new("dist/out.exe.lock")
        );
    }

    #[test]
    fn acquiring_creates_and_dropping_releases_the_lock() {
        let dir = temp_dir("acquire-release");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let output = dir.join("out.exe");

        let lock = OutputLock::acquire(&output).expect("acquire");
        assert!(lock_path(&output).exists());

        drop(lock);
        assert!(!lock_path(&output).exists());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_second_acquire_times_out_while_the_lock_is_held() {
        let dir = temp_dir("timeout");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let output = dir.join("out.exe");

        let _held = OutputLock::acquire(&output).expect("acquire");
        let result = OutputLock::acquire_with(
            &output,
            Duration::from_millis(80),
            STALE_AFTER,
            Duration::from_millis(10),
        );
        assert!(
            matches!(result, Err(BuildLockError::Timeout { .. })),
            "expected timeout, got {result:?}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_stale_lock_is_reclaimed() {
        let dir = temp_dir("stale");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let output = dir.join("out.exe");

        // Plant a lock file that already looks abandoned.
        let lock_path = lock_path(&output);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .expect("plant lock");
        let old = SystemTime::now() - Duration::from_secs(120);
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .expect("age the lock");
        drop(file);

        let lock = OutputLock::acquire_with(
            &output,
            Duration::from_millis(500),
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .expect("reclaim the stale lock");

        assert!(lock_path.exists());
        drop(lock);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
