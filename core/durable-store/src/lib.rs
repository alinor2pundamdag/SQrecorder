//! Crash-conscious atomic file promotion and recovery inspection.
#![forbid(unsafe_code)]
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    InvalidPath,
    VerificationFailed,
    /// File promotion and directory sync succeeded; journal reconciliation is required.
    JournalCommitPending,
}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    FinalPresent,
    StagedOnly,
    BothPresent,
    NeitherPresent,
}
/// Sync stage, validate, atomically rename, sync parent, then journal callback. Failed stages remain for recovery.
pub fn durable_promote<V, J>(
    dest: &Path,
    bytes: &[u8],
    verify: V,
    commit: J,
) -> Result<(), StoreError>
where
    V: Fn(&Path) -> Result<(), StoreError>,
    J: FnOnce() -> Result<(), StoreError>,
{
    let p = dest.parent().ok_or(StoreError::InvalidPath)?;
    if !p.is_dir() {
        return Err(StoreError::InvalidPath);
    }
    let n = dest
        .file_name()
        .ok_or(StoreError::InvalidPath)?
        .to_string_lossy();
    let stage = p.join(format!(
        ".{n}.sqstage-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    verify(&stage)?;
    fs::rename(&stage, dest)?;
    File::open(p)?.sync_all()?;
    commit().map_err(|_| StoreError::JournalCommitPending)
}
/// Inspection is non-destructive; it never deletes or truncates candidates.
pub fn inspect_recovery(d: &Path, s: &Path) -> RecoveryState {
    match (d.exists(), s.exists()) {
        (true, false) => RecoveryState::FinalPresent,
        (false, true) => RecoveryState::StagedOnly,
        (true, true) => RecoveryState::BothPresent,
        (false, false) => RecoveryState::NeitherPresent,
    }
}
pub fn staging_path(d: &Path, t: &str) -> Result<PathBuf, StoreError> {
    if t.is_empty() || t.contains('/') || t.contains(char::from(92)) || t == "." || t == ".." {
        return Err(StoreError::InvalidPath);
    }
    Ok(d.parent().ok_or(StoreError::InvalidPath)?.join(format!(
        ".{}.sqstage-{t}",
        d.file_name()
            .ok_or(StoreError::InvalidPath)?
            .to_string_lossy()
    )))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    fn td() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sqstage-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn promotes_then_journal_commits() {
        let d = td();
        let f = d.join("sealed");
        let mut called = false;
        durable_promote(
            &f,
            b"ciphertext",
            |p| {
                assert_eq!(fs::read(p)?, b"ciphertext");
                Ok(())
            },
            || {
                called = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(called);
        assert_eq!(fs::read(&f).unwrap(), b"ciphertext");
        fs::remove_dir_all(d).unwrap()
    }
    #[test]
    fn failed_validation_preserves_final() {
        let d = td();
        let f = d.join("final");
        fs::write(&f, b"old").unwrap();
        assert!(durable_promote(
            &f,
            b"bad",
            |_| Err(StoreError::VerificationFailed),
            || Ok(())
        )
        .is_err());
        assert_eq!(fs::read(&f).unwrap(), b"old");
        fs::remove_dir_all(d).unwrap()
    }
    #[test]
    fn journal_failure_is_explicit_after_durable_promotion() {
        let d = td();
        let f = d.join("final");
        let result = durable_promote(
            &f,
            b"promoted",
            |_| Ok(()),
            || Err(StoreError::VerificationFailed),
        );
        assert!(matches!(result, Err(StoreError::JournalCommitPending)));
        assert_eq!(fs::read(&f).unwrap(), b"promoted");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn staged_recovery_is_not_deleted() {
        let d = td();
        let f = d.join("final");
        let s = d.join("stage");
        fs::write(&s, b"evidence").unwrap();
        assert_eq!(inspect_recovery(&f, &s), RecoveryState::StagedOnly);
        assert!(s.exists());
        fs::remove_dir_all(d).unwrap()
    }
}
