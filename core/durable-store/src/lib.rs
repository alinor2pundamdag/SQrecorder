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
    /// Rename occurred but parent-directory sync failed; inspect recovery before reporting state.
    PromotionDurabilityUnknown,
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
/// Operations are separated so crash/failure boundaries can be fault-injected in tests.
trait PromotionOps {
    fn write_and_sync_stage(&self, stage: &Path, bytes: &[u8]) -> Result<(), StoreError>;
    fn rename_stage(&self, stage: &Path, dest: &Path) -> Result<(), StoreError>;
    fn sync_parent(&self, parent: &Path) -> Result<(), StoreError>;
}
struct OsPromotionOps;
impl PromotionOps for OsPromotionOps {
    fn write_and_sync_stage(&self, stage: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(stage)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    fn rename_stage(&self, stage: &Path, dest: &Path) -> Result<(), StoreError> {
        fs::rename(stage, dest)?;
        Ok(())
    }
    fn sync_parent(&self, parent: &Path) -> Result<(), StoreError> {
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}
/// Sync stage, validate, atomically rename, sync parent, then journal callback.
/// Errors preserve candidates and communicate whether promotion is ambiguous.
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
    durable_promote_with_ops(&OsPromotionOps, dest, bytes, verify, commit)
}
fn durable_promote_with_ops<O, V, J>(
    ops: &O,
    dest: &Path,
    bytes: &[u8],
    verify: V,
    commit: J,
) -> Result<(), StoreError>
where
    O: PromotionOps,
    V: Fn(&Path) -> Result<(), StoreError>,
    J: FnOnce() -> Result<(), StoreError>,
{
    let parent = dest.parent().ok_or(StoreError::InvalidPath)?;
    if !parent.is_dir() {
        return Err(StoreError::InvalidPath);
    }
    let name = dest.file_name().ok_or(StoreError::InvalidPath)?.to_string_lossy();
    let stage = parent.join(format!(
        ".{name}.sqstage-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    ops.write_and_sync_stage(&stage, bytes)?;
    verify(&stage)?;
    ops.rename_stage(&stage, dest)?;
    ops.sync_parent(parent)
        .map_err(|_| StoreError::PromotionDurabilityUnknown)?;
    commit().map_err(|_| StoreError::JournalCommitPending)
}
/// Recovery action combines filesystem evidence with the journal's durable commit marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationAction {
    AlreadyCommitted,
    AppendMissingJournalCommit,
    ValidateAndRecoverStage,
    PreserveAndInvestigateBoth,
    ReportMissingArtifact,
}
pub fn reconciliation_action(
    filesystem: RecoveryState,
    journal_commit_present: bool,
) -> ReconciliationAction {
    match (filesystem, journal_commit_present) {
        (RecoveryState::FinalPresent, true) => ReconciliationAction::AlreadyCommitted,
        (RecoveryState::FinalPresent, false) => ReconciliationAction::AppendMissingJournalCommit,
        (RecoveryState::StagedOnly, _) => ReconciliationAction::ValidateAndRecoverStage,
        (RecoveryState::BothPresent, _) => ReconciliationAction::PreserveAndInvestigateBoth,
        (RecoveryState::NeitherPresent, _) => ReconciliationAction::ReportMissingArtifact,
    }
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

    #[derive(Clone, Copy)]
    enum FaultPoint { PartialStageWrite, FileSync, Rename, ParentSync }
    struct FaultOps(FaultPoint);
    impl PromotionOps for FaultOps {
        fn write_and_sync_stage(&self, stage: &Path, bytes: &[u8]) -> Result<(), StoreError> {
            match self.0 {
                FaultPoint::PartialStageWrite => {
                    let mut f = OpenOptions::new().write(true).create_new(true).open(stage)?;
                    f.write_all(&bytes[..bytes.len().min(3)])?;
                    Err(StoreError::Io(io::Error::new(io::ErrorKind::WriteZero, "injected partial write")))
                }
                FaultPoint::FileSync => {
                    let mut f = OpenOptions::new().write(true).create_new(true).open(stage)?;
                    f.write_all(bytes)?;
                    Err(StoreError::Io(io::Error::new(io::ErrorKind::Other, "injected fsync failure")))
                }
                _ => OsPromotionOps.write_and_sync_stage(stage, bytes),
            }
        }
        fn rename_stage(&self, stage: &Path, dest: &Path) -> Result<(), StoreError> {
            if matches!(self.0, FaultPoint::Rename) {
                return Err(StoreError::Io(io::Error::new(io::ErrorKind::Other, "injected rename failure")));
            }
            OsPromotionOps.rename_stage(stage, dest)
        }
        fn sync_parent(&self, parent: &Path) -> Result<(), StoreError> {
            if matches!(self.0, FaultPoint::ParentSync) {
                return Err(StoreError::Io(io::Error::new(io::ErrorKind::Other, "injected directory sync failure")));
            }
            OsPromotionOps.sync_parent(parent)
        }
    }
    #[test]
    fn fault_injection_preserves_old_final_before_rename() {
        for point in [FaultPoint::PartialStageWrite, FaultPoint::FileSync, FaultPoint::Rename] {
            let d = td();
            let final_path = d.join("final");
            fs::write(&final_path, b"old").unwrap();
            let result = durable_promote_with_ops(
                &FaultOps(point), &final_path, b"replacement", |_| Ok(()), || Ok(())
            );
            assert!(result.is_err());
            assert_eq!(fs::read(&final_path).unwrap(), b"old");
            fs::remove_dir_all(d).unwrap();
        }
    }
    #[test]
    fn directory_sync_failure_reports_ambiguous_promotion() {
        let d = td();
        let final_path = d.join("final");
        let result = durable_promote_with_ops(
            &FaultOps(FaultPoint::ParentSync), &final_path, b"promoted", |_| Ok(()), || Ok(())
        );
        assert!(matches!(result, Err(StoreError::PromotionDurabilityUnknown)));
        assert_eq!(fs::read(&final_path).unwrap(), b"promoted");
        assert_eq!(inspect_recovery(&final_path, &d.join("not-the-stage")), RecoveryState::FinalPresent);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn recovery_reconciliation_never_silently_discards_evidence() {
        assert_eq!(reconciliation_action(RecoveryState::FinalPresent, true), ReconciliationAction::AlreadyCommitted);
        assert_eq!(reconciliation_action(RecoveryState::FinalPresent, false), ReconciliationAction::AppendMissingJournalCommit);
        assert_eq!(reconciliation_action(RecoveryState::StagedOnly, false), ReconciliationAction::ValidateAndRecoverStage);
        assert_eq!(reconciliation_action(RecoveryState::BothPresent, true), ReconciliationAction::PreserveAndInvestigateBoth);
        assert_eq!(reconciliation_action(RecoveryState::NeitherPresent, false), ReconciliationAction::ReportMissingArtifact);
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
