//! Durable append-only filesystem adapter for the SQJ writer.
//!
//! The sink never truncates or rewrites journal bytes. A partial write or failed
//! sync is treated as ambiguous; the owning JournalWriter latches terminal state
//! and startup must run verification/recovery before another append.
#![forbid(unsafe_code)]

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use crate::{JournalSink, JournalSinkError, JournalVerificationStatus, verify_journal};

#[derive(Debug)]
pub enum FileJournalOpenError {
    Io(io::Error),
    InvalidJournal,
    DamagedJournal,
}

impl From<io::Error> for FileJournalOpenError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// File-backed SQJ append sink. Keep the containing directory app-private and
/// apply platform directory-sync/promotion policy at the owning storage layer.
pub struct FileJournalSink {
    file: File,
}

impl FileJournalSink {
    /// Creates a fresh journal without clobbering an existing session journal.
    pub fn create_new(path: &Path) -> Result<Self, FileJournalOpenError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        Ok(Self { file })
    }

    /// Opens an existing journal only after verifying the entire byte stream.
    /// Returns the verified bytes so JournalWriter::resume can restore sequence,
    /// digest and monotonic timestamp. Damaged/torn input is never truncated.
    pub fn open_verified(path: &Path) -> Result<(Self, Vec<u8>), FileJournalOpenError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            return Err(FileJournalOpenError::InvalidJournal);
        }
        let verification = verify_journal(&bytes);
        if verification.status != JournalVerificationStatus::Valid
            || verification.valid_prefix_bytes != bytes.len()
        {
            return Err(FileJournalOpenError::DamagedJournal);
        }
        file.seek(SeekFrom::End(0))?;
        Ok((Self { file }, bytes))
    }

    /// Flushes userspace buffers and requests stable storage for the appended
    /// record. The journal writer updates its chain state only after this succeeds.
    pub fn sync_all(&mut self) -> Result<(), io::Error> {
        self.file.sync_all()
    }
}

impl JournalSink for FileJournalSink {
    fn append_bytes(&mut self, record_bytes: &[u8]) -> Result<(), JournalSinkError> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|_| JournalSinkError::WriteFailed)?;
        self.file
            .write_all(record_bytes)
            .map_err(|_| JournalSinkError::WriteFailed)
    }

    fn sync(&mut self) -> Result<(), JournalSinkError> {
        self.file
            .sync_all()
            .map_err(|_| JournalSinkError::SyncFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        JOURNAL_DIGEST_BYTES, JournalRecordInput, JournalRecordType, JournalVerificationStatus,
        JournalWriter,
    };
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_path() -> (std::path::PathBuf, std::path::PathBuf) {
        loop {
            let n = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("sqj-file-sink-{}-{n}", std::process::id()));
            match fs::create_dir(&dir) {
                Ok(()) => return (dir.clone(), dir.join("session.sqj")),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create journal fixture directory: {error}"),
            }
        }
    }

    fn input(sequence: u64, previous: [u8; JOURNAL_DIGEST_BYTES]) -> JournalRecordInput<'static> {
        JournalRecordInput {
            sequence,
            monotonic_timestamp_ns: sequence * 100,
            session_uuid: [0x31; 16],
            record_type: JournalRecordType::CaptureStarted,
            canonical_payload: br#"{"captureEpoch":"1","eventCode":2,"schemaVersion":1}"#,
            previous_digest: previous,
        }
    }

    #[test]
    fn file_sink_durably_appends_and_resumes_verified_chain() {
        let (dir, path) = test_path();
        let sink = FileJournalSink::create_new(&path).unwrap();
        let mut writer = JournalWriter::new(sink);
        let first = writer.append(input(1, [0; 32])).unwrap();
        drop(writer);

        let (sink, bytes) = FileJournalSink::open_verified(&path).unwrap();
        let mut resumed = JournalWriter::resume(sink, &bytes).unwrap();
        let second = resumed.append(input(2, first.digest)).unwrap();
        drop(resumed);

        let final_bytes = fs::read(&path).unwrap();
        let verified = verify_journal(&final_bytes);
        assert_eq!(verified.status, JournalVerificationStatus::Valid);
        assert_eq!(verified.last_sequence, 2);
        assert_eq!(verified.last_digest, second.digest);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_sink_refuses_torn_journal_without_truncating_evidence() {
        let (dir, path) = test_path();
        fs::write(&path, b"SQJR-torn-tail").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            FileJournalSink::open_verified(&path),
            Err(FileJournalOpenError::DamagedJournal)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_sink_creation_is_exclusive() {
        let (dir, path) = test_path();
        let _first = FileJournalSink::create_new(&path).unwrap();
        assert!(matches!(
            FileJournalSink::create_new(&path),
            Err(FileJournalOpenError::Io(ref error))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
