//! Small audited Windows rename boundary: replace atomically and request write-through.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
pub fn rename_write_through(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    use std::{iter::once, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::GetLastError,
        Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(once(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect();
    // SAFETY: both paths are valid NUL-terminated UTF-16 buffers kept alive for
    // the call; flags request same-volume replace + write-through, no pointers escape.
    let succeeded = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        // SAFETY: GetLastError is thread-local and has no pointer arguments.
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn rename_write_through(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}
