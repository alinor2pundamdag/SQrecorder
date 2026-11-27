//! Capture-engine C ABI v1. Caller owns handle lifetime and must not destroy it
//! concurrently with another operation. Input pointers must reference valid ranges.
use crate::{
    ABI_MAJOR_V1, ABI_MINOR_V1, BoundedPcmQueue, CaptureEventMetadata, CaptureStatus,
    PCM_S16_LE_V1, PcmMetadata,
    SqAbiInfoV1, SqCaptureConfigV1, SqCaptureEventV1, SqPcmBlockV1, SqStatusV1,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_FFI_PCM_BYTES: usize = 256 * 1024;

pub struct SqCaptureEngine {
    queue: BoundedPcmQueue,
    started: AtomicBool,
}

fn guarded(f: impl FnOnce() -> Result<(), SqStatusV1>) -> SqStatusV1 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => SqStatusV1::Ok,
        Ok(Err(status)) => status,
        Err(_) => SqStatusV1::Internal,
    }
}

/// # Safety
/// `raw` must be a valid, live engine handle for the duration of this borrow.
unsafe fn engine<'a>(raw: *mut SqCaptureEngine) -> Result<&'a SqCaptureEngine, SqStatusV1> {
    if raw.is_null() {
        return Err(SqStatusV1::InvalidArgument);
    }
    // SAFETY: ABI caller guarantees a live handle returned by create, not destroyed concurrently.
    Ok(unsafe { &*raw })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_get_abi_info_v1(out: *mut SqAbiInfoV1) -> SqStatusV1 {
    guarded(|| {
        if out.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller supplies writable storage for the ABI struct.
        unsafe {
            ptr::write(
                out,
                SqAbiInfoV1 {
                    struct_size: core::mem::size_of::<SqAbiInfoV1>() as u32,
                    abi_major: ABI_MAJOR_V1,
                    abi_minor: ABI_MINOR_V1,
                    feature_bits: 0,
                    reserved: [0; 4],
                },
            )
        };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_create_v1(
    config: *const SqCaptureConfigV1,
    out: *mut *mut SqCaptureEngine,
) -> SqStatusV1 {
    guarded(|| {
        if config.is_null() || out.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller provides readable config and writable output pointer.
        let c = unsafe { &*config };
        if c.struct_size as usize != core::mem::size_of::<SqCaptureConfigV1>()
            || c.sample_rate_hz != 48_000 && c.sample_rate_hz != 44_100
            || c.channels != 1
            || c.sample_format != PCM_S16_LE_V1
            || c.flags != 0
            || c.reserved.iter().any(|v| *v != 0)
        {
            return Err(SqStatusV1::InvalidArgument);
        }
        let queue = BoundedPcmQueue::new(c.queue_block_capacity, c.max_block_frames)
            .map_err(|_| SqStatusV1::InvalidArgument)?;
        let boxed = Box::new(SqCaptureEngine {
            queue,
            started: AtomicBool::new(false),
        });
        // SAFETY: validated output pointer; transfer ownership to the ABI handle.
        unsafe {
            ptr::write(out, Box::into_raw(boxed));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_start_v1(raw: *mut SqCaptureEngine) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        e.started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SqStatusV1::InvalidState)?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_submit_pcm_v1(
    raw: *mut SqCaptureEngine,
    block: *const SqPcmBlockV1,
    pcm: *const u8,
    pcm_bytes: u64,
) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if !e.started.load(Ordering::Acquire) {
            return Err(SqStatusV1::InvalidState);
        }
        if block.is_null() || pcm_bytes > MAX_FFI_PCM_BYTES as u64 {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller guarantees readable block and PCM range of pcm_bytes.
        let b = unsafe { &*block };
        if b.struct_size as usize != core::mem::size_of::<SqPcmBlockV1>()
            || b.flags != 0
            || b.reserved0 != 0
            || b.reserved1 != 0
            || b.payload_bytes != pcm_bytes
            || b.payload_bytes == 0
            || b.sequence == 0
            || b.capture_epoch == 0
            || b.monotonic_timestamp_ns == 0
        {
            return Err(SqStatusV1::InvalidArgument);
        }
        let len = usize::try_from(pcm_bytes).map_err(|_| SqStatusV1::InvalidArgument)?;
        if pcm.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: pointer and length are supplied by the ABI caller and validated non-null/bounded.
        let bytes = unsafe { slice::from_raw_parts(pcm, len) };
        let metadata = PcmMetadata {
            sample_rate_hz: b.sample_rate_hz,
            channels: b.channels,
            sample_format: b.sample_format,
            frames: b.frame_count,
            first_frame_index: b.first_frame_index,
            monotonic_timestamp_ns: b.monotonic_timestamp_ns,
            capture_epoch: b.capture_epoch,
            sequence: b.sequence,
        };
        e.queue
            .submit(metadata, bytes)
            .map_err(|error| match error {
                crate::CaptureError::QueueOverflow => SqStatusV1::Resource,
                crate::CaptureError::InvalidState => SqStatusV1::InvalidState,
                crate::CaptureError::ResourcePoisoned | crate::CaptureError::QueueContention => {
                    SqStatusV1::Resource
                }
                _ => SqStatusV1::InvalidArgument,
            })
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_push_event_v1(
    raw: *mut SqCaptureEngine,
    event: *const SqCaptureEventV1,
) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if event.is_null() || !e.started.load(Ordering::Acquire) {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller provides a readable event descriptor.
        let event = unsafe { &*event };
        if event.struct_size as usize != core::mem::size_of::<SqCaptureEventV1>()
            || event.reserved0 != 0 || event.reserved1 != 0
        {
            return Err(SqStatusV1::InvalidArgument);
        }
        let metadata = CaptureEventMetadata {
            event_type: event.event_type, flags: event.flags,
            event_sequence: event.event_sequence,
            monotonic_timestamp_ns: event.monotonic_timestamp_ns,
            capture_epoch: event.capture_epoch, detail_code: event.detail_code,
        };
        e.queue.push_event(metadata).map_err(|error| match error {
            crate::CaptureError::QueueOverflow | crate::CaptureError::QueueContention
            | crate::CaptureError::ResourcePoisoned => SqStatusV1::Resource,
            crate::CaptureError::InvalidState => SqStatusV1::InvalidState,
            _ => SqStatusV1::InvalidArgument,
        })
    })
}


#[unsafe(no_mangle)]
/// # Safety
/// `raw` must be a live engine handle and `out_event` must be writable for one ABI event struct.
pub unsafe extern "C" fn sq_capture_read_event_v1(
    raw: *mut SqCaptureEngine,
    out_event: *mut SqCaptureEventV1,
) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if out_event.is_null() || !e.started.load(Ordering::Acquire) {
            return Err(SqStatusV1::InvalidArgument);
        }
        let event = e.queue.pop_event().map_err(|_| SqStatusV1::Resource)?
            .ok_or(SqStatusV1::WouldBlock)?;
        let value = SqCaptureEventV1 {
            struct_size: core::mem::size_of::<SqCaptureEventV1>() as u32,
            event_type: event.event_type, flags: event.flags, reserved0: 0,
            event_sequence: event.event_sequence,
            monotonic_timestamp_ns: event.monotonic_timestamp_ns,
            capture_epoch: event.capture_epoch, detail_code: event.detail_code,
            reserved1: 0,
        };
        unsafe { ptr::write(out_event, value); }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_request_stop_v1(raw: *mut SqCaptureEngine) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if !e.started.load(Ordering::Acquire) {
            return Err(SqStatusV1::InvalidState);
        }
        e.queue.request_stop().map_err(|_| SqStatusV1::InvalidState)
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_get_state_v1(
    raw: *const SqCaptureEngine,
    out: *mut u32,
) -> SqStatusV1 {
    guarded(|| {
        if raw.is_null() || out.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: handle is live and caller provides writable u32.
        let e = unsafe { &*raw };
        let state = if !e.started.load(Ordering::Acquire) {
            0
        } else {
            match e.queue.status().map_err(|_| SqStatusV1::Resource)? {
                CaptureStatus::Running => 1,
                CaptureStatus::Stopping => 2,
                CaptureStatus::Stopped => 3,
                CaptureStatus::Failed => 4,
            }
        };
        // SAFETY: validated non-null output pointer.
        unsafe {
            ptr::write(out, state);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_destroy_v1(raw: *mut SqCaptureEngine) {
    if !raw.is_null() {
        // SAFETY: caller must destroy exactly once and ensure no concurrent use.
        drop(unsafe { Box::from_raw(raw) });
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_read_pcm_v1(
    raw: *mut SqCaptureEngine,
    out_block: *mut SqPcmBlockV1,
    out_pcm: *mut u8,
    capacity: u64,
    out_written: *mut u64,
) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if !e.started.load(Ordering::Acquire)
            || out_block.is_null()
            || out_written.is_null()
            || capacity > MAX_FFI_PCM_BYTES as u64
        {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller provides writable metadata and buffer capacity.
        let output = if capacity == 0 {
            &mut []
        } else {
            if out_pcm.is_null() {
                return Err(SqStatusV1::InvalidArgument);
            }
            unsafe { slice::from_raw_parts_mut(out_pcm, capacity as usize) }
        };
        unsafe {
            ptr::write(out_written, 0);
        }
        let (metadata, len) = match e.queue.pop_into(output) {
            Ok(Some(item)) => item,
            Ok(None) => return Err(SqStatusV1::WouldBlock),
            Err(crate::CaptureError::InvalidBlock) => return Err(SqStatusV1::BufferTooSmall),
            Err(crate::CaptureError::ResourcePoisoned) => return Err(SqStatusV1::Resource),
            Err(_) => return Err(SqStatusV1::InvalidState),
        };
        let b = SqPcmBlockV1 {
            struct_size: core::mem::size_of::<SqPcmBlockV1>() as u32,
            flags: 0,
            sample_rate_hz: metadata.sample_rate_hz,
            channels: metadata.channels,
            sample_format: metadata.sample_format,
            frame_count: metadata.frames,
            reserved0: 0,
            first_frame_index: metadata.first_frame_index,
            monotonic_timestamp_ns: metadata.monotonic_timestamp_ns,
            capture_epoch: metadata.capture_epoch,
            payload_bytes: len as u64,
            sequence: metadata.sequence,
            reserved1: 0,
        };
        unsafe {
            ptr::write(out_block, b);
            ptr::write(out_written, len as u64);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Pointer arguments must reference valid readable/writable memory as required by the ABI.
/// Engine handles must remain live and must not be concurrently destroyed.
pub unsafe extern "C" fn sq_capture_finish_v1(raw: *mut SqCaptureEngine) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        e.queue.mark_stopped().map_err(|_| SqStatusV1::InvalidState)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SqCaptureConfigV1 {
        SqCaptureConfigV1 {
            struct_size: core::mem::size_of::<SqCaptureConfigV1>() as u32,
            sample_rate_hz: 48_000,
            channels: 1,
            sample_format: PCM_S16_LE_V1,
            queue_block_capacity: 2,
            max_block_frames: 128,
            flags: 0,
            reserved: [0; 4],
        }
    }

    #[test]
    fn ffi_round_trip_and_stop_requires_drain() {
        let mut handle = ptr::null_mut();
        let cfg = config();
        assert_eq!(
            unsafe { sq_capture_create_v1(&cfg, &mut handle) },
            SqStatusV1::Ok
        );
        assert!(!handle.is_null());
        assert_eq!(unsafe { sq_capture_start_v1(handle) }, SqStatusV1::Ok);
        assert_eq!(
            unsafe { sq_capture_start_v1(handle) },
            SqStatusV1::InvalidState
        );

        let samples = [0x12u8, 0x34, 0x56, 0x78];
        let block = SqPcmBlockV1 {
            struct_size: core::mem::size_of::<SqPcmBlockV1>() as u32,
            flags: 0,
            sample_rate_hz: 48_000,
            channels: 1,
            sample_format: PCM_S16_LE_V1,
            frame_count: 2,
            reserved0: 0,
            first_frame_index: 0,
            monotonic_timestamp_ns: 10,
            capture_epoch: 1,
            payload_bytes: 4,
            sequence: 1,
            reserved1: 0,
        };
        assert_eq!(
            unsafe { sq_capture_submit_pcm_v1(handle, &block, samples.as_ptr(), 4) },
            SqStatusV1::Ok
        );
        assert_eq!(
            unsafe { sq_capture_request_stop_v1(handle) },
            SqStatusV1::Ok
        );
        assert_eq!(
            unsafe { sq_capture_finish_v1(handle) },
            SqStatusV1::InvalidState
        );

        let mut out_block = SqPcmBlockV1 {
            struct_size: 0,
            flags: 0,
            sample_rate_hz: 0,
            channels: 0,
            sample_format: 0,
            frame_count: 0,
            reserved0: 0,
            first_frame_index: 0,
            monotonic_timestamp_ns: 0,
            capture_epoch: 0,
            payload_bytes: 0,
            sequence: 0,
            reserved1: 0,
        };
        let mut output = [0u8; 4];
        let mut written = 0u64;
        assert_eq!(
            unsafe {
                sq_capture_read_pcm_v1(handle, &mut out_block, output.as_mut_ptr(), 4, &mut written)
            },
            SqStatusV1::Ok
        );
        assert_eq!(output, samples);
        assert_eq!(written, 4);
        assert_eq!(out_block.sequence, 1);
        assert_eq!(unsafe { sq_capture_finish_v1(handle) }, SqStatusV1::Ok);
        let mut state = 0;
        assert_eq!(
            unsafe { sq_capture_get_state_v1(handle, &mut state) },
            SqStatusV1::Ok
        );
        assert_eq!(state, 3);
        unsafe { sq_capture_destroy_v1(handle) };
    }

    #[test]
    fn ffi_rejects_invalid_configuration_and_event_round_trip() {
        let mut handle = ptr::null_mut();
        let mut cfg = config();
        cfg.reserved[0] = 1;
        assert_eq!(
            unsafe { sq_capture_create_v1(&cfg, &mut handle) },
            SqStatusV1::InvalidArgument
        );
        cfg = config();
        assert_eq!(
            unsafe { sq_capture_create_v1(&cfg, &mut handle) },
            SqStatusV1::Ok
        );
        assert_eq!(unsafe { sq_capture_start_v1(handle) }, SqStatusV1::Ok);
        let event = SqCaptureEventV1 {
            struct_size: core::mem::size_of::<SqCaptureEventV1>() as u32,
            event_type: 1, flags: 0, reserved0: 0, event_sequence: 1,
            monotonic_timestamp_ns: 1, capture_epoch: 1, detail_code: 7,
            reserved1: 0,
        };
        assert_eq!(unsafe { sq_capture_push_event_v1(handle, &event) }, SqStatusV1::Ok);
        let mut out = event;
        out.event_type = 0;
        assert_eq!(unsafe { sq_capture_read_event_v1(handle, &mut out) }, SqStatusV1::Ok);
        assert_eq!(out.event_type, event.event_type);
        assert_eq!(out.detail_code, event.detail_code);
        assert_eq!(unsafe { sq_capture_request_stop_v1(handle) }, SqStatusV1::Ok);
        assert_eq!(unsafe { sq_capture_finish_v1(handle) }, SqStatusV1::Ok);
        unsafe { sq_capture_destroy_v1(handle) };
    }
}
