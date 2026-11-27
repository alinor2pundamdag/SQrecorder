//! Capture-engine C ABI v1. Caller owns handle lifetime and must not destroy it
//! concurrently with another operation. Input pointers must reference valid ranges.
use crate::{
    BoundedPcmQueue, CaptureStatus, PcmMetadata, SqCaptureConfigV1, SqPcmBlockV1,
    SqCaptureEventV1, SqAbiInfoV1, SqStatusV1, ABI_MAJOR_V1, ABI_MINOR_V1,
    PCM_S16_LE_V1, CHANNEL_LAYOUT_MONO_V1,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
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

unsafe fn engine<'a>(raw: *mut SqCaptureEngine) -> Result<&'a SqCaptureEngine, SqStatusV1> {
    if raw.is_null() { return Err(SqStatusV1::InvalidArgument); }
    // SAFETY: ABI caller guarantees a live handle returned by create, not destroyed concurrently.
    Ok(unsafe { &*raw })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_get_abi_info_v1(out: *mut SqAbiInfoV1) -> SqStatusV1 {
    guarded(|| {
        if out.is_null() { return Err(SqStatusV1::InvalidArgument); }
        // SAFETY: caller supplies writable storage for the ABI struct.
        unsafe { ptr::write(out, SqAbiInfoV1 {
            struct_size: core::mem::size_of::<SqAbiInfoV1>() as u32,
            abi_major: ABI_MAJOR_V1, abi_minor: ABI_MINOR_V1,
            feature_bits: 0, reserved: [0; 4],
        }) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_create_v1(
    config: *const SqCaptureConfigV1,
    out: *mut *mut SqCaptureEngine,
) -> SqStatusV1 {
    guarded(|| {
        if config.is_null() || out.is_null() { return Err(SqStatusV1::InvalidArgument); }
        // SAFETY: caller provides readable config and writable output pointer.
        let c = unsafe { &*config };
        if c.struct_size as usize != core::mem::size_of::<SqCaptureConfigV1>()
            || c.sample_rate_hz != 48_000 && c.sample_rate_hz != 44_100
            || c.channels != 1 || c.sample_format != PCM_S16_LE_V1
            || c.flags != 0 || c.reserved.iter().any(|v| *v != 0)
        { return Err(SqStatusV1::InvalidArgument); }
        let queue = BoundedPcmQueue::new(c.queue_block_capacity, c.max_block_frames)
            .map_err(|_| SqStatusV1::InvalidArgument)?;
        let boxed = Box::new(SqCaptureEngine { queue, started: AtomicBool::new(false) });
        // SAFETY: validated output pointer; transfer ownership to the ABI handle.
        unsafe { ptr::write(out, Box::into_raw(boxed)); }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_start_v1(raw: *mut SqCaptureEngine) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        e.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SqStatusV1::InvalidState)?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_submit_pcm_v1(
    raw: *mut SqCaptureEngine, block: *const SqPcmBlockV1,
    pcm: *const u8, pcm_bytes: u64,
) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if !e.started.load(Ordering::Acquire) { return Err(SqStatusV1::InvalidState); }
        if block.is_null() || pcm_bytes > MAX_FFI_PCM_BYTES as u64 {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller guarantees readable block and PCM range of pcm_bytes.
        let b = unsafe { &*block };
        if b.struct_size as usize != core::mem::size_of::<SqPcmBlockV1>()
            || b.flags != 0 || b.reserved0 != 0 || b.reserved1 != 0
            || b.payload_bytes != pcm_bytes || b.payload_bytes == 0
            || b.sequence == 0 || b.capture_epoch == 0 || b.monotonic_timestamp_ns == 0
        { return Err(SqStatusV1::InvalidArgument); }
        let len = usize::try_from(pcm_bytes).map_err(|_| SqStatusV1::InvalidArgument)?;
        if pcm.is_null() { return Err(SqStatusV1::InvalidArgument); }
        // SAFETY: pointer and length are supplied by the ABI caller and validated non-null/bounded.
        let bytes = unsafe { slice::from_raw_parts(pcm, len) };
        let metadata = PcmMetadata {
            sample_rate_hz: b.sample_rate_hz, channels: b.channels,
            sample_format: b.sample_format, frames: b.frame_count,
            first_frame_index: b.first_frame_index,
            monotonic_timestamp_ns: b.monotonic_timestamp_ns,
            capture_epoch: b.capture_epoch, sequence: b.sequence,
        };
        e.queue.submit(metadata, bytes).map_err(|error| match error {
            crate::CaptureError::QueueOverflow => SqStatusV1::Resource,
            crate::CaptureError::InvalidState => SqStatusV1::InvalidState,
            crate::CaptureError::ResourcePoisoned => SqStatusV1::Resource,
            _ => SqStatusV1::InvalidArgument,
        })
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_push_event_v1(
    raw: *mut SqCaptureEngine, event: *const SqCaptureEventV1,
) -> SqStatusV1 {
    guarded(|| {
        let _ = unsafe { engine(raw)? };
        if event.is_null() { return Err(SqStatusV1::InvalidArgument); }
        // Event persistence/dispatch is not implemented in this ABI slice.
        Err(SqStatusV1::Unsupported)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_request_stop_v1(raw: *mut SqCaptureEngine) -> SqStatusV1 {
    guarded(|| {
        let e = unsafe { engine(raw)? };
        if !e.started.load(Ordering::Acquire) { return Err(SqStatusV1::InvalidState); }
        e.queue.request_stop().map_err(|_| SqStatusV1::InvalidState)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_get_state_v1(
    raw: *const SqCaptureEngine, out: *mut u32,
) -> SqStatusV1 {
    guarded(|| {
        if raw.is_null() || out.is_null() { return Err(SqStatusV1::InvalidArgument); }
        // SAFETY: handle is live and caller provides writable u32.
        let e = unsafe { &*raw };
        let state = if !e.started.load(Ordering::Acquire) { 0 } else {
            match e.queue.status().map_err(|_| SqStatusV1::Resource)? {
                CaptureStatus::Running => 1, CaptureStatus::Stopping => 2,
                CaptureStatus::Stopped => 3, CaptureStatus::Failed => 4,
            }
        };
        // SAFETY: validated non-null output pointer.
        unsafe { ptr::write(out, state); }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sq_capture_destroy_v1(raw: *mut SqCaptureEngine) {
    if !raw.is_null() {
        // SAFETY: caller must destroy exactly once and ensure no concurrent use.
        drop(unsafe { Box::from_raw(raw) });
    }
}
