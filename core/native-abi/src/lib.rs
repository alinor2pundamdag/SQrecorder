//! SQRecorder native ABI v1 foundational types.
//!
//! The exported C functions are declared in protocols/native-abi/abi_v1.h.
//! Engine behavior and exported symbol implementations are introduced in later batches.
//! Unsafe code at the eventual FFI boundary must be isolated, documented, and reviewed.
#![deny(unsafe_op_in_unsafe_fn)]

/// Native ABI major version.
pub const ABI_MAJOR_V1: u16 = 1;
/// Native ABI minor version.
pub const ABI_MINOR_V1: u16 = 0;
/// Signed 16-bit little-endian PCM sample format identifier.
pub const PCM_S16_LE_V1: u16 = 1;
/// Mono channel-layout identifier.
pub const CHANNEL_LAYOUT_MONO_V1: u32 = 1;

/// Stable status values shared with the C header.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqStatusV1 {
    Ok = 0,
    InvalidArgument = -1,
    AbiMismatch = -2,
    InvalidState = -3,
    BufferTooSmall = -4,
    WouldBlock = -5,
    Cancelled = -6,
    Resource = -7,
    Unsupported = -8,
    Internal = -9,
}

/// ABI information returned by the version negotiation function.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqAbiInfoV1 {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub feature_bits: u64,
    pub reserved: [u32; 4],
}

/// Canonical PCM format descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqPcmFormatV1 {
    pub struct_size: u32,
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub sample_format: u16,
    pub channel_layout: u32,
    pub reserved: u32,
}

/// Capture engine configuration. Queue capacity and block size are bounded inputs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqCaptureConfigV1 {
    pub struct_size: u32,
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub sample_format: u16,
    pub queue_block_capacity: u32,
    pub max_block_frames: u32,
    pub flags: u32,
    pub reserved: [u32; 4],
}

/// Fixed-width PCM metadata; serialized PCM bytes are described separately.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqPcmBlockV1 {
    pub struct_size: u32,
    pub flags: u32,
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub sample_format: u16,
    pub frame_count: u32,
    pub reserved0: u32,
    pub first_frame_index: u64,
    pub monotonic_timestamp_ns: u64,
    pub capture_epoch: u64,
    pub payload_bytes: u64,
    pub sequence: u32,
    pub reserved1: u32,
}

/// Capture event; event payload details are represented by stable numeric codes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqCaptureEventV1 {
    pub struct_size: u32,
    pub event_type: u32,
    pub flags: u32,
    pub reserved0: u32,
    pub event_sequence: u64,
    pub monotonic_timestamp_ns: u64,
    pub capture_epoch: u64,
    pub detail_code: u32,
    pub reserved1: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn status_values_match_c_contract() {
        assert_eq!(SqStatusV1::Ok as i32, 0);
        assert_eq!(SqStatusV1::WouldBlock as i32, -5);
        assert_eq!(SqStatusV1::Internal as i32, -9);
    }

    #[test]
    fn abi_struct_layouts_match_v1_header() {
        assert_eq!(size_of::<SqAbiInfoV1>(), 32);
        assert_eq!(size_of::<SqPcmFormatV1>(), 20);
        assert_eq!(size_of::<SqCaptureConfigV1>(), 40);
        assert_eq!(size_of::<SqPcmBlockV1>(), 64);
        assert_eq!(size_of::<SqCaptureEventV1>(), 48);
    }

    #[test]
    fn format_constants_match_v1_header() {
        assert_eq!(PCM_S16_LE_V1, 1);
        assert_eq!(CHANNEL_LAYOUT_MONO_V1, 1);
    }
}
