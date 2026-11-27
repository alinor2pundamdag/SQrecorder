//! JNI bridge for the native bounded capture ABI.
//! Java-side contract uses preallocated direct ByteBuffers for PCM payloads.
use crate::{
    PCM_S16_LE_V1, SqCaptureConfigV1, SqCaptureEventV1, SqPcmBlockV1, SqStatusV1,
    capture_ffi::{
        SqCaptureEngine, sq_capture_create_v1, sq_capture_destroy_v1, sq_capture_finish_v1,
        sq_capture_get_state_v1, sq_capture_push_event_v1, sq_capture_read_event_v1,
        sq_capture_read_pcm_v1, sq_capture_request_stop_v1, sq_capture_start_v1,
        sq_capture_submit_pcm_v1,
    },
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JByteBuffer, JObject},
    sys::{jint, jlong},
};
use std::{mem::size_of, ptr, slice};

const PCM_BLOCK_SIZE: usize = size_of::<SqPcmBlockV1>();
const EVENT_SIZE: usize = size_of::<SqCaptureEventV1>();

fn handle(value: jlong) -> *mut SqCaptureEngine {
    if value <= 0 {
        ptr::null_mut()
    } else {
        value as usize as *mut SqCaptureEngine
    }
}

fn copy_struct_to_java(env: &mut JNIEnv, array: &JByteArray, bytes: &[u8]) -> bool {
    if env
        .get_array_length(array)
        .map(|len| len as usize)
        .unwrap_or(0)
        < bytes.len()
    {
        return false;
    }
    // SAFETY: byte slice is valid for the duration of the JNI copy; signed byte has same layout.
    let signed = unsafe { slice::from_raw_parts(bytes.as_ptr().cast::<i8>(), bytes.len()) };
    env.set_byte_array_region(array, 0, signed).is_ok()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeCreate(
    mut env: JNIEnv,
    _this: JObject,
    rate: jint,
    capacity: jint,
    max_frames: jint,
) -> jlong {
    if rate <= 0 || capacity <= 0 || max_frames <= 0 {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "capture queue configuration must be positive",
        );
        return 0;
    }
    let config = SqCaptureConfigV1 {
        struct_size: size_of::<SqCaptureConfigV1>() as u32,
        sample_rate_hz: rate as u32,
        channels: 1,
        sample_format: PCM_S16_LE_V1,
        queue_block_capacity: capacity as u32,
        max_block_frames: max_frames as u32,
        flags: 0,
        reserved: [0; 4],
    };
    let mut raw = ptr::null_mut();
    let status = unsafe { sq_capture_create_v1(&config, &mut raw) };
    if status != SqStatusV1::Ok || raw.is_null() {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            "native bounded capture queue creation failed",
        );
        return 0;
    }
    let status = unsafe { sq_capture_start_v1(raw) };
    if status != SqStatusV1::Ok {
        unsafe { sq_capture_destroy_v1(raw) };
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            "native bounded capture queue start failed",
        );
        return 0;
    }
    raw as usize as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeSubmit(
    env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
    pcm: JByteBuffer,
    rate: jint,
    bytes: jint,
    frames: jint,
    first_frame: jlong,
    timestamp_ns: jlong,
    epoch: jlong,
    sequence: jint,
) -> jint {
    let raw = handle(raw_handle);
    if raw.is_null()
        || bytes <= 0
        || frames <= 0
        || first_frame < 0
        || timestamp_ns <= 0
        || epoch <= 0
        || sequence <= 0
    {
        return SqStatusV1::InvalidArgument as jint;
    }
    let capacity = match env.get_direct_buffer_capacity(&pcm) {
        Ok(value) => value,
        Err(_) => return SqStatusV1::InvalidArgument as jint,
    };
    if capacity < bytes as usize {
        return SqStatusV1::BufferTooSmall as jint;
    }
    let address = match env.get_direct_buffer_address(&pcm) {
        Ok(value) if !value.is_null() => value,
        _ => return SqStatusV1::InvalidArgument as jint,
    };
    let block = SqPcmBlockV1 {
        struct_size: PCM_BLOCK_SIZE as u32,
        flags: 0,
        sample_rate_hz: rate as u32,
        channels: 1,
        sample_format: PCM_S16_LE_V1,
        frame_count: frames as u32,
        reserved0: 0,
        first_frame_index: first_frame as u64,
        monotonic_timestamp_ns: timestamp_ns as u64,
        capture_epoch: epoch as u64,
        payload_bytes: bytes as u64,
        sequence: sequence as u32,
        reserved1: 0,
    };
    // The queue's negotiated rate is validated by the Kotlin constructor and the C ABI.
    unsafe { sq_capture_submit_pcm_v1(raw, &block, address.cast_const(), bytes as u64) as jint }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeRead(
    mut env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
    pcm: JByteBuffer,
    metadata: JByteArray,
    capacity: jint,
) -> jlong {
    let raw = handle(raw_handle);
    if raw.is_null()
        || capacity <= 0
        || env
            .get_array_length(&metadata)
            .map(|len| len as usize)
            .unwrap_or(0)
            < PCM_BLOCK_SIZE
    {
        return SqStatusV1::InvalidArgument as jlong;
    }
    let direct_capacity = match env.get_direct_buffer_capacity(&pcm) {
        Ok(value) => value,
        Err(_) => return SqStatusV1::InvalidArgument as jlong,
    };
    if direct_capacity < capacity as usize {
        return SqStatusV1::BufferTooSmall as jlong;
    }
    let address = match env.get_direct_buffer_address(&pcm) {
        Ok(value) if !value.is_null() => value,
        _ => return SqStatusV1::InvalidArgument as jlong,
    };
    let mut block = SqPcmBlockV1 {
        struct_size: PCM_BLOCK_SIZE as u32,
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
    let mut written = 0u64;
    let status =
        unsafe { sq_capture_read_pcm_v1(raw, &mut block, address, capacity as u64, &mut written) };
    if status != SqStatusV1::Ok {
        return status as jlong;
    }
    // SAFETY: repr(C) block is initialized and has the declared ABI size.
    let bytes = unsafe {
        slice::from_raw_parts((&block as *const SqPcmBlockV1).cast::<u8>(), PCM_BLOCK_SIZE)
    };
    if !copy_struct_to_java(&mut env, &metadata, bytes) {
        return SqStatusV1::Internal as jlong;
    }
    written as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativePushEvent(
    _env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
    event_type: jint,
    sequence: jlong,
    timestamp_ns: jlong,
    epoch: jlong,
    detail: jint,
) -> jint {
    let raw = handle(raw_handle);
    if raw.is_null() {
        return SqStatusV1::InvalidArgument as jint;
    }
    let event = SqCaptureEventV1 {
        struct_size: EVENT_SIZE as u32,
        event_type: event_type as u32,
        flags: 0,
        reserved0: 0,
        event_sequence: sequence as u64,
        monotonic_timestamp_ns: timestamp_ns as u64,
        capture_epoch: epoch as u64,
        detail_code: detail as u32,
        reserved1: 0,
    };
    unsafe { sq_capture_push_event_v1(raw, &event) as jint }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeReadEvent(
    mut env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
    metadata: JByteArray,
) -> jint {
    let raw = handle(raw_handle);
    if raw.is_null()
        || env
            .get_array_length(&metadata)
            .map(|len| len as usize)
            .unwrap_or(0)
            < EVENT_SIZE
    {
        return SqStatusV1::InvalidArgument as jint;
    }
    let mut event = SqCaptureEventV1 {
        struct_size: EVENT_SIZE as u32,
        event_type: 0,
        flags: 0,
        reserved0: 0,
        event_sequence: 0,
        monotonic_timestamp_ns: 0,
        capture_epoch: 0,
        detail_code: 0,
        reserved1: 0,
    };
    let status = unsafe { sq_capture_read_event_v1(raw, &mut event) };
    if status != SqStatusV1::Ok {
        return status as jint;
    }
    // SAFETY: repr(C) event is initialized and has the declared ABI size.
    let bytes = unsafe {
        slice::from_raw_parts((&event as *const SqCaptureEventV1).cast::<u8>(), EVENT_SIZE)
    };
    if !copy_struct_to_java(&mut env, &metadata, bytes) {
        return SqStatusV1::Internal as jint;
    }
    SqStatusV1::Ok as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeRequestStop(
    _env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
) -> jint {
    unsafe { sq_capture_request_stop_v1(handle(raw_handle)) as jint }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeFinish(
    _env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
) -> jint {
    unsafe { sq_capture_finish_v1(handle(raw_handle)) as jint }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeState(
    _env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
) -> jint {
    let mut state = 0u32;
    let status = unsafe { sq_capture_get_state_v1(handle(raw_handle), &mut state) };
    if status == SqStatusV1::Ok {
        state as jint
    } else {
        status as jint
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_alinor_sqrecorder_capture_JniCaptureQueue_nativeDestroy(
    _env: JNIEnv,
    _this: JObject,
    raw_handle: jlong,
) {
    unsafe {
        sq_capture_destroy_v1(handle(raw_handle));
    }
}
