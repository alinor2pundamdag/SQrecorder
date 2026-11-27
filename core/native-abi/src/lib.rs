//! SQRecorder native ABI v1 foundational types.
//!
//! The exported C functions are declared in protocols/native-abi/abi_v1.h.
//! Engine behavior and exported symbol implementations are introduced in later batches.
//! Unsafe code at the eventual FFI boundary must be isolated, documented, and reviewed.
#![deny(unsafe_op_in_unsafe_fn)]

/// Native ABI major version.
pub const ABI_MAJOR_V1: u16 = 1;
/// Native ABI minor version.
pub const ABI_MINOR_V1: u16 = 1;
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
    AuthenticationFailed = -10,
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
        assert_eq!(SqStatusV1::AuthenticationFailed as i32, -10);
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

/// B4 opaque Vault key handles. Handles are process-local identifiers, not key bytes.
mod vault_ffi {
    use super::SqStatusV1;
    use sqrec_vault_crypto::{
        DEK_BYTES, GCM_NONCE_BYTES, GCM_TAG_BYTES, VaultCryptoError, VaultFileKey,
        decrypt_chunk_in_place, encrypt_chunk_in_place,
    };
    use std::{
        collections::HashMap,
        panic::{AssertUnwindSafe, catch_unwind},
        ptr, slice,
        sync::{
            Mutex, OnceLock,
            atomic::{AtomicU64, Ordering},
        },
    };
    use zeroize::Zeroize;

    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    static KEYS: OnceLock<Mutex<HashMap<u64, VaultFileKey>>> = OnceLock::new();

    fn registry() -> &'static Mutex<HashMap<u64, VaultFileKey>> {
        KEYS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn guarded(operation: impl FnOnce() -> Result<(), SqStatusV1>) -> SqStatusV1 {
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(Ok(())) => SqStatusV1::Ok,
            Ok(Err(status)) => status,
            Err(_) => SqStatusV1::Internal,
        }
    }

    fn map_crypto(error: VaultCryptoError) -> SqStatusV1 {
        match error {
            VaultCryptoError::InvalidKeyLength
            | VaultCryptoError::InvalidNonceLength
            | VaultCryptoError::InvalidTagLength => SqStatusV1::InvalidArgument,
            VaultCryptoError::AuthenticationFailed => SqStatusV1::AuthenticationFailed,
            VaultCryptoError::RandomSourceUnavailable => SqStatusV1::Resource,
            _ => SqStatusV1::Internal,
        }
    }

    unsafe fn input_slice<'a>(data: *const u8, len: usize) -> Result<&'a [u8], SqStatusV1> {
        if len == 0 {
            return Ok(&[]);
        }
        if data.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller contract requires a readable range of len bytes.
        Ok(unsafe { slice::from_raw_parts(data, len) })
    }

    unsafe fn output_slice<'a>(data: *mut u8, len: usize) -> Result<&'a mut [u8], SqStatusV1> {
        if len == 0 {
            return Ok(&mut []);
        }
        if data.is_null() {
            return Err(SqStatusV1::InvalidArgument);
        }
        // SAFETY: caller contract requires a writable range of len bytes.
        Ok(unsafe { slice::from_raw_parts_mut(data, len) })
    }

    fn allocate_handle(key: VaultFileKey) -> Result<u64, SqStatusV1> {
        let id = loop {
            let current = NEXT_HANDLE.load(Ordering::Relaxed);
            let next = current.checked_add(1).ok_or(SqStatusV1::Resource)?;
            if NEXT_HANDLE
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break current;
            }
        };
        let mut keys = registry().lock().map_err(|_| SqStatusV1::Resource)?;
        if keys.insert(id, key).is_some() {
            return Err(SqStatusV1::Internal);
        }
        Ok(id)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_key_create_v1(out_handle: *mut u64) -> SqStatusV1 {
        guarded(|| {
            if out_handle.is_null() {
                return Err(SqStatusV1::InvalidArgument);
            }
            let key = VaultFileKey::generate().map_err(map_crypto)?;
            let handle = allocate_handle(key)?;
            // SAFETY: validated non-null; caller provides writable u64 storage.
            unsafe { ptr::write(out_handle, handle) };
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_key_import_v1(
        dek: *const u8,
        dek_len: u32,
        out_handle: *mut u64,
    ) -> SqStatusV1 {
        guarded(|| {
            if out_handle.is_null() || dek_len as usize != DEK_BYTES {
                return Err(SqStatusV1::InvalidArgument);
            }
            // SAFETY: validated fixed length and caller-provided readable pointer.
            let input = unsafe { input_slice(dek, DEK_BYTES)? };
            let mut temporary = [0u8; DEK_BYTES];
            temporary.copy_from_slice(input);
            let key = VaultFileKey::from_bytes(&temporary).map_err(map_crypto)?;
            temporary.zeroize();
            let handle = allocate_handle(key)?;
            // SAFETY: validated non-null; caller provides writable u64 storage.
            unsafe { ptr::write(out_handle, handle) };
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_key_copy_for_wrap_v1(
        handle: u64,
        out_dek: *mut u8,
        capacity: u32,
        out_written: *mut u32,
    ) -> SqStatusV1 {
        guarded(|| {
            if out_written.is_null() {
                return Err(SqStatusV1::InvalidArgument);
            }
            // SAFETY: validated non-null; caller provides writable u32 storage.
            unsafe { ptr::write(out_written, DEK_BYTES as u32) };
            if (capacity as usize) < DEK_BYTES {
                return Err(SqStatusV1::BufferTooSmall);
            }
            // SAFETY: validated fixed writable range.
            let output = unsafe { output_slice(out_dek, DEK_BYTES)? };
            let keys = registry().lock().map_err(|_| SqStatusV1::Resource)?;
            let key = keys.get(&handle).ok_or(SqStatusV1::InvalidState)?;
            let mut temporary = key.copy_for_public_wrap();
            output.copy_from_slice(&temporary);
            temporary.zeroize();
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_key_destroy_v1(handle: u64) -> SqStatusV1 {
        guarded(|| {
            let mut keys = registry().lock().map_err(|_| SqStatusV1::Resource)?;
            keys.remove(&handle).ok_or(SqStatusV1::InvalidState)?;
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_encrypt_chunk_v1(
        handle: u64,
        nonce: *const u8,
        nonce_len: u32,
        aad: *const u8,
        aad_len: u32,
        buffer: *mut u8,
        buffer_len: u32,
        out_tag: *mut u8,
        tag_capacity: u32,
    ) -> SqStatusV1 {
        guarded(|| {
            if nonce_len as usize != GCM_NONCE_BYTES || tag_capacity < GCM_TAG_BYTES as u32 {
                return Err(SqStatusV1::InvalidArgument);
            }
            let nonce_slice = unsafe { input_slice(nonce, GCM_NONCE_BYTES)? };
            let mut nonce_array = [0u8; GCM_NONCE_BYTES];
            nonce_array.copy_from_slice(nonce_slice);
            let aad_slice = unsafe { input_slice(aad, aad_len as usize)? };
            let data = unsafe { output_slice(buffer, buffer_len as usize)? };
            let tag_out = unsafe { output_slice(out_tag, GCM_TAG_BYTES)? };
            let keys = registry().lock().map_err(|_| SqStatusV1::Resource)?;
            let key = keys.get(&handle).ok_or(SqStatusV1::InvalidState)?;
            let tag =
                encrypt_chunk_in_place(key, nonce_array, aad_slice, data).map_err(map_crypto)?;
            tag_out.copy_from_slice(&tag);
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sq_vault_decrypt_chunk_v1(
        handle: u64,
        nonce: *const u8,
        nonce_len: u32,
        aad: *const u8,
        aad_len: u32,
        buffer: *mut u8,
        buffer_len: u32,
        tag: *const u8,
        tag_len: u32,
    ) -> SqStatusV1 {
        guarded(|| {
            if nonce_len as usize != GCM_NONCE_BYTES || tag_len as usize != GCM_TAG_BYTES {
                return Err(SqStatusV1::InvalidArgument);
            }
            let nonce_slice = unsafe { input_slice(nonce, GCM_NONCE_BYTES)? };
            let mut nonce_array = [0u8; GCM_NONCE_BYTES];
            nonce_array.copy_from_slice(nonce_slice);
            let aad_slice = unsafe { input_slice(aad, aad_len as usize)? };
            let tag_slice = unsafe { input_slice(tag, GCM_TAG_BYTES)? };
            let data = unsafe { output_slice(buffer, buffer_len as usize)? };
            let keys = registry().lock().map_err(|_| SqStatusV1::Resource)?;
            let key = keys.get(&handle).ok_or(SqStatusV1::InvalidState)?;
            decrypt_chunk_in_place(key, nonce_array, aad_slice, data, tag_slice)
                .map_err(map_crypto)?;
            Ok(())
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn opaque_handle_copy_wrap_import_and_destroy_lifecycle() {
            let mut handle = 0u64;
            assert_eq!(
                unsafe { sq_vault_key_create_v1(&mut handle) },
                SqStatusV1::Ok
            );
            assert_ne!(handle, 0);

            let mut bytes = [0u8; DEK_BYTES];
            let mut written = 0u32;
            assert_eq!(
                unsafe {
                    sq_vault_key_copy_for_wrap_v1(
                        handle,
                        bytes.as_mut_ptr(),
                        bytes.len() as u32,
                        &mut written,
                    )
                },
                SqStatusV1::Ok
            );
            assert_eq!(written as usize, DEK_BYTES);

            let mut imported = 0u64;
            assert_eq!(
                unsafe {
                    sq_vault_key_import_v1(bytes.as_ptr(), bytes.len() as u32, &mut imported)
                },
                SqStatusV1::Ok
            );
            let mut expected = bytes;
            bytes.zeroize();

            let mut copied = [0u8; DEK_BYTES];
            assert_eq!(
                unsafe {
                    sq_vault_key_copy_for_wrap_v1(
                        imported,
                        copied.as_mut_ptr(),
                        copied.len() as u32,
                        &mut written,
                    )
                },
                SqStatusV1::Ok
            );
            assert_eq!(copied, expected);
            copied.zeroize();
            expected.zeroize();

            assert_eq!(unsafe { sq_vault_key_destroy_v1(handle) }, SqStatusV1::Ok);
            assert_eq!(unsafe { sq_vault_key_destroy_v1(imported) }, SqStatusV1::Ok);
            assert_eq!(
                unsafe {
                    sq_vault_key_copy_for_wrap_v1(
                        handle,
                        copied.as_mut_ptr(),
                        copied.len() as u32,
                        &mut written,
                    )
                },
                SqStatusV1::InvalidState
            );
        }

        #[test]
        fn ffi_chunk_encrypt_decrypt_and_tamper_zeroization() {
            let mut handle = 0u64;
            assert_eq!(
                unsafe { sq_vault_key_create_v1(&mut handle) },
                SqStatusV1::Ok
            );
            let nonce = [7u8; GCM_NONCE_BYTES];
            let aad = b"file|chunk=0";
            let original = b"ciphertext evidence";
            let mut buffer = original.to_vec();
            let mut tag = [0u8; GCM_TAG_BYTES];

            assert_eq!(
                unsafe {
                    sq_vault_encrypt_chunk_v1(
                        handle,
                        nonce.as_ptr(),
                        nonce.len() as u32,
                        aad.as_ptr(),
                        aad.len() as u32,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        tag.as_mut_ptr(),
                        tag.len() as u32,
                    )
                },
                SqStatusV1::Ok
            );
            assert_ne!(buffer, original);

            assert_eq!(
                unsafe {
                    sq_vault_decrypt_chunk_v1(
                        handle,
                        nonce.as_ptr(),
                        nonce.len() as u32,
                        aad.as_ptr(),
                        aad.len() as u32,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        tag.as_ptr(),
                        tag.len() as u32,
                    )
                },
                SqStatusV1::Ok
            );
            assert_eq!(buffer, original);

            buffer.copy_from_slice(original);
            let mut bad_tag = tag;
            bad_tag[0] ^= 1;
            assert_eq!(
                unsafe {
                    sq_vault_decrypt_chunk_v1(
                        handle,
                        nonce.as_ptr(),
                        nonce.len() as u32,
                        aad.as_ptr(),
                        aad.len() as u32,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        bad_tag.as_ptr(),
                        bad_tag.len() as u32,
                    )
                },
                SqStatusV1::AuthenticationFailed
            );
            assert!(buffer.iter().all(|b| *b == 0));
            assert_eq!(unsafe { sq_vault_key_destroy_v1(handle) }, SqStatusV1::Ok);
        }
    }
}

/// JNI entry points used by the Android KMP Vault adapter. The Java/Kotlin
/// arrays are copied to native memory, consumed by the C ABI, then zeroized.
mod jni_vault {
    use super::vault_ffi::*;
    use jni::{
        JNIEnv,
        objects::{JByteArray, JObject},
        sys::{jbyteArray, jint, jlong},
    };
    use std::ptr;
    use zeroize::Zeroize;

    fn throw_state(env: &mut JNIEnv, message: &str) {
        let _ = env.throw_new("java/lang/IllegalStateException", message);
    }

    fn status_ok(status: super::SqStatusV1) -> bool {
        status == super::SqStatusV1::Ok
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeCreateFileKeyHandle(
        mut env: JNIEnv,
        _this: JObject,
    ) -> jlong {
        let mut handle = 0u64;
        let status = unsafe { sq_vault_key_create_v1(&mut handle) };
        if !status_ok(status) {
            throw_state(&mut env, "native Vault key creation failed");
            return 0;
        }
        handle as jlong
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeDestroyFileKeyHandle(
        _env: JNIEnv,
        _this: JObject,
        handle: jlong,
    ) -> jint {
        unsafe { sq_vault_key_destroy_v1(handle as u64) as jint }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeCopyFileKeyForWrapping(
        mut env: JNIEnv,
        _this: JObject,
        handle: jlong,
    ) -> jbyteArray {
        let mut dek = [0u8; DEK_BYTES];
        let mut written = 0u32;
        let status = unsafe {
            sq_vault_key_copy_for_wrap_v1(
                handle as u64,
                dek.as_mut_ptr(),
                dek.len() as u32,
                &mut written,
            )
        };
        if !status_ok(status) || written as usize != DEK_BYTES {
            dek.zeroize();
            throw_state(&mut env, "native Vault DEK wrap-copy failed");
            return ptr::null_mut();
        }
        let result = env.byte_array_from_slice(&dek);
        dek.zeroize();
        match result {
            Ok(array) => array.into_raw(),
            Err(_) => {
                throw_state(&mut env, "JNI DEK byte-array allocation failed");
                ptr::null_mut()
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeImportUnwrappedFileKey(
        mut env: JNIEnv,
        _this: JObject,
        input: JByteArray<'_>,
    ) -> jlong {
        let mut dek = match env.convert_byte_array(input) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI DEK input conversion failed");
                return 0;
            }
        };
        let mut handle = 0u64;
        let status = unsafe {
            sq_vault_key_import_v1(dek.as_ptr(), dek.len() as u32, &mut handle)
        };
        dek.zeroize();
        if !status_ok(status) {
            throw_state(&mut env, "native Vault DEK import failed");
            return 0;
        }
        handle as jlong
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeEncryptChunk(
        mut env: JNIEnv,
        _this: JObject,
        handle: jlong,
        nonce_array: JByteArray<'_>,
        aad_array: JByteArray<'_>,
        plaintext_array: JByteArray<'_>,
    ) -> jbyteArray {
        let nonce = match env.convert_byte_array(nonce_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI nonce conversion failed");
                return ptr::null_mut();
            }
        };
        let aad = match env.convert_byte_array(aad_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI AAD conversion failed");
                return ptr::null_mut();
            }
        };
        let mut data = match env.convert_byte_array(plaintext_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI plaintext conversion failed");
                return ptr::null_mut();
            }
        };
        if nonce.len() != GCM_NONCE_BYTES {
            data.zeroize();
            throw_state(&mut env, "invalid Vault chunk nonce length");
            return ptr::null_mut();
        }
        let mut tag = [0u8; GCM_TAG_BYTES];
        let status = unsafe {
            sq_vault_encrypt_chunk_v1(
                handle as u64,
                nonce.as_ptr(),
                nonce.len() as u32,
                aad.as_ptr(),
                aad.len() as u32,
                data.as_mut_ptr(),
                data.len() as u32,
                tag.as_mut_ptr(),
                tag.len() as u32,
            )
        };
        if !status_ok(status) {
            data.zeroize();
            tag.zeroize();
            throw_state(&mut env, "native Vault chunk encryption failed");
            return ptr::null_mut();
        }
        data.extend_from_slice(&tag);
        tag.zeroize();
        let result = env.byte_array_from_slice(&data);
        data.zeroize();
        match result {
            Ok(array) => array.into_raw(),
            Err(_) => {
                throw_state(&mut env, "JNI ciphertext allocation failed");
                ptr::null_mut()
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_alinor_sqrecorder_vault_android_JniVaultNativeKeyBridge_nativeDecryptChunk(
        mut env: JNIEnv,
        _this: JObject,
        handle: jlong,
        nonce_array: JByteArray<'_>,
        aad_array: JByteArray<'_>,
        ciphertext_array: JByteArray<'_>,
    ) -> jbyteArray {
        let nonce = match env.convert_byte_array(nonce_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI nonce conversion failed");
                return ptr::null_mut();
            }
        };
        let aad = match env.convert_byte_array(aad_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI AAD conversion failed");
                return ptr::null_mut();
            }
        };
        let mut combined = match env.convert_byte_array(ciphertext_array) {
            Ok(bytes) => bytes,
            Err(_) => {
                throw_state(&mut env, "JNI ciphertext conversion failed");
                return ptr::null_mut();
            }
        };
        if nonce.len() != GCM_NONCE_BYTES || combined.len() < GCM_TAG_BYTES {
            combined.zeroize();
            throw_state(&mut env, "invalid Vault ciphertext or nonce length");
            return ptr::null_mut();
        }
        let mut tag = combined.split_off(combined.len() - GCM_TAG_BYTES);
        let mut data = combined;
        let status = unsafe {
            sq_vault_decrypt_chunk_v1(
                handle as u64,
                nonce.as_ptr(),
                nonce.len() as u32,
                aad.as_ptr(),
                aad.len() as u32,
                data.as_mut_ptr(),
                data.len() as u32,
                tag.as_ptr(),
                tag.len() as u32,
            )
        };
        tag.zeroize();
        if !status_ok(status) {
            data.zeroize();
            throw_state(&mut env, "native Vault chunk authentication/decryption failed");
            return ptr::null_mut();
        }
        let result = env.byte_array_from_slice(&data);
        data.zeroize();
        match result {
            Ok(array) => array.into_raw(),
            Err(_) => {
                throw_state(&mut env, "JNI plaintext allocation failed");
                ptr::null_mut()
            }
        }
    }
}
