#ifndef SQREC_NATIVE_ABI_V1_H
#define SQREC_NATIVE_ABI_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SQ_ABI_MAJOR_V1 1u
#define SQ_ABI_MINOR_V1 1u
#define SQ_ABI_PCM_BLOCK_V1_SIZE 64u

typedef struct sq_capture_engine sq_capture_engine;

typedef int32_t sq_status_v1;
enum {
    SQ_OK = 0,
    SQ_ERR_INVALID_ARGUMENT = -1,
    SQ_ERR_ABI_MISMATCH = -2,
    SQ_ERR_INVALID_STATE = -3,
    SQ_ERR_BUFFER_TOO_SMALL = -4,
    SQ_ERR_WOULD_BLOCK = -5,
    SQ_ERR_CANCELLED = -6,
    SQ_ERR_RESOURCE = -7,
    SQ_ERR_UNSUPPORTED = -8,
    SQ_ERR_INTERNAL = -9,
    SQ_ERR_AUTHENTICATION_FAILED = -10
};

typedef struct sq_abi_info_v1 {
    uint32_t struct_size;
    uint16_t abi_major;
    uint16_t abi_minor;
    uint64_t feature_bits;
    uint32_t reserved[4];
} sq_abi_info_v1;

typedef struct sq_pcm_format_v1 {
    uint32_t struct_size;
    uint32_t sample_rate_hz;
    uint16_t channels;
    uint16_t sample_format;
    uint32_t channel_layout;
    uint32_t reserved;
} sq_pcm_format_v1;

enum {
    SQ_PCM_S16_LE = 1u,
    SQ_CHANNEL_LAYOUT_MONO = 1u
};

typedef struct sq_capture_config_v1 {
    uint32_t struct_size;
    uint32_t sample_rate_hz;
    uint16_t channels;
    uint16_t sample_format;
    uint32_t queue_block_capacity;
    uint32_t max_block_frames;
    uint32_t flags;
    uint32_t reserved[4];
} sq_capture_config_v1;

/* This descriptor is metadata only. PCM bytes are passed separately. */
typedef struct sq_pcm_block_v1 {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t sample_rate_hz;
    uint16_t channels;
    uint16_t sample_format;
    uint32_t frame_count;
    uint32_t reserved0;
    uint64_t first_frame_index;
    uint64_t monotonic_timestamp_ns;
    uint64_t capture_epoch;
    uint64_t payload_bytes;
    uint32_t sequence;
    uint32_t reserved1;
} sq_pcm_block_v1;

typedef struct sq_capture_event_v1 {
    uint32_t struct_size;
    uint32_t event_type;
    uint32_t flags;
    uint32_t reserved0;
    uint64_t event_sequence;
    uint64_t monotonic_timestamp_ns;
    uint64_t capture_epoch;
    uint32_t detail_code;
    uint32_t reserved1;
} sq_capture_event_v1;

enum {
    SQ_CAPTURE_STATE_CREATED = 0u,
    SQ_CAPTURE_STATE_RUNNING = 1u,
    SQ_CAPTURE_STATE_STOPPING = 2u,
    SQ_CAPTURE_STATE_STOPPED = 3u,
    SQ_CAPTURE_STATE_FAILED = 4u
};

sq_status_v1 sq_get_abi_info_v1(sq_abi_info_v1 *out_info);
sq_status_v1 sq_capture_create_v1(
    const sq_capture_config_v1 *config,
    sq_capture_engine **out_engine);
sq_status_v1 sq_capture_start_v1(sq_capture_engine *engine);
sq_status_v1 sq_capture_submit_pcm_v1(
    sq_capture_engine *engine,
    const sq_pcm_block_v1 *block,
    const uint8_t *pcm_data,
    uint64_t pcm_data_bytes);
sq_status_v1 sq_capture_push_event_v1(
    sq_capture_engine *engine,
    const sq_capture_event_v1 *event);
sq_status_v1 sq_capture_request_stop_v1(sq_capture_engine *engine);
sq_status_v1 sq_capture_get_state_v1(
    const sq_capture_engine *engine,
    uint32_t *out_state);
void sq_capture_destroy_v1(sq_capture_engine *engine);

/* Vault v1: opaque process-local key handles; no plaintext DEK is returned
 * to shared/KMP models. copy_for_wrap is restricted to public-key wrapping and
 * the caller must zeroize its temporary buffer immediately. */
typedef uint64_t sq_vault_key_handle_v1;
sq_status_v1 sq_vault_key_create_v1(uint64_t *out_handle);
sq_status_v1 sq_vault_key_import_v1(
    const uint8_t *dek, uint32_t dek_bytes, uint64_t *out_handle);
sq_status_v1 sq_vault_key_copy_for_wrap_v1(
    uint64_t handle, uint8_t *out_dek, uint32_t capacity, uint32_t *out_written);
sq_status_v1 sq_vault_key_destroy_v1(uint64_t handle);
sq_status_v1 sq_vault_encrypt_chunk_v1(
    uint64_t handle, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *aad, uint32_t aad_len, uint8_t *buffer, uint32_t buffer_len,
    uint8_t *out_tag, uint32_t tag_capacity);
sq_status_v1 sq_vault_decrypt_chunk_v1(
    uint64_t handle, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *aad, uint32_t aad_len, uint8_t *buffer, uint32_t buffer_len,
    const uint8_t *tag, uint32_t tag_len);


#ifdef __cplusplus
}
#endif

#endif /* SQREC_NATIVE_ABI_V1_H */
