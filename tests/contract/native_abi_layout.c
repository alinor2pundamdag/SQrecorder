#include "abi_v1.h"
#include <stddef.h>

_Static_assert(sizeof(sq_abi_info_v1) == 32, "sq_abi_info_v1 size");
_Static_assert(sizeof(sq_pcm_format_v1) == 20, "sq_pcm_format_v1 size");
_Static_assert(sizeof(sq_capture_config_v1) == 40, "sq_capture_config_v1 size");
_Static_assert(sizeof(sq_pcm_block_v1) == SQ_ABI_PCM_BLOCK_V1_SIZE, "sq_pcm_block_v1 size");
_Static_assert(sizeof(sq_capture_event_v1) == 48, "sq_capture_event_v1 size");
_Static_assert(offsetof(sq_pcm_block_v1, first_frame_index) == 24, "PCM first-frame offset");
_Static_assert(offsetof(sq_pcm_block_v1, payload_bytes) == 48, "PCM payload-size offset");
_Static_assert(offsetof(sq_pcm_block_v1, sequence) == 56, "PCM sequence offset");

int main(void) {
    return SQ_ABI_MAJOR_V1 != 1u || SQ_ABI_MINOR_V1 != 1u;
}
