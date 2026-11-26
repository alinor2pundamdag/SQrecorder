# SQPC PCM block serialization v1

**Status:** Contract for B2. This is a byte serialization format, not a C/Rust memory layout. Never serialize a native struct by copying its memory.

## Header

Each block is exactly a 64-byte header followed by PCM payload. All multi-byte integers are unsigned and little-endian. Version 1 requires reserved bytes to be zero.

| Offset | Bytes | Field | v1 rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SQPC` |
| 4 | 2 | version | 1 |
| 6 | 2 | header_bytes | 64 |
| 8 | 4 | flags | Defined bits below |
| 12 | 4 | sample_rate_hz | 48000 canonical; 44100 fallback |
| 16 | 2 | channels | 1 |
| 18 | 2 | sample_format | 1 = signed 16-bit little-endian |
| 20 | 4 | frame_count | Nonzero for a data block |
| 24 | 8 | first_frame_index | Session-monotonic source frame index |
| 32 | 8 | monotonic_timestamp_ns | Monotonic clock, never wall-clock time |
| 40 | 8 | capture_epoch | Increment after a discontinuity/re-established capture |
| 48 | 8 | payload_bytes | Must equal frame_count × channels × 2 |
| 56 | 4 | sequence | Strictly increasing block sequence; do not wrap within a session |
| 60 | 4 | reserved | Zero |

Payload is interleaved S16LE sample data. For v1 mono, each frame is exactly two bytes. The serialized header has no implicit padding.

## Flags

| Bit | Name | Meaning |
|---:|---|---|
| 0 | DISCONTINUITY | A gap or continuity break occurred; journal its cause and extent |
| 1 | ROUTE_CHANGE | Input route changed; continuity must be evaluated, not assumed |
| 2 | OVERRUN_RECOVERED | Device overrun was detected and capture resumed |
| 3 | FORMAT_CHANGE | Explicit format boundary; must be accompanied by an epoch change and journal event |
| 4 | TIMESTAMP_ESTIMATED | Timestamp is estimated rather than directly measured |
| 5 | FINAL_BLOCK | Final data block for this capture stream |

Unknown flag bits are rejected by v1 readers. A flag does not replace the durable session event journal.

## Validation

Reject a block before consuming it if any of these apply:

- Wrong magic, unsupported version, or header size other than 64.
- Nonzero reserved field, unsupported channel count/sample format, or sample rate outside the declared capture contract.
- Zero frame count for a data block; arithmetic overflow; payload length mismatch; truncated or trailing bytes.
- Sequence regression/wrap, frame-index regression, invalid epoch transition, or invalid timestamp ordering.
- Payload is not a whole number of frames.

A capture format is selected before recording. A format transition is not permission for silent live sample-rate switching; any actual transition is explicit, journaled, and integrity-visible.

## Queue and ownership

The native ABI copies accepted PCM into a preallocated bounded queue before the submit call returns and retains no caller-owned pointer. Submission performs no disk I/O, network, inference, or unbounded wait. Queue pressure returns `SQ_ERR_WOULD_BLOCK`; the capture coordinator must raise an integrity incident and perform a controlled stop rather than silently dropping audio.

The original WAV remains the evidence source. PCM blocks and DSP output do not replace its finalization/hash/journal responsibilities.
