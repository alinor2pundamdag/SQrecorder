# Native ABI v1

The canonical declaration is [abi_v1.h](abi_v1.h). The ABI is C-compatible, versioned, and uses opaque engine handles, fixed-width scalar fields, explicit structure sizes, status returns, and reserved fields.

## Lifecycle

- `sq_capture_create_v1` validates configuration and allocates bounded resources; it does not start capture.
- `sq_capture_start_v1` transitions `CREATED → RUNNING`. A handle is started once; create a new handle for a new capture session.
- PCM and capture events are accepted only in the states documented by the implementation contract. PCM submit is valid while running.
- `sq_capture_request_stop_v1` requests a controlled stop; `RUNNING → STOPPING → STOPPED`. Stop is asynchronous and must not block a capture callback.
- `FAILED` is terminal. Query state before teardown.
- Destroy only after stop/failure and in-flight operations have quiesced. A null destroy handle is a no-op.

## Compatibility rules

- ABI major mismatch is fatal. Minor-version capability negotiation is explicit.
- A caller supplies `struct_size`; implementations validate the required v1 prefix and ignore only documented trailing extensions.
- Reserved fields and v1 configuration flags must be zero.
- No C++ exceptions, Rust panics, platform types, `size_t`, or `long` cross the boundary.
- Caller-owned input memory is valid only for the call. PCM submit copies into bounded native-owned storage before returning.
- Setup/control calls occur off the capture callback. Capture submit is bounded and never performs disk or inference work.
- Queue saturation returns `SQ_ERR_WOULD_BLOCK`; the coordinator records an integrity incident and performs controlled stop rather than silently losing samples.

The PCM payload format is independently specified in [PCM block v1](../pcm/pcm-block-v1.md). B2 defines the contract; later batches implement adapters and runtime behavior.
