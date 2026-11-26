# Native ABI v1

The canonical declaration is [abi_v1.h](abi_v1.h). The ABI is C-compatible, versioned, and uses opaque engine handles, fixed-width scalar fields, explicit structure sizes, status returns, and reserved fields.

## Compatibility rules

- ABI major mismatch is fatal. Minor-version capability negotiation is explicit.
- A caller supplies `struct_size`; implementations validate the required v1 prefix and ignore only documented trailing extensions.
- Reserved fields must be zero.
- No C++ exceptions, Rust panics, platform types, `size_t`, or `long` cross the boundary.
- Caller-owned input memory is valid only for the call. PCM submit copies into bounded native-owned storage before returning.
- Setup/control calls occur off the capture callback. Capture submit is bounded and never performs disk or inference work.
- Destroy is called only after stop and in-flight operations have quiesced.

The PCM payload format is independently specified in [PCM block v1](../pcm/pcm-block-v1.md). B2 defines the contract; later batches implement adapters and runtime behavior.
