# B2 validation record

## Contract and source review

- Defined the v1 C ABI in `protocols/native-abi/abi_v1.h`: fixed-width values, opaque engine handle, explicit status codes, structure sizes, reserved fields, and lifecycle functions.
- Defined PCM v1 as a 64-byte little-endian wire header plus S16LE payload. Serialization is independent of native compiler packing.
- Added the Rust `repr(C)` mirror for ABI info, PCM format, capture configuration, PCM descriptor, and capture event, with status/constants and size assertions.
- Added committed C11/C++17 layout smoke-test sources and a byte-level PCM test fixture.
- Reviewed the serialized fixture's field offsets and payload arithmetic (64-byte header + 4-byte payload = 68 bytes).

## Executed checks

- C11 and C++17 static layout assertions compiled and executed successfully in the available local compiler, against a local transcription of the v1 declarations matching the committed header's types and field order.
- GitHub confirmed the contract and test files are committed to the implementation branch.

## Not run / remaining

- The committed C/C++ test source files were not built from a repository checkout because this environment cannot resolve GitHub.
- Rust unit/layout tests were not run: `rustc` and `cargo` are unavailable.
- No target-platform ABI linking, runtime capture calls, queue-pressure tests, PCM decoder/round-trip, or device tests were run. Those require implementation and platform validation in dependent batches.

B2 defines and checks the contract surface; it does not claim that the capture engine or PCM parser is implemented.
