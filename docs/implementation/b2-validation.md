# B2 validation record

## Contract review

- C ABI uses explicit v1 names, fixed-width integer fields, opaque engine handle, status codes, and struct-size/reserved-field rules.
- PCM serialization is specified byte-by-byte as 64-byte little-endian header plus S16LE payload; it is not tied to host compiler packing.
- Capture submission ownership, bounded queue behavior, and WOULD_BLOCK integrity handling are documented.
- Rust contract types mirror the header's fixed-width status and PCM descriptor; compile-time/runtime layout assertions are included as unit tests.

## Not run

The environment has no `rustc`, `cargo`, or `gradle` installed, and cannot resolve GitHub for a checkout. Rust tests and C/C++ header compilation therefore were not run. The code and protocol were reviewed statically only; platform ABI smoke tests remain required before B2 can be marked fully verified.
