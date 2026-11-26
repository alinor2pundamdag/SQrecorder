# B6 validation record

## Implemented

- Rust PCM crate enforces mono S16LE and only 48 kHz canonical / 44.1 kHz fallback, checks exact frame/payload arithmetic, and decodes into caller-owned storage without allocation.
- Rust DSP graph crate validates node IDs, gain values, single-input edges, root/output, and cycles during prepare.
- Graph preparation performs topological sorting and allocates node buffers off the processing path.
- Processing uses bounded frame counts, rejects non-finite input/output, supports pass-through, gain, and peak-meter nodes, and returns peak/RMS metrics.
- Capture WAV/evidence is explicitly outside the derived DSP path.
- Added unit tests for format restrictions, endianness, truncated input, graph output/metrics, cycle/edge rejection, NaN handling, and invalid gain.
- Added the two dependency-free Rust crates to the workspace and lockfile.

## Not run

Rust/Cargo are unavailable in this environment, so `cargo test --workspace`, Clippy, and benchmark execution were not run. The implementation received static review only. Runtime throughput, allocation instrumentation, audio-quality listening/measurement, and device performance remain unverified.
