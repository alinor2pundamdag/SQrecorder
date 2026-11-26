# Audio core

- `pcm`: canonical mono S16LE format validation and caller-buffer decoding.
- `dsp-graph`: validated acyclic single-input DSP graph with preallocated per-node buffers.

Capture WAV is the evidence source and is never modified by this processing graph. DSP output is derived audio. Graph construction/topological sorting/allocation happen during prepare, off the capture callback. The process path performs bounded arithmetic over caller-provided frames and graph-owned buffers; no per-block heap allocation, I/O, inference, or UI calls.

B6 provides a correctness/latency foundation, not a claim of advanced denoising, restoration, or production audio-quality certification.
