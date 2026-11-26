# Contract smoke tests

Run from the repository root with a C11 and C++17 compiler:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -Iprotocols/native-abi tests/contract/native_abi_layout.c \
  -o /tmp/sqrec-abi-c && /tmp/sqrec-abi-c

c++ -std=c++17 -Wall -Wextra -Werror -pedantic \
  -Iprotocols/native-abi tests/contract/native_abi_layout.cpp \
  -o /tmp/sqrec-abi-cpp && /tmp/sqrec-abi-cpp
```

Rust layout/status assertions are in `core/native-abi/src/lib.rs` and run with `cargo test --workspace`.

These tests check declaration/layout compatibility, not the runtime behavior of the capture engine. The capture implementation and cross-language calls are added and tested in their dependent batches.
