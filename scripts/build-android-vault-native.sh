#!/usr/bin/env bash
set -euo pipefail

NDK_VERSION="28.2.13676358"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$SDK_ROOT" ]]; then
  echo "Android SDK root is not set" >&2
  exit 2
fi
NDK_ROOT="${ANDROID_NDK_HOME:-$SDK_ROOT/ndk/$NDK_VERSION}"
if [[ ! -d "$NDK_ROOT" ]]; then
  echo "Required NDK $NDK_VERSION not found at $NDK_ROOT" >&2
  exit 2
fi
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -x "$TOOLCHAIN/llvm-readelf" ]]; then
  echo "NDK LLVM toolchain missing: $TOOLCHAIN" >&2
  exit 2
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android35-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android35-clang"
export RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"

build_one() {
  local target="$1"
  local abi="$2"
  cargo build --locked --release --target "$target" -p sqrec-native-abi
  local library="target/$target/release/libsqrec_native_abi.so"
  local destination="shared/vault-keystore-android/src/androidMain/jniLibs/$abi/libsqrec_native_abi.so"
  test -f "$library"
  install -D "$library" "$destination"

  "$TOOLCHAIN/llvm-readelf" -l "$destination" |
    awk '$1 == "LOAD" { count++; if ($NF != "0x4000") bad=1 }
         END { if (count == 0 || bad) exit 1 }'
  echo "Verified 16 KB LOAD alignment: $abi"
}

build_one aarch64-linux-android arm64-v8a
build_one x86_64-linux-android x86_64
