#!/usr/bin/env bash
# Build the pave library for the app and generate its Kotlin and Swift
# bindings.
#
#   ./build-rust.sh android    # the .so for each Android ABI (needs cargo-ndk and the NDK)
#   ./build-rust.sh ios        # static libraries for device and simulator (needs Xcode)
#   ./build-rust.sh bindings   # regenerate the UniFFI bindings
set -euo pipefail
cd "$(dirname "$0")/../.."   # the pave workspace root
APP=mobile/app

bindings() {
    cargo build --release -p pave-mobile
    cargo run --release -q -p pave-mobile --bin uniffi-bindgen -- generate \
        --library target/release/libpave_mobile.so --language kotlin \
        --out-dir "$APP/shared/src/androidMain/kotlin"
    cargo run --release -q -p pave-mobile --bin uniffi-bindgen -- generate \
        --library target/release/libpave_mobile.so --language swift \
        --out-dir "$APP/iosApp/generated"
}

android() {
    for abi in arm64-v8a x86_64; do
        cargo ndk -t "$abi" -o "$APP/androidApp/src/main/jniLibs" build --release -p pave-mobile
    done
}

ios() {
    for t in aarch64-apple-ios aarch64-apple-ios-sim; do
        cargo build --release -p pave-mobile --target "$t"
    done
}

case "${1:-all}" in
    android) android ;;
    ios) ios ;;
    bindings) bindings ;;
    all) bindings; android ;;
    *) echo "usage: $0 android|ios|bindings|all" >&2; exit 2 ;;
esac
