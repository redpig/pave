# pave-mobile

The pave wallet for phone apps: the whole wallet in one library, behind a small C interface ([`include/pave.h`](include/pave.h)). An app opens a wallet and sends it the JSON commands `pave-node` takes ([`board/src/commands`](../board/src/commands)); `{"cmd": "help"}` lists them. It shows and scans QR codes and carries sealed bytes over its radios; the library does the rest.

## The interface

| Call | What it does |
|---|---|
| `pave_join_begin` | Make this device's keys, in memory, and return the join request for the town |
| `pave_join_finish` | Take the town's reply and create the wallet, sealed by the app's keystore |
| `pave_open_with` | Open a wallet sealed by the app's keystore |
| `pave_open` | Open one sealed by the software keystore beside it (tests, demos) |
| `pave_call` | Run one JSON command; the reply has `"ok"`, and `"error"` when it fails |
| `pave_string_free`, `pave_close`, `pave_version` | |

**The keystore is the app's.** It passes callbacks to seal under a fresh key, open, and retire older keys, so the platform key never leaves the platform. The library seals the whole state under them each save; a copy of the state from before a commit no longer opens. What each platform can promise is in [docs/phone-keys.md](../docs/phone-keys.md).

**In person**, the app uses the `link_*` commands ([`board/src/link.rs`](../board/src/link.rs)):

1. One phone runs `link_show` and puts the `code` in a QR code.
2. The other runs `link_scan` on what its camera read. It learns the radios to connect on, and the link's token to look for in the advertisement.
3. Each message is `link_seal` on one side and `link_open` on the other. A meet is `have`, `bundle_for` and `absorb`, sealed both ways.
4. With no radio, `link_frames` gives QR codes to show in a loop, and `link_collect` takes each one scanned.

**On the radio**, the token goes where the other phone looks for it:

| Radio | Android | iPhone |
|---|---|---|
| Wi-Fi Aware | `WifiAwareManager`: publish a service named in the invite, with the token as its service-specific info; open a data path to the subscriber that matches | The `WiFiAware` framework (iOS 26, iPhone 12 and later), same service name |
| Bluetooth LE | Advertise the invite's service UUID with the token as service data | Core Bluetooth, the same |

## What's verified here and what isn't

- **Verified:** the library, built for this machine, x86-64 Linux.
  - [`tests/c/check.py`](tests/c/check.py) builds [`tests/c/smoke.c`](tests/c/smoke.c) against `pave.h` with `-Wall -Wextra -Werror`. It enrolls a wallet through the header with its own keystore callbacks against a real town, uses the wallet and reopens it. A stale copy of the state is refused.
  - [`demo/phone_demo.py`](../demo/phone_demo.py) drives three wallets through the C interface:
    - online steps with the town;
    - a counter pickup over a socket standing in for Wi-Fi Aware;
    - a door handoff in QR frames alone.
- **Not built here:** [`android/Pave.kt`](android/Pave.kt) (JNA, with an Android Keystore vault) and [`ios/Pave.swift`](ios/Pave.swift) (with a Secure Enclave vault). The machine this was written on can't reach the Android SDK and NDK, Xcode, or Rust's phone targets. They follow the header and make the same calls as the demo.

## Building

    # this machine: the library, the C check and the phone demo
    cargo build --release -p pave-board -p pave-mobile
    python3 mobile/tests/c/check.py
    python3 demo/phone_demo.py

    # Android (with the NDK and cargo-ndk)
    rustup target add aarch64-linux-android x86_64-linux-android
    cargo ndk -t arm64-v8a -t x86_64 -o app/src/main/jniLibs build --release -p pave-mobile

    # iOS (on a Mac with Xcode)
    rustup target add aarch64-apple-ios aarch64-apple-ios-sim
    cargo build --release -p pave-mobile --target aarch64-apple-ios
    cargo build --release -p pave-mobile --target aarch64-apple-ios-sim
    mkdir -p build/headers && cp mobile/include/pave.h mobile/ios/module.modulemap build/headers/
    xcodebuild -create-xcframework \
      -library target/aarch64-apple-ios/release/libpave_mobile.a -headers build/headers \
      -library target/aarch64-apple-ios-sim/release/libpave_mobile.a -headers build/headers \
      -output build/Pave.xcframework

## Next

- Build the two wrappers in real apps and run the C check's steps on a device.
- Time [`board/examples/devices.rs`](../board/examples/devices.rs) on a phone.
- Carry the link over Wi-Fi Aware and Bluetooth, Android to iPhone.
