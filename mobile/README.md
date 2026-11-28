# pave-mobile

The pave wallet for phone apps: the whole wallet in one library, behind two interfaces over the same commands:
- **UniFFI** ([`src/pave.udl`](src/pave.udl)): generated Kotlin and Swift bindings, the same toolchain Briolette's app uses. This is what [the app](#the-app) calls.
- **A small C interface** ([`include/pave.h`](include/pave.h)): for other hosts. An app opens a wallet and sends it the JSON commands `pave-node` takes ([`board/src/commands`](../board/src/commands)); `{"cmd": "help"}` lists them. It shows and scans QR codes and carries sealed bytes over its radios; the library does the rest.

## The interface

| Call | What it does |
|---|---|
| `pave_join_begin` | Make this device's keys, in memory, and return the join request for the town, with the challenge an attestation must bind |
| `pave_join_attest` | Attach the platform's attestation (Android Key Attestation's chain, or App Attest's object and key id); a town grants a hardware class only on one ([`board/src/attest.rs`](../board/src/attest.rs)) |
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

## The app

[`app/`](app) is a Kotlin Multiplatform app on Briolette's Gradle setup (Compose Multiplatform, UniFFI, CameraX and ML Kit for scanning, ZXing for drawing):

| | |
|---|---|
| `shared/src/commonMain/.../Pave.kt` | The wallet as the screens see it: JSON commands, joining, the platform |
| `.../Link.kt` | In-person links: invites, sealing, QR frames, and a meet over a radio |
| `.../Flows.kt` | The counter pickup (`Counter.cafe`, `Counter.courier`) over a radio, and the door handoff (`Door`) in alternating QR turns |
| `.../ui/App.kt` | Join (with this device's attestation), hand a bag to a courier, pick one up, hand one over at the door, receive one |
| `shared/src/androidMain/.../AndroidPlatform.kt` | The UniFFI wallet; the Android Keystore vault (rollback-resistant AES-GCM); Key Attestation |
| `.../WifiAwareRadio.kt` | The counter's radio: publish and subscribe on the invite's service, matched by its token, a data path with the token as passphrase, framed over a socket |
| `.../AndroidQr.kt` | Drawing codes, and a camera that keeps reading them through a frame loop |
| `iosApp/PaveVault.swift` | The Secure Enclave vault and App Attest, over UniFFI's Swift protocol |

`build-rust.sh bindings` regenerates the Kotlin and Swift bindings into the app, `build-rust.sh android` builds the library for each ABI, then `./gradlew :androidApp:assembleDebug`. The iOS app shell (an Xcode project embedding the shared framework, as Briolette's does) and a Bluetooth radio are still to come.

[`demo/phone_demo.py`](../demo/phone_demo.py) runs the same turns as `Flows.kt` against the library, so the steps are checked here even though the Kotlin isn't compiled.

## What's verified here and what isn't

- **Verified:** the library, built for this machine, x86-64 Linux.
  - [`tests/uniffi/check.py`](tests/uniffi/check.py) generates UniFFI's Python bindings from the built library, which come from the same place as its Kotlin and Swift. It joins a town with a keystore written in Python, uses the wallet and reopens it. A stale copy of the state, a bad attestation and a second finish of the same join are refused.
  - [`tests/c/check.py`](tests/c/check.py) builds [`tests/c/smoke.c`](tests/c/smoke.c) against `pave.h` with `-Wall -Wextra -Werror`. It enrolls a wallet through the header with its own keystore callbacks against a real town, uses the wallet and reopens it. A stale copy of the state is refused.
  - [`demo/phone_demo.py`](../demo/phone_demo.py) drives three wallets through the C interface:
    - online steps with the town;
    - a counter pickup over a socket standing in for Wi-Fi Aware;
    - a door handoff in QR frames alone.
- **Not built here:** the app's Kotlin and Swift. The machine this was written on can't reach the Android SDK and NDK, Google's Maven, Xcode, or Rust's phone targets. The app calls the generated bindings, and its flows are the demo's.

## Building

    # this machine: the library, both interfaces' checks and the phone demo
    cargo build --release -p pave-board -p pave-mobile
    python3 mobile/tests/c/check.py
    python3 mobile/tests/uniffi/check.py
    python3 demo/phone_demo.py

    # the app (with the Android SDK, NDK and cargo-ndk)
    mobile/app/build-rust.sh all
    (cd mobile/app && ./gradlew :androidApp:assembleDebug)

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

- Build the app on a device; the iOS shell; a Bluetooth radio beside Wi-Fi Aware.
- Time [`board/examples/devices.rs`](../board/examples/devices.rs) on a phone.
- Carry the link over Wi-Fi Aware and Bluetooth, Android to iPhone.
