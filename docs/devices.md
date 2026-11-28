# What pave asks of a phone

What a wallet sends and computes, measured on the real flows, and what phones can do with it today. The numbers come from [`board/examples/devices.rs`](../board/examples/devices.rs):

    cargo run --release -p pave-board --example devices

Signatures are stored without the signer's credential, which every record and request already carries beside them (Briolette's `deflate_signature`); verifying puts it back. That saves 192 bytes a signature: a signature is 98 bytes, not 291.

They were measured on one core of a 2.3 GHz Xeon build machine, not a phone. The group signatures are ECDAA over BLS12-381 in pure Rust (`briolette-crypto`, `bls12_381_plus`). A recent phone's big core should be in the same range, but that is an estimate until the numbers are run on a device; doing so is the first item under [next](#next).

## Measured

**Primitives**

| | Size | Time |
|---|---|---|
| A fresh credential (a new unlinkable key for one holding or role) | 192 B | 1.7 ms |
| Sign | 98 B | 0.9 ms |
| Sign with a basename (a pseudonym that links on reuse) | 146 B | 1.8 ms |
| Verify | | 6.3 ms |

**A payment, by how many hands the coin has passed through.** What crosses is the coin with its history and the payment record. The payee's checks (every signature in the history, standing, tickets) grow with it. A coin may make five offline transfers before it must be swapped with the town, which bounds both.

| Hops | Bytes | Payee checks |
|---|---|---|
| 1 | 3.4 KB | 35 ms |
| 2 | 4.9 KB | 57 ms |
| 3 | 6.3 KB | 75 ms |
| 4 | 7.8 KB | 97 ms |
| 5 | refused: swap first | |

**Meets**

| | Bytes |
|---|---|
| First meet between two wallets that know only the town | 3.1 KB |
| The next meet, after one payment | 188 B |
| A meet with the town (time, both ways) | 113 ms |

**What a food delivery shows in person**

| | Bytes |
|---|---|
| A courier's badge (the ticket) | 662 B |
| The badge shown for a job (ticket and signature) | 977 B |
| A bag's manifest, naming its dispatch's roster | 703 B (it was 3.0 KB carrying the whole dispatch, 2.5 KB of it) |
| A refill: request for 16 tickets / the 16 tickets | 7.3 KB / 9.5 KB |

## What that means

- **The bytes are small.** Every in-person exchange is under 8 KB, and a repeat meet is a few hundred bytes. Bluetooth LE moves that in well under a second; Wi-Fi Aware moves it in milliseconds. Only a QR-only exchange feels the size.
- **The CPU is fine.** The heaviest offline step, checking a four-hop payment, is about 0.1 s here. Verification dominates, at about 6 ms a signature, so a phone doing several times worse is still well under a second per exchange.
- **Refills belong online.** Sixteen tickets are 17 KB both ways and need the clerk; a wallet refills when it has signal, as it does already.
- **A manifest names only the dispatch's roster.** Its id, label and clerk are all a reader needs to check tickets and badges. The members' group key and the records that set up its ticks stay with members and travel as records, as any do. A badge job names the roster the same way.

## Phones today

| | Android | iPhone |
|---|---|---|
| The member key | In app storage, encrypted under a hardware-held key. Phone secure hardware (StrongBox, Secure Enclave) does P-256, not the pairings these signatures need | Same |
| Device binding at enrollment | Key Attestation, verified by the town ([`board/src/attest.rs`](../board/src/attest.rs)) | App Attest, verified by the town |
| Online: board, offers, posts, vouches, refills | Yes | Yes |
| Offline, both apps open: Bluetooth LE | Yes | Yes |
| Offline, both apps open: Wi-Fi Aware (peer-to-peer Wi-Fi) | Yes, for years | iOS 26 and later, iPhone 12 and later; interoperates with Android |
| Offline: QR codes on screen | Yes | Yes |
| Offline: tap phones (NFC card emulation) | Yes | Only in the EEA, with an entitlement |
| Gossip in the background, without the app open | Limited | No, in practice |
| Embedded web views for profile screens | Yes | Yes |
| A `navigator.pave` browser API ([web.md](../spec/web.md)) | No | No |

So the realistic first app:

- **Key class.** The key is a software key bound to an attested device. That is the town's lower-assurance class, with tighter limits, as the threat model already expects.
- **Online first.** Most deliveries have signal, so the board server carries the flow.
- **In person, a QR code opens the channel** ([`board/src/link.rs`](../board/src/link.rs)). It carries a fresh session key, a token to find in the advertisement, the radios the phone is listening on, and an expiry, and the exchange runs over the radio, sealed. That covers the counter pickup and the door handoff, iPhone to Android included. With no radio, the same sealed messages go as loops of QR frames. [`board/tests/link.rs`](../board/tests/link.rs) does a pickup both ways.
- **No NFC, and no background mesh.** Revocations and records spread when the app opens or has signal. So the town's epoch length, and the soft expiry that pushes swaps, should allow for wallets that are offline for hours, not minutes.
- **One app.** A host app that renders profiles in web views, not a browser feature.

## In person, measured

| | |
|---|---|
| The invite | about 185 characters: a version 6 or 7 QR code |
| A QR-only frame | up to 600 bytes of sealed message, 981 characters: about a version 20 code at low error correction, which phones read off another screen |
| A shown badge | 1.0 KB sealed: 2 frames |
| A manifest | 773 B sealed: 2 frames |
| A four-hop payment | about 7.8 KB: 14 frames |

The session key travels in the code, so there is no key agreement: only who scanned it can read or inject on the radio. Someone who films the screen holds the key too; what crosses is signed and checked anyway, and the invite expires in minutes. Wi-Fi Aware's and Bluetooth's own pairing can add link-layer encryption under it.

## The app side

The wallet for apps is [`mobile/`](../mobile/): one library behind a C interface, `pave.h`. An app sends it the JSON commands `pave-node` takes, and passes its platform keystore as callbacks. [`demo/phone_demo.py`](../demo/phone_demo.py) drives three wallets through that interface:

- **At the counter,** a QR invite (a version 7 code) opens the link. Badge, meets and manifest go over a socket standing in for Wi-Fi Aware: about 8.5 KB in all.
- **At the door,** with no radio, the handoff and confirmation go as 19 QR frames.

Kotlin and Swift wrappers are there, not yet built on a device.

## Next

- Build the Kotlin and Swift wrappers in real apps; run the measurements on an Android and an iPhone.
- Carry the link over Wi-Fi Aware and Bluetooth LE, Android to iPhone.
