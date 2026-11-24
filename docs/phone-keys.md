# Keeping keys safe on phones

A pave wallet has three things to protect:

1. **Its keys.** The transfer key signs coins away. The access key signs anonymous requests to the town.
2. **Its signing log.** This is every coin state the wallet has signed away. An honest wallet that forgets an entry, for example after restoring an old backup, can sign the same state twice. Evidence then names its owner as a cheat.
3. **Its owner's consent.** What the wallet signs must be what the person agreed to.

This document says what phones can and can't do for each, how pave uses that, and what is built so far.

## What phones offer

| | Android (TEE / StrongBox KeyMint) | iOS (Secure Enclave) |
|---|---|---|
| Keys inside secure hardware | P-256 ECDSA/ECDH, RSA, AES, HMAC. StrongBox supports a subset: RSA 2048, AES, P-256, HMAC-SHA256 | P-256 only, for signing and key agreement. iOS 26 adds ML-KEM and ML-DSA. No key import |
| Pairing curves (BLS12-381), so ECDAA in hardware | No | No |
| Rollback resistance | `ROLLBACK_RESISTANCE`: a deleted key can't be restored, typically backed by replay-protected memory (RPMB). Storage is limited, and key creation can fail when it's full | No app-facing equivalent. A local backup restored to the same device brings back device-only keychain items |
| Limited-use keys | `setMaxUsageCount` (Android 12) | No |
| Attestation | Key Attestation: a certificate chain naming the security level and the key's properties | App Attest |
| Trusted display for consent | Android Protected Confirmation. Little adoption, and Android deprecated it and then reverted the deprecation. Don't rely on it | None |

## What follows

**The transfer key can't live in phone hardware.** ECDAA needs a pairing curve, and no phone's secure hardware offers one. The key is sealed at rest by a hardware key, but while it signs it is in the app's memory. A compromised OS can copy it.

That is the phone half of the class break: one exploit, every phone of a model, every key copied. Pave can't prevent that on a phone alone, so it bounds it:

- **Classes.** Each assurance level is its own class, with its own ticket terms. A phone-only wallet gets small `max_spend`, few tickets per epoch and short lifetimes.
- **Standing and evidence.** These stop each copied identity everywhere its first double spend has reached.
- **Class closure.** Closing a broken model's class stops new tickets and taints its recent coins.

**Rollback resistance differs by platform.**
- *Android:* it's real where `ROLLBACK_RESISTANCE` is available.
- *iOS:* it isn't available to apps. An iOS-only wallet can be restored from a same-device backup and made to sign again. Software can only detect this through evidence, not prevent it.

**Consent is weak on a phone alone.** The screen belongs to the same OS that can be compromised. Binding the sealing key to user authentication (biometric or passcode) means malware can't sign in the background without the person present. It doesn't stop malware that shows one amount and signs another.

## The tiers

| Class | Keys | Signing log | Terms |
|---|---|---|---|
| **phone-basic** | ECDAA keys sealed by a hardware key, unsealed under user authentication | Sealed; not rollback-resistant (iOS, or Android without rollback resistance) | Smallest caps, shortest lifetimes |
| **phone-ratchet** | Same | Sealed under a key that rotates on every save in a rollback-resistant keystore (Android with `ROLLBACK_RESISTANCE`, shown in attestation) | Small caps |
| **phone + card** | Split ECDAA key: `sk = card share + phone share`. The card (an NFC card, a SIM applet or a Briolette credstick) never releases its share | On the card, behind a hardware monotonic counter | Normal caps |
| **card alone** | The credstick's full key | On the card | Normal caps, plus the card's own trusted display and PIN |

The class is set at enrollment from attestation: Key Attestation on Android, App Attest on iOS, or the card's manufacturer key. The join request binds the attestation challenge to the new public keys, as Briolette's registrar does.

### The split key

Briolette already splits the ECDAA key between a phone and a card. The card holds `card_sk` and does only scalar multiplication in G1 and arithmetic in the scalar field, with no pairings, which a JavaCard can do. The phone holds `host_sk` and does the rest. The resulting signature is an ordinary ECDAA signature, so verifiers can't tell it was split. It also makes the same pseudonym, so evidence and standing work unchanged.

Malware that owns the phone gets `host_sk`, which is useless alone. The card refuses to sign a basename twice, and its counter can't be rolled back. That moves both the key and the signing log off the phone. Briolette v1 has the split protocol (`generate_split_wallet_keypair`, `sign_split`), so pave can adopt it as another `Scheme` implementation.

### The key ratchet

This is what [`vault.rs`](../board/src/vault.rs) implements, and how a phone would back it:

1. Seal the whole wallet state (keys, signing log, view) under a fresh key from the keystore.
2. Write the sealed state.
3. Delete every older key.

On a rollback-resistant keystore, step 3 is final: a copy of an older state file no longer opens, and loading it fails with "sealed under a retired key". Restoring a backup then fails loudly, instead of quietly re-enabling spent coins.

The signing log is saved *before* a signature leaves the wallet. If the wallet dies right after signing, it comes back refusing to sign that state for anyone else. Retrying the same operation returns the record it already released, rather than a second signature.

On Android, each save costs one rollback-resistant key creation and one deletion, which are writes to RPMB. Only one or two such keys are live at a time, so capacity isn't the limit. Wear might be, at many saves a day, and that needs measuring on devices.

## What is built

- [`board/src/vault.rs`](../board/src/vault.rs):
  - The `Keystore` trait (seal, commit, open, and whether the keystore is rollback-resistant).
  - `SoftwareKeystore`: keys in a mode-0600 file beside the state. This is what the repo runs. It protects the state file alone, not a copy of both files.
  - `MemoryKeystore`: a stand-in for a rollback-resistant device keystore in tests.
- [`board/src/node.rs`](../board/src/node.rs):
  - Every save is sealed.
  - Every signature, including the town's role keys (the clerk's epoch rolls and the minter), goes through the signing log.
  - The demo's `cheat` command is the one path that deliberately skips the log, playing a tampered wallet.
- [`board/tests/vault.rs`](../board/tests/vault.rs) checks four things:
  - The secret key isn't in the file, and a tampered file won't open.
  - A wallet that dies right after signing refuses to sign that state again.
  - A software restore can still sign twice, and evidence names the owner.
  - On a rollback-resistant keystore, the old copy won't open.

## Not built yet

- Platform keystores:
  - an Android Keystore backend (AES-GCM keys with `ROLLBACK_RESISTANCE` and user-auth binding);
  - an iOS backend (a Secure Enclave P-256 key sealing by ECIES).
- Attestation at enrollment, setting the class.
- The split-key scheme with a card.
- Pruning the signing log once its states are past hard expiry.
- Spending caps that a node enforces for the agent driving it.

## Sources

- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore): StrongBox algorithms, extraction prevention.
- [KeyMint functions](https://source.android.com/docs/security/features/keystore/implementer-ref): rollback resistance and its storage limits.
- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave): P-256 only.
- [Keychain data protection](https://support.apple.com/guide/security/secb0694df1a): device-only items in backups.
- [Android Protected Confirmation](https://developer.android.com/training/articles/security-android-protected-confirmation).
- Briolette's `ecdaa_analysis.md` (split key) and the credstick hardware docs.
