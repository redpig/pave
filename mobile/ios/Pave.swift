// The pave wallet from Swift, through pave.h.
//
// NOT BUILT HERE: Xcode and the iOS SDK aren't available on the machine
// this was written on. It follows mobile/include/pave.h and the Python
// demo (demo/phone_demo.py), which runs the same calls. Build the library
// as an XCFramework (see mobile/README.md) and import its module `Pave`.
import DeviceCheck
import Foundation
import Security
import Pave

/// The wallet's state sealed to Secure Enclave P-256 keys, a fresh key per
/// save, older ones deleted on commit. The enclave can't do AES itself, so
/// each seal is ECIES to the enclave key's public half (AES-GCM under a key
/// agreed with it); only the enclave can open it. iOS gives apps no
/// rollback resistance: a same-device backup restores the keys too (see
/// docs/phone-keys.md).
final class EnclaveVault {
    let prefix: String
    private let alg: SecKeyAlgorithm = .eciesEncryptionStandardVariableIVX963SHA256AESGCM

    init(prefix: String) { self.prefix = prefix }

    private func tag(_ v: UInt32) -> Data { "\(prefix).\(v)".data(using: .utf8)! }

    private func key(_ v: UInt32) -> SecKey? {
        let q: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag(v), kSecReturnRef as String: true]
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? (out as! SecKey) : nil
    }

    private func versions() -> [UInt32] {
        let q: [String: Any] = [kSecClass as String: kSecClassKey, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let items = out as? [[String: Any]] else { return [] }
        return items.compactMap { ($0[kSecAttrApplicationTag as String] as? Data).flatMap { String(data: $0, encoding: .utf8) } }
            .filter { $0.hasPrefix(prefix + ".") }.compactMap { UInt32($0.dropFirst(prefix.count + 1)) }.sorted()
    }

    func seal(_ data: Data) throws -> Data {
        let v = (versions().last ?? 0) + 1
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag(v), kSecAttrAccessControl as String: access],
        ]
        var err: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err), let pub = SecKeyCopyPublicKey(priv),
              let ct = SecKeyCreateEncryptedData(pub, alg, data as CFData, &err) as Data? else { throw err!.takeRetainedValue() }
        var be = v.bigEndian
        return Data(bytes: &be, count: 4) + ct
    }

    func open(_ sealed: Data) throws -> Data {
        let v = sealed.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard let priv = key(v) else { throw NSError(domain: "pave", code: 1, userInfo: [NSLocalizedDescriptionKey: "sealed under a retired key: an old copy"]) }
        var err: Unmanaged<CFError>?
        guard let pt = SecKeyCreateDecryptedData(priv, alg, sealed.dropFirst(4) as CFData, &err) as Data? else { throw err!.takeRetainedValue() }
        return pt
    }

    func commit() {
        for v in versions().dropLast() {
            SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag(v)] as CFDictionary)
        }
    }

    /// The callbacks pave.h takes; `self` is the context and must outlive the wallet.
    func callbacks() -> PaveKeystore {
        func run(_ ctx: UnsafeMutableRawPointer?, _ f: (EnclaveVault) -> (Data) throws -> Data, _ data: UnsafePointer<UInt8>?, _ len: Int, _ out: UnsafeMutablePointer<UInt8>?, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
            let me = Unmanaged<EnclaveVault>.fromOpaque(ctx!).takeUnretainedValue()
            guard let r = try? f(me)(Data(bytes: data!, count: len)) else { return 2 }
            outLen!.pointee = r.count
            if r.count > cap { return 1 }
            r.copyBytes(to: out!, count: r.count)
            return 0
        }
        return PaveKeystore(
            ctx: Unmanaged.passUnretained(self).toOpaque(),
            seal: { run($0, EnclaveVault.seal, $1, $2, $3, $4, $5) },
            open: { run($0, EnclaveVault.open, $1, $2, $3, $4, $5) },
            commit: { Unmanaged<EnclaveVault>.fromOpaque($0!).takeUnretainedValue().commit(); return 0 },
            rollback_resistant: 0)
    }
}

enum PaveError: Error { case failed(String) }

private func take(_ p: UnsafeMutablePointer<CChar>?) -> [String: Any] {
    guard let p else { return ["ok": false, "error": "null"] }
    defer { pave_string_free(p) }
    return (try? JSONSerialization.jsonObject(with: Data(String(cString: p).utf8))) as? [String: Any] ?? [:]
}

/// An open wallet. Calls block: run them off the main thread.
final class Wallet {
    private let w: OpaquePointer
    private let vault: EnclaveVault

    private init(_ w: OpaquePointer, _ vault: EnclaveVault) { self.w = w; self.vault = vault }
    deinit { pave_close(w) }

    static func open(path: String, vault: EnclaveVault) throws -> Wallet {
        var err: UnsafeMutablePointer<CChar>?
        guard let w = pave_open_with(path, vault.callbacks(), &err) else { throw PaveError.failed(take(err)["error"] as? String ?? "") }
        return Wallet(w, vault)
    }

    private static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private static func unhex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return d
    }

    /// Start joining: the request (hex) to take to the town, and a function to finish with
    /// its reply. With `attest`, the request carries App Attest's attestation of a new key,
    /// binding the join's challenge, which a town needs before it grants a hardware class.
    static func join(name: String, path: String, vault: EnclaveVault, attest: Bool = true) async throws -> (request: String, finish: (String) throws -> Wallet) {
        var req: UnsafeMutablePointer<CChar>?
        let j = pave_join_begin(&req)
        var begun = take(req)
        if attest {
            let service = DCAppAttestService.shared
            guard service.isSupported else { throw PaveError.failed("App Attest isn't supported on this device") }
            let keyId = try await service.generateKey()
            let object = try await service.attestKey(keyId, clientDataHash: unhex(begun["challenge"] as? String ?? ""))
            let body: [String: Any] = ["apple": ["object": hex(object), "key_id": hex(Data(base64Encoded: keyId)!)]]
            let json = String(data: try JSONSerialization.data(withJSONObject: body), encoding: .utf8)!
            begun = take(pave_join_attest(j, json))
            guard begun["ok"] as? Bool == true else { throw PaveError.failed(begun["error"] as? String ?? "") }
        }
        let request = begun["request"] as? String ?? ""
        return (request, { reply in
            var err: UnsafeMutablePointer<CChar>?
            guard let w = pave_join_finish(j, reply, name, path, vault.callbacks(), &err) else { throw PaveError.failed(take(err)["error"] as? String ?? "") }
            return Wallet(w, vault)
        })
    }

    @discardableResult
    func call(_ cmd: String, _ args: [String: Any] = [:]) throws -> [String: Any] {
        var a = args
        a["cmd"] = cmd
        let json = String(data: try JSONSerialization.data(withJSONObject: a), encoding: .utf8)!
        let r = take(pave_call(w, json))
        guard r["ok"] as? Bool == true else { throw PaveError.failed(r["error"] as? String ?? "") }
        return r
    }
}
