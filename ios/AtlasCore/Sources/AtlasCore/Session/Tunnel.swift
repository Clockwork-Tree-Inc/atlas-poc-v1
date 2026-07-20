import Foundation

/// The two send modes and the shared encryption core (§9). Mirrors
/// `backend/atlas/session/tunnel.py`. Content-type-agnostic (text, photo, …).
public enum SendMode: Int { case normal = 1, verifiedHuman = 2 }

public enum AccessDenied: Error { case offline, epochExpired, notVerifiedLive, epochMismatch, wrongEnclave, gateUnwrapFailed }

public final class Message {
    public let mode: SendMode
    public let ciphertext: Data
    public let wrappedContentKey: Data
    public let requiredBeaconComponent: Data
    public let enclaveRequirement: Data
    public private(set) var accessLog: [String] = []
    init(mode: SendMode, ciphertext: Data, wrappedContentKey: Data = Data(),
         requiredBeaconComponent: Data = Data(), enclaveRequirement: Data = Data()) {
        self.mode = mode; self.ciphertext = ciphertext; self.wrappedContentKey = wrappedContentKey
        self.requiredBeaconComponent = requiredBeaconComponent; self.enclaveRequirement = enclaveRequirement
    }
    func log(_ s: String) { accessLog.append(s) }
}

public enum Tunnel {
    static func contentKeyMode1(_ key: Data) -> Data {
        Primitives.hkdfCombine([key], info: Data("atlas/mode1/content".utf8), length: 32)
    }
    static func gateKey(_ key: Data, _ beaconComponent: Data, _ enclaveReq: Data) -> Data {
        Primitives.hkdfCombine([key, beaconComponent, enclaveReq], info: Data("atlas/mode2/gate".utf8), length: 32)
    }

    public static func seal(_ plaintext: Data, mode: SendMode, key: Data, aad: Data = Data(),
                            beaconComponent: Data? = nil,
                            recipientEnclavePublic: HybridSign.PublicKey? = nil) throws -> Message {
        switch mode {
        case .normal:
            let ck = contentKeyMode1(key)
            return Message(mode: .normal, ciphertext: try Primitives.aeadEncrypt(key: ck, plaintext: plaintext, aad: aad))
        case .verifiedHuman:
            guard let comp = beaconComponent, let enclave = recipientEnclavePublic else {
                throw AccessDenied.gateUnwrapFailed
            }
            let ck = Primitives.randomBytes(32)
            let ciphertext = try Primitives.aeadEncrypt(key: ck, plaintext: plaintext, aad: aad)
            let enclaveReq = Primitives.H(Data("atlas/enclave-req".utf8), enclave.encode())
            let gate = gateKey(key, comp, enclaveReq)
            let wrapped = try Primitives.aeadEncrypt(key: gate, plaintext: ck, aad: Data("atlas/mode2/wrap".utf8))
            return Message(mode: .verifiedHuman, ciphertext: ciphertext, wrappedContentKey: wrapped,
                           requiredBeaconComponent: comp, enclaveRequirement: enclaveReq)
        }
    }

    /// Mode 2 enforces the live-human gate (§9.2). `attestationProvider` is the
    /// recipient enclave producing a FRESH attestation at view time.
    public static func open(_ msg: Message, key: Data, aad: Data = Data(),
                            currentBeaconComponent: Data? = nil,
                            attestationProvider: (() -> LivenessAttestation?)? = nil,
                            expectedDrandRound: Data? = nil) throws -> Data {
        if msg.mode == .normal {
            return try Primitives.aeadDecrypt(key: contentKeyMode1(key), blob: msg.ciphertext, aad: aad)
        }
        // (1) must be online: current beacon component, still matching the bound epoch.
        guard let comp = currentBeaconComponent else { msg.log("denied: offline"); throw AccessDenied.offline }
        guard comp == msg.requiredBeaconComponent else { msg.log("denied: epoch expired/revoked"); throw AccessDenied.epochExpired }
        // (2) must be verified-live: fresh valid enclave attestation.
        guard let att = attestationProvider?(), att.verify(), att.operate else {
            msg.log("denied: not verified-live"); throw AccessDenied.notVerifiedLive
        }
        if let e = expectedDrandRound, att.drandRound != e { msg.log("denied: attestation epoch mismatch"); throw AccessDenied.epochMismatch }
        guard Primitives.H(Data("atlas/enclave-req".utf8), att.enclavePublic.encode()) == msg.enclaveRequirement else {
            msg.log("denied: wrong enclave"); throw AccessDenied.wrongEnclave
        }
        let gate = gateKey(key, comp, msg.enclaveRequirement)
        guard let ck = try? Primitives.aeadDecrypt(key: gate, blob: msg.wrappedContentKey, aad: Data("atlas/mode2/wrap".utf8)) else {
            msg.log("denied: gate unwrap failed"); throw AccessDenied.gateUnwrapFailed
        }
        let plaintext = try Primitives.aeadDecrypt(key: ck, blob: msg.ciphertext, aad: aad)
        msg.log("granted: verified-live, on-network")
        return plaintext  // non-persistent: re-verify each view, no plaintext storage
    }

    /// Convenience: seal a NORMAL message and return just the opaque blob (the
    /// full nonce||ct||tag). Use for the blind-relay path where callers move raw
    /// bytes, not `Message` objects (whose initializer is internal).
    public static func sealNormalBlob(_ plaintext: Data, key: Data, aad: Data = Data()) throws -> Data {
        try seal(plaintext, mode: .normal, key: key, aad: aad).ciphertext
    }

    /// Convenience: open a NORMAL blob produced by `sealNormalBlob` / a peer's
    /// `seal(mode:.normal)`. Lets a separate module (AtlasApp) decrypt without the
    /// internal `Message` initializer.
    public static func openNormalBlob(_ ciphertext: Data, key: Data, aad: Data = Data()) throws -> Data {
        try Primitives.aeadDecrypt(key: contentKeyMode1(key), blob: ciphertext, aad: aad)
    }
}
