import Foundation

/// Secure Enclave biometric-bound key release (§0.3, §7). Mirrors
/// `backend/atlas/keys/enclave.py`.
///
/// Device-present recovery + normal auth release `share_bio` through a robust
/// biometric match against a DEVICE-BOUND sealed secret. This is the ONLY place
/// biometric material is matched (the fuzzy extractor is retired — TRUST_LAYER.md
/// #7; total loss uses the portable shares + the in-person ceremony). The protocol
/// lets `AtlasCore.Recovery` stay pure: the app injects the REAL Secure Enclave
/// (AtlasApp/Enclave), and tests/previews inject `ModelEnclave`.
///
/// Invariant: the biometric is never exposed — the enrolled template is sealed
/// under a non-extractable key and matched inside the boundary.
public protocol BiometricEnclave {
    var deviceID: Data { get }
    /// Whether a biometric is already enrolled/bound on this enclave. Callers must
    /// NOT re-enrol over an existing binding (mirrors Python SecureEnclave.has_biometric):
    /// overwriting the template re-points every secret sealed under it to a new biometric.
    var hasBiometric: Bool { get }
    func enrolBiometric(_ template: Data)
    /// Seal a secret to THIS device, releasable only on a biometric match.
    func seal(_ secret: Data, label: Data) -> Data
    /// Release iff the live biometric matches (robustly) on THIS device; nil
    /// otherwise or if the blob was sealed on a different device.
    func release(_ sealed: Data, liveSample: Data, label: Data) -> Data?
}

/// Pure-Swift model of one device's Enclave (Mac tests / previews). The real
/// device implementation is `SecureEnclaveStore` in AtlasApp, backed by a
/// Secure Enclave key gated by `biometryCurrentSet` + LAContext.
public final class ModelEnclave: BiometricEnclave {
    public let deviceID: Data
    private let master: Data                  // models the non-extractable HW key
    private var sealedTemplate: Data?

    /// Apple's matcher tolerates real variation; "robust" = within this bit-diff.
    public static let robustMatchMaxBitDiff = 0.35

    public init(deviceID: Data = Primitives.randomBytes(16)) {
        self.deviceID = deviceID
        self.master = Primitives.randomBytes(32)
    }

    public var hasBiometric: Bool { sealedTemplate != nil }

    public func enrolBiometric(_ template: Data) {
        sealedTemplate = try? Primitives.aeadEncrypt(key: master, plaintext: template, aad: Data("atlas/se/tmpl".utf8))
    }

    private func match(_ sample: Data) -> Bool {
        guard let sealed = sealedTemplate,
              let template = try? Primitives.aeadDecrypt(key: master, blob: sealed, aad: Data("atlas/se/tmpl".utf8)),
              template.count == sample.count, !template.isEmpty else { return false }
        var diff = 0
        for (a, b) in zip(template, sample) { diff += (a ^ b).nonzeroBitCount }
        return Double(diff) / Double(template.count * 8) <= Self.robustMatchMaxBitDiff
    }

    private func aad(_ label: Data) -> Data { Data("atlas/se/seal|".utf8) + deviceID + Data("|".utf8) + label }

    public func seal(_ secret: Data, label: Data) -> Data {
        (try? Primitives.aeadEncrypt(key: master, plaintext: secret, aad: aad(label))) ?? Data()
    }

    public func release(_ sealed: Data, liveSample: Data, label: Data) -> Data? {
        guard match(liveSample) else { return nil }
        return try? Primitives.aeadDecrypt(key: master, blob: sealed, aad: aad(label))
    }
}
