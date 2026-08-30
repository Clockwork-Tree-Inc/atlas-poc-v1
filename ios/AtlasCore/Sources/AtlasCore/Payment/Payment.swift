import Foundation
import CryptoKit

/// Arm-per-use payment — protocol-logic core (Payment spec §4). Mirrors
/// `backend/atlas/payment/`. Pure Swift so the binding/freshness/single-use
/// logic builds and tests on the Mac.
///
/// ⚠️  NOT THE AIR GAP. The air-gap property exists only with the physical
/// Card 2 over a real NFC/APDU session (Step Zero, §1). `ModelPaymentCard` is a
/// logic model; the real card is the JavaCard applet (javacard/Card2Applet.java)
/// driven over NFC (AtlasApp/Payment).
public struct TransactionDescriptor {
    public let amount: Int          // smallest unit
    public let recipientID: String
    public let nonce: String        // hex; nullifier key
    public let timestamp: Int
    public let epoch: Int
    public init(amount: Int, recipientID: String, nonce: String, timestamp: Int, epoch: Int) {
        self.amount = amount; self.recipientID = recipientID; self.nonce = nonce
        self.timestamp = timestamp; self.epoch = epoch
    }
    /// Canonical bytes — must match the Python core.
    public func canonical() -> Data {
        Data("{\"amount\":\(amount),\"epoch\":\(epoch),\"nonce\":\"\(nonce)\",\"recipient_id\":\"\(recipientID)\",\"timestamp\":\(timestamp)}".utf8)
    }
    public var wellFormed: Bool { amount > 0 && !recipientID.isEmpty && !nonce.isEmpty && timestamp > 0 && epoch >= 0 }
}

public func armingMessage(_ d: TransactionDescriptor, cardID: Data, cardNonce: Data) -> Data {
    Primitives.H(Data("atlas/arming".utf8), d.canonical()) + cardID + cardNonce
}

public enum PaymentError: Error { case armingRefused(String), cardRefused(String), doubleSpend }

public struct Arming { public let signature: Data; public let cardID: Data; public let cardNonce: Data }

/// Enclave arming authority (§4 steps 2–4). Real impl: Secure Enclave key +
/// LAContext side-button gate (AtlasApp/Payment/ArmingMinter). This model uses a
/// software Ed25519 key for Mac tests.
public final class EnclaveArmingAuthority {
    private let key = Curve25519.Signing.PrivateKey()
    public var publicKey: Data { key.publicKey.rawRepresentation }
    public init() {}
    public func mint(descriptor: TransactionDescriptor, cardID: Data, cardNonce: Data,
                     liveness: LivenessAttestation?, intentPressed: Bool, coMotion: Bool,
                     requireCoMotion: Bool) throws -> Arming {
        guard let l = liveness, l.verify(), l.operate else { throw PaymentError.armingRefused("no liveness") }
        guard intentPressed else { throw PaymentError.armingRefused("no side-button intent") }
        if requireCoMotion && !coMotion { throw PaymentError.armingRefused("co-motion required") }
        guard descriptor.wellFormed else { throw PaymentError.armingRefused("malformed descriptor") }
        let sig = try key.signature(for: armingMessage(descriptor, cardID: cardID, cardNonce: cardNonce))
        return Arming(signature: sig, cardID: cardID, cardNonce: cardNonce)
    }
}

/// Logic model of Card 2 (§4 steps 4–6). Private key never exported.
public final class ModelPaymentCard {
    private let signingKey = Curve25519.Signing.PrivateKey()   // on-card; never exported
    public let cardID: Data
    private let enclavePub: Curve25519.Signing.PublicKey
    private var pendingNonce: Data?
    public init(enclaveArmingPublic: Data, cardID: Data = Primitives.randomBytes(8)) throws {
        self.cardID = cardID
        self.enclavePub = try Curve25519.Signing.PublicKey(rawRepresentation: enclaveArmingPublic)
    }
    public var publicKey: Data { signingKey.publicKey.rawRepresentation }
    public func issueChallenge() -> (Data, Data) { let n = Primitives.randomBytes(16); pendingNonce = n; return (cardID, n) }
    public func sign(_ d: TransactionDescriptor, arming: Arming) throws -> Data {
        guard let pending = pendingNonce else { throw PaymentError.cardRefused("not armed this tap") }
        guard arming.cardID == cardID else { throw PaymentError.cardRefused("wrong card") }
        guard arming.cardNonce == pending else { throw PaymentError.cardRefused("card_nonce mismatch") }
        guard d.wellFormed else { throw PaymentError.cardRefused("malformed") }
        guard enclavePub.isValidSignature(arming.signature, for: armingMessage(d, cardID: cardID, cardNonce: pending))
        else { throw PaymentError.cardRefused("invalid arming signature") }
        let sig = try signingKey.signature(for: d.canonical())
        pendingNonce = nil                                     // single-use
        return sig
    }
}

public final class NullifierRegistry {
    private var spent = Set<String>()
    public init() {}
    public func isSpent(_ nonce: String) -> Bool { spent.contains(nonce) }
    public func nullify(_ nonce: String) { spent.insert(nonce) }
}

public struct PaymentVerifier {
    let registry: NullifierRegistry
    public init(registry: NullifierRegistry) { self.registry = registry }
    public func verifyAndSubmit(_ d: TransactionDescriptor, paymentSig: Data, cardPublic: Data) throws -> Bool {
        if registry.isSpent(d.nonce) { throw PaymentError.doubleSpend }
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: cardPublic),
              pub.isValidSignature(paymentSig, for: d.canonical()) else { return false }
        registry.nullify(d.nonce)
        return true
    }
}
