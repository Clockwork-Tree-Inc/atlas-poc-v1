import Foundation

/// Threshold biometric-key seal — (user-TSK-bound half ∧ m-of-n custodians), with storage
/// decoupled from confidentiality ("ciphertext-anywhere").
///
/// Mirrors `backend/atlas/recovery/threshold_seal.py` (TRUST_LAYER.md #1/#2). The Python core
/// is the reference-of-record; this must reproduce it byte-for-byte. The parity-critical piece
/// is `unlockKey` (a deterministic HKDF); Shamir and AES-GCM/HKDF are already parity-covered, so
/// an interop-checked `unseal` of a Python-produced sketch proves the whole path (see ParityTests).
public enum ThresholdSeal {

    public enum SealError: Error, Equatable {
        case policyInvalid                              // 1 < m <= n < 256 violated
        case custodianCountMismatch(expected: Int, got: Int)
        case thresholdNotMet(need: Int, got: Int)       // fewer than m shares presented
        case unsealFailed                                // wrong half/shares or tampered ciphertext
    }

    /// WHERE a sealed sketch is kept. Advisory only — confidentiality is identical for every
    /// value (the ciphertext-anywhere property, #2). Raw values match the Python enum.
    public enum StorageLocation: String {
        case selfCustody = "self"          // the user's own custody (paper/card/device)
        case homeNode = "home_node"        // a self-hosted home node
        case laptop = "laptop"             // a second personal device
        case guardians = "guardians"       // dispersed among the guardianship set
        case serverSharded = "server_sharded"  // sharded across operators/jurisdictions
    }

    /// m-of-n threshold over the custodians. Shamir requires m>1, so a threshold is always a
    /// genuine quorum; "store it all yourself" is a StorageLocation.selfCustody storage choice.
    public struct ThresholdPolicy: Equatable {
        public let n: Int
        public let m: Int
        public init(n: Int, m: Int) throws {
            guard 1 < m && m <= n && n < 256 else { throw SealError.policyInvalid }
            self.n = n; self.m = m
        }
    }

    /// A holder of one share. `label` is an OPAQUE handle — guardianship (#4) keeps the real
    /// membership private. `institutional` marks operators so #4 can enforce "no all-institutional
    /// subset reaches threshold"; this type records it but does not enforce it.
    public struct Custodian: Equatable {
        public let label: String
        public let institutional: Bool
        public init(label: String, institutional: Bool = false) {
            self.label = label; self.institutional = institutional
        }
    }

    /// One custodian's share of the custodian secret.
    public struct CustodianShare: Equatable {
        public let custodian: Custodian
        public let share: Shamir.Share
        public init(custodian: Custodian, share: Shamir.Share) {
            self.custodian = custodian; self.share = share
        }
    }

    /// Opaque ciphertext + where it is stored (#2). Holding this reveals nothing without the user
    /// half AND m custodian shares. `context` binds the AEAD (and the unlock key) so a sketch
    /// cannot be confused for another or moved between users/purposes.
    public struct SealedSketch {
        public let ciphertext: Data
        public let storage: StorageLocation
        public let policy: ThresholdPolicy
        public let context: Data
        public init(ciphertext: Data, storage: StorageLocation, policy: ThresholdPolicy, context: Data) {
            self.ciphertext = ciphertext; self.storage = storage
            self.policy = policy; self.context = context
        }
    }

    // HKDF label for the unlock key; bound to the seal's context (domain separation across seals).
    private static let unlockInfo = Data("atlas/threshold-seal/v1".utf8)
    static let keyBytes = 32  // custodian secret + AEAD key width (matches Primitives.aesKeyBytes)

    /// The seal key needs BOTH the user-TSK-bound half AND the threshold-combined custodian
    /// secret. Deterministic (HKDF) — the parity-critical derivation. Mirrors
    /// `recovery_anchor._bridge_key` / Python `threshold_seal._unlock_key`.
    public static func unlockKey(userHalf: Data, custodianSecret: Data, context: Data) -> Data {
        Primitives.hkdf(ikm: userHalf + custodianSecret, info: unlockInfo + context, length: keyBytes)
    }

    /// Seal `secret` under (userHalf ∧ m-of-n custodians). Returns the opaque `SealedSketch`
    /// (store anywhere) and one `CustodianShare` per custodian (distribute them). The custodian
    /// secret is fresh CSPRNG — never password-derived — so there is nothing low-entropy to grind.
    public static func seal(_ secret: Data, userHalf: Data, custodians: [Custodian],
                            policy: ThresholdPolicy, storage: StorageLocation,
                            context: Data = Data()) throws -> (SealedSketch, [CustodianShare]) {
        guard custodians.count == policy.n else {
            throw SealError.custodianCountMismatch(expected: policy.n, got: custodians.count)
        }
        let custodianSecret = Primitives.randomBytes(keyBytes)
        let shares = Shamir.split(custodianSecret, n: policy.n, k: policy.m)
        let key = unlockKey(userHalf: userHalf, custodianSecret: custodianSecret, context: context)
        let ct = try Primitives.aeadEncrypt(key: key, plaintext: secret, aad: context)
        let sealed = SealedSketch(ciphertext: ct, storage: storage, policy: policy, context: context)
        let cshares = zip(custodians, shares).map { CustodianShare(custodian: $0, share: $1) }
        return (sealed, cshares)
    }

    /// Reopen a `SealedSketch`. Needs the `userHalf` AND at least m custodian shares. Fail-closed:
    /// below threshold throws `.thresholdNotMet`; any wrong factor throws `.unsealFailed` with no
    /// distinguishing oracle. The declared storage location is never consulted (#2).
    public static func unseal(_ sealed: SealedSketch, userHalf: Data,
                              custodianShares: [CustodianShare]) throws -> Data {
        guard custodianShares.count >= sealed.policy.m else {
            throw SealError.thresholdNotMet(need: sealed.policy.m, got: custodianShares.count)
        }
        let custodianSecret = Shamir.combine(custodianShares.map { $0.share })
        let key = unlockKey(userHalf: userHalf, custodianSecret: custodianSecret, context: sealed.context)
        do {
            return try Primitives.aeadDecrypt(key: key, blob: sealed.ciphertext, aad: sealed.context)
        } catch {
            throw SealError.unsealFailed
        }
    }
}
