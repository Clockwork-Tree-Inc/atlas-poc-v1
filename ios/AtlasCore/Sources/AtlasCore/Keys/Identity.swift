import Foundation

/// True-Self-Key identity tree and one-to-one verification (§2.1, §7.1).
/// Mirrors `backend/atlas/keys/identity.py`.
///
/// CORRECTED IDENTITY MODEL (supersedes the earlier single-seed System-ID):
/// the permanent TSK is ONE key, SPLIT into two halves — a USER-HELD half
/// (the Atlas Card / possession factor) and a SERVER-HSM-HELD half
/// (non-exportable, HSM-resident). There is NO separate System-ID secret; the
/// System-ID is *reassembled* from BOTH halves — neither half alone reassembles
/// it. The SPHINCS+ root is injected via `SphincsProvider` (see HybridSign.swift
/// seam note).
///
/// TSK (permanent; split user-half + server-HSM-half) -> System-ID (reassembled
/// from both halves; blind) -> children (real-id / anonymous / authorship /
/// recovery) and user-selected pseudonyms, forward-derivation only.
public enum IdentityContext: String, CaseIterable {
    case realID = "real-id"
    case anonymous = "anonymous"
    case authorship = "authorship"
    case recovery = "recovery"
}

public func handleOf(_ publicEncoded: Data) -> Data {
    Primitives.H(Data("atlas/handle".utf8), publicEncoded)
}

// ---------------------------------------------------------------------------
// Split TSK  ->  reassembled System-ID  (Locked Model §2.1-2.2)
// ---------------------------------------------------------------------------

/// User-selected disclosure tier per pseudonym (identity / pseudonym /
/// anonymity tiers).
public enum PseudonymTier: String {
    case `public` = "public"
    case `private` = "private"
    case anonymous = "anonymous"
}

/// Split the permanent TSK into a user-held half (Atlas Card) and a server-HSM
/// half. Deterministic AT GENESIS only; post-genesis the whole seed is destroyed
/// and neither party holds both halves.
public func tskHalves(tskSeed: Data, rotation: Int = 0) -> (userHalf: Data, serverHalf: Data) {
    let salt = rotation == 0 ? Data() : Data("/v\(rotation)".utf8)
    let userHalf = Primitives.hkdf(ikm: tskSeed, info: Data("atlas/tsk/user-half".utf8) + salt, length: 32)
    let serverHalf = Primitives.hkdf(ikm: tskSeed, info: Data("atlas/tsk/server-half".utf8) + salt, length: 32)
    return (userHalf, serverHalf)
}

/// The blind System-ID, reassembled from BOTH halves. Neither half alone can
/// compute it (each is an independent 32-byte secret; the KDF needs both).
public func reassembleSystemID(userHalf: Data, serverHalf: Data) -> Data {
    Primitives.hkdf(ikm: userHalf + serverHalf, info: Data("atlas/system-id/reassembled".utf8), length: 32)
}

/// Models the (distributed) server HSM holding the server half of a split TSK.
/// It participates in System-ID reassembly but exposes NO accessor for its half.
///
/// HONEST BOUNDARY: true non-exportability is a hardware-HSM property (the key
/// physically cannot leave tamper-resistant hardware); Swift cannot enforce it,
/// so this models the API contract (no method returns the half), not memory
/// protection. Same hardware-gated boundary as the Secure Enclave.
public final class ServerHSM {
    private let serverHalf: Data                 // non-exportable (no accessor)

    public init(serverHalf: Data) {
        self.serverHalf = serverHalf
    }

    /// Combine the caller's user half with the sealed server half. The server
    /// half never leaves the HSM; only the reassembled System-ID is returned.
    public func reassembleSystemID(userHalf: Data) -> Data {
        AtlasCore.reassembleSystemID(userHalf: userHalf, serverHalf: serverHalf)
    }
}

/// x-of-n split of the (biometric-associated) user half, distributed ACROSS
/// servers for card-loss recovery — no single node holds it.
public func splitUserHalfForRecovery(userHalf: Data, n: Int = 5, k: Int = 3) -> [Shamir.Share] {
    Shamir.split(userHalf, n: n, k: k)
}

/// Reconstruct the user half from >= k distributed shares (safe-setting,
/// in-person card-loss recovery).
public func reconstructUserHalf(_ shares: [Shamir.Share]) -> Data {
    Shamir.combine(shares)
}

public struct Child {
    public let context: String
    public let keypair: HybridSign.Keypair
    public var publicKey: HybridSign.PublicKey { keypair.publicKey }
    public var handle: Data { handleOf(publicKey.encode()) }
}

public final class IdentityTree {
    public let tskSeed: Data               // 32B+ root seed (whole TSK; genesis only)
    public let tskPublic: Data             // SPHINCS+ public root
    private let tskSecret: Data            // SPHINCS+ secret (held; never surfaced)
    let systemIDSecret: Data               // REASSEMBLED from both halves; blind root, never exposed
    let userHalf: Data                     // the card factor
    private let serverHSM: ServerHSM?      // holds the non-exportable server half
    public private(set) var children: [IdentityContext: Child] = [:]
    public let rotation: Int               // System-ID re-rooting generation (§5)
    private let sphincs: SphincsProvider

    init(tskSeed: Data, tskPublic: Data, tskSecret: Data, systemIDSecret: Data,
         userHalf: Data = Data(), serverHSM: ServerHSM? = nil, rotation: Int = 0,
         sphincs: SphincsProvider) {
        self.tskSeed = tskSeed; self.tskPublic = tskPublic
        self.tskSecret = tskSecret; self.systemIDSecret = systemIDSecret
        self.userHalf = userHalf; self.serverHSM = serverHSM; self.rotation = rotation
        self.sphincs = sphincs
    }

    /// Static standing identifier H(TSK_public) (§7.1). Durable across re-roots.
    public var rootHandle: Data { handleOf(tskPublic) }

    /// Handle of the blind System-ID. The secret itself is never exposed.
    public func systemIDHandle() -> Data {
        Primitives.H(Data("atlas/system-id-handle".utf8), systemIDSecret)
    }

    public func child(_ ctx: IdentityContext) -> Child { children[ctx]! }

    /// Derive a user-defined pseudonym (PUBLIC / PRIVATE / ANONYMOUS tier)
    /// forward from the reassembled System-ID. Distinct label or tier -> distinct,
    /// unlinkable pseudonym.
    public func pseudonym(_ label: String, tier: PseudonymTier) throws -> Child {
        let info = Data("atlas/pseudonym/".utf8) + Data(tier.rawValue.utf8)
            + Data("/".utf8) + Data(label.utf8)
        let seed = Primitives.hkdf(ikm: systemIDSecret, info: info, length: 32)
        return Child(context: "\(tier.rawValue):\(label)", keypair: try HybridSign.keypair(fromSeed: seed))
    }

    /// The TSK signs re-enrolment / continuity (§2.1 "Root only").
    public func signContinuity(_ message: Data) -> Data {
        sphincs.sign(secretKey: tskSecret, message: message)
    }

    /// Genesis: construct the tree from a (QRNG-seeded) whole TSK (§6, §2.1).
    ///
    /// The whole TSK exists only transiently at genesis. It is SPLIT into a
    /// user-held half and a server-HSM half; the System-ID is then REASSEMBLED
    /// from both (neither half alone reassembles it). `serverHSM` lets a caller
    /// supply the HSM that already holds the server half (the normal case after
    /// genesis); if omitted, genesis creates one and seals the deterministically-
    /// split server half into it. `rotation` is the System-ID re-rooting
    /// generation: the TSK (and rootHandle) is DURABLE across re-roots; only the
    /// System-ID (and thus pseudonyms) rotate.
    public static func build(tskSeed: Data, rotation: Int = 0,
                             serverHSM: ServerHSM? = nil, sphincs: SphincsProvider) throws -> IdentityTree {
        precondition(tskSeed.count >= 32, "tskSeed must be >= 32 bytes")
        // TSK SPHINCS+ keypair from a domain-separated seed (rotation-independent).
        let spxSeed = Primitives.hkdf(ikm: tskSeed, info: Data("atlas/tsk/spx".utf8), length: 48)
        let tsk = sphincs.keypair(fromSeed: spxSeed)

        // Split the whole TSK; reassemble the blind System-ID from BOTH halves.
        let (userHalf, serverHalf) = tskHalves(tskSeed: tskSeed, rotation: rotation)
        let hsm = serverHSM ?? ServerHSM(serverHalf: serverHalf)
        let systemIDSecret = hsm.reassembleSystemID(userHalf: userHalf)   // needs both halves

        let tree = IdentityTree(tskSeed: tskSeed, tskPublic: tsk.publicKey, tskSecret: tsk.secretKey,
                                systemIDSecret: systemIDSecret, userHalf: userHalf, serverHSM: hsm,
                                rotation: rotation, sphincs: sphincs)
        // Forward-derive each fixed child from the reassembled System-ID.
        for ctx in IdentityContext.allCases {
            let info = Data("atlas/child/\(ctx.rawValue)/0".utf8)
            let childSeed = Primitives.hkdf(ikm: systemIDSecret, info: info, length: 32)
            tree.children[ctx] = Child(context: ctx.rawValue, keypair: try HybridSign.keypair(fromSeed: childSeed))
        }
        return tree
    }
}

/// One-to-one verification (§7.1): selector -> retrieve one identity -> verify
/// (not identify). The blind System-ID root is never touched.
public struct VerificationResult {
    public let matchedHandle: Bool
    public let signatureValid: Bool
    public let biometricMatched: Bool
    public var ok: Bool { matchedHandle && signatureValid && biometricMatched }
}

public func verifyOneToOne(assertedHandle: Data, revealedPublic: HybridSign.PublicKey,
                           challenge: Data, signature: Data, liveBiometricMatches: Bool) -> VerificationResult {
    let matched = handleOf(revealedPublic.encode()) == assertedHandle
    let sigOK = matched && HybridSign.verify(revealedPublic, challenge, signature)
    return VerificationResult(matchedHandle: matched, signatureValid: sigOK, biometricMatched: liveBiometricMatches)
}
