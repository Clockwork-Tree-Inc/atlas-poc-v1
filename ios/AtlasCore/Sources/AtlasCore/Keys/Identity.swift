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

/// A PERSONA — a top-level compartment under the blind System-ID that owns its OWN full
/// stack (vault, messaging, forum, …). Mirrors `backend/atlas/keys/identity.py` `Profile`.
/// Its PUBLIC identity is `identity.handle`; `username` is only the human label the person
/// chose. Distinct (username, tier) -> a distinct, mutually UNLINKABLE persona — a pseudonym
/// cannot be tied to the real you or to your other personas by anyone who only sees handles.
/// Every per-feature slice derives UNDER the per-persona seed, so even one persona's own
/// surfaces (its messaging vs its vault) don't cross-link. Build via `IdentityTree.profile`.
public struct Profile {
    public let username: String
    public let tier: PseudonymTier
    public let identity: Child          // the persona's signing identity; its handle IS the persona
    let seed: Data                      // per-persona root; parent of every feature slice (never exposed)

    /// The persona's public, opaque standing handle (what a relay / forum sees).
    public var handle: Data { identity.handle }

    /// A per-feature slice of THIS persona (e.g. "messaging", "vault", "forum"). Its own
    /// one-way handle, unlinkable to the persona's other features or to any other persona.
    public func feature(_ feature: String) throws -> Child {
        let s = Primitives.hkdf(ikm: seed,
                                info: Data("atlas/feature/".utf8) + Data(feature.utf8), length: 32)
        return Child(context: "\(username)/\(feature)", keypair: try HybridSign.keypair(fromSeed: s))
    }
}

public enum IdentityRestoreError: Error { case malformed }

public final class IdentityTree {
    // SECURITY (mirrors backend): the whole TSK seed is NEVER stored on the tree. It exists only
    // transiently at genesis; post-genesis it lives ONLY in the 2-of-3 recovery shares. reroot/
    // recovery are handed it momentarily — they never read it off this object.
    public let tskPublic: Data             // SPHINCS+ public root
    private let tskSecret: Data            // SPHINCS+ secret (held; never surfaced)
    let systemIDSecret: Data               // REASSEMBLED from both halves; blind root, never exposed
    let userHalf: Data                     // the card factor
    private let serverHSM: ServerHSM?      // holds the non-exportable server half
    public private(set) var children: [IdentityContext: Child] = [:]
    public let rotation: Int               // System-ID re-rooting generation (§5)
    private let sphincs: SphincsProvider

    init(tskPublic: Data, tskSecret: Data, systemIDSecret: Data,
         userHalf: Data = Data(), serverHSM: ServerHSM? = nil, rotation: Int = 0,
         sphincs: SphincsProvider) {
        self.tskPublic = tskPublic
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

    /// Derive a PERSONA (top-level compartment) from the blind System-ID. Mirrors
    /// `identity.py` `profile`. The persona's identity and ALL its feature slices hang off a
    /// per-persona seed, so personas are mutually unlinkable and unlinkable to the real you —
    /// only the holder of the System-ID can prove two personas are the same person. Use
    /// tier=.public for a persona you intend to certify as the real you; .anonymous otherwise.
    public func profile(_ username: String, tier: PseudonymTier = .anonymous) throws -> Profile {
        let seed = Primitives.hkdf(ikm: systemIDSecret,
                                   info: Data("atlas/profile/".utf8) + Data(tier.rawValue.utf8)
                                       + Data("/".utf8) + Data(username.utf8),
                                   length: 32)
        let identitySeed = Primitives.hkdf(ikm: seed, info: Data("atlas/profile/identity".utf8), length: 32)
        let identity = Child(context: "profile:\(tier.rawValue):\(username)",
                             keypair: try HybridSign.keypair(fromSeed: identitySeed))
        return Profile(username: username, tier: tier, identity: identity, seed: seed)
    }

    /// A designated DECOY persona presented under duress (#40). Mirrors `identity.py`
    /// `duress_persona`. Derived under a DISTINCT HKDF domain (`atlas/duress-profile/`) so it can
    /// never collide with any real `profile(username)` — yet it is a full, plausible compartment,
    /// cryptographically unlinkable to the System-ID and to every real persona. Deterministic per
    /// (user, slot). Present ONLY this when unlocked via the duress code.
    public func duressPersona(_ slot: Int = 0) throws -> Profile {
        let seed = Primitives.hkdf(ikm: systemIDSecret,
                                   info: Data("atlas/duress-profile/".utf8) + Data(String(slot).utf8),
                                   length: 32)
        let identitySeed = Primitives.hkdf(ikm: seed, info: Data("atlas/profile/identity".utf8), length: 32)
        let identity = Child(context: "duress:\(slot)", keypair: try HybridSign.keypair(fromSeed: identitySeed))
        return Profile(username: "duress:\(slot)", tier: .anonymous, identity: identity, seed: seed)
    }

    /// The per-persona seed for a REAL persona (same value `profile(username, tier)` derives from).
    /// Used to seal a SELF-SELECTED persona as the duress decoy: a persona you actually use has real
    /// history, so it is plausible under coercion in a way a synthetic empty persona never is.
    public func profileSeed(_ username: String, tier: PseudonymTier = .anonymous) -> Data {
        Primitives.hkdf(ikm: systemIDSecret,
                        info: Data("atlas/profile/".utf8) + Data(tier.rawValue.utf8)
                            + Data("/".utf8) + Data(username.utf8), length: 32)
    }

    /// The decoy persona's per-persona seed (the value `duress_persona` derives from). Persist this
    /// sealed under the PANIC code at arming time so the duress session can rebuild the SAME decoy
    /// (via `personaFromSeed`) without ever reassembling the real System-ID — the panic code can
    /// unlock the decoy alone, never the root.
    public func duressPersonaSeed(_ slot: Int = 0) -> Data {
        Primitives.hkdf(ikm: systemIDSecret,
                        info: Data("atlas/duress-profile/".utf8) + Data(String(slot).utf8), length: 32)
    }

    /// Rebuild a persona from its stored per-persona seed alone (no System-ID needed). Reproduces
    /// the identical handle/keys/features as the derivation that produced the seed.
    public static func personaFromSeed(_ seed: Data, username: String,
                                       tier: PseudonymTier = .anonymous) throws -> Profile {
        let identitySeed = Primitives.hkdf(ikm: seed, info: Data("atlas/profile/identity".utf8), length: 32)
        let identity = Child(context: "duress:\(username)", keypair: try HybridSign.keypair(fromSeed: identitySeed))
        return Profile(username: username, tier: tier, identity: identity, seed: seed)
    }

    /// The TSK signs re-enrolment / continuity (§2.1 "Root only").
    public func signContinuity(_ message: Data) -> Data {
        sphincs.sign(secretKey: tskSecret, message: message)
    }

    // -- device-local persistence (session restore across app launches) ------

    /// SENSITIVE: the tree's secret material, serialized for DEVICE-LOCAL restore only. The caller
    /// MUST seal this under the Secure Enclave before persisting (never store or transmit it in
    /// the clear). Contains no TSK seed (that stays recovery-shares-only); the System-ID secret and
    /// SPHINCS+ secret here are exactly what the running tree already holds in memory.
    public func exportState() -> Data {
        let obj: [String: Any] = ["v": 1,
                                  "tskPublic": tskPublic.base64EncodedString(),
                                  "tskSecret": tskSecret.base64EncodedString(),
                                  "systemIDSecret": systemIDSecret.base64EncodedString(),
                                  "userHalf": userHalf.base64EncodedString(),
                                  "rotation": rotation]
        return (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
    }

    /// Rebuild a tree from `exportState()` output — children re-derive from the System-ID exactly
    /// as at genesis. (No ServerHSM on restore: it is only needed to REASSEMBLE at genesis/re-root.)
    public static func restore(from data: Data, sphincs: SphincsProvider) throws -> IdentityTree {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tskPub = (obj["tskPublic"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let tskSec = (obj["tskSecret"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let sysID = (obj["systemIDSecret"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let userHalf = (obj["userHalf"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let rotation = obj["rotation"] as? Int
        else { throw IdentityRestoreError.malformed }
        let tree = IdentityTree(tskPublic: tskPub, tskSecret: tskSec, systemIDSecret: sysID,
                                userHalf: userHalf, serverHSM: nil, rotation: rotation, sphincs: sphincs)
        for ctx in IdentityContext.allCases {
            let info = Data("atlas/child/\(ctx.rawValue)/0".utf8)
            let childSeed = Primitives.hkdf(ikm: sysID, info: info, length: 32)
            tree.children[ctx] = Child(context: ctx.rawValue, keypair: try HybridSign.keypair(fromSeed: childSeed))
        }
        return tree
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

        let tree = IdentityTree(tskPublic: tsk.publicKey, tskSecret: tsk.secretKey,
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
                           challenge: Data, signature: Data,
                           matcherPublic: HybridSign.PublicKey? = nil,
                           matchAttestation: Data = Data()) -> VerificationResult {
    let matched = handleOf(revealedPublic.encode()) == assertedHandle
    let sigOK = matched && HybridSign.verify(revealedPublic, challenge, signature)
    // The biometric match is a VERIFIABLE ATTESTATION (the SE on-device, or an accountable
    // recovery attestor, signs a challenge-bound match statement), not a forgeable bool
    // (security review #9; mirrors backend keys/identity.py).
    let matchStmt = Primitives.H(Data("atlas/biometric-match-1to1".utf8), assertedHandle, challenge)
    let biometricMatched: Bool
    if let mp = matcherPublic, !matchAttestation.isEmpty {
        biometricMatched = HybridSign.verify(mp, matchStmt, matchAttestation)
    } else {
        biometricMatched = false
    }
    return VerificationResult(matchedHandle: matched, signatureValid: sigOK, biometricMatched: biometricMatched)
}

/// The trusted matcher (Secure Enclave on device, or an accountable live-recovery attestor)
/// signs the one-to-one biometric-match verdict, bound to THIS challenge — unforgeable and
/// matcher-key-rooted, replacing a forgeable bool (security review #9; mirrors backend).
public func attestBiometricMatch(_ matcher: HybridSign.Keypair,
                                 assertedHandle: Data, challenge: Data) throws -> Data {
    try HybridSign.sign(matcher, Primitives.H(Data("atlas/biometric-match-1to1".utf8), assertedHandle, challenge))
}
