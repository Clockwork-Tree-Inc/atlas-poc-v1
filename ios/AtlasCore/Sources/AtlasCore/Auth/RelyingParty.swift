import Foundation

/// Atlas as the verified-human AUTHENTICATOR — for the bank and everything else.
/// Mirrors `backend/atlas/auth/relying_party.py`.
///
/// Atlas is NOT a bank / wallet / payment rail. It authenticates a PERSON to a
/// relying party: proves "a verified, live, present human — optionally with a YubiKey
/// step-up — authorized THIS action", bound to the relying party's challenge
/// (passkey/WebAuthn-shaped, but stronger). Relay-resistant (the relying party is
/// bound in), fail-closed (no presence / missing required step-up -> no assertion).
///
/// The hardware CARDS are a future EXTRA-STRENGTH, AIR-GAPPED factor for the shipped
/// product; the USB is recovery-only.
public enum AuthError: Error { case refused(String) }

public struct AuthChallenge {
    public let relyingParty: String
    public let action: String
    public let challenge: Data
    public let requireStepUp: Bool

    public init(relyingParty: String, action: String, challenge: Data, requireStepUp: Bool = false) {
        self.relyingParty = relyingParty; self.action = action
        self.challenge = challenge; self.requireStepUp = requireStepUp
    }

    public func binding() -> Data {
        Primitives.H(Data("atlas/auth/challenge".utf8), Data(relyingParty.utf8), Data(action.utf8),
                     challenge, Data([requireStepUp ? 1 : 0]))
    }
}

public struct VerifiedHumanAssertion {
    public var relyingParty: String
    public var action: String
    public var challenge: Data
    public var authorshipHandle: Data
    public var authorshipPublic: HybridSign.PublicKey
    public var live: Bool
    public var steppedUp: Bool
    public var signature: Data
    public var stepUpPublic: Data?
    public var stepUpSignature: Data?

    public func core() -> Data {
        Primitives.H(Data("atlas/auth/assertion".utf8), Data(relyingParty.utf8), Data(action.utf8),
                     challenge, authorshipHandle, Data([live ? 1 : 0]), Data([steppedUp ? 1 : 0]))
    }
}

/// Produce a verified-human assertion for the relying party's challenge. Requires
/// live presence; for a step-up challenge, requires a YubiKey fingerprint (throws if
/// absent — fail-closed).
public func authenticate(_ challenge: AuthChallenge, authorship: Child, pole: PoLEState,
                         yubikey: YubiKeyBio? = nil, fingerprintMatched: Bool = false) throws -> VerifiedHumanAssertion {
    guard pole.operate else { throw AuthError.refused("no live presence") }

    var steppedUp = false
    var suPub: Data? = nil
    var suSig: Data? = nil
    if challenge.requireStepUp {
        guard let yubikey else { throw AuthError.refused("relying party requires a YubiKey step-up") }
        let req = HighStakesRequest(action: "auth:" + challenge.action, context: challenge.binding(),
                                    challenge: challenge.challenge)
        suSig = try yubikey.authorize(req, fingerprintMatched: fingerprintMatched)
        suPub = yubikey.publicKey
        steppedUp = true
    }

    var assertion = VerifiedHumanAssertion(
        relyingParty: challenge.relyingParty, action: challenge.action, challenge: challenge.challenge,
        authorshipHandle: authorship.handle, authorshipPublic: authorship.publicKey,
        live: true, steppedUp: steppedUp, signature: Data(), stepUpPublic: suPub, stepUpSignature: suSig)
    assertion.signature = try HybridSign.sign(authorship.keypair, assertion.core())
    return assertion
}

/// Relying-party side. The assertion must be by the REGISTERED authenticator over
/// THIS exact challenge (incl. this relying party — relay-resistant), from a live
/// human, and — if a step-up was required — carry a valid authorization by the
/// REGISTERED YubiKey. Any mismatch -> false (fail-closed).
public func verifyAssertion(_ assertion: VerifiedHumanAssertion, _ challenge: AuthChallenge,
                            registeredHandle: Data, registeredPublic: HybridSign.PublicKey,
                            registeredStepUpPublic: Data? = nil) -> Bool {
    if assertion.relyingParty != challenge.relyingParty
        || assertion.action != challenge.action
        || assertion.challenge != challenge.challenge { return false }
    if assertion.authorshipHandle != registeredHandle { return false }
    if handleOf(assertion.authorshipPublic.encode()) != assertion.authorshipHandle { return false }
    if assertion.authorshipPublic.encode() != registeredPublic.encode() { return false }
    if !assertion.live { return false }
    if !HybridSign.verify(assertion.authorshipPublic, assertion.core(), assertion.signature) { return false }
    if challenge.requireStepUp {
        guard assertion.steppedUp, let suPub = assertion.stepUpPublic, let suSig = assertion.stepUpSignature else { return false }
        guard let reg = registeredStepUpPublic, suPub == reg else { return false }
        let req = HighStakesRequest(action: "auth:" + challenge.action, context: challenge.binding(),
                                    challenge: challenge.challenge)
        if !verifyHighStakes(suPub, req, suSig) { return false }
    }
    return true
}

// MARK: - wire serialization (matches the Python auth wire: assertion/challenge JSON)

extension AuthChallenge {
    public func toJSON() -> [String: Any] {
        ["relying_party": relyingParty, "action": action,
         "challenge": challenge.base64EncodedString(), "require_step_up": requireStepUp]
    }
    public static func fromJSON(_ o: [String: Any]) -> AuthChallenge? {
        guard let rp = o["relying_party"] as? String, let action = o["action"] as? String,
              let ch = (o["challenge"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return nil }
        return AuthChallenge(relyingParty: rp, action: action, challenge: ch,
                             requireStepUp: (o["require_step_up"] as? Bool) ?? false)
    }
}

public func authPubToJSON(_ p: HybridSign.PublicKey) -> [String: String] {
    ["mldsa_pk": p.mldsaPK.base64EncodedString(), "ed_pk": p.edPK.base64EncodedString()]
}
public func authPubFromJSON(_ o: [String: Any]) -> HybridSign.PublicKey? {
    guard let m = (o["mldsa_pk"] as? String).flatMap({ Data(base64Encoded: $0) }),
          let e = (o["ed_pk"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return nil }
    return HybridSign.PublicKey(mldsaPK: m, edPK: e)
}

extension VerifiedHumanAssertion {
    public func toJSON() -> [String: Any] {
        var o: [String: Any] = [
            "relying_party": relyingParty, "action": action,
            "challenge": challenge.base64EncodedString(),
            "authorship_handle": authorshipHandle.base64EncodedString(),
            "authorship_public": authPubToJSON(authorshipPublic),
            "live": live, "stepped_up": steppedUp,
            "signature": signature.base64EncodedString(),
        ]
        if let su = stepUpPublic { o["step_up_public"] = su.base64EncodedString() }
        if let ss = stepUpSignature { o["step_up_signature"] = ss.base64EncodedString() }
        return o
    }
}
