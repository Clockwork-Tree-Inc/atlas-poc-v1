import XCTest
@testable import AtlasCore

/// Atlas as the verified-human authenticator for a relying party. Mirrors
/// `backend/tests/test_auth.py`, with the byte-exact challenge-binding vector.
final class AuthTests: XCTestCase {

    private func livePole() -> PoLEState {
        let g = LivenessGate()
        for (_, l) in Synthetic.liveStream(40) { g.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        return g.state(sensorDigest: Data("s".utf8), drandRound: Data(count: 8))
    }
    private func deadPole() -> PoLEState {
        PoLEState(pLive: 0, stateDigest: Data("d".utf8), drandRound: Data(count: 8), operate: false)
    }
    private func user() throws -> Child {
        try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs()).child(.authorship)
    }
    private func chal(_ rp: String = "acme-bank", _ action: String = "login", stepUp: Bool = false) -> AuthChallenge {
        AuthChallenge(relyingParty: rp, action: action, challenge: Primitives.randomBytes(16), requireStepUp: stepUp)
    }

    func testChallengeBindingParity() {
        let ch = AuthChallenge(relyingParty: "acme-bank", action: "login",
                               challenge: Data("fixed-nonce-1234".utf8), requireStepUp: false)
        XCTAssertEqual(ch.binding().base64EncodedString(), "jckXTK7av4LZbz46mF0t2pFgWOYmEMIMDnOISVhl6hE=")
        let su = AuthChallenge(relyingParty: "acme-bank", action: "authorize-transfer",
                               challenge: Data("fixed-nonce-1234".utf8), requireStepUp: true)
        XCTAssertEqual(su.binding().base64EncodedString(), "zP2Rk7eACd1WZ70TPGu/mRf9cRhDbuAxMvo7S80f6h8=")
    }

    func testRegisteredUserAuthenticates() throws {
        let u = try user(); let ch = chal()
        let a = try authenticate(ch, authorship: u, pole: livePole())
        XCTAssertTrue(verifyAssertion(a, ch, registeredHandle: u.handle, registeredPublic: u.publicKey))
    }

    func testNoLivePresenceFailsClosed() throws {
        XCTAssertThrowsError(try authenticate(chal(), authorship: try user(), pole: deadPole()))
    }

    func testCannotBeRelayedToADifferentRelyingParty() throws {
        let u = try user(); let ch = chal("acme-bank")
        let a = try authenticate(ch, authorship: u, pole: livePole())
        let evil = AuthChallenge(relyingParty: "evil-bank", action: "login", challenge: ch.challenge)
        XCTAssertFalse(verifyAssertion(a, evil, registeredHandle: u.handle, registeredPublic: u.publicKey))
    }

    func testWrongRegisteredKeyRejected() throws {
        let u = try user(), stranger = try user(); let ch = chal()
        let a = try authenticate(ch, authorship: u, pole: livePole())
        XCTAssertFalse(verifyAssertion(a, ch, registeredHandle: stranger.handle, registeredPublic: stranger.publicKey))
    }

    func testStepUpWithYubiKeyVerifies() throws {
        let u = try user(); let yk = YubiKeyBio(); let ch = chal("acme-bank", "authorize-transfer", stepUp: true)
        let a = try authenticate(ch, authorship: u, pole: livePole(), yubikey: yk, fingerprintMatched: true)
        XCTAssertTrue(verifyAssertion(a, ch, registeredHandle: u.handle, registeredPublic: u.publicKey,
                                      registeredStepUpPublic: yk.publicKey))
    }

    func testStepUpRequiresYubiKey() throws {
        XCTAssertThrowsError(try authenticate(chal("acme-bank", "authorize-transfer", stepUp: true),
                                              authorship: try user(), pole: livePole()))
    }

    func testAttackersYubiKeyCannotStandIn() throws {
        let u = try user(); let yk = YubiKeyBio(); let attacker = YubiKeyBio()
        let ch = chal("acme-bank", "authorize-transfer", stepUp: true)
        let a = try authenticate(ch, authorship: u, pole: livePole(), yubikey: yk, fingerprintMatched: true)
        XCTAssertFalse(verifyAssertion(a, ch, registeredHandle: u.handle, registeredPublic: u.publicKey,
                                       registeredStepUpPublic: attacker.publicKey))
    }
}
