import XCTest
@testable import AtlasCore

/// Conversation state model: ordering, out-of-order, replay, persistence across
/// restart, accountable/deniable toggle. Mirrors `backend/tests/test_conversation.py`.
final class ConversationTests: XCTestCase {
    private let channelKey = Data(repeating: 0x4B, count: 32)   // "K"
    private let lk = Data(repeating: 0x4C, count: 32)           // "L"
    private let epoch = Data(repeating: 0, count: 8)
    private let beacon = Data("beacon-epoch-1".utf8)
    private let a2b = Data("A->B".utf8)
    private let b2a = Data("B->A".utf8)

    private func makePair(_ mode: ConversationMode) throws -> (a: Conversation, b: Conversation, aAuth: Child, bAuth: Child) {
        let aTree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let bTree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let aAuth = aTree.child(.authorship), bAuth = bTree.child(.authorship)
        let a = try Conversation.create(mode: mode, myDirection: a2b, peerDirection: b2a,
                                        channelKey: channelKey, lk: lk, drandRound: epoch, beaconT: beacon,
                                        authorship: aAuth, peerPublic: bAuth.publicKey)
        let b = try Conversation.create(mode: mode, myDirection: b2a, peerDirection: a2b,
                                        channelKey: channelKey, lk: lk, drandRound: epoch, beaconT: beacon,
                                        authorship: bAuth, peerPublic: aAuth.publicKey)
        return (a, b, aAuth, bAuth)
    }

    func testInOrderRoundtripBothModes() throws {
        for mode in [ConversationMode.accountable, .deniable] {
            let (a, b, _, _) = try makePair(mode)
            for text in ["hi", "meet at 9", "bring the ring"] {
                XCTAssertEqual(try b.receive(try a.send(Data(text.utf8))), Data(text.utf8))
            }
            for text in ["on my way", "ok"] {
                XCTAssertEqual(try a.receive(try b.send(Data(text.utf8))), Data(text.utf8))
            }
        }
    }

    func testOutOfOrderDeliveryViaSkippedCache() throws {
        let (a, b, _, _) = try makePair(.deniable)
        let e0 = try a.send(Data("zero".utf8))
        let e1 = try a.send(Data("one".utf8))
        let e2 = try a.send(Data("two".utf8))
        XCTAssertEqual(try b.receive(e2), Data("two".utf8))   // first -> 0,1 cached
        XCTAssertEqual(try b.receive(e0), Data("zero".utf8))  // earlier still open
        XCTAssertEqual(try b.receive(e1), Data("one".utf8))
    }

    func testReplayIsRejected() throws {
        let (a, b, _, _) = try makePair(.deniable)
        let e0 = try a.send(Data("once".utf8))
        XCTAssertEqual(try b.receive(e0), Data("once".utf8))
        XCTAssertThrowsError(try b.receive(e0))               // same index again -> refused
    }

    func testTooManySkippedIsGuarded() throws {
        let (a, b, _, _) = try makePair(.deniable)
        var far: Envelope?
        for _ in 0..<300 { far = try a.send(Data("x".utf8)) }
        XCTAssertThrowsError(try b.receive(far!)) { err in
            guard case ConversationError.tooManySkipped = err else { return XCTFail("expected tooManySkipped") }
        }
    }

    func testPersistenceAcrossRestartResumesLockstep() throws {
        let (a, b, aAuth, bAuth) = try makePair(.accountable)
        _ = try b.receive(try a.send(Data("before 1".utf8)))
        _ = try b.receive(try a.send(Data("before 2".utf8)))
        // "app restart": serialize positions, drop objects, reload with keys.
        let a2 = try Conversation.deserialize(a.serialize(), authorship: aAuth, peerPublic: bAuth.publicKey)
        let b2 = try Conversation.deserialize(b.serialize(), authorship: bAuth, peerPublic: aAuth.publicKey)
        XCTAssertEqual(try b2.receive(try a2.send(Data("after".utf8))), Data("after".utf8))
        XCTAssertEqual(try a2.receive(try b2.send(Data("reply".utf8))), Data("reply".utf8))
    }

    func testForwardSecrecyConsumedKeyGoneAfterRestart() throws {
        let (a, b, aAuth, bAuth) = try makePair(.accountable)
        let e0 = try a.send(Data("secret zero".utf8))
        _ = try b.receive(e0)                                  // consume index 0
        let b2 = try Conversation.deserialize(b.serialize(), authorship: bAuth, peerPublic: aAuth.publicKey)
        XCTAssertThrowsError(try b2.receive(e0))               // consumed key discarded -> unrecoverable
    }

    func testAccountableValidSignatureVerifies() throws {
        let (a, b, _, _) = try makePair(.accountable)
        XCTAssertEqual(try b.receive(try a.send(Data("I authorize".utf8))), Data("I authorize".utf8))
    }

    func testAccountableTamperedSignatureRejected() throws {
        let (a, b, _, _) = try makePair(.accountable)
        var env = try a.send(Data("I authorize".utf8))
        env.signature[env.signature.count - 1] ^= 1
        XCTAssertThrowsError(try b.receive(env)) { err in
            guard case ConversationError.signatureRejected = err else { return XCTFail("expected signatureRejected") }
        }
    }

    func testAccountableWrongAuthorKeyRejected() throws {
        let (a, _, _, _) = try makePair(.accountable)
        let stranger = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs()).child(.authorship)
        let bMe = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs()).child(.authorship)
        let bWrong = try Conversation.create(mode: .accountable, myDirection: b2a, peerDirection: a2b,
                                             channelKey: channelKey, lk: lk, drandRound: epoch, beaconT: beacon,
                                             authorship: bMe, peerPublic: stranger.publicKey)  // not A's real key
        XCTAssertThrowsError(try bWrong.receive(try a.send(Data("genuine".utf8))))
    }

    func testDeniableCarriesNoSignature() throws {
        let (a, b, _, _) = try makePair(.deniable)
        let env = try a.send(Data("off the record".utf8))
        XCTAssertEqual(env.signature.count, 0)                 // nothing binds authorship -> deniable
        XCTAssertEqual(try b.receive(env), Data("off the record".utf8))
    }

    func testWrongChannelKeyCannotOpen() throws {
        let (a, _, _, _) = try makePair(.deniable)
        let bBad = try Conversation.create(mode: .deniable, myDirection: b2a, peerDirection: a2b,
                                           channelKey: Data(repeating: 0x58, count: 32), lk: lk,
                                           drandRound: epoch, beaconT: beacon)
        XCTAssertThrowsError(try bBad.receive(try a.send(Data("secret".utf8))))
    }

    func testEnvelopeWireRoundtrip() throws {
        let (a, b, _, _) = try makePair(.accountable)
        let env = try a.send(Data("over the relay".utf8))
        let rewired = try Envelope.fromWire(env.toWire())
        XCTAssertEqual(try b.receive(rewired), Data("over the relay".utf8))
    }
}
