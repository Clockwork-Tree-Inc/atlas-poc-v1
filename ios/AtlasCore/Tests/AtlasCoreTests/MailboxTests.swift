import XCTest
@testable import AtlasCore

/// Rotating mailboxes + sealed sender (Swift), parity with `backend/atlas/net/privacy/mailbox.py`
/// / `backend/tests/test_mailbox.py`. The relay sees rotating unlinkable addresses and opaque
/// blobs — no stable handle, no sender, no recipient identity, and no directory to enumerate.
final class MailboxTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private let A = Data("persona-A".utf8)
    private let B = Data("persona-B".utf8)
    private let secret = Data(repeating: 0x5a, count: 32)
    private let e1 = Data([0, 0, 0, 1])
    private let e2 = Data([0, 0, 0, 2])

    // ---- cross-language KATs (from the Python reference) ----

    func testDerivationMatchesPythonKAT() throws {
        XCTAssertEqual(hex(try Mailbox.derive(pairSecret: secret, sender: A, recipient: B, epoch: e1)),
                       "badbe62bd2372d56fa7b5f57a1bc6967")
        XCTAssertEqual(hex(try Mailbox.derive(pairSecret: secret, sender: B, recipient: A, epoch: e1)),
                       "6d83c70c5199cbaa85a0e1d42847a54d")   // direction separates inbound/outbound
        XCTAssertEqual(hex(try Mailbox.publicInboxID(personaPub: Data("B-published-key".utf8))),
                       "b59549f4b33606a690a8b25657b9dee6")
    }

    // ---- rotation + unlinkability ----

    func testRotatesAndUnlinkableAcrossEpochs() throws {
        let m1 = try Mailbox.derive(pairSecret: secret, sender: A, recipient: B, epoch: e1)
        let m2 = try Mailbox.derive(pairSecret: secret, sender: A, recipient: B, epoch: e2)
        XCTAssertNotEqual(m1, m2)
        XCTAssertNotEqual(m1.prefix(4), m2.prefix(4))
        XCTAssertEqual(m1.count, Mailbox.mailboxBytes)
    }

    func testDifferentPairsDoNotCollide() throws {
        let other = Data(repeating: 0xa1, count: 32)
        XCTAssertNotEqual(try Mailbox.derive(pairSecret: secret, sender: A, recipient: B, epoch: e1),
                          try Mailbox.derive(pairSecret: other, sender: A, recipient: B, epoch: e1))
    }

    // ---- sealed sender ----

    func testSealedSenderRoundtripAndNoIdentityLeak() throws {
        let env = try Mailbox.seal(pairSecret: secret, sender: A, recipient: B, epoch: e1, seq: 7, plaintext: Data("hi".utf8))
        XCTAssertFalse(env.blob.range(of: A) != nil)         // sender not in the clear
        XCTAssertFalse(env.mailbox.range(of: B) != nil)      // recipient id not in the address
        let opened = Mailbox.open(pairSecret: secret, envelope: env, epoch: e1)
        XCTAssertEqual(opened?.sender, A)
        XCTAssertEqual(opened?.seq, 7)
        XCTAssertEqual(opened?.plaintext, Data("hi".utf8))
    }

    func testWrongSecretOrEpochOpensToNil() throws {
        let env = try Mailbox.seal(pairSecret: secret, sender: A, recipient: B, epoch: e1, seq: 1, plaintext: Data("x".utf8))
        XCTAssertNil(Mailbox.open(pairSecret: Data(repeating: 0, count: 32), envelope: env, epoch: e1))
        XCTAssertNil(Mailbox.open(pairSecret: secret, envelope: env, epoch: e2))   // stale epoch
    }

    func testReaddressReplayFailsViaAAD() throws {
        let env = try Mailbox.seal(pairSecret: secret, sender: A, recipient: B, epoch: e1, seq: 1, plaintext: Data("x".utf8))
        let moved = SealedEnvelope(mailbox: Data(repeating: 0x99, count: Mailbox.mailboxBytes), blob: env.blob)
        XCTAssertNil(Mailbox.open(pairSecret: secret, envelope: moved, epoch: e1))
    }

    // ---- endpoint through the relay, no directory ----

    func testEndpointSendReceiveThroughRelay() throws {
        let relay = MailboxRelay()
        let a = MailboxEndpoint(myID: A, relay: relay)
        let b = MailboxEndpoint(myID: B, relay: relay)
        a.addContact(peerID: B, pairSecret: secret)
        b.addContact(peerID: A, pairSecret: secret)
        // No registration: B never told the relay it was listening.
        try a.send(peerID: B, plaintext: Data("first".utf8), epoch: e1)
        try a.send(peerID: B, plaintext: Data("second".utf8), epoch: e1)
        let got = try b.receive(peerID: A, epoch: e1)
        XCTAssertEqual(got.map { $0.plaintext }, [Data("first".utf8), Data("second".utf8)])
        XCTAssertEqual(got.map { $0.seq }, [1, 2])
        XCTAssertTrue(try b.receive(peerID: A, epoch: e2).isEmpty)   // next epoch: nothing leaks back
    }

    func testNoDirectoryRelayLearnsBoxesOnlyOnUse() throws {
        let relay = MailboxRelay()
        XCTAssertEqual(relay.activeBoxCount, 0)                     // no directory of who exists
        let env = try Mailbox.seal(pairSecret: secret, sender: A, recipient: B, epoch: e1, seq: 1, plaintext: Data("hi".utf8))
        relay.deliver(env)
        XCTAssertEqual(relay.activeBoxCount, 1)                     // exists only after delivery
        _ = relay.fetch(env.mailbox)
        XCTAssertEqual(relay.activeBoxCount, 0)                     // and vanishes on fetch
    }

    func testPublicInboxIsStableAndColdContactDelivers() throws {
        let pub = Data("B-published-key".utf8)
        XCTAssertEqual(try Mailbox.publicInboxID(personaPub: pub), try Mailbox.publicInboxID(personaPub: pub))
        let key = Data("kkkkkkkk".utf8)
        let sealToPub: (Data) -> Data = { m in Data(m.enumerated().map { $0.element ^ key[$0.offset % key.count] }) }
        let relay = MailboxRelay()
        let env = try Mailbox.sealFirstContact(personaPub: pub, sender: A, plaintext: Data("connect?".utf8), sealToPub: sealToPub)
        XCTAssertEqual(env.mailbox, try Mailbox.publicInboxID(personaPub: pub))
        XCTAssertFalse(env.blob.range(of: A) != nil)               // sender sealed inside
        relay.deliver(env)
        XCTAssertEqual(relay.fetch(env.mailbox), [env.blob])
    }

    func testBeaconEpochAndCatchUpWindowParity() throws {
        // epoch = 8-byte big-endian round index (matches mailbox.py epoch_for_round)
        XCTAssertEqual(Mailbox.epochForRound(1), Data([0, 0, 0, 0, 0, 0, 0, 1]))
        XCTAssertEqual(Mailbox.epochForRound(258), Data([0, 0, 0, 0, 0, 0, 1, 2]))
        // newest-first, inclusive both ends
        XCTAssertEqual(Mailbox.catchUpEpochs(nowRound: 102, window: 2),
                       ([102, 101, 100] as [UInt64]).map { Mailbox.epochForRound($0) })
        // clamps at round 0
        XCTAssertEqual(Mailbox.catchUpEpochs(nowRound: 1, window: 5),
                       [Mailbox.epochForRound(1), Mailbox.epochForRound(0)])
        // a mailbox derived at a beacon-round epoch is stable for that round
        let s = Data(repeating: 0x5a, count: 32)
        let m1 = try Mailbox.derive(pairSecret: s, sender: A, recipient: Data("B".utf8), epoch: Mailbox.epochForRound(100))
        let m1b = try Mailbox.derive(pairSecret: s, sender: A, recipient: Data("B".utf8), epoch: Mailbox.epochForRound(100))
        let m2 = try Mailbox.derive(pairSecret: s, sender: A, recipient: Data("B".utf8), epoch: Mailbox.epochForRound(101))
        XCTAssertEqual(m1, m1b)
        XCTAssertNotEqual(m1, m2)                                   // rotates each round
    }
}
