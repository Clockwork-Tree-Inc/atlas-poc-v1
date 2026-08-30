import XCTest
@testable import AtlasCore

/// Parity with backend/tests/test_contact.py.
final class ContactTests: XCTestCase {
    private let secret = Data(repeating: 0x07, count: 32)

    func testConnectCodeRotatesEachEpoch() {
        let a = ContactBootstrap.currentCode(secret, nowRound: 1000)
        let b = ContactBootstrap.currentCode(secret, nowRound: 1001)
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(a.count, ContactBootstrap.codeDigits)
        XCTAssertTrue(a.allSatisfy { $0.isNumber })
    }

    func testCodeValidWithinWindowDeadOutside() {
        let code = ContactBootstrap.currentCode(secret, nowRound: 1000)
        XCTAssertTrue(ContactBootstrap.codeValid(secret, code: code, nowRound: 1000, window: 2))
        XCTAssertTrue(ContactBootstrap.codeValid(secret, code: code, nowRound: 1001, window: 2))
        XCTAssertFalse(ContactBootstrap.codeValid(secret, code: code, nowRound: 1010, window: 2))
        XCTAssertFalse(ContactBootstrap.codeValid(secret, code: "00000000", nowRound: 1000, window: 2))
    }

    func testOpenRendezvousRotatesAndIsPubkeyDerivable() {
        let pub = Data("PUBKEY-ENC".utf8)
        let e0 = Mailbox.epochForRound(1000), e1 = Mailbox.epochForRound(1001)
        let r0 = ContactBootstrap.openRendezvous(pub, epoch: e0)
        let r1 = ContactBootstrap.openRendezvous(pub, epoch: e1)
        XCTAssertNotEqual(r0, r1)
        XCTAssertEqual(r0.count, 16)
        XCTAssertEqual(ContactBootstrap.openRendezvous(pub, epoch: e0), r0)
    }

    func testCodeRendezvousNeedsTheCode() {
        let e = Mailbox.epochForRound(1000)
        let code = ContactBootstrap.currentCode(secret, nowRound: 1000)
        let drop = ContactBootstrap.codeRendezvous(code, epoch: e)
        XCTAssertEqual(ContactBootstrap.codeRendezvous(code, epoch: e), drop)
        XCTAssertNotEqual(ContactBootstrap.codeRendezvous("00000000", epoch: e), drop)
    }

    func testGateOpenLetsAnyoneRing() {
        let d = ContactBootstrap.gateKnock(.open, callerPubEnc: Data("CALLER".utf8), presentedCode: nil,
                                  codeSecret: Data(), nowRound: 1, knownContacts: [])
        XCTAssertTrue(d.allowed)
        XCTAssertEqual(d.caller, Data("CALLER".utf8))
    }

    func testGateCodeOnlyRequiresAValidCode() {
        let good = ContactBootstrap.currentCode(secret, nowRound: 1000)
        let ok = ContactBootstrap.gateKnock(.codeOnly, callerPubEnc: Data("CALLER".utf8), presentedCode: good,
                                   codeSecret: secret, nowRound: 1000, knownContacts: [])
        XCTAssertTrue(ok.allowed)
        let bad = ContactBootstrap.gateKnock(.codeOnly, callerPubEnc: Data("CALLER".utf8), presentedCode: "00000000",
                                    codeSecret: secret, nowRound: 1000, knownContacts: [])
        XCTAssertFalse(bad.allowed)
        XCTAssertNil(bad.caller)
    }

    func testGateContactsOnlyAndClosed() {
        let known: Set<Data> = [Data("FRIEND".utf8)]
        XCTAssertTrue(ContactBootstrap.gateKnock(.contactsOnly, callerPubEnc: Data("FRIEND".utf8), presentedCode: nil,
                                        codeSecret: Data(), nowRound: 1, knownContacts: known).allowed)
        XCTAssertFalse(ContactBootstrap.gateKnock(.contactsOnly, callerPubEnc: Data("STRANGER".utf8), presentedCode: nil,
                                         codeSecret: Data(), nowRound: 1, knownContacts: known).allowed)
        XCTAssertFalse(ContactBootstrap.gateKnock(.closed, callerPubEnc: Data("ANYONE".utf8), presentedCode: nil,
                                         codeSecret: Data(), nowRound: 1, knownContacts: known).allowed)
    }

    func testCrossLanguageKnownAnswers() {
        // Pinned vectors — identical to backend/tests/test_contact.py (byte-for-byte parity).
        XCTAssertEqual(ContactBootstrap.currentCode(secret, nowRound: 1000), "11394522")
        XCTAssertEqual(ContactBootstrap.openRendezvous(Data("PUBKEY-ENC".utf8), epoch: Mailbox.epochForRound(1000)).hexString,
                       "c9cc4e74edf2c8ff576ebb37c14fdb67")
        XCTAssertEqual(ContactBootstrap.promotePairSecret(Data(repeating: 0x22, count: 32)).hexString,
                       "4aef3bef4184eeefec827f5f7270c4e4a2a8d2217bcc851853536d44c2692395")
    }

    func testPromotionIsDeterministicAndDistinct() {
        let shared = Data(repeating: 0x22, count: 32)
        let p = ContactBootstrap.promotePairSecret(shared)
        XCTAssertEqual(p, ContactBootstrap.promotePairSecret(shared))
        XCTAssertNotEqual(p, shared)
    }
}
