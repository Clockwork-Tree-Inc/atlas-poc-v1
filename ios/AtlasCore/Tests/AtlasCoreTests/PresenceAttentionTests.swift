import XCTest
@testable import AtlasCore

final class PresenceReceiptTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private let subject = Data("persona-handle-01".utf8)
    private let commit = Data("fused-pole-evidence-commit".utf8)
    typealias PR = PresenceReceiptNS

    func testSingleSignerReceiptAndWallet() throws {
        let r = try PR.mintReceipt(signers: [kp(2)], subject: subject, windowStart: 100, windowEnd: 200, poleCommit: commit)
        XCTAssertTrue(PR.verifyReceipt(r))
        let w = PR.ReceiptWallet()
        XCTAssertTrue(w.add(r))
        XCTAssertEqual(w.receipts.count, 1)
        XCTAssertEqual(w.totalPresence(), 100)
    }

    func testMultiStreamCorroboration() throws {
        let solo = try PR.mintReceipt(signers: [kp(2)], subject: subject, windowStart: 1, windowEnd: 2, poleCommit: commit)
        let corr = try PR.mintReceipt(signers: [kp(2), kp(3)], subject: subject, windowStart: 1, windowEnd: 2, poleCommit: commit)
        XCTAssertFalse(PR.verifyReceipt(solo, minSigners: 2))
        XCTAssertTrue(PR.verifyReceipt(corr, minSigners: 2))
    }

    func testTamperedReceiptFails() throws {
        let r = try PR.mintReceipt(signers: [kp(2)], subject: subject, windowStart: 100, windowEnd: 200, poleCommit: commit)
        let forged = PR.PresenceReceipt(subject: subject, windowStart: 100, windowEnd: 999,
                                        poleCommit: commit, signers: r.signers, sigs: r.sigs)
        XCTAssertFalse(PR.verifyReceipt(forged))
    }

    func testCovering() throws {
        let r = try PR.mintReceipt(signers: [kp(2)], subject: subject, windowStart: 100, windowEnd: 200, poleCommit: commit)
        let w = PR.ReceiptWallet(); w.add(r)
        XCTAssertEqual(w.covering(at: 150).count, 1)
        XCTAssertEqual(w.covering(at: 500).count, 0)
    }
}

final class AttentionTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private let subject = Data("persona-handle-01".utf8)
    private let commit = Data("fused".utf8)
    typealias PR = PresenceReceiptNS

    private func offer(_ store: HybridSign.Keypair, reward: Int = 10, ws: Int = 100, we: Int = 200) throws -> Attention.AttentionOffer {
        try Attention.makeOffer(store, productID: Data("prod-1".utf8), reward: reward, windowStart: ws, windowEnd: we)
    }
    private func receipt(_ persona: HybridSign.Keypair, ws: Int = 120, we: Int = 180) throws -> PR.PresenceReceipt {
        try PR.mintReceipt(signers: [persona], subject: subject, windowStart: ws, windowEnd: we, poleCommit: commit)
    }

    func testOfferVerifies() throws {
        XCTAssertTrue(Attention.verifyOffer(try offer(kp(1))))
    }

    func testLiveHumanGetsPaidOnce() throws {
        let store = kp(1), persona = kp(2)
        let o = try offer(store)
        let claim = try Attention.claimAttention(persona, offer: o, receipt: try receipt(persona))
        XCTAssertTrue(Attention.verifyClaim(o, claim))
        let ledger = Attention.AttentionLedger()
        XCTAssertEqual(try ledger.redeem(o, claim), 10)
        XCTAssertThrowsError(try ledger.redeem(o, claim))    // no farming
        XCTAssertEqual(ledger.totalPaid(), 10)
    }

    func testNoPresenceNoPay() throws {
        let store = kp(1), persona = kp(2)
        let o = try offer(store)
        let outOfWindow = try receipt(persona, ws: 500, we: 600)
        let claim = try Attention.claimAttention(persona, offer: o, receipt: outOfWindow)
        XCTAssertFalse(Attention.verifyClaim(o, claim))
    }

    func testClaimMustBeSignedByPresenceCosigner() throws {
        let store = kp(1), persona = kp(2), imposter = kp(9)
        let o = try offer(store)
        let r = try receipt(persona)
        let good = try Attention.claimAttention(persona, offer: o, receipt: r)
        let forged = Attention.AttentionClaim(offerID: good.offerID, subject: good.subject, receipt: r,
                                              nullifier: good.nullifier, signer: imposter.publicKey, sig: good.sig)
        XCTAssertFalse(Attention.verifyClaim(o, forged))
    }

    func testForgedOfferRewardRejected() throws {
        let store = kp(1), persona = kp(2)
        let o = try offer(store, reward: 10)
        let claim = try Attention.claimAttention(persona, offer: o, receipt: try receipt(persona))
        let tampered = Attention.AttentionOffer(store: o.store, productID: o.productID, reward: 999,
                                                windowStart: o.windowStart, windowEnd: o.windowEnd, sig: o.sig)
        XCTAssertFalse(Attention.verifyClaim(tampered, claim))
    }
}
