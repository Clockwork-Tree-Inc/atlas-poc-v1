import XCTest
@testable import AtlasCore

/// The phone CONSUMES + VERIFIES signed epoch rounds against the pinned aggregator key; it never runs
/// the aggregator (that is Atlas-server infra). Mirrors the relay's consume-and-verify discipline.
final class EpochBeaconClientTests: XCTestCase {

    private func served(_ r: EpochRound, aggregator: HybridSign.PublicKey?) -> [String: Any] {
        var d: [String: Any] = ["epoch": r.epoch, "randomness": r.randomness.hexString,
                                "anchor": r.anchor.hexString, "signature": r.signature.hexString]
        if let a = aggregator { d["aggregator_pub"] = a.encode().hexString }
        return d
    }

    func testVerifiesRoundUnderPinnedKey() throws {
        let agg = HybridSign.generate()
        let r = try EpochBeacon(signer: agg).fire(
            lkArrivals: ArrivalTiming(timestamps: [0, 0.03, 0.07]), anchor: Data([7, 7, 7, 7, 7, 7, 7, 7]))
        let out = try EpochBeaconClient.verified(served(r, aggregator: agg.publicKey),
                                                 pinnedAggregator: agg.publicKey)
        XCTAssertEqual(out.epoch, r.epoch)
        XCTAssertEqual(out.randomness, r.randomness)
    }

    func testRejectsSubstitutedAggregatorKey() throws {
        let agg = HybridSign.generate(), attacker = HybridSign.generate()
        let r = try EpochBeacon(signer: attacker).fire(lkArrivals: ArrivalTiming(timestamps: [0, 0.1]))
        // the node advertises the ATTACKER's key; the phone pins the real aggregator -> reject
        XCTAssertThrowsError(try EpochBeaconClient.verified(served(r, aggregator: attacker.publicKey),
                                                            pinnedAggregator: agg.publicKey)) {
            XCTAssertEqual($0 as? EpochBeaconClient.ClientError, .unpinnedAggregator)
        }
    }

    func testRejectsBadSignatureUnderPinnedKey() throws {
        let agg = HybridSign.generate()
        let r = try EpochBeacon(signer: agg).fire(lkArrivals: ArrivalTiming(timestamps: [0, 0.1]))
        XCTAssertThrowsError(try EpochBeaconClient.verified(served(r, aggregator: nil),
                                                            pinnedAggregator: HybridSign.generate().publicKey)) {
            XCTAssertEqual($0 as? EpochBeaconClient.ClientError, .badSignature)
        }
    }

    func testRejectsTamperedRandomness() throws {
        let agg = HybridSign.generate()
        let r = try EpochBeacon(signer: agg).fire(lkArrivals: ArrivalTiming(timestamps: [0, 0.1]))
        var json = served(r, aggregator: agg.publicKey)
        json["randomness"] = Data(repeating: 9, count: 32).hexString      // tamper
        XCTAssertThrowsError(try EpochBeaconClient.verified(json, pinnedAggregator: agg.publicKey)) {
            XCTAssertEqual($0 as? EpochBeaconClient.ClientError, .badSignature)
        }
    }

    func testRejectsUnsignedRound() throws {
        let r = try EpochBeacon().fire(lkArrivals: ArrivalTiming(timestamps: [0, 0.1]))   // no signer
        XCTAssertThrowsError(try EpochBeaconClient.verified(served(r, aggregator: nil),
                                                            pinnedAggregator: HybridSign.generate().publicKey)) {
            XCTAssertEqual($0 as? EpochBeaconClient.ClientError, .badSignature)
        }
    }
}
