import XCTest
@testable import AtlasCore

/// TSK t-of-n threshold. The pinned KAT (fixed shares -> seed via the deterministic
/// `Shamir.combine`) is the byte-parity contract with `backend/tests/test_tsk_threshold.py`.
final class TSKThresholdTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }
    private func C(_ label: String, _ inst: Bool = false) -> ThresholdSeal.Custodian {
        ThresholdSeal.Custodian(label: label, institutional: inst)
    }

    func testDefault2of3AnyTwoReconstruct() throws {
        let seed = Data((0..<32).map { UInt8($0) })
        let shares = try TSKThreshold.splitTSK(seed)
        XCTAssertEqual(shares.count, 3)
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            XCTAssertEqual(try TSKThreshold.reconstructTSK([shares[a], shares[b]]), seed)
        }
    }

    func testGeneralMofN() throws {
        let seed = Data((0..<40).map { UInt8($0) })
        let holders = [C("wallet-se"), C("usb"), C("recovery-card"), C("guardian-alice"), C("server-hsm", true)]
        let policy = try ThresholdSeal.ThresholdPolicy(n: 5, m: 3)
        let shares = try TSKThreshold.splitTSK(seed, policy: policy, holders: holders)
        XCTAssertEqual(shares.count, 5)
        XCTAssertEqual(try TSKThreshold.reconstructTSK([shares[0], shares[1], shares[2]]), seed)
        XCTAssertNotEqual(try TSKThreshold.reconstructTSK([shares[0], shares[1]]), seed)  // below threshold
    }

    func testAntiRemoteRejectsAllInstitutionalAtSplit() throws {
        let holders = [C("hsm-a", true), C("hsm-b", true), C("wallet-se")]
        let seed = Data((0..<32).map { UInt8($0) })
        let policy = try ThresholdSeal.ThresholdPolicy(n: 3, m: 2)
        XCTAssertThrowsError(try TSKThreshold.splitTSK(seed, policy: policy, holders: holders)) {
            XCTAssertEqual($0 as? TSKThreshold.TSKError, .allInstitutionalQuorum)
        }
    }

    func testAntiRemoteRejectsAllInstitutionalAtReconstruct() throws {
        let raw = Shamir.split(Data((0..<32).map { UInt8($0) }), n: 3, k: 2)
        let inst = [TSKThreshold.TSKShare(holder: C("hsm-a", true), share: raw[0]),
                    TSKThreshold.TSKShare(holder: C("hsm-b", true), share: raw[1])]
        XCTAssertThrowsError(try TSKThreshold.reconstructTSK(inst)) {
            XCTAssertEqual($0 as? TSKThreshold.TSKError, .allInstitutionalQuorum)
        }
    }

    // --- parity KAT: fixed shares -> seed (must match test_tsk_threshold.py) ---
    private let katSeed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    private let katShares: [Int: String] = [
        1: "2e72bea056b5ef6b9bb7bcd066bfd53516b9701fc66476b7bbd709caf316a71b",
        2: "5cd7010e608e6f4faec5866d831998702c5a866b5b3746ecee05f759b2507c2c",
        3: "72b49d9d726ee653bdeb9006297ba3ba3af2d447d906562cdd4b54288d9b35c8",
    ]
    private func katShare(_ idx: Int) -> TSKThreshold.TSKShare {
        let share = Shamir.Share.decode(Data([UInt8(idx)]) + hex(katShares[idx]!))
        return TSKThreshold.TSKShare(holder: C("h\(idx)"), share: share)
    }

    func testParityKATAnyTwoOfThree() throws {
        let seed = hex(katSeed)
        for (a, b) in [(1, 2), (1, 3), (2, 3)] {
            XCTAssertEqual(try TSKThreshold.reconstructTSK([katShare(a), katShare(b)]), seed)
        }
    }
}
