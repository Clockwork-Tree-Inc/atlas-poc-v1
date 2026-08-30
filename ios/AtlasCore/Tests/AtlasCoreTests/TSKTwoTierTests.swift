import XCTest
@testable import AtlasCore

/// Two-tier recovery parity with tsk_two_tier.py: the server side alone can NEVER reconstruct.
final class TSKTwoTierTests: XCTestCase {
    private let seed = Data((0..<64).map { UInt8($0 % 256) })
    private lazy var upol = try! ThresholdSeal.ThresholdPolicy(n: 3, m: 2)
    private lazy var spol = try! ThresholdSeal.ThresholdPolicy(n: 3, m: 2)

    private func split() throws -> TSKTwoTier.TwoTierShares {
        let (u, s) = TSKTwoTier.defaultHolders()
        return try TSKTwoTier.split(seed: seed, userHolders: u, serverHolders: s,
                                    userPolicy: upol, serverPolicy: spol)
    }

    func testRoundtripNeedsBothHalves() throws {
        let sh = try split()
        let got = try TSKTwoTier.reconstruct(userShares: Array(sh.userShares.prefix(2)),
                                             serverShares: Array(sh.serverShares.prefix(2)),
                                             userPolicy: upol, serverPolicy: spol)
        XCTAssertEqual(got, seed)
    }

    func testServerSideAloneCannotReconstruct() throws {
        let sh = try split()
        XCTAssertThrowsError(try TSKTwoTier.reconstruct(userShares: [], serverShares: sh.serverShares,
                                                        userPolicy: upol, serverPolicy: spol))
    }

    func testYourSideAloneCannotReconstruct() throws {
        let sh = try split()
        XCTAssertThrowsError(try TSKTwoTier.reconstruct(userShares: sh.userShares, serverShares: [],
                                                        userPolicy: upol, serverPolicy: spol))
    }

    func testFaultTolerantLoseOneEachSide() throws {
        let sh = try split()
        let got = try TSKTwoTier.reconstruct(
            userShares: [sh.userShares[0], sh.userShares[2]],
            serverShares: [sh.serverShares[1], sh.serverShares[2]],
            userPolicy: upol, serverPolicy: spol)
        XCTAssertEqual(got, seed)
    }

    func testServerHalfIndependentOfSeed() throws {
        let sh = try split()
        let serverHalf = Shamir.combine(sh.serverShares.prefix(2).map { $0.share })
        XCTAssertNotEqual(serverHalf, seed)
        XCTAssertEqual(serverHalf.count, seed.count)
    }

    func testRejectsInstitutionalUserHolder() throws {
        let (_, s) = TSKTwoTier.defaultHolders()
        let u = [ThresholdSeal.Custodian(label: "phone", institutional: true),
                 ThresholdSeal.Custodian(label: "usb", institutional: false),
                 ThresholdSeal.Custodian(label: "contact", institutional: false)]
        XCTAssertThrowsError(try TSKTwoTier.split(seed: seed, userHolders: u, serverHolders: s,
                                                  userPolicy: upol, serverPolicy: spol))
    }
}
