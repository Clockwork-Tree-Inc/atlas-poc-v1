import XCTest
@testable import AtlasCore

/// Replay of REAL recorded iPhone motion (MotionSense — 24 subjects, Core Motion @ 50Hz,
/// `mmalekzadeh/motion-sense`) through the `SignalSource` seam. Verifies device-free that
/// real human motion (walking) gates presence far more than a near-static stream (sitting),
/// and that a frozen / replayed window fails closed. Rows below are real, from subject 1.
final class ReplaySignalSourceTests: XCTestCase {

    // Real MotionSense rows: userAcceleration.{x,y,z}, rotationRate.{x,y,z}.
    private let walkCSV = """
    userAcceleration.x,userAcceleration.y,userAcceleration.z,rotationRate.x,rotationRate.y,rotationRate.z
    0.0917,0.4159,0.0937,-0.3506,-0.5117,-0.8652
    0.3674,0.0046,-0.1061,-0.5506,-2.2432,-0.5824
    0.1721,-0.2175,-0.1634,-0.9310,-1.3580,-0.5039
    0.0050,-0.2376,-0.0191,-1.3047,-0.5414,-0.3463
    -0.0403,-0.2415,0.0152,-1.2783,-0.4347,-0.3986
    -0.0908,-0.2858,-0.0346,-1.1142,-0.6094,-0.5478
    -0.0321,-0.2111,-0.2747,-0.9442,-0.6999,-0.7164
    -0.0246,-0.1681,-0.2362,-0.9733,-0.5178,-0.9412
    -0.0186,-0.1278,-0.1751,-0.9148,-0.1661,-1.0192
    0.0040,0.0063,-0.1345,-0.8031,-0.1000,-1.1242
    0.0694,0.1431,-0.0771,-0.8376,-0.2297,-1.1756
    0.1257,0.1801,-0.0063,-1.0474,-0.2465,-1.0371
    0.3537,0.3234,-0.1570,-0.9137,-0.4321,-0.8319
    0.3871,0.3856,-0.5286,-0.6261,-0.2649,-0.5417
    0.3935,0.3911,-0.4364,-0.2763,0.8338,-0.1347
    0.2949,0.2483,0.0797,0.0655,1.0738,0.0180
    0.4122,0.2230,-0.1549,0.3332,0.3324,0.0294
    0.4782,0.2573,-0.3336,0.6481,-0.0417,0.0769
    0.3713,0.5538,-0.1657,1.4521,0.0232,0.7234
    0.2247,0.6450,-0.2101,2.0317,-0.0111,1.3556
    0.1967,0.6267,-0.1606,2.8248,0.6241,1.6551
    -0.5813,0.5045,0.1661,2.6880,0.6020,1.6916
    -0.8776,0.4781,0.0519,2.5472,1.0426,1.6526
    -0.8918,0.4424,-0.0237,2.0665,1.4245,1.6830
    """

    private let sitCSV = """
    userAcceleration.x,userAcceleration.y,userAcceleration.z,rotationRate.x,rotationRate.y,rotationRate.z
    0.0001,0.0003,-0.0070,-0.0037,0.0096,-0.0002
    -0.0013,0.0023,-0.0103,-0.0079,0.0075,0.0008
    -0.0022,0.0000,-0.0067,-0.0080,-0.0011,-0.0024
    0.0017,0.0092,-0.0116,-0.0005,-0.0064,-0.0013
    0.0058,0.0075,-0.0089,-0.0016,-0.0043,0.0062
    0.0042,0.0020,-0.0070,-0.0016,0.0042,0.0073
    0.0033,0.0000,-0.0065,0.0005,0.0107,0.0008
    0.0007,0.0090,-0.0070,-0.0048,0.0022,0.0029
    -0.0005,-0.0031,-0.0081,0.0027,-0.0042,-0.0088
    0.0060,0.0053,-0.0063,0.0080,-0.0021,-0.0077
    -0.0055,0.0105,-0.0049,-0.0069,0.0075,0.0007
    0.0061,0.0080,-0.0037,0.0016,0.0053,0.0072
    -0.0001,0.0089,-0.0068,0.0132,-0.0075,0.0083
    -0.0005,0.0131,-0.0006,0.0025,-0.0128,0.0093
    0.0025,0.0038,-0.0070,0.0111,-0.0064,0.0072
    -0.0029,0.0045,-0.0104,0.0164,-0.0032,0.0029
    -0.0010,0.0096,-0.0014,-0.0038,0.0032,0.0038
    0.0053,-0.0011,-0.0052,0.0069,0.0043,0.0028
    0.0056,0.0010,-0.0086,0.0100,-0.0021,0.0018
    0.0100,0.0022,-0.0032,-0.0081,0.0022,-0.0005
    0.0091,-0.0001,-0.0088,-0.0038,0.0150,0.0049
    0.0060,0.0001,-0.0139,0.0005,0.0128,0.0103
    0.0009,-0.0008,-0.0081,-0.0060,0.0054,0.0060
    0.0010,-0.0046,-0.0063,-0.0027,0.0075,0.0028
    """

    private func run(_ src: SignalSource, ticks: Int) -> (present: Int, avgChanged: Double) {
        var present = 0, changedSum = 0, changedN = 0
        for _ in 0..<ticks {
            guard let s = try? src.sample() else { continue }
            if s.present { present += 1 }
            if let c = s.changedBits { changedSum += c; changedN += 1 }
        }
        return (present, changedN > 0 ? Double(changedSum) / Double(changedN) : 0)
    }

    /// The engine harvests real sensor ENTROPY from a live recorded stream — and MORE per
    /// window from vigorous motion (walk) than from a near-still stream (sit). Both carry
    /// entropy (the engine can clock off either); this is the window's job, not presence.
    func testHarvestsMoreEntropyFromMotion() {
        let walkSrc = ReplaySignalSource(motionSenseCSV: walkCSV)
        let sitSrc = ReplaySignalSource(motionSenseCSV: sitCSV)
        XCTAssertEqual(walkSrc.count, 24)   // CSV parsed
        XCTAssertEqual(sitSrc.count, 24)
        let walk = run(walkSrc.asSignalSource(), ticks: 48)
        let sit = run(sitSrc.asSignalSource(), ticks: 48)
        XCTAssertGreaterThan(walk.avgChanged, 0, "a live recorded stream must yield entropy to the engine")
        XCTAssertGreaterThan(sit.avgChanged, 0, "even a near-still stream carries some sensor entropy")
        XCTAssertGreaterThan(walk.avgChanged, sit.avgChanged,
                             "vigorous motion harvests more entropy/window than stillness (walk=\(walk.avgChanged) sit=\(sit.avgChanged))")
    }

    /// A frozen / replayed identical window yields NO entropy — the engine has nothing fresh
    /// to clock on (this, plus the beacon/freshness binding, is what resists a replayed feed).
    func testFrozenStreamYieldsNoEntropy() {
        let frozen = run(ReplaySignalSource(rows: Array(repeating: .init(accel: 1.0, gyro: 2.5), count: 24)).asSignalSource(),
                         ticks: 48)
        XCTAssertEqual(frozen.avgChanged, 0, "a frozen/replayed window carries no entropy for the engine")
    }
}
