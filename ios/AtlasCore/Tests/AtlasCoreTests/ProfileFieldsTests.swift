import XCTest
@testable import AtlasCore

/// Parity with backend/tests/test_profile_fields.py.
final class ProfileFieldsTests: XCTestCase {
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private typealias PF = ProfileFields

    func testUnendorsedValueIsJustAClaim() throws {
        let me = kp(1)
        let v = PF.view(try PF.makeField(me, label: "favourite colour", values: ["blue"]))
        XCTAssertTrue(v.ownerSigned)
        XCTAssertEqual(v.entries[0].value, "blue")
        XCTAssertFalse(v.entries[0].confirmed)
        XCTAssertTrue(v.entries[0].endorsers.isEmpty)
    }

    func testTamperedClaimIsFlagged() throws {
        let me = kp(1)
        var f = try PF.makeField(me, label: "favourite colour", values: ["blue"])
        f = PF.ProfileField(owner: f.owner, label: f.label, values: ["red"])  // edited, not re-signed
        XCTAssertFalse(PF.view(f).ownerSigned)
    }

    func testManyPeopleAndOrgsCanEndorseAValue() throws {
        let me = kp(1)
        var ends: [Attestation] = []
        for n: UInt8 in 10...22 {   // 13 endorsers for BSc
            ends.append(try PF.endorse(kp(n), subject: me.publicKey, label: "work", value: "BSc", endorserName: "E\(n)"))
        }
        for n: UInt8 in 30...31 {   // 2 for MSc
            ends.append(try PF.endorse(kp(n), subject: me.publicKey, label: "work", value: "MSc"))
        }
        let v = PF.view(try PF.makeField(me, label: "work", values: ["BSc", "MSc", "doctor"], endorsements: ends))
        var byValue: [String: PF.ValueEntry] = [:]
        for e in v.entries { byValue[e.value] = e }
        XCTAssertEqual(byValue["BSc"]?.endorsers.count, 13)
        XCTAssertEqual(byValue["MSc"]?.endorsers.count, 2)
        XCTAssertEqual(byValue["doctor"]?.confirmed, false)   // plain claim, nobody endorsed it
    }

    func testEachEndorsementIsAnOpenableProof() throws {
        let me = kp(1), school = kp(2)
        let e = try PF.endorse(school, subject: me.publicKey, label: "work", value: "BSc", endorserName: "Northgate University")
        let v = PF.view(try PF.makeField(me, label: "work", values: ["BSc"], endorsements: [e]))
        let endorser = v.entries[0].endorsers[0]
        XCTAssertEqual(endorser.name, "Northgate University")
        XCTAssertTrue(verifyAttestation(endorser.proof))
        XCTAssertEqual(endorser.key.encode(), school.publicKey.encode())
    }

    func testWorksAtIsEndorsedByTheNamedPlace() throws {
        let me = kp(1), hospital = kp(6)
        let e = try PF.endorse(hospital, subject: me.publicKey, label: "works at", value: "Northgate Hospital",
                               endorserName: "Northgate Hospital")
        let v = PF.view(try PF.makeField(me, label: "works at", values: ["Northgate Hospital"], endorsements: [e]))
        XCTAssertTrue(v.entries[0].confirmed)
        XCTAssertEqual(v.entries[0].endorsers[0].name, "Northgate Hospital")
    }

    func testForgedEndorsementDoesNotCount() throws {
        let me = kp(1), school = kp(2)
        var e = try PF.endorse(school, subject: me.publicKey, label: "work", value: "BSc")
        e.sig = Data(repeating: 0, count: e.sig.count)
        let v = PF.view(try PF.makeField(me, label: "work", values: ["BSc"], endorsements: [e]))
        XCTAssertFalse(v.entries[0].confirmed)
    }

    func testEndorsementForDifferentValueOrLabelDoesNotAttach() throws {
        let me = kp(1), school = kp(2)
        let wrongValue = try PF.endorse(school, subject: me.publicKey, label: "work", value: "PhD")
        let wrongLabel = try PF.endorse(school, subject: me.publicKey, label: "education", value: "BSc")
        let v = PF.view(try PF.makeField(me, label: "work", values: ["BSc"], endorsements: [wrongValue, wrongLabel]))
        XCTAssertFalse(v.entries[0].confirmed)
    }

    func testEndorsementsAccrueOverTime() throws {
        let me = kp(1), a = kp(2), b = kp(3)
        var f = try PF.makeField(me, label: "work", values: ["BSc"])
        XCTAssertFalse(PF.view(f).entries[0].confirmed)
        f = PF.addEndorsements(f, [try PF.endorse(a, subject: me.publicKey, label: "work", value: "BSc")])
        f = PF.addEndorsements(f, [try PF.endorse(b, subject: me.publicKey, label: "work", value: "BSc")])
        XCTAssertEqual(PF.view(f).entries[0].endorsers.count, 2)
        XCTAssertTrue(PF.view(f).ownerSigned)
    }

    func testCustomProfileRejectsForeignField() throws {
        let me = kp(1), other = kp(5)
        let prof = try PF.CustomProfile(owner: me.publicKey).withField(PF.makeField(me, label: "city", values: ["Rivertown"]))
        XCTAssertEqual(prof.fields.count, 1)
        XCTAssertThrowsError(try prof.withField(PF.makeField(other, label: "city", values: ["Lakeside"])))
    }
}
