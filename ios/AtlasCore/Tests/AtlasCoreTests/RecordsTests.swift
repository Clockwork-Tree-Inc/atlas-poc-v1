import XCTest
@testable import AtlasCore

final class RecordsTests: XCTestCase {
    private let FILE = Data("Dx: hypertension. anticoagulant: warfarin. allergy: penicillin.".utf8)
    private func key() -> Data { Primitives.randomBytes(32) }

    func testPatientOpensOwnFileAnytimeAndItIsLogged() throws {
        let ck = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let log = Records.AccessLog()
        XCTAssertEqual(try Records.patientOpenOwn(rec, contentKey: ck, log: log, nowRound: 1000), FILE)
        XCTAssertEqual(log.entries.count, 1)
        XCTAssertEqual(log.entries[0].action, "open-own")
        XCTAssertTrue(log.verify())
    }

    func testTreatingClinicianOnlyWithinEpisodePresentAndBeforeDischarge() throws {
        let ck = key(), ek = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let wrapped = try Primitives.aeadEncrypt(key: ek, plaintext: ck)
        let grant = Records.EpisodeGrant(wrappedKey: wrapped, opensFrom: 100, opensUntil: 200)
        let log = Records.AccessLog()

        // in-window + present -> opens
        XCTAssertEqual(try Records.clinicianOpenEpisode(grant, record: rec, episodeKey: ek,
                                                        nowRound: 150, presenceLive: true, log: log), FILE)
        // not present -> denied
        XCTAssertThrowsError(try Records.clinicianOpenEpisode(grant, record: rec, episodeKey: ek,
                                                              nowRound: 150, presenceLive: false, log: log))
        // outside window -> denied
        XCTAssertThrowsError(try Records.clinicianOpenEpisode(grant, record: rec, episodeKey: ek,
                                                              nowRound: 999, presenceLive: true, log: log))
        // after discharge -> denied
        Records.discharge(grant)
        XCTAssertThrowsError(try Records.clinicianOpenEpisode(grant, record: rec, episodeKey: ek,
                                                              nowRound: 150, presenceLive: true, log: log))
    }

    func testClinicianNoteRetainedThenUnreadablePastRetention() throws {
        let nk = key()
        let note = try Records.sealRecord(Data("encounter note".utf8), contentKey: nk)
        let log = Records.AccessLog()
        XCTAssertEqual(try Records.clinicianOpenNote(note, noteKey: nk, nowRound: 500, retentionEnd: 1000, log: log),
                       Data("encounter note".utf8))
        XCTAssertThrowsError(try Records.clinicianOpenNote(note, noteKey: nk, nowRound: 1001, retentionEnd: 1000, log: log))
    }

    func testReopenNeedsBothSharesNotifiesAndIsPerRecord() throws {
        let ck = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let (doctor, body) = Records.splitReopenShares(ck)
        let log = Records.AccessLog()

        XCTAssertEqual(try Records.reopenRetained(rec, doctorShare: doctor, bodyShare: body,
                                                  nowRound: 50, retentionEnd: 1000, log: log), FILE)
        XCTAssertEqual(log.notifications().count, 1)   // a reopen is not silent

        // a DIFFERENT record's body-share can't reopen this one
        let (_, otherBody) = Records.splitReopenShares(key())
        XCTAssertThrowsError(try Records.reopenRetained(rec, doctorShare: doctor, bodyShare: otherBody,
                                                        nowRound: 51, retentionEnd: 1000, log: log)) { e in
            XCTAssertEqual(e as? Records.RecordsError, .thresholdNotMet)
        }
    }

    func testReopenBlockedPastRetention() throws {
        let ck = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let (doctor, body) = Records.splitReopenShares(ck)
        XCTAssertThrowsError(try Records.reopenRetained(rec, doctorShare: doctor, bodyShare: body,
                                                        nowRound: 2000, retentionEnd: 1000, log: Records.AccessLog())) { e in
            XCTAssertEqual(e as? Records.RecordsError, .accessDenied)
        }
    }

    func testBreakGlassOpensButIsLoud() throws {
        let ck = key(), bg = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let log = Records.AccessLog()
        let wrapped = try Primitives.aeadEncrypt(key: bg, plaintext: ck)
        XCTAssertEqual(try Records.breakGlassOpen(rec, breakGlassKey: bg, wrappedContentKey: wrapped,
                                                  nowRound: 7, log: log), FILE)
        XCTAssertEqual(log.notifications().count, 1)
        XCTAssertEqual(log.entries[0].action, "break-glass")
    }

    func testAccessLogSymmetricAndTamperEvident() throws {
        let ck = key()
        let rec = try Records.sealRecord(FILE, contentKey: ck)
        let log = Records.AccessLog()
        _ = try Records.patientOpenOwn(rec, contentKey: ck, log: log, nowRound: 1)
        _ = try Records.patientOpenOwn(rec, contentKey: ck, log: log, nowRound: 2)
        XCTAssertTrue(log.verify())
        XCTAssertEqual(log.entries.count, 2)   // even the patient's own opens are recorded
    }
}
