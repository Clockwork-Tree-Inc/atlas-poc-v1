import XCTest
@testable import AtlasCore

/// Mirrors backend/tests/test_presence_resume.py — a blip resumes on the right code; a
/// swap, wrong code, timeout, or replay all fail closed to `.locked`.
final class PresenceResumeTests: XCTestCase {

    func testResumeCodesDeterministicAndSwapCannotForge() {
        let bind = Primitives.randomBytes(32)
        XCTAssertEqual(resumeCode(bind, 0), resumeCode(bind, 0))
        XCTAssertNotEqual(resumeCode(bind, 0), resumeCode(bind, 1))
        XCTAssertNotEqual(resumeCode(Primitives.randomBytes(32), 0), resumeCode(bind, 0))
    }

    func testBlipResumesWithinGraceOnCorrectCode() {
        let bind = Primitives.randomBytes(32)
        let s = PresenceSession(bindSecret: bind, atS: 0, graceS: 30)
        XCTAssertTrue(s.operating)
        s.disconnect(atS: 10)
        XCTAssertEqual(s.state, .suspended)
        XCTAssertFalse(s.operating)
        XCTAssertTrue(s.reconnect(code: resumeCode(bind, 0), atS: 15))
        XCTAssertEqual(s.state, .present)
    }

    func testWrongCodeLocks() {
        let bind = Primitives.randomBytes(32)
        let s = PresenceSession(bindSecret: bind, atS: 0, graceS: 30)
        s.disconnect(atS: 5)
        XCTAssertFalse(s.reconnect(code: Data(repeating: 0, count: 16), atS: 6))
        XCTAssertEqual(s.state, .locked)
        XCTAssertEqual(s.lockEvent?.reason, "bad_code")
    }

    func testReconnectAfterGraceLocks() {
        let bind = Primitives.randomBytes(32)
        let s = PresenceSession(bindSecret: bind, atS: 0, graceS: 30)
        s.disconnect(atS: 5)
        XCTAssertFalse(s.reconnect(code: resumeCode(bind, 0), atS: 40))   // correct code, too late
        XCTAssertEqual(s.state, .locked)
        XCTAssertEqual(s.lockEvent?.reason, "timeout")
    }

    func testReplayedOldCodeRejected() {
        let bind = Primitives.randomBytes(32)
        let s = PresenceSession(bindSecret: bind, atS: 0, graceS: 30)
        s.disconnect(atS: 5)
        XCTAssertTrue(s.reconnect(code: resumeCode(bind, 0), atS: 6))     // counter -> 1
        s.disconnect(atS: 10)
        XCTAssertFalse(s.reconnect(code: resumeCode(bind, 0), atS: 11))   // replay code 0
        XCTAssertEqual(s.state, .locked)
        XCTAssertEqual(s.lockEvent?.reason, "bad_code")
    }

    func testLockIsTerminal() {
        let bind = Primitives.randomBytes(32)
        let s = PresenceSession(bindSecret: bind, atS: 0, graceS: 30)
        s.remove(atS: 1)
        XCTAssertEqual(s.state, .locked)
        s.pulse(atS: 2)                                                    // no silent un-lock
        XCTAssertEqual(s.state, .locked)
        XCTAssertFalse(s.reconnect(code: resumeCode(bind, 0), atS: 3))
    }
}
