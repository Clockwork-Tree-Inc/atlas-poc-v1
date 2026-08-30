import XCTest
@testable import AtlasCore

/// Persona (`Profile`) parity + unlinkability — mirrors `backend/atlas/keys/identity.py`.
/// The expected handles are asserted BYTE-IDENTICAL to the Python reference-of-record,
/// generated from a fixed tskSeed (bytes 0..31) via `IdentityTree.profile(...)`.
final class ProfileTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private func tree() throws -> IdentityTree {
        let seed = Data((0..<32).map { UInt8($0) })
        return try IdentityTree.build(tskSeed: seed, sphincs: StubSphincs())
    }

    /// Byte-for-byte parity with the Python reference (fixed seed, persona "alice"/PUBLIC).
    func testProfileHandlesMatchPythonReference() throws {
        let p = try tree().profile("alice", tier: .public)
        XCTAssertEqual(hex(p.handle),
                       "f54897e23bd80f689fd265eaf89ceb5ae20a69e11acd74c65f86b1157de37216")
        XCTAssertEqual(hex(try p.feature("messaging").handle),
                       "94bdab3067990fd0f7db181294806006312cff1dab32e652ce66390fab7c5b52")
        XCTAssertEqual(hex(try p.feature("vault").handle),
                       "52b6d3ac714b2bd895ac7b198cc4bd7d2b52be95150ccfd52d6b3f89abdba812")
    }

    /// Personas are mutually unlinkable; feature slices within a persona don't cross-link;
    /// derivation is deterministic (re-derivable on any device from the System-ID).
    func testPersonasUnlinkableAndFeaturesIsolated() throws {
        let t = try tree()
        let alicePub = try t.profile("alice", tier: .public)
        let aliceAnon = try t.profile("alice", tier: .anonymous)
        let bobPub = try t.profile("bob", tier: .public)

        XCTAssertNotEqual(alicePub.handle, aliceAnon.handle)   // tier changes the persona
        XCTAssertNotEqual(alicePub.handle, bobPub.handle)      // username changes the persona

        let msg = try alicePub.feature("messaging").handle
        let vault = try alicePub.feature("vault").handle
        XCTAssertNotEqual(msg, vault)                          // a persona's own surfaces don't cross-link
        XCTAssertEqual(msg, try alicePub.feature("messaging").handle)  // deterministic re-derivation
    }

    /// #40 — the duress DECOY persona. Byte-identical to the Python reference, and provably
    /// unlinkable to the root / real personas / a same-named real profile.
    func testDuressPersonaParityAndUnlinkability() throws {
        let t = try tree()
        let d0 = try t.duressPersona(0)
        XCTAssertEqual(hex(d0.handle),
                       "faf936d279db198ecd8502d84a0e10a01e80caa6104b6d93c19f8cc2cd3c024f")
        XCTAssertEqual(hex(try d0.feature("messaging").handle),
                       "be8b13611608a36a5f5c328a2fa3a278ffee36726bc4b98c049ce0119fbb22cb")
        XCTAssertEqual(hex(try t.duressPersona(1).handle),
                       "c0b04f49f57e312bd08d395d7650186d59037329341afd23b5537a5426e62330")
        // unlinkable to root/System-ID and to real personas; and it does NOT collide with a real
        // profile literally named "duress:0" (distinct HKDF domain).
        XCTAssertNotEqual(d0.handle, t.rootHandle)
        XCTAssertNotEqual(d0.handle, t.systemIDHandle())
        XCTAssertNotEqual(d0.handle, try t.profile("aun", tier: .public).handle)
        XCTAssertNotEqual(d0.handle, try t.profile("duress:0", tier: .anonymous).handle)
    }

    /// #40 wiring: the decoy rebuilt from its sealed seed (`personaFromSeed`) must reproduce the
    /// SAME persona as `duressPersona` — otherwise a duress unlock would open a different account
    /// than the one armed. Handle + a feature slice must match.
    func testPersonaFromSeedReproducesDuressPersona() throws {
        let t = try tree()
        let derived = try t.duressPersona(0)
        let rebuilt = try IdentityTree.personaFromSeed(t.duressPersonaSeed(0), username: "whatever")
        XCTAssertEqual(rebuilt.handle, derived.handle)
        XCTAssertEqual(try rebuilt.feature("vault").handle, try derived.feature("vault").handle)
    }
}
