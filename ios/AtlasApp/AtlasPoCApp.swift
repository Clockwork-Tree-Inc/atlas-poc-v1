import SwiftUI
import CryptoKit
import AtlasCore

/// Atlas PoC iOS app entry (§1.4). Tier 3: the iPhone is simultaneously wallet
/// and interface device, with the Secure Enclave as the isolation boundary.
@main
struct AtlasPoCApp: App {
    // ONE session for the whole app — the enrolled identity + live presence + stores
    // that every feature shares (see AtlasSession).
    @StateObject private var session = AtlasSession()
    var body: some Scene {
        WindowGroup { ContentView().environmentObject(session) }
    }
}

/// Stand-in SPHINCS+ root provider for the iOS app (the Python reference uses REAL
/// SLH-DSA via `pyspx`; CryptoKit has no SLH-DSA yet, so the app substitutes here).
///
///  ⚠️  NOT SPHINCS+ and NOT post-quantum — this is a REAL Ed25519 signature used as a
///  stand-in so `verify()` genuinely verifies (a forged, absent, or tampered signature
///  FAILS) instead of the old `return true` footgun. It is a classical signature: replace
///  with SLH-DSA (CryptoKit when available / a vendored SPHINCS+ / an on-card root) before
///  any post-quantum claim. The TSK root only signs rare continuity/rotation events.
struct PlaceholderSphincs: SphincsProvider {
    private func key(fromSeed seed: Data) -> Curve25519.Signing.PrivateKey {
        // Deterministic 32-byte seed -> Ed25519 key (any 32 bytes is a valid seed).
        try! Curve25519.Signing.PrivateKey(rawRepresentation: Primitives.H(Data("PLACEHOLDER/spx".utf8), seed))
    }
    func keypair(fromSeed seed: Data) -> (publicKey: Data, secretKey: Data) {
        let sk = key(fromSeed: seed)
        return (sk.publicKey.rawRepresentation, sk.rawRepresentation)   // pk derived FROM sk
    }
    func sign(secretKey: Data, message: Data) -> Data {
        (try? Curve25519.Signing.PrivateKey(rawRepresentation: secretKey).signature(for: message)) ?? Data()
    }
    func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: message)   // REAL check, not `true`
    }
}
