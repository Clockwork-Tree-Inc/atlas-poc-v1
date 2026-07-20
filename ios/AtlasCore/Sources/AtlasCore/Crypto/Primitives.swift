import Foundation
import CryptoKit

/// Symmetric primitives, hashes and KDF (§1.3, §4.1).
/// Mirrors `backend/atlas/crypto/primitives.py`.
public enum Primitives {
    public static let aesKeyBytes = 32

    public static func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        let rc = d.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, n, buf.baseAddress!)
        }
        // NEVER ignore the CSPRNG return code: on failure the buffer stays all-zeros and
        // we would hand back predictable "randomness" (keys, nonces, the QRNG core) with
        // no signal. Fail hard instead of silently emitting zeros.
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed (\(rc)) — refusing to return non-random bytes")
        return d
    }

    /// SHA3-256 protocol hash H(...) used for PoLE_state, handles, etc.
    /// Byte-identical to Python's `hashlib.sha3_256` (see Crypto/SHA3.swift).
    public static func H(_ chunks: Data...) -> Data {
        var buf = Data()
        for c in chunks { buf.append(c) }
        return SHA3.sha3_256(buf)
    }

    public static func sha256(_ chunks: Data...) -> Data {
        var h = SHA256()
        for c in chunks { h.update(data: c) }
        return Data(h.finalize())
    }

    /// HKDF<SHA-256> (§1.3).
    public static func hkdf(ikm: Data, info: Data, salt: Data = Data(), length: Int = 32) -> Data {
        let key = SymmetricKey(data: ikm)
        let out = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: length)
        return out.withUnsafeBytes { Data($0) }
    }

    /// Multi-input HKDF with unambiguous length-prefix framing (matches Python
    /// `hkdf_combine`: (a,b) cannot collide with (a||b,"")).
    public static func hkdfCombine(_ parts: [Data], info: Data, length: Int = 32) -> Data {
        var buf = Data()
        for p in parts {
            var n = UInt32(p.count).bigEndian
            withUnsafeBytes(of: &n) { buf.append(contentsOf: $0) }
            buf.append(p)
        }
        return hkdf(ikm: buf, info: info, length: length)
    }

    // MARK: AES-256-GCM (§4.1)

    /// Returns nonce(12) || ciphertext || tag(16).
    public static func aeadEncrypt(key: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
        precondition(key.count == aesKeyBytes, "AES-256-GCM needs a 32-byte key")
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), authenticating: aad)
        // combined = nonce || ciphertext || tag
        return sealed.combined!
    }

    public static func aeadDecrypt(key: Data, blob: Data, aad: Data = Data()) throws -> Data {
        precondition(key.count == aesKeyBytes, "AES-256-GCM needs a 32-byte key")
        let box = try AES.GCM.SealedBox(combined: blob)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }
}
