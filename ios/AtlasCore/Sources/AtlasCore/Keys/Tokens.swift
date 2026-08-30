import Foundation
import CryptoKit

/// Scoped capability tokens (§2.3). Mirrors `backend/atlas/keys/tokens.py`.
/// Token = MAC(SessKey, { scope, purpose, expiry, nonce }). The token is the
/// only thing crossing the enclave↔UI boundary — a scoped, expiring capability,
/// never a key.
public struct CapabilityToken {
    public let scope: String
    public let purpose: String
    public let expiry: Double
    public let nonce: String
    public let mac: String

    /// Canonical JSON payload (sorted keys, compact) — must match Python.
    static func payload(scope: String, purpose: String, expiry: Double, nonce: String) -> Data {
        // Keys in lexicographic order: expiry, nonce, purpose, scope
        let expiryStr = expiry == expiry.rounded() ? String(Int(expiry)) + ".0" : String(expiry)
        let json = "{\"expiry\":\(expiryStr),\"nonce\":\"\(nonce)\",\"purpose\":\"\(purpose)\",\"scope\":\"\(scope)\"}"
        return Data(json.utf8)
    }
}

public enum Tokens {
    public static func issue(sessKey: Data, scope: String, purpose: String, expiry: Double) -> CapabilityToken {
        let nonce = Primitives.randomBytes(16).hexString
        let mac = hmac(sessKey, CapabilityToken.payload(scope: scope, purpose: purpose, expiry: expiry, nonce: nonce))
        return CapabilityToken(scope: scope, purpose: purpose, expiry: expiry, nonce: nonce, mac: mac)
    }

    public static func verify(sessKey: Data, _ token: CapabilityToken, now: Double,
                              scope: String? = nil, purpose: String? = nil) -> Bool {
        let expected = hmac(sessKey, CapabilityToken.payload(scope: token.scope, purpose: token.purpose,
                                                             expiry: token.expiry, nonce: token.nonce))
        guard constantTimeEquals(expected, token.mac) else { return false }
        // Fail closed on non-finite expiry/clock: `now > nan` is false in IEEE-754,
        // so a NaN expiry would otherwise mint a never-expiring token (and a NaN
        // clock would accept any expired token).
        if !now.isFinite || !token.expiry.isFinite { return false }
        if now > token.expiry { return false }
        if let s = scope, token.scope != s { return false }
        if let p = purpose, token.purpose != p { return false }
        return true
    }

    private static func hmac(_ key: Data, _ message: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac).hexString
    }
    private static func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let da = Array(a.utf8), db = Array(b.utf8)
        guard da.count == db.count else { return false }
        var diff: UInt8 = 0
        for i in da.indices { diff |= da[i] ^ db[i] }
        return diff == 0
    }
}

/// Single-use enforcement for capability tokens (§2.3 / T-02). Mirrors
/// `ReplayCache` in `backend/atlas/keys/tokens.py`.
///
/// `Tokens.verify` is stateless (MAC + TTL + scope only), so a captured token
/// can be replayed any number of times before it expires. For one-shot
/// capabilities wrap verification in a `ReplayCache`: the first successful
/// presentation consumes the token's nonce; any later presentation of the same
/// nonce is rejected even though the MAC and TTL still check out.
///
/// A presentation that fails `verify()` is never recorded, so an attacker cannot
/// poison the cache with forged nonces. Memory is BOUNDED: a nonce only needs
/// remembering until its token expires, so expired entries are evicted on each
/// call — cache size tracks live tokens, not the all-time count. Check-and-set
/// runs under a lock, so concurrent presentations of the same one-shot token
/// cannot both win (no TOCTOU double-use). NOTE: state is per-instance/process;
/// cross-node single-use needs a shared store (a DB unique constraint on the
/// nonce), same as the nullifier rail.
public final class ReplayCache {
    private var seen: [String: Double] = [:]   // nonce -> token expiry
    private let lock = NSLock()

    public init() {}

    public func verifyOnce(sessKey: Data, _ token: CapabilityToken, now: Double,
                           scope: String? = nil, purpose: String? = nil) -> Bool {
        guard Tokens.verify(sessKey: sessKey, token, now: now, scope: scope, purpose: purpose) else {
            return false
        }
        lock.lock()
        defer { lock.unlock() }
        evictExpired(now)
        if seen[token.nonce] != nil { return false }   // replay: nonce already consumed
        seen[token.nonce] = token.expiry
        return true
    }

    private func evictExpired(_ now: Double) {
        guard now.isFinite else { return }
        let dead = seen.filter { now > $0.value }.map { $0.key }
        for nonce in dead { seen[nonce] = nil }
    }
}
