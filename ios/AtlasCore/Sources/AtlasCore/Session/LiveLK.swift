import Foundation

/// Two-device co-derived Living Key (LK) — the live LK for the two-phone run.
/// Mirrors `backend/atlas/session/live_lk.py` byte-for-byte.
///
/// Replaces the single-device `randomBytes(32)` stub. The LK VALUE is co-derived
/// from BOTH devices' fresh secret contributions: each device draws a fresh
/// CSPRNG secret and they are combined (HKDF) into the epoch's LK. Neither device
/// alone controls it and neither can predict it before the other's contribution
/// is combined — unpredictable-to-either, controllable-by-neither, epoch-bound.
///
/// INVARIANT (unchanged): only fresh secret VALUES are combined. Timing never
/// enters the value — drand, if used at all, only paces WHEN a device fires its
/// contribution, never the bytes. Combination is order-independent (contributions
/// are sorted), so A and B agree with no designated leader.
public enum LiveLK {
    static let lkInfo = Data("atlas/live-lk/co-derived".utf8)
    public static let contribBytes = 32

    /// A device's fresh secret LK contribution — a clean CSPRNG value. Never a
    /// function of timing; exchanged only over the E2E channel (node stays blind).
    public static func deviceContribution() -> Data { Primitives.randomBytes(contribBytes) }

    /// Combine >= 2 mutually-unknown device contributions into the epoch LK.
    /// Order-independent (contributions sorted lexicographically, matching the
    /// Python reference) so both devices compute the identical LK. Throws on < 2 —
    /// a live LK is co-derived by definition, never single-device.
    public static func coDeriveLK(_ contributions: [Data], drandRound: Data) throws -> Data {
        guard contributions.count >= 2 else {
            throw LiveLKError.tooFewContributions
        }
        let ordered = contributions.sorted(by: lexLess)
        return Primitives.hkdfCombine(ordered + [drandRound], info: lkInfo, length: 32)
    }

    /// Unsigned lexicographic byte order — the same ordering Python's `sorted()`
    /// gives a list of equal-length byte strings, so the co-derived LK matches.
    static func lexLess(_ a: Data, _ b: Data) -> Bool {
        let n = min(a.count, b.count)
        for i in 0..<n {
            let ai = a[a.index(a.startIndex, offsetBy: i)]
            let bi = b[b.index(b.startIndex, offsetBy: i)]
            if ai != bi { return ai < bi }
        }
        return a.count < b.count
    }
}

public enum LiveLKError: Error { case tooFewContributions }
