import Foundation

/// Session key derivation, forward-secret ratchet, contexts and tokens
/// (§2.2, §2.3). Mirrors `backend/atlas/keys/derivation.py` + `tokens.py`.
public enum KeyError: Error { case destroyed }

/// RAM-only session key (§2.2). `destroy()` zeroises it — the primary
/// containment mechanism. Reference type so a wipe is observed by all holders.
///
/// ROLE SEPARATION (§2.3). This is a ROOT, not a working key. Nothing outside
/// this class should consume the raw bytes: every consumer takes a purpose-scoped
/// leaf via `contextKey()` (`storage`, `recognition`, `tunnel`, `chain`,
/// `continuity`). The epoch chain and the continuity chain tick on different
/// clocks and are exposed through different surfaces; handing the same 32 bytes
/// to both turns one compromise into three.
///
/// KEY LIFETIME. The buffer is EXPLICITLY allocated rather than held in a Swift
/// `Array`/`Data`: those are copy-on-write and the runtime may reallocate them,
/// leaving stale plaintext at the old address that no wipe can reach. One
/// allocation, one address, wiped in place, freed on `deinit`.
///
/// The wipe goes through `memset_s` where available. A plain zeroing loop over
/// memory that is never read again is a dead store, and an optimising compiler
/// is entitled to delete it — which is the reason `memset_s`/`explicit_bzero`
/// exist at all.
///
/// Prefer `withKey { }` (borrow, no copy) over `.key` (escaping copy) anywhere
/// the caller does not need to RETAIN the bytes past the call: `destroy()` can
/// only reach the buffer this object owns, so containment is exactly as strong
/// as the copies that were never made.
public final class SessionKey {
    public let drandRound: Data
    private let buf: UnsafeMutableRawBufferPointer
    private(set) public var alive = true

    init(drandRound: Data, key: Data) {
        self.drandRound = drandRound
        // Explicit allocation: fixed address, no COW, no silent realloc.
        self.buf = UnsafeMutableRawBufferPointer.allocate(
            byteCount: key.count, alignment: MemoryLayout<UInt8>.alignment)
        key.withUnsafeBytes { self.buf.copyMemory(from: $0) }
    }

    /// Borrow the key material without minting a copy the wipe cannot reach.
    /// The pointer is valid ONLY for the duration of `body` — do not escape it.
    public func withKey<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard alive else { throw KeyError.destroyed }
        return try body(UnsafeRawBufferPointer(buf))
    }

    /// ESCAPING COPY — the returned `Data` outlives `destroy()`. Kept for the
    /// callers that legitimately RETAIN key bytes (the ratchet chain feeds
    /// `prevKey` forward, see `Session/Device.swift`). Everything else should
    /// use `withKey`.
    public var key: Data {
        get throws {
            guard alive else { throw KeyError.destroyed }
            return Data(buf)
        }
    }

    /// Derive a purpose-scoped LEAF. Every consumer of a session key takes one of
    /// these; nothing outside this class consumes the raw root. HKDF is one-way,
    /// so a leaked leaf yields neither the root nor a sibling leaf.
    public func contextKey(_ context: String) throws -> Data {
        let info: Data
        switch context {
        case "storage": info = Params.contextStorage
        case "recognition": info = Params.contextRecognition
        case "tunnel": info = Params.contextTunnel
        case "chain": info = Params.contextChain
        case "continuity": info = Params.contextContinuity
        default: fatalError("unknown context \(context)")
        }
        return try withKey { raw in
            // Transient — hkdfCombine takes [Data]; wipe it before it is dropped.
            var ikm = Data(raw)
            defer { ikm.withUnsafeMutableBytes { SessionKey.wipe($0) } }
            return Primitives.hkdfCombine([ikm], info: info, length: 32)
        }
    }

    /// Zeroise the key (the primary containment mechanism, §2.2). Idempotent.
    public func destroy() {
        SessionKey.wipe(buf)
        alive = false
    }

    deinit {
        // A key dropped without an explicit destroy() must not leave plaintext
        // behind for the allocator to hand out again.
        SessionKey.wipe(buf)
        buf.deallocate()
    }

    static func wipe(_ b: UnsafeMutableRawBufferPointer) { secureWipe(b) }
}

/// Wipe that the optimiser is not permitted to elide. A zeroing loop over memory
/// never read again is a dead store the compiler may delete — which is precisely
/// why `memset_s`/`explicit_bzero` exist.
func secureWipe(_ b: UnsafeMutableRawBufferPointer) {
    guard let base = b.baseAddress, b.count > 0 else { return }
    #if canImport(Darwin)
    _ = memset_s(base, b.count, 0, b.count)
    #else
    // No memset_s: write through a runtime-obtained pointer (the optimiser
    // cannot prove the store dead) and keep the buffer alive across it.
    let p = base.assumingMemoryBound(to: UInt8.self)
    for i in 0..<b.count { p.advanced(by: i).pointee = 0 }
    withExtendedLifetime(b) {}
    #endif
}

/// A wipeable buffer for key material that must be HELD ACROSS CALLS.
///
/// `Data` cannot be wiped: reassigning (`x = Data(repeating: 0, count: 32)`)
/// drops the old copy-on-write allocation intact for the allocator to hand out
/// again. Anything that RETAINS key material on a long-lived object — the
/// ratchet's prev-key, the continuity chain — must live here instead, so a
/// device seized right after a liveness break holds no usable material
/// (§2.2, §5.3). Mirrors `SecretBytes` in `backend/atlas/keys/derivation.py`.
///
/// `setFrom()` overwrites IN PLACE; the buffer's address never changes, so
/// there is never a second copy to chase.
public final class SecretBytes {
    private let buf: UnsafeMutableRawBufferPointer

    public init(count: Int = 32) {
        buf = UnsafeMutableRawBufferPointer.allocate(
            byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        secureWipe(buf)
    }

    /// Borrow the material without minting a copy the wipe cannot reach.
    /// Valid ONLY for the duration of `body` — do not escape it.
    public func withBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try body(UnsafeRawBufferPointer(buf))
    }

    /// Overwrite in place from any raw buffer of the same length.
    public func setFrom(_ src: UnsafeRawBufferPointer) {
        precondition(src.count == buf.count, "length mismatch")
        buf.copyMemory(from: src)
    }

    public func setFrom(_ src: Data) {
        src.withUnsafeBytes { setFrom($0) }
    }

    /// Zeroise in place. Idempotent.
    public func wipe() { secureWipe(buf) }

    deinit {
        secureWipe(buf)
        buf.deallocate()
    }
}

public enum Derivation {
    /// SessKey = HKDF(PoLE_value, LK, epoch_key, prev_key, ctx) (§2.3).
    /// `poleValue` is a physio-timed clean QRNG value (the ring's live signal
    /// timed the firing; the value is clean QRNG). No continuity flag, no raw
    /// physiology, no drand. Input list order preserved for cross-impl parity.
    public static func sessionKeyDecoupled(lk: Data, epochKey: Data, poleValue: Data,
                                           prevKey: Data, contextSeparator: Data,
                                           drandRound: Data) -> SessionKey {
        let m = Primitives.hkdfCombine([lk, epochKey, poleValue, prevKey, contextSeparator],
                                       info: Params.labelSession, length: 32)
        return SessionKey(drandRound: drandRound, key: m)
    }

    /// Claimed embodiment (Math Spec §A); built for parity, not the default.
    public static func sessionKeyCoupled(tsk: Data, devKey: Data, poleState: Data,
                                         beacon: Data, drandRound: Data) -> SessionKey {
        let m = Primitives.hkdfCombine([tsk, devKey, poleState, beacon],
                                       info: Params.labelSession, length: 32)
        return SessionKey(drandRound: drandRound, key: m)
    }

    /// Forward-secret ratchet (§2.2):
    /// K[t+1] = HKDF( K[t] || H(entropy_t) || beacon_t || drand_round ).
    public static func ratchet(_ prevKey: Data, entropyT: Data, beaconT: Data, drandRound: Data) -> Data {
        Primitives.hkdfCombine([prevKey, Primitives.H(entropyT), beaconT, drandRound],
                               info: Params.labelRatchet, length: 32)
    }
}
