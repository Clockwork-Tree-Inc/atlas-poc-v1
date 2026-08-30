import CBlst
import CryptoKit
import Foundation

/// BLS12-381 group arithmetic over vendored blst — the on-device backend for the anonymous-credential
/// stack (Pointcheval-Sanders). Mirrors the semantics of backend/atlas/realid/ps_credential.py so the
/// Swift holder can do the same operations the Python reference does. G1 serialization is x||y 48-byte
/// big-endian (matches the Python _ser_g1), so credentials (G1 points) are portable from the backend.
///
/// blst is tuned for pairing-verify, so a couple of ops are built here: GT exponentiation by a scalar
/// is square-and-multiply over blst_fp12_sqr/mul; hash-to-scalar reduces a SHA-512 digest mod r via
/// blst_scalar_from_be_bytes (matching the Python wide-reduction).

// MARK: - Scalar (Fr, the prime field mod r)

public struct Fr: Equatable, @unchecked Sendable {
    var v: blst_fr

    init(_ v: blst_fr) { self.v = v }

    public static let zero = Fr(fromUInt64: 0)
    public static let one = Fr(fromUInt64: 1)

    public init(fromUInt64 x: UInt64) {
        var limbs = (x, UInt64(0), UInt64(0), UInt64(0))
        var fr = blst_fr()
        withUnsafePointer(to: &limbs) {
            $0.withMemoryRebound(to: UInt64.self, capacity: 4) { blst_fr_from_uint64(&fr, $0) }
        }
        self.v = fr
    }

    /// Reduce arbitrary big-endian bytes mod r (used for hash-to-scalar and loading 32-byte scalars).
    public init(reducingBE bytes: [UInt8]) {
        var sc = blst_scalar()
        blst_scalar_from_be_bytes(&sc, bytes, bytes.count)
        var fr = blst_fr()
        blst_fr_from_scalar(&fr, &sc)
        self.v = fr
    }

    public static func random() -> Fr { Fr(reducingBE: [UInt8](Primitives.randomBytes(64))) }

    /// Hash chunks to a scalar: SHA-512 over length-prefixed chunks, reduced mod r (parity with the
    /// Python _hash_to_scalar wide reduction).
    public static func hash(_ chunks: [Data]) -> Fr {
        var h = SHA512()
        for c in chunks {
            var n = UInt32(c.count).bigEndian
            withUnsafeBytes(of: &n) { h.update(bufferPointer: $0) }
            h.update(data: c)
        }
        return Fr(reducingBE: [UInt8](Data(h.finalize())))
    }

    /// Map a claim string to a scalar (parity with ps_credential.msg_scalar).
    public static func msg(_ s: String) -> Fr { hash([Data("atlas/ps-msg".utf8), Data(s.utf8)]) }

    public static func + (a: Fr, b: Fr) -> Fr {
        var r = blst_fr(); var x = a.v; var y = b.v; blst_fr_add(&r, &x, &y); return Fr(r)
    }
    public static func - (a: Fr, b: Fr) -> Fr {
        var r = blst_fr(); var x = a.v; var y = b.v; blst_fr_sub(&r, &x, &y); return Fr(r)
    }
    public static func * (a: Fr, b: Fr) -> Fr {
        var r = blst_fr(); var x = a.v; var y = b.v; blst_fr_mul(&r, &x, &y); return Fr(r)
    }
    public var negated: Fr {
        var r = blst_fr(); var x = v; blst_fr_cneg(&r, &x, true); return Fr(r)
    }
    public var inverse: Fr {
        var r = blst_fr(); var x = v; blst_fr_inverse(&r, &x); return Fr(r)
    }

    public static func == (a: Fr, b: Fr) -> Bool { a.bytesBE() == b.bytesBE() }

    /// 32-byte big-endian encoding (matches Python's (m % R).to_bytes(32, "big")).
    public func bytesBE() -> [UInt8] {
        var sc = blst_scalar(); var fr = v; blst_scalar_from_fr(&sc, &fr)
        var out = [UInt8](repeating: 0, count: 32); blst_bendian_from_scalar(&out, &sc); return out
    }
    fileprivate func bytesLE() -> [UInt8] {
        var sc = blst_scalar(); var fr = v; blst_scalar_from_fr(&sc, &fr)
        var out = [UInt8](repeating: 0, count: 32); blst_lendian_from_scalar(&out, &sc); return out
    }
}

// MARK: - G1

public struct G1: Equatable, @unchecked Sendable {
    var p: blst_p1

    init(_ p: blst_p1) { self.p = p }

    public static var generator: G1 { G1(blst_p1_generator().pointee) }

    public func mul(_ s: Fr) -> G1 {
        var r = blst_p1(); var base = p
        let le = s.bytesLE()
        blst_p1_mult(&r, &base, le, 255)
        return G1(r)
    }
    public static func + (a: G1, b: G1) -> G1 {
        var r = blst_p1(); var x = a.p; var y = b.p; blst_p1_add_or_double(&r, &x, &y); return G1(r)
    }

    /// 96-byte uncompressed x||y big-endian (matches Python _ser_g1).
    public func serialize() -> [UInt8] {
        var aff = blst_p1_affine(); var pp = p; blst_p1_to_affine(&aff, &pp)
        var out = [UInt8](repeating: 0, count: 96); blst_p1_affine_serialize(&out, &aff); return out
    }
    public static func deserialize(_ bytes: [UInt8]) -> G1? {
        guard bytes.count == 96 else { return nil }
        var aff = blst_p1_affine()
        guard blst_p1_deserialize(&aff, bytes) == BLST_SUCCESS else { return nil }
        var pp = blst_p1(); blst_p1_from_affine(&pp, &aff); return G1(pp)
    }
    /// On-curve AND in the prime-order subgroup (fail-closed check for received points).
    public func isValid() -> Bool {
        var aff = blst_p1_affine(); var pp = p; blst_p1_to_affine(&aff, &pp)
        return blst_p1_affine_on_curve(&aff) && blst_p1_affine_in_g1(&aff)
    }

    public static func == (a: G1, b: G1) -> Bool { a.serialize() == b.serialize() }

    fileprivate func affine() -> blst_p1_affine {
        var aff = blst_p1_affine(); var pp = p; blst_p1_to_affine(&aff, &pp); return aff
    }
}

// MARK: - G2

public struct G2: @unchecked Sendable {
    var p: blst_p2

    init(_ p: blst_p2) { self.p = p }

    public static var generator: G2 { G2(blst_p2_generator().pointee) }

    public func mul(_ s: Fr) -> G2 {
        var r = blst_p2(); var base = p
        blst_p2_mult(&r, &base, s.bytesLE(), 255)
        return G2(r)
    }
    public static func + (a: G2, b: G2) -> G2 {
        var r = blst_p2(); var x = a.p; var y = b.p; blst_p2_add_or_double(&r, &x, &y); return G2(r)
    }

    fileprivate func affine() -> blst_p2_affine {
        var aff = blst_p2_affine(); var pp = p; blst_p2_to_affine(&aff, &pp); return aff
    }

    private static func fpBytes(_ f: blst_fp) -> [UInt8] {
        var v = f; var o = [UInt8](repeating: 0, count: 48); blst_bendian_from_fp(&o, &v); return o
    }
    private static func fpFrom(_ bytes: ArraySlice<UInt8>) -> blst_fp {
        var f = blst_fp(); var b = Array(bytes); blst_fp_from_bendian(&f, &b); return f
    }

    /// 192-byte serialization in py_ecc coefficient order: x.c0 || x.c1 || y.c0 || y.c1 (each 48 BE) —
    /// matches backend _ser_g2, so a backend-issued public key is byte-portable here.
    public func serialize() -> [UInt8] {
        let aff = affine()
        return G2.fpBytes(aff.x.fp.0) + G2.fpBytes(aff.x.fp.1) + G2.fpBytes(aff.y.fp.0) + G2.fpBytes(aff.y.fp.1)
    }
    public static func deserialize(_ bytes: [UInt8]) -> G2? {
        guard bytes.count == 192 else { return nil }
        var aff = blst_p2_affine()
        aff.x.fp.0 = fpFrom(bytes[0..<48]);   aff.x.fp.1 = fpFrom(bytes[48..<96])
        aff.y.fp.0 = fpFrom(bytes[96..<144]); aff.y.fp.1 = fpFrom(bytes[144..<192])
        guard blst_p2_affine_on_curve(&aff), blst_p2_affine_in_g2(&aff) else { return nil }
        var pp = blst_p2(); blst_p2_from_affine(&pp, &aff); return G2(pp)
    }
    /// Canonical bytes for the transcript hash (same as serialize()).
    public func rawBytes() -> [UInt8] { serialize() }

    /// On-curve AND in the prime-order subgroup (fail-closed check for a received G2 element).
    public func isValid() -> Bool {
        var aff = affine()
        return blst_p2_affine_on_curve(&aff) && blst_p2_affine_in_g2(&aff)
    }
}

// MARK: - GT (the target group, Fp12)

public struct GT: Equatable, @unchecked Sendable {
    var f: blst_fp12

    init(_ f: blst_fp12) { self.f = f }

    public static var one: GT { GT(blst_fp12_one().pointee) }

    /// The pairing e(a in G1, b in G2).
    public static func pairing(_ a: G1, _ b: G2) -> GT {
        var q = b.affine(); var p = a.affine()
        var ml = blst_fp12(); blst_miller_loop(&ml, &q, &p)
        var f = blst_fp12(); blst_final_exp(&f, &ml)
        return GT(f)
    }

    public static func * (a: GT, b: GT) -> GT {
        var r = blst_fp12(); var x = a.f; var y = b.f; blst_fp12_mul(&r, &x, &y); return GT(r)
    }
    public var inverse: GT {
        var r = blst_fp12(); var x = f; blst_fp12_inverse(&r, &x); return GT(r)
    }
    fileprivate var squared: GT {
        var r = blst_fp12(); var x = f; blst_fp12_sqr(&r, &x); return GT(r)
    }
    public func isOne() -> Bool { var x = f; return blst_fp12_is_one(&x) }

    /// GT exponentiation by a scalar — square-and-multiply over the scalar's big-endian bits (blst has
    /// no direct GT^scalar). Exponents are taken mod r, which is fine since GT here has order r.
    public func pow(_ e: Fr) -> GT {
        let bytes = e.bytesBE()
        var result = GT.one
        var started = false
        for byte in bytes {
            for bit in (0..<8).reversed() {
                if started { result = result.squared }
                if (byte >> bit) & 1 == 1 {
                    result = started ? result * self : self
                    started = true
                }
            }
        }
        return started ? result : GT.one   // e == 0 -> identity
    }

    public static func == (a: GT, b: GT) -> Bool {
        var x = a.f; var y = b.f; return blst_fp12_is_equal(&x, &y)
    }

    /// Raw serialization for the transcript hash (self-consistent within Swift).
    public func rawBytes() -> [UInt8] {
        var x = f
        return withUnsafeBytes(of: &x) { Array($0) }
    }
}
