import Foundation

/// Shamir 2-of-3 over GF(256) (§1.3, §7.3). Mirrors `backend/atlas/crypto/shamir.py`.
/// Production uses the audited `dsprenkels/sss`; this is the byte-wise reference.
public enum Shamir {
    private static let (expT, logT): ([UInt8], [UInt8]) = {
        var exp = [UInt8](repeating: 0, count: 512)
        var log = [UInt8](repeating: 0, count: 256)
        var a: UInt8 = 1
        for i in 0..<255 {
            exp[i] = a
            log[Int(a)] = UInt8(i)
            a = gfMul(a, 0x03)
        }
        for i in 255..<512 { exp[i] = exp[i - 255] }
        return (exp, log)
    }()

    private static func xtime(_ x: UInt8) -> UInt8 {
        let s = UInt16(x) << 1
        return UInt8((s ^ ((s & 0x100) != 0 ? 0x11B : 0)) & 0xFF)
    }
    private static func gfMul(_ a0: UInt8, _ b0: UInt8) -> UInt8 {
        var a = a0, b = b0, p: UInt8 = 0
        for _ in 0..<8 {
            if b & 1 != 0 { p ^= a }
            b >>= 1
            a = xtime(a)
        }
        return p
    }
    private static func mul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        if a == 0 || b == 0 { return 0 }
        return expT[Int(logT[Int(a)]) + Int(logT[Int(b)])]
    }
    private static func div(_ a: UInt8, _ b: UInt8) -> UInt8 {
        precondition(b != 0)
        if a == 0 { return 0 }
        return expT[(Int(logT[Int(a)]) - Int(logT[Int(b)]) + 255) % 255]
    }

    public struct Share: Equatable {
        public let index: UInt8
        public let y: Data
        public func encode() -> Data { Data([index]) + y }
        public static func decode(_ d: Data) -> Share { Share(index: d.first!, y: d.dropFirst()) }
    }

    public static func split(_ secret: Data, n: Int = 3, k: Int = 2) -> [Share] {
        precondition(k > 1 && k <= n && n < 256)
        var ys = (0..<n).map { _ in Data() }
        for byte in secret {
            var coeffs = [byte]
            coeffs.append(contentsOf: Primitives.randomBytes(k - 1))
            for si in 0..<n {
                let x = UInt8(si + 1)
                var acc: UInt8 = 0
                for c in coeffs.reversed() { acc = mul(acc, x) ^ c }
                ys[si].append(acc)
            }
        }
        return (0..<n).map { Share(index: UInt8($0 + 1), y: ys[$0]) }
    }

    public static func combine(_ shares: [Share]) -> Data {
        precondition(shares.count >= 2)
        let length = shares[0].y.count
        // Share validation (mirrors backend/atlas/crypto/shamir.py:combine). Without
        // these, a malformed/forged share silently corrupts reconstruction:
        //  - x == 0 is the interpolation point (the secret); a share at x=0 makes its
        //    Lagrange basis 1 and every other 0, so combine() returns THAT share's y
        //    verbatim — a single forged index-0 share hijacks a k-of-N recovery.
        //  - duplicate indices -> a zero denominator (div precondition trap).
        //  - inconsistent lengths -> out-of-bounds read.
        precondition(shares.allSatisfy { $0.index >= 1 }, "share index out of range (must be 1...255)")
        precondition(Set(shares.map { $0.index }).count == shares.count, "duplicate share indices")
        precondition(shares.allSatisfy { $0.y.count == length }, "shares have inconsistent length")
        var out = Data()
        for pos in 0..<length {
            var secretByte: UInt8 = 0
            for i in 0..<shares.count {
                let xi = shares[i].index
                let yi = shares[i].y[shares[i].y.startIndex + pos]
                var num: UInt8 = 1, den: UInt8 = 1
                for j in 0..<shares.count where j != i {
                    num = mul(num, shares[j].index)
                    den = mul(den, xi ^ shares[j].index)
                }
                secretByte ^= mul(yi, div(num, den))
            }
            out.append(secretByte)
        }
        return out
    }
}
