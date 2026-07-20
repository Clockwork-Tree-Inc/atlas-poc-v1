import Foundation

/// SHA3-256 (FIPS 202 / Keccak-f[1600]).
///
/// CryptoKit ships SHA-2 but not SHA-3, while the Python core uses
/// `hashlib.sha3_256` for the protocol hash H(). This minimal implementation
/// keeps H() byte-identical across the Swift and Python cores so handles,
/// PoLE_state digests, and commitments interoperate across the wire.
enum SHA3 {
    private static let rounds = 24
    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rotc: [Int] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ]
    private static let piln: [Int] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ]

    private static func rotl(_ x: UInt64, _ n: Int) -> UInt64 { (x << UInt64(n)) | (x >> UInt64(64 - n)) }

    private static func keccakF(_ s: inout [UInt64]) {
        for round in 0..<rounds {
            // theta
            var bc = [UInt64](repeating: 0, count: 5)
            for i in 0..<5 { bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20] }
            for i in 0..<5 {
                let t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1)
                for j in stride(from: 0, to: 25, by: 5) { s[j + i] ^= t }
            }
            // rho + pi
            var t = s[1]
            for i in 0..<24 {
                let j = piln[i]
                let tmp = s[j]
                s[j] = rotl(t, rotc[i])
                t = tmp
            }
            // chi
            for j in stride(from: 0, to: 25, by: 5) {
                for i in 0..<5 { bc[i] = s[j + i] }
                for i in 0..<5 { s[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5] }
            }
            // iota
            s[0] ^= rc[round]
        }
    }

    /// SHA3-256: rate = 136 bytes, capacity = 64 bytes, output = 32 bytes.
    static func sha3_256(_ message: Data) -> Data {
        let rate = 136
        var state = [UInt64](repeating: 0, count: 25)
        var input = [UInt8](message)
        // pad10*1 with the SHA-3 domain separator 0x06.
        input.append(0x06)
        while input.count % rate != 0 { input.append(0x00) }
        input[input.count - 1] |= 0x80

        var offset = 0
        while offset < input.count {
            for i in 0..<(rate / 8) {
                var lane: UInt64 = 0
                for b in 0..<8 { lane |= UInt64(input[offset + i * 8 + b]) << UInt64(8 * b) }
                state[i] ^= lane
            }
            keccakF(&state)
            offset += rate
        }

        var out = Data()
        for i in 0..<4 {  // 4 lanes * 8 bytes = 32 bytes
            var lane = state[i]
            for _ in 0..<8 { out.append(UInt8(lane & 0xFF)); lane >>= 8 }
        }
        return out
    }
}
