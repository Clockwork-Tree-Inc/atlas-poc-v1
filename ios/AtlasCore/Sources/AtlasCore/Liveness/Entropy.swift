import Foundation

/// Entropy operators for liveness assessment (Math Spec v1.4 / GBSS). Mirrors
/// `backend/atlas/liveness/entropy.py` byte-for-byte on the math: Shannon,
/// min-entropy, Lempel-Ziv complexity, spectral entropy.
///
/// LOAD-BEARING INVARIANT: these are MEASUREMENTS of liveness/freshness. Their
/// outputs only TIME and GATE the ratchet (feed the PoLE gate); NONE is ever folded
/// into a key/value. The value stays clean QRNG.
public enum Entropy {

    /// (Shannon, min-entropy) in bits over a sequence of symbols. Shannon = average
    /// unpredictability (-Σ p·log2 p); min-entropy = worst-case (-log2 max p).
    public static func distributionEntropies(_ symbols: [Data]) -> (shannon: Double, minEntropy: Double) {
        if symbols.isEmpty { return (0, 0) }
        var counts: [Data: Int] = [:]
        for s in symbols { counts[s, default: 0] += 1 }
        let n = Double(symbols.count)
        var shannon = 0.0, pMax = 0.0
        for c in counts.values {
            let p = Double(c) / n
            shannon -= p * log2(p)
            pMax = max(pMax, p)
        }
        return (shannon, -log2(pMax))
    }

    /// Shannon entropy of the byte distribution, bits/byte (0..8).
    public static func shannonBits(_ data: Data) -> Double {
        distributionEntropies(data.map { Data([$0]) }).shannon
    }

    /// Normalized Lempel-Ziv (LZ76) complexity of the bit sequence, ~[0,1]. Genuine
    /// noise ~1 (incompressible); a repetitive / looped / constant stream -> low.
    /// Complements min-entropy for replay/loop detection.
    public static func lempelZivComplexity(_ data: Data) -> Double {
        var chars: [Character] = []
        chars.reserveCapacity(data.count * 8)
        for b in data {
            let s = String(b, radix: 2)
            chars.append(contentsOf: String(repeating: "0", count: 8 - s.count) + s)
        }
        let n = chars.count
        if n == 0 { return 0.0 }
        var i = 0, c = 1, ln = 1, k = 1, kMax = 1
        while ln + k <= n {
            if chars[i + k - 1] == chars[ln + k - 1] {
                k += 1
            } else {
                kMax = max(kMax, k)
                i += 1
                if i == ln {
                    c += 1
                    ln += kMax
                    i = 0; k = 1; kMax = 1
                } else {
                    k = 1
                }
            }
        }
        if k != 1 { c += 1 }
        let norm = n > 1 ? Double(n) / log2(Double(n)) : 1.0
        return Double(c) / norm
    }

    /// Normalized spectral entropy of a waveform, [0,1]. Entropy of the power
    /// spectral density (DC removed) over its bins, /log2(bins). Flat spectrum
    /// (broadband/live) -> ~1; a single tone or constant -> ~0. Pure direct DFT.
    public static func spectralEntropy(_ waveform: [Double]) -> Double {
        let n = waveform.count
        if n < 4 { return 0.0 }
        let mean = waveform.reduce(0, +) / Double(n)
        let x = waveform.map { $0 - mean }
        let half = n / 2
        var psd: [Double] = []
        for kf in 1...half {
            var re = 0.0, im = 0.0
            let w = 2.0 * Double.pi * Double(kf) / Double(n)
            for t in 0..<n {
                re += x[t] * cos(w * Double(t))
                im -= x[t] * sin(w * Double(t))
            }
            psd.append(re * re + im * im)
        }
        let total = psd.reduce(0, +)
        if total <= 0 || psd.count < 2 { return 0.0 }
        var h = 0.0
        for power in psd where power > 0 {
            let p = power / total
            h -= p * log2(p)
        }
        return h / log2(Double(psd.count))
    }
}
