import Foundation

/// The Epoch beacon — Atlas's OWN public beacon, i.e. the epoch key (§3.2, XV §2.2).
/// Mirrors `backend/atlas/beacon/epoch.py`.
///
/// The public epoch key is NOT external drand. It is the QRNG epoch value the LKG
/// aggregator fires when Living Keys arrive from the collector nodes:
///   * Living Keys (LKs) are network-wide secrets, each sealed in SE/HSM throughout the
///     whole system. No one, under any circumstance, sees an LK; the ONLY party that
///     observes them is the LKG aggregator, and even it consumes only their ARRIVALS.
///   * The aggregate ARRIVAL TIMING of LKs reaching the aggregator TIMES the firing of
///     the QRNG (§2.3: timing times the firing, it NEVER enters the value). So the epoch
///     advances on a RANDOM CADENCE, not a fixed period.
///   * Each firing publishes a fresh CLEAN-QRNG epoch value with a monotonic epoch index,
///     signed by the aggregator so any device can verify authenticity.
///
/// External drand (`Beacon.swift`) is NOT the epoch key. It serves two bounded roles only:
///   * BOOTSTRAP — a public timeline before enough LKs exist to fire the aggregator.
///   * DEFENCE-IN-DEPTH ANCHOR — an independent public value recorded ALONGSIDE the epoch
///     (bound into the signature, never into the epoch VALUE) so the epoch cannot be
///     back-dated and Atlas's own beacon cannot be dismissed as self-fabricated.

public struct EpochRound: Sendable, Equatable {
    public let epoch: Int          // monotonic epoch index (advances once per QRNG firing)
    public let randomness: Data    // CLEAN QRNG epoch value (core only; never timing/anchor)
    public let anchor: Data        // OPTIONAL external-drand round, bound into `signature`, never the value
    public let signature: Data     // aggregator's signature over (epoch, randomness, anchor); empty when unsigned

    public init(epoch: Int, randomness: Data, anchor: Data = Data(), signature: Data = Data()) {
        self.epoch = epoch; self.randomness = randomness
        self.anchor = anchor; self.signature = signature
    }

    /// The 8-byte epoch index — the public round identifier used as the freshness /
    /// domain-separation label throughout the protocol.
    public func epochRound() -> Data {
        var r = UInt64(epoch).bigEndian
        return withUnsafeBytes(of: &r) { Data($0) }
    }
}

/// The message the aggregator signs to publish an epoch. Binding the drand `anchor`
/// here (not into the value) is what makes it defence-in-depth.
public func epochSigningMessage(epoch: Int, randomness: Data, anchor: Data) -> Data {
    var r = UInt64(epoch).bigEndian
    let e = withUnsafeBytes(of: &r) { Data($0) }
    return Primitives.H(Data("atlas/epoch/v1".utf8), e, randomness, anchor)
}

/// The LKG aggregator's public epoch beacon (the source of the epoch key).
public final class EpochBeacon {
    private let signer: HybridSign.Keypair?
    private let qrng: ServerQRNG
    private var epoch = 0
    private var last: EpochRound?

    public init(signer: HybridSign.Keypair? = nil, qrng: ServerQRNG = ServerQRNG()) {
        self.signer = signer; self.qrng = qrng
    }

    /// The aggregator verification key (nil when running unsigned).
    public var publicKey: HybridSign.PublicKey? { signer?.publicKey }

    /// Advance the epoch, driven by aggregate LK-arrival timing. Pass `anchor` to fold
    /// an external-drand round in for bootstrap / defence-in-depth.
    public func fire(lkArrivals: ArrivalTiming, anchor: Data = Data()) throws -> EpochRound {
        epoch += 1
        let draw = qrng.fire(arrival: lkArrivals, anchor: anchor)
        let randomness = draw.randomness   // CLEAN QRNG value (the anchor is not folded in)
        var signature = Data()
        if let signer = signer {
            signature = try HybridSign.sign(signer, epochSigningMessage(epoch: epoch, randomness: randomness, anchor: anchor))
        }
        let rnd = EpochRound(epoch: epoch, randomness: randomness, anchor: anchor, signature: signature)
        last = rnd
        return rnd
    }

    public func latest() throws -> EpochRound {
        guard let last = last else { throw EpochBeaconError.notFired }
        return last
    }
}

public enum EpochBeaconError: Error { case notFired }

/// Verify the aggregator's signature over an epoch round — fail-closed on a missing or
/// invalid signature. The epoch-beacon analogue of external drand's BLS verification; the
/// two are independent, so a verifier can require BOTH as defence-in-depth.
public func verifyEpochRound(_ rnd: EpochRound, _ pub: HybridSign.PublicKey) -> Bool {
    guard !rnd.signature.isEmpty else { return false }
    return HybridSign.verify(pub, epochSigningMessage(epoch: rnd.epoch, randomness: rnd.randomness, anchor: rnd.anchor), rnd.signature)
}
