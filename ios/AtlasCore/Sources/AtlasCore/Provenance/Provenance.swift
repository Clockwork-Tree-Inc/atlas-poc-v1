import Foundation

/// Content provenance and capture core (§8, §10.2). Mirrors
/// `backend/atlas/provenance/`. Pure Swift so it builds and tests on the Mac;
/// the camera/LiDAR capture that feeds it lives in AtlasApp/Capture.
///
/// Honest boundary (§8.2): proves captured-through-an-attested-flow, by a
/// verified live human, at a verifiable time, PAD-checked, unmodified since. It
/// does NOT prove the camera saw a real scene (analog hole / sub-OS injection).

// MARK: Ledger stand-in (§8.1) — only the content hash is anchored.

public struct AnchorReceipt { public let index: Int; public let contentHash: Data; public let entryHash: Data; public let prevHash: Data }

public final class LedgerStub {
    public static let genesis = Data(repeating: 0, count: 32)
    private var entries: [AnchorReceipt] = []
    public init() {}
    public var head: Data { entries.last?.entryHash ?? Self.genesis }

    public func anchor(_ contentHash: Data) -> AnchorReceipt {
        let prev = head, idx = entries.count
        var ib = UInt64(idx).bigEndian
        let entryHash = Primitives.H(Data("atlas/ledger".utf8), prev, contentHash, withUnsafeBytes(of: &ib) { Data($0) })
        let r = AnchorReceipt(index: idx, contentHash: contentHash, entryHash: entryHash, prevHash: prev)
        entries.append(r); return r
    }
    public func contains(_ contentHash: Data) -> Bool { entries.contains { $0.contentHash == contentHash } }
    public func verifyChain() -> Bool {
        var prev = Self.genesis
        for (i, e) in entries.enumerated() {
            var ib = UInt64(i).bigEndian
            let expect = Primitives.H(Data("atlas/ledger".utf8), prev, e.contentHash, withUnsafeBytes(of: &ib) { Data($0) })
            if e.entryHash != expect || e.prevHash != prev { return false }
            prev = e.entryHash
        }
        return true
    }
}

// MARK: Presentation-attack detection (§8.2)

public enum ProvenanceError: Error { case padRejected(String), notLive }

public struct PADResult {
    public let passed: Bool
    public let depthVariance: Double
    public let moireScore: Double
    public let reasons: [String]
    public func digest() -> Data {
        Primitives.H(Data("atlas/pad".utf8),
                     Data(String(format: "%d|%.6f|%.6f", passed ? 1 : 0, depthVariance, moireScore).utf8))
    }
}

public enum PAD {
    public static let depthVarianceMin = 0.01   // a flat screen is near-planar
    public static let moireMax = 0.6

    public static func check(depthMap: [Double], moireScore: Double) -> PADResult {
        guard depthMap.count >= 4 else { return PADResult(passed: false, depthVariance: 0, moireScore: moireScore, reasons: ["insufficient depth samples"]) }
        let mean = depthMap.reduce(0, +) / Double(depthMap.count)
        let variance = depthMap.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(depthMap.count)
        var reasons: [String] = []
        let flat = variance < depthVarianceMin
        let moire = moireScore > moireMax
        if flat { reasons.append("depth variance \(String(format: "%.4f", variance)) < \(depthVarianceMin) (reads as a flat plane)") }
        if moire { reasons.append("moiré score \(String(format: "%.2f", moireScore)) > \(moireMax) (periodic texture)") }
        return PADResult(passed: !(flat || moire), depthVariance: variance, moireScore: moireScore, reasons: reasons)
    }
}

// MARK: Authorship signing + provenance bundle (§8.1, §10.2)

public struct CaptureMetadata {
    public let cameraIntrinsics: String
    public let motion: String
    public let capturedAt: String
    public let depthSummary: String
    public init(cameraIntrinsics: String, motion: String, capturedAt: String, depthSummary: String) {
        self.cameraIntrinsics = cameraIntrinsics; self.motion = motion
        self.capturedAt = capturedAt; self.depthSummary = depthSummary
    }
    /// Canonical (sorted-key, compact) JSON — must match the Python core.
    public func canonical() -> Data {
        let json = "{\"camera_intrinsics\":\"\(cameraIntrinsics)\",\"captured_at\":\"\(capturedAt)\",\"depth_summary\":\"\(depthSummary)\",\"motion\":\"\(motion)\"}"
        return Data(json.utf8)
    }
}

public final class ProvenanceBundle {
    public let contentHash: Data
    public let authorshipHandle: Data
    public let authorshipPublic: HybridSign.PublicKey
    public let metadata: CaptureMetadata
    public let drandRound: Data
    public let epochRandomness: Data
    public let pad: PADResult
    public let liveness: LivenessAttestation
    public var signature: Data
    public let anchorIndex: Int

    init(contentHash: Data, authorshipHandle: Data, authorshipPublic: HybridSign.PublicKey,
         metadata: CaptureMetadata, drandRound: Data, epochRandomness: Data, pad: PADResult,
         liveness: LivenessAttestation, signature: Data, anchorIndex: Int) {
        self.contentHash = contentHash; self.authorshipHandle = authorshipHandle
        self.authorshipPublic = authorshipPublic; self.metadata = metadata
        self.drandRound = drandRound; self.epochRandomness = epochRandomness; self.pad = pad
        self.liveness = liveness; self.signature = signature; self.anchorIndex = anchorIndex
    }

    public func transcript() -> Data {
        Primitives.H(Data("atlas/provenance".utf8), contentHash, metadata.canonical(),
                     drandRound, epochRandomness, pad.digest(), liveness.poleDigest, authorshipHandle)
    }
}

public struct ProvenanceVerdict {
    // load-bearing: accountable attribution
    public let integrityOK, handleOK, signatureOK, livenessOK, anchoredOK: Bool
    // advisory (NOT part of the guarantee)
    public let padAdvisory: PADResult
    public let reasons: [String]
    /// The guarantee: bound to an accountable verified-human pseudonym. PAD does
    /// not gate it (accountability reframe).
    public var accountable: Bool { integrityOK && handleOK && signatureOK && livenessOK && anchoredOK }
    public var ok: Bool { accountable }
}

public enum Provenance {
    public enum PADPolicy { case advisory, reject }

    // MARK: Capture-binding domain separators (anti-transplant, §8.1)
    //
    // The inherited verification proof and the liveness attestation are meant to
    // be bound to THIS author + THIS content + THIS epoch, so neither can be
    // transplanted from another author/capture. These are the byte-exact
    // cross-language constants + helper from the Python core
    // (`_LIVENESS_BIND`, `_INHERITED_BIND`, `_capture_binding`).
    //
    // NOTE (incomplete port — see the file owner's handoff): the actual binding
    // cannot be enforced in Swift yet. Enforcing the liveness binding requires
    // `LivenessAttestation` to carry a `challenge` that is SIGNED into the enclave
    // message (both live in Liveness/Attestation.swift, not owned here, and that
    // port currently lacks the field). Enforcing the inherited binding requires
    // the BBS+ / Real-ID verification stack (InheritedProof, VerificationCredential,
    // AtlasVerificationAuthority, AssuranceLevel), which does not exist in Swift
    // (deliberately deferred — see RealID/Unlinkability.swift's Step-Zero rule:
    // do not hand-roll BBS+). The helper is landed so the shared constants match;
    // wiring it into signing/verification must not be faked without those pieces.
    public static let livenessBindLabel = Data("atlas/provenance/liveness-binding".utf8)
    public static let inheritedBindLabel = Data("atlas/provenance/inherited-binding".utf8)

    /// H(label, authorship_handle, content_hash, drand_round) — the capture binding.
    public static func captureBinding(label: Data, authorshipHandle: Data,
                                      contentHash: Data, drandRound: Data) -> Data {
        Primitives.H(label, authorshipHandle, contentHash, drandRound)
    }

    public static func signCapture(content: Data, depthMap: [Double], moireScore: Double,
                                   metadata: CaptureMetadata, authorship: Child,
                                   attestation: LivenessAttestation, beaconRound: BeaconRound,
                                   ledger: LedgerStub, padPolicy: PADPolicy = .advisory) throws -> ProvenanceBundle {
        // PAD is advisory by default (accountability is the guarantee); `.reject`
        // opts into the capture-time fraud filter.
        let pad = PAD.check(depthMap: depthMap, moireScore: moireScore)
        if padPolicy == .reject && !pad.passed { throw ProvenanceError.padRejected(pad.reasons.joined(separator: "; ")) }
        guard attestation.verify(), attestation.operate else { throw ProvenanceError.notLive }
        let contentHash = Primitives.H(Data("atlas/content".utf8), content)
        let receipt = ledger.anchor(contentHash)
        let bundle = ProvenanceBundle(contentHash: contentHash, authorshipHandle: authorship.handle,
                                      authorshipPublic: authorship.publicKey, metadata: metadata,
                                      drandRound: beaconRound.drandRound(), epochRandomness: beaconRound.randomness,
                                      pad: pad, liveness: attestation, signature: Data(), anchorIndex: receipt.index)
        bundle.signature = (try? HybridSign.sign(authorship.keypair, bundle.transcript())) ?? Data()
        return bundle
    }

    public static func verify(_ bundle: ProvenanceBundle, content: Data, ledger: LedgerStub,
                              assertedHandle: Data? = nil) -> ProvenanceVerdict {
        var reasons: [String] = []
        let integrityOK = Primitives.H(Data("atlas/content".utf8), content) == bundle.contentHash
        if !integrityOK { reasons.append("content modified since capture") }
        var handleOK = handleOf(bundle.authorshipPublic.encode()) == bundle.authorshipHandle
        if let a = assertedHandle, bundle.authorshipHandle != a { handleOK = false; reasons.append("authorship handle mismatch") }
        let signatureOK = handleOK && HybridSign.verify(bundle.authorshipPublic, bundle.transcript(), bundle.signature)
        if !signatureOK { reasons.append("authorship signature invalid") }
        let livenessOK = bundle.liveness.verify() && bundle.liveness.operate && bundle.liveness.drandRound == bundle.drandRound
        if !livenessOK { reasons.append("author not verified-live / wrong epoch") }
        let anchoredOK = ledger.contains(bundle.contentHash) && ledger.verifyChain()
        if !anchoredOK { reasons.append("content hash not anchored") }
        // PAD is advisory — attached, never gates the verdict (accountability reframe).
        if !bundle.pad.passed { reasons.append("ADVISORY: PAD flagged a possible presentation attack (not a verdict gate)") }
        return ProvenanceVerdict(integrityOK: integrityOK, handleOK: handleOK, signatureOK: signatureOK,
                                 livenessOK: livenessOK, anchoredOK: anchoredOK,
                                 padAdvisory: bundle.pad, reasons: reasons)
    }
}
