import Foundation

/// Media capture -> sealed vault ingestion — the capture->seal->vault reference.
/// Mirrors `backend/atlas/session/media_vault.py`.
///
/// A photo, video, or audio clip captured through the attested flow is, in ONE
/// presence-gated step:
///   1. PROVENANCE-SIGNED at capture (`Provenance.signCapture`) — bound to a
///      verified-live author, the epoch, PAD-checked, ledger-anchored;
///   2. SEALED into the presence-gated `SecureVaultStore` (storage key stays
///      Enclave-sealed, released only on live presence);
///   3. retrievable ONLY through live presence, whereupon its provenance is
///      re-verified and anything not accountable is refused (fail-closed).
///
/// Plaintext never lands outside the seal: "take a photo, it goes straight into
/// the Atlas folder" — the folder being the sealed vault. This is what the app's
/// AudioCaptureController / camera controllers feed on device.
///
/// AUDIO AND PAD (honest boundary): PAD's depth-plane + moiré checks are CAMERA
/// anti-spoofing. Audio has no LiDAR depth, so for audio PAD is recorded honestly
/// as NOT-APPLICABLE (no depth samples) and stays purely ADVISORY — the
/// accountable verdict rests on authorship + liveness + integrity + anchor, which
/// apply to audio exactly as to a photo.
///
/// DEFERRED (parity gap, tracked): the Python `MediaVault` also folds the
/// Priority-1 live-LK/session binding into each capture. The Swift `Provenance`
/// core has not ported `live_binding` yet (it needs the witness registry + LK
/// plumbing — see Provenance.swift's note), so this store's accountability is the
/// current Swift provenance scope (integrity + handle + signature + liveness +
/// anchor). It is NOT faked; it lands when the Swift live-binding port does.
public enum MediaKind: Sendable {
    case photo, video, audio

    public var label: String {
        switch self { case .photo: return "photo"; case .video: return "video"; case .audio: return "audio" }
    }
    public var motion: String {
        switch self { case .photo: return "still"; case .video: return "video"; case .audio: return "audio" }
    }
    public var hasCameraPAD: Bool { self != .audio }
}

public enum MediaVaultError: Error { case provenanceRefused(String), missingDepth(String) }

public struct MediaRecord {
    public let kind: MediaKind
    public let name: String
    public let bundle: ProvenanceBundle
    public let anchorIndex: Int
}

public final class MediaVaultStore {
    private let vault: SecureVaultStore
    private let author: Child
    private let ledger = LedgerStub()
    private var records: [String: MediaRecord] = [:]

    public init(vault: SecureVaultStore, authorship: Child) {
        self.vault = vault
        self.author = authorship
    }

    public func contains(_ name: String) -> Bool { records[name] != nil }
    public func rawAtRest(_ name: String) -> Data? { vault.rawAtRest(name) }

    /// Capture one item: provenance-sign it, then seal the bytes into the vault —
    /// all under the SAME live presence. Photo/video require a real `depthMap`
    /// (+ optional `moireScore`) for PAD; `padPolicy = .reject` additionally
    /// refuses an obvious screen-replay at capture. Audio takes no depth (PAD is
    /// advisory-N/A) and always stays advisory.
    @discardableResult
    public func capture(kind: MediaKind, name: String, content: Data,
                        liveBiometric: Data, pole: PoLEState, beacon: BeaconRound,
                        attestation: LivenessAttestation,
                        depthMap: [Double]? = nil, moireScore: Double = 0.0,
                        cameraIntrinsics: String = "iPhone",
                        padPolicy: Provenance.PADPolicy = .advisory) throws -> MediaRecord {
        var depth = depthMap ?? []
        var moire = moireScore
        var policy = padPolicy
        let depthSummary: String
        if kind == .audio {
            depth = []; moire = 0.0; policy = .advisory       // no camera -> PAD N/A, never gates
            depthSummary = "n/a (audio: no LiDAR depth)"
        } else {
            guard depthMap != nil else { throw MediaVaultError.missingDepth("\(kind.label) capture requires a depthMap for PAD") }
            depthSummary = "lidar-depth-plane"
        }

        let meta = CaptureMetadata(cameraIntrinsics: cameraIntrinsics, motion: kind.motion,
                                   capturedAt: hexEpoch(beacon.drandRound()), depthSummary: depthSummary)

        // 1. provenance: verified-live author + anchor.
        let bundle = try Provenance.signCapture(content: content, depthMap: depth, moireScore: moire,
                                                metadata: meta, authorship: author, attestation: attestation,
                                                beaconRound: beacon, ledger: ledger, padPolicy: policy)
        // 2. seal the media bytes into the presence-gated vault (same live presence).
        try vault.put(name, content, liveBiometric: liveBiometric, pole: pole, beacon: beacon)

        let rec = MediaRecord(kind: kind, name: name, bundle: bundle, anchorIndex: bundle.anchorIndex)
        records[name] = rec
        return rec
    }

    /// Retrieve a captured item under live presence and re-verify its provenance.
    /// Refuses (fail-closed) anything not accountable.
    public func open(_ name: String, liveBiometric: Data, pole: PoLEState) throws -> (content: Data, verdict: ProvenanceVerdict) {
        guard let rec = records[name] else { throw MediaVaultError.provenanceRefused("\(name): no such item") }
        let content = try vault.get(name, liveBiometric: liveBiometric, pole: pole)   // presence-gated decrypt + stamp check
        let verdict = Provenance.verify(rec.bundle, content: content, ledger: ledger)
        guard verdict.accountable else {
            throw MediaVaultError.provenanceRefused("\(name): provenance not accountable: \(verdict.reasons.joined(separator: "; "))")
        }
        return (content, verdict)
    }

    private func hexEpoch(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    /// TEST-ONLY (internal): graft another capture's provenance bundle onto `name`
    /// to prove `open` fails closed when the bundle no longer binds the sealed
    /// content. Not part of the public surface.
    func _testGraftBundle(onto name: String, from other: MediaRecord) {
        guard let existing = records[name] else { return }
        records[name] = MediaRecord(kind: existing.kind, name: existing.name,
                                    bundle: other.bundle, anchorIndex: other.anchorIndex)
    }
}
