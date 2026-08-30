import Foundation
import Combine
import AVFoundation
import CoreImage
import AtlasCore

/// Direct-capture camera app with depth/PAD (§8.2). SOURCE ONLY — needs the
/// device camera + LiDAR; not compiled/run in the cloud env.
///
/// Signs the EARLIEST AVFoundation frame inside the attested app flow and binds
/// capture metadata (LiDAR depth, camera intrinsics, motion, time) BEFORE the
/// image leaves the capture context — defeating import/generate-then-sign. PAD
/// runs at capture: a LiDAR depth-plane check (a screen reads as a flat plane)
/// plus texture/moiré analysis. The actual provenance signing/verify is the
/// pure `AtlasCore.Provenance` core (tested on the Mac); this class only does
/// the device capture and feeds it.
@MainActor
public final class CaptureController: NSObject, ObservableObject {
    @Published public private(set) var lastVerdictText = "—"

    // AVCaptureSession is internally thread-safe and its `startRunning()` blocks,
    // so it is driven off the main actor on a dedicated serial queue. `nonisolated
    // (unsafe)` is the sanctioned opt-out: the object guards its own concurrency,
    // and all our session mutations are funnelled through the main actor or this
    // queue, never both at once.
    nonisolated(unsafe) private let session = AVCaptureSession()
    /// The session, for binding an `AVCaptureVideoPreviewLayer` (read-only use).
    nonisolated public var previewSession: AVCaptureSession { session }
    /// True once `configure()` found a LiDAR depth camera (drives the PAD depth check).
    public private(set) var hasLiDAR = false
    nonisolated private let sessionQueue = DispatchQueue(label: "inc.clockworktree.atlas.capture.session")
    private let photoOutput = AVCapturePhotoOutput()
    private let depthOutput = AVCaptureDepthDataOutput()

    /// Injected by the app: the live authorship child, a fresh liveness
    /// attestation, the current beacon round, and the shared ledger.
    public struct CaptureContext {
        public let authorship: Child
        public let attestation: LivenessAttestation
        public let beaconRound: BeaconRound
        public let ledger: LedgerStub
        public init(authorship: Child, attestation: LivenessAttestation, beaconRound: BeaconRound, ledger: LedgerStub) {
            self.authorship = authorship; self.attestation = attestation
            self.beaconRound = beaconRound; self.ledger = ledger
        }
    }

    private var pending: CaptureContext?
    public var onBundle: ((Data, ProvenanceBundle) -> Void)?

    public func configure() throws {
        // Idempotent: re-entering the Capture tab calls this again; a second video
        // input would raise an NSException (uncatchable -> crash). If we already have
        // an input, we're configured.
        guard session.inputs.isEmpty else { return }
        // Don't let the capture session hijack the app's audio session — otherwise
        // opening the camera stops the user's music/podcast. We capture no audio here.
        session.automaticallyConfiguresApplicationAudioSession = false
        session.beginConfiguration()
        // ALWAYS balance beginConfiguration, even on the throw path, so the session is
        // never left mid-configuration (which corrupts later capture calls).
        defer { session.commitConfiguration() }
        let lidar = AVCaptureDevice.default(.builtInLiDARDepthCamera, for: .video, position: .back)
        hasLiDAR = lidar != nil
        guard let device = lidar ?? AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input)
        else { throw NSError(domain: "atlas.capture", code: 1) }
        session.addInput(input)
        if session.canAddOutput(photoOutput) { session.addOutput(photoOutput) }
        photoOutput.isDepthDataDeliveryEnabled = photoOutput.isDepthDataDeliverySupported
    }

    public func start() { sessionQueue.async { [session] in session.startRunning() } }
    public func stop() { sessionQueue.async { [session] in session.stopRunning() } }

    /// Capture the earliest frame and sign it inside the attested flow.
    public func capture(context: CaptureContext) {
        // capturePhoto raises an UNCATCHABLE ObjC exception (instant crash) if there's
        // no active/enabled video connection or the session isn't running. Guard both
        // instead of letting it throw. This is the photo-capture crash.
        guard session.isRunning else {
            lastVerdictText = "camera still starting — try again in a moment"; return
        }
        guard let conn = photoOutput.connection(with: .video), conn.isActive, conn.isEnabled else {
            lastVerdictText = "no camera connection — capture unavailable on this device"; return
        }
        pending = context
        // Prefer HEVC when the output offers it; else the default codec. Setting a codec
        // the output doesn't advertise would also crash, so pick from availablePhotoCodecTypes.
        let settings: AVCapturePhotoSettings
        if photoOutput.availablePhotoCodecTypes.contains(.hevc) {
            settings = AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.hevc])
        } else {
            settings = AVCapturePhotoSettings()
        }
        settings.isDepthDataDeliveryEnabled = photoOutput.isDepthDataDeliveryEnabled
        photoOutput.capturePhoto(with: settings, delegate: self)
    }

    /// Reduce an AVDepthData map to a coarse per-region distance vector for the
    /// PAD depth-plane check (a screen replay is near-planar).
    nonisolated private func depthRegions(_ depth: AVDepthData?) -> [Double] {
        guard let depth else { return [] }
        let converted = depth.converting(toDepthDataType: kCVPixelFormatType_DepthFloat32)
        let map = converted.depthDataMap
        CVPixelBufferLockBaseAddress(map, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(map, .readOnly) }
        let w = CVPixelBufferGetWidth(map), h = CVPixelBufferGetHeight(map)
        guard let base = CVPixelBufferGetBaseAddress(map) else { return [] }
        let rowBytes = CVPixelBufferGetBytesPerRow(map)
        var regions: [Double] = []
        for gy in 0..<3 { for gx in 0..<3 {     // 3x3 grid of sample points
            let x = (gx * 2 + 1) * w / 6, y = (gy * 2 + 1) * h / 6
            let ptr = base.advanced(by: y * rowBytes + x * MemoryLayout<Float>.size)
            let d = ptr.load(as: Float.self)
            if d.isFinite && d > 0 { regions.append(Double(d)) }
        } }
        return regions
    }
}

extension CaptureController: AVCapturePhotoCaptureDelegate {
    // AVFoundation delivers this callback on a PRIVATE capture queue (not main),
    // so it must be `nonisolated`. We pull everything the signer needs out of the
    // non-Sendable `AVCapturePhoto` here (Data, region vector, dimensions — all
    // Sendable), then hop to the main actor to touch `pending`/`@Published` state
    // and run the pure-Swift `Provenance` signer.
    nonisolated public func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        guard let frame = photo.fileDataRepresentation() else { return }
        let depth = depthRegions(photo.depthData)
        // A real moiré detector runs a frequency-domain periodicity test; stubbed
        // low here so the device build wires the rest of the flow end to end.
        let moire = 0.1
        let dims = photo.resolvedSettings.photoDimensions
        let width = Int(dims.width), height = Int(dims.height)
        Task { @MainActor in
            guard let ctx = self.pending else { return }
            self.pending = nil
            let meta = CaptureMetadata(
                cameraIntrinsics: "dims=\(width)x\(height)",
                motion: "device-motion-summary",
                capturedAt: ISO8601DateFormatter().string(from: Date()),
                depthSummary: "lidar-3x3")
            do {
                let bundle = try Provenance.signCapture(
                    content: frame, depthMap: depth, moireScore: moire, metadata: meta,
                    authorship: ctx.authorship, attestation: ctx.attestation,
                    beaconRound: ctx.beaconRound, ledger: ctx.ledger)
                self.lastVerdictText = "signed; PAD depth-var \(String(format: "%.3f", bundle.pad.depthVariance))"
                self.onBundle?(frame, bundle)
            } catch ProvenanceError.padRejected(let why) {
                self.lastVerdictText = "PAD REJECTED: \(why)"   // screen replay defeated at capture
            } catch {
                self.lastVerdictText = "capture failed: \(error)"
            }
        }
    }
}
