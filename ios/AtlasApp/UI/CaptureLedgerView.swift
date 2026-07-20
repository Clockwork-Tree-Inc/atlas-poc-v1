import SwiftUI
import AVFoundation
import AtlasCore

/// The "Capture" tab. Opens an in-app camera with a LIVE PREVIEW + shutter (not the
/// system picker — that can't give depth). On LiDAR iPhones it captures the depth map
/// for the PAD anti-spoof (a screen replay reads as a flat plane); on non-LiDAR phones
/// it still captures + signs (PAD advisory). The photo is provenance-signed under your
/// live presence (ring pulse gates it), anchored to the ledger, and saved to the vault.
@MainActor
final class CaptureLedgerModel: ObservableObject {
    @Published var log: [String] = []

    func onAppear() {
        add("Capture — in-app camera; the photo is signed under your live presence, LiDAR-depth PAD-checked, anchored, and saved to your vault.")
    }
    func add(_ s: String) { log.append(s) }

    /// Build the signing context from live presence. Nil (with a logged reason) if not
    /// enrolled or the presence gate isn't operating.
    func makeContext(session: AtlasSession) async -> CaptureController.CaptureContext? {
        guard let authorship = session.authorship else { add("enrol first"); return nil }
        let beaconRound = session.beacon()
        let pole = await session.currentPoLE()
        guard let attestation = AttestationSubsystem().attest(pole) else {
            add("Not attested — no live presence. Wear your ring so your pulse gates the capture.")
            return nil
        }
        return CaptureController.CaptureContext(authorship: authorship, attestation: attestation,
                                                beaconRound: beaconRound, ledger: session.ledger)
    }

    /// A signed photo came back from the controller: verify + log, then save to vault.
    func handleBundle(_ content: Data, _ bundle: ProvenanceBundle, session: AtlasSession) async {
        let verdict = Provenance.verify(bundle, content: content, ledger: session.ledger)
        add("Signed ✓ (\(content.count) B) · ACCOUNTABLE=\(verdict.accountable) · PAD passed=\(bundle.pad.passed) depth-var \(String(format: "%.4f", bundle.pad.depthVariance))")
        add("· anchored at ledger index \(bundle.anchorIndex); chainOK=\(session.ledger.verifyChain()).")
        let name = "capture-\(Int(Date().timeIntervalSince1970)).jpg"
        if let err = await session.vaultAddFile(name: name, data: content, kind: "image") {
            add("· saved to vault failed: \(err)")
        } else {
            session.attachProvenance(name: name, bundle: bundle)
            add("· saved as \(name) — verified-human provenance attached; open it in the Vault.")
        }
    }
}

struct CaptureLedgerView: View {
    @EnvironmentObject var session: AtlasSession
    @StateObject private var model = CaptureLedgerModel()
    @StateObject private var controller = CaptureController()
    @State private var showCamera = false

    var body: some View {
        NavigationStack {
            Form {
                if session.authorship != nil {
                    Section("Capture") {
                        Button {
                            showCamera = true
                        } label: { Label("Open camera", systemImage: "camera.fill") }
                        Text("In-app camera with live preview. Signed under your live presence, LiDAR-depth checked where available, anchored, and saved to your vault.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Section("Log") {
                        ForEach(Array(model.log.enumerated().reversed()), id: \.offset) { _, l in
                            Text(l).font(.caption2.monospaced())
                        }
                    }
                } else {
                    Section { Text("enrol first").font(.caption).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Capture")
            .onAppear {
                model.onAppear()
                controller.onBundle = { content, bundle in
                    Task { @MainActor in
                        showCamera = false
                        await model.handleBundle(content, bundle, session: session)
                    }
                }
            }
            .fullScreenCover(isPresented: $showCamera) {
                CameraCaptureView(controller: controller, model: model, session: session) {
                    showCamera = false
                }
            }
        }
    }
}

/// In-app camera screen: live preview + shutter. Configures/starts the capture session
/// on appear, stops it on dismiss. The shutter builds the live-presence context and
/// asks the controller to capture + sign; the controller's onBundle closes this screen.
struct CameraCaptureView: View {
    @ObservedObject var controller: CaptureController
    @ObservedObject var model: CaptureLedgerModel
    let session: AtlasSession
    var onClose: () -> Void
    @State private var capturing = false
    @State private var failed: String?

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if failed == nil {
                CameraPreview(session: controller.previewSession).ignoresSafeArea()
            }
            VStack {
                HStack {
                    Spacer()
                    Button(action: onClose) {
                        Image(systemName: "xmark.circle.fill").font(.largeTitle)
                            .symbolRenderingMode(.hierarchical)
                    }.padding()
                }
                Spacer()
                if let failed {
                    Text(failed).font(.callout).multilineTextAlignment(.center).padding()
                }
                Text(controller.hasLiDAR ? "LiDAR depth PAD active" : "no LiDAR on this phone — PAD advisory")
                    .font(.caption2).foregroundStyle(.white.opacity(0.7))
                Button(action: shutter) {
                    ZStack {
                        Circle().fill(.white.opacity(0.25)).frame(width: 82, height: 82)
                        Circle().strokeBorder(.white, lineWidth: 5).frame(width: 74, height: 74)
                    }
                }
                .disabled(capturing || failed != nil)
                .padding(.bottom, 40)
            }
            .foregroundStyle(.white)
        }
        .onAppear {
            do { try controller.configure(); controller.start() }
            catch { failed = "Camera unavailable on this device.\n\(error.localizedDescription)" }
        }
        .onDisappear { controller.stop() }
    }

    private func shutter() {
        capturing = true
        Task {
            guard let ctx = await model.makeContext(session: session) else {
                capturing = false
                failed = "Not attested — wear your ring so your live pulse gates the capture."
                return
            }
            controller.capture(context: ctx)     // onBundle (in the parent) closes this screen
            capturing = false
        }
    }
}

/// Live camera preview backed by `AVCaptureVideoPreviewLayer`.
struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession
    func makeUIView(context: Context) -> PreviewView {
        let v = PreviewView()
        v.videoPreviewLayer.session = session
        v.videoPreviewLayer.videoGravity = .resizeAspectFill
        return v
    }
    func updateUIView(_ uiView: PreviewView, context: Context) {}

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var videoPreviewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }
}
