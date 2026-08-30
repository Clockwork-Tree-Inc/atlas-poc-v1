import SwiftUI
import UIKit
import AVFoundation

/// CAPTURE — photo (the real in-app AVFoundation camera with live preview + depth/PAD, which
/// produces a signed ProvenanceBundle), video, and audio. Everything is sealed into the target
/// space with verified-human provenance. Used by the Capture tab and by a space's "+".

// MARK: - camera for VIDEO (basic system capture UI; photo uses the attested AtlasCameraSheet)

struct CameraPicker: UIViewControllerRepresentable {
    let onCaptured: (Data) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let p = UIImagePickerController()
        p.sourceType = UIImagePickerController.isSourceTypeAvailable(.camera) ? .camera : .photoLibrary
        p.mediaTypes = ["public.movie"]
        if p.sourceType == .camera { p.cameraCaptureMode = .video }
        p.delegate = context.coordinator
        return p
    }
    func updateUIViewController(_ c: UIImagePickerController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let parent: CameraPicker
        init(_ p: CameraPicker) { parent = p }
        func imagePickerController(_ picker: UIImagePickerController,
                                   didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
            if let url = info[.mediaURL] as? URL, let data = try? Data(contentsOf: url) { parent.onCaptured(data) }
            parent.dismiss()
        }
        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) { parent.dismiss() }
    }
}

// MARK: - audio recording

@MainActor
final class AudioRecorder: ObservableObject {
    private var recorder: AVAudioRecorder?
    private var url: URL?
    @Published private(set) var recording = false

    func start() {
        let s = AVAudioSession.sharedInstance()
        try? s.setCategory(.playAndRecord, mode: .default)
        try? s.setActive(true)
        let u = FileManager.default.temporaryDirectory
            .appendingPathComponent("atlas-\(UUID().uuidString.prefix(6)).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44_100.0,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue,
        ]
        recorder = try? AVAudioRecorder(url: u, settings: settings)
        recorder?.record()
        url = u; recording = true
    }

    func stop() -> Data? {
        recorder?.stop(); recording = false
        defer { recorder = nil }
        guard let u = url else { return nil }
        return try? Data(contentsOf: u)
    }
}

// MARK: - capture controls (bound to a target space)

/// Photo / Video / Audio, all sealed into `space` with verified-human provenance. Photo uses
/// the attested in-app camera; video/audio sign via `captureSave(attested:true)`.
struct CaptureControls: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var space: AppSpace
    /// When true (the Capture tab) each capture routes to ITS type's default folder; when false
    /// (capture into a specific folder from the navigator) everything lands in `space`.
    var routeByType: Bool = false
    @State private var busy = false
    @State private var err: String?
    @State private var showCamera = false
    @State private var showVideo = false
    @StateObject private var audio = AudioRecorder()

    var body: some View {
        VStack(spacing: 14) {
            button("Photo", "camera.fill") { showCamera = true }
            button("Video", "video.fill") { showVideo = true }
            if audio.recording {
                button("Stop recording", "stop.circle.fill", tint: .red) {
                    if let data = audio.stop() { save(data, "audio", "m4a") }
                }
            } else {
                button("Record audio", "mic.fill") { audio.start() }
            }
            if busy { ProgressView("Saving…").padding(.top, 4) }
        }
        .fullScreenCover(isPresented: $showCamera) {
            AtlasCameraSheet(space: routeByType ? (session.defaultCaptureFolder(for: "image") ?? space) : space)
                .environmentObject(session)
        }
        .fullScreenCover(isPresented: $showVideo) {
            CameraPicker { data in save(data, "video", "mov") }.ignoresSafeArea()
        }
        .alert("Capture failed", isPresented: Binding(get: { err != nil }, set: { if !$0 { err = nil } })) {
            Button("OK") { err = nil }
        } message: { Text(err ?? "") }
    }

    private func save(_ data: Data, _ kind: String, _ ext: String) {
        let dest = routeByType ? (session.defaultCaptureFolder(for: kind) ?? space) : space
        Task {
            busy = true
            err = await session.captureSave(name: "\(kind)-\(UUID().uuidString.prefix(6)).\(ext)",
                                            data: data, kind: kind, to: dest)
            busy = false
        }
    }

    private func button(_ title: String, _ icon: String, tint: Color = .accentColor,
                        _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon).font(.headline)
                .frame(maxWidth: .infinity).padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent).tint(tint).controlSize(.large).disabled(busy)
    }
}

/// The attested in-app camera (live preview + depth/PAD). The signed bundle is saved straight
/// into `space` with verified-human provenance.
struct AtlasCameraSheet: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var space: AppSpace
    @Environment(\.dismiss) private var dismiss
    @StateObject private var controller = CaptureController()
    @StateObject private var model = CaptureLedgerModel()

    var body: some View {
        CameraCaptureView(controller: controller, model: model, session: session) { dismiss() }
            .onAppear {
                controller.onBundle = { content, bundle in
                    Task { @MainActor in
                        _ = await session.saveBundle(content, bundle, kind: "image", to: space)
                        dismiss()
                    }
                }
            }
    }
}
