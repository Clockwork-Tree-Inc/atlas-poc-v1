import Foundation
import AVFoundation
import Combine
import AtlasCore

/// In-app voice recorder that feeds the capture->seal->vault path (§ media). SOURCE
/// ONLY — needs the device microphone; not compiled/run in the cloud env.
///
/// There is no system "invoke Voice Memos and get the file back" API, so audio is
/// captured with `AVAudioRecorder` writing to a private temp file we own; on stop
/// we read the bytes and hand them to `onAudio`, which the app seals into the
/// vault via `MediaVaultStore.capture(kind: .audio, ...)` under the SAME live
/// presence as the rest of the session. The temp file is deleted immediately after
/// the bytes are read — plaintext only ever lives in the sealed vault.
///
/// Audio carries no camera PAD (depth/moiré are camera anti-spoofing); the
/// accountable verdict rests on authorship + liveness + integrity + anchor. See
/// `MediaVaultStore` for the honest boundary.
@MainActor
public final class AudioCaptureController: NSObject, ObservableObject {
    @Published public private(set) var isRecording = false
    @Published public private(set) var status = "idle"

    /// Called on stop with the recorded audio bytes + a suggested vault item name.
    /// The app supplies this and seals via MediaVaultStore under live presence.
    public var onAudio: ((Data, String) -> Void)?

    private var recorder: AVAudioRecorder?
    private var url: URL?

    public func requestPermissionAndStart() {
        AVAudioApplication.requestRecordPermission { [weak self] granted in
            Task { @MainActor in
                guard let self else { return }
                guard granted else { self.status = "microphone permission denied"; return }
                do { try self.start() } catch { self.status = "start failed: \(error)" }
            }
        }
    }

    private func start() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.record, mode: .default)
        try session.setActive(true)
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("atlas-voice-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44_100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue,
        ]
        let rec = try AVAudioRecorder(url: tmp, settings: settings)
        rec.delegate = self
        guard rec.record() else { throw NSError(domain: "atlas.audio", code: 1) }
        self.recorder = rec
        self.url = tmp
        self.isRecording = true
        self.status = "recording…"
    }

    public func stop() {
        recorder?.stop()                 // triggers audioRecorderDidFinishRecording
    }

    private func finish() {
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false)
        guard let url else { status = "no recording"; return }
        defer { try? FileManager.default.removeItem(at: url); self.url = nil; self.recorder = nil }
        guard let data = try? Data(contentsOf: url), !data.isEmpty else { status = "empty recording"; return }
        let name = "voice-\(Int(url.deletingPathExtension().lastPathComponent.hashValue & 0xffffff))"
        status = "recorded \(data.count) bytes -> sealing to vault"
        onAudio?(data, name)             // app seals into the vault under live presence
    }
}

extension AudioCaptureController: @preconcurrency AVAudioRecorderDelegate {
    public func audioRecorderDidFinishRecording(_ recorder: AVAudioRecorder, successfully flag: Bool) {
        Task { @MainActor in
            if flag { self.finish() } else { self.isRecording = false; self.status = "recording failed" }
        }
    }
}
