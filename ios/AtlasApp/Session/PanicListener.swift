import Foundation
import Speech
import AVFoundation

/// Opt-in, ON-DEVICE listener for the spoken panic phrase. Runs the mic + Apple's Speech framework
/// with `requiresOnDeviceRecognition` (audio + transcript NEVER leave the device); on hearing the
/// configured phrase it fires the duress witness SILENTLY. Default OFF (`voicePanicEnabled`) — when
/// on, the iOS mic indicator shows (a tell + a battery cost), which is the user's deliberate choice.
///
/// NEEDS ON-DEVICE TUNING: recognition accuracy, false-positive threshold, number-word handling
/// ("2456" vs "twenty-four fifty-six"), and mic-session coordination with the ambient witness can
/// only be validated by speaking into a real device. This is a working first cut, not a tuned system.
@MainActor
final class PanicListener {
    private weak var session: AtlasSession?
    private let recognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US"))
    private let engine = AVAudioEngine()
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private(set) var running = false
    private var lastFire = Date(timeIntervalSince1970: 0)

    init(session: AtlasSession) { self.session = session }

    func start() {
        guard !running, session?.voicePanicEnabled == true, session?.hasPanicPhrase == true else { return }
        SFSpeechRecognizer.requestAuthorization { [weak self] status in
            guard status == .authorized else { return }
            Task { @MainActor in self?.begin() }
        }
    }

    func stop() {
        task?.cancel(); task = nil
        request?.endAudio(); request = nil
        if engine.isRunning { engine.stop() }
        engine.inputNode.removeTap(onBus: 0)
        running = false
    }

    private func begin() {
        guard !running, let recognizer, recognizer.isAvailable else { return }
        do {
            let audio = AVAudioSession.sharedInstance()
            try audio.setCategory(.playAndRecord, mode: .measurement,
                                  options: [.duckOthers, .allowBluetooth, .defaultToSpeaker])
            try audio.setActive(true, options: .notifyOthersOnDeactivation)
        } catch { return }
        let req = SFSpeechAudioBufferRecognitionRequest()
        req.requiresOnDeviceRecognition = true
        req.shouldReportPartialResults = true
        let input = engine.inputNode
        let fmt = input.outputFormat(forBus: 0)
        input.installTap(onBus: 0, bufferSize: 1024, format: fmt) { buf, _ in req.append(buf) }
        engine.prepare()
        do { try engine.start() } catch { engine.inputNode.removeTap(onBus: 0); return }
        request = req
        running = true
        task = recognizer.recognitionTask(with: req) { [weak self] result, error in
            let text = result?.bestTranscription.formattedString
            let isFinal = result?.isFinal ?? false
            let hadError = error != nil
            Task { @MainActor in                                   // hop to the actor for all session access
                guard let self else { return }
                if let text, self.session?.voiceMatchesPanicPhrase(text) == true { self.fire() }
                if hadError || isFinal { self.restart() }          // tasks are time-limited — relaunch to stay live
            }
        }
    }

    /// Fire the silent witness. Debounced so one utterance can't fire repeatedly.
    private func fire() {
        guard Date().timeIntervalSince(lastFire) > 10 else { return }
        lastFire = Date()
        let s = session
        Task { @MainActor in await s?.triggerDuress(silentInPlace: true, trigger: "voice-panic-phrase") }
    }

    private func restart() {
        stop()
        if session?.voicePanicEnabled == true, session?.hasPanicPhrase == true { begin() }
    }
}
