import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Signal-safe crash marker (module scope so the C handler can touch it)

/// A pre-opened fd + a pre-built byte buffer, so the signal handler only does async-signal-safe
/// work (a single `write`). Formatting or Swift-object access inside a signal handler is unsafe.
nonisolated(unsafe) private var gCrashFD: Int32 = -1
private let gCrashMsg = Array("\n=== ATLAS CRASH: fatal signal — the lines above are the last activity before it died ===\n".utf8)

private func atlasSignalHandler(_ sig: Int32) {
    if gCrashFD >= 0 {
        gCrashMsg.withUnsafeBytes { _ = write(gCrashFD, $0.baseAddress, $0.count) }
    }
    signal(sig, SIG_DFL)   // restore default and re-raise so the OS still reports the crash
    raise(sig)
}

/// Persisted, exportable developer log. Unlike `AtlasSession.log` (RAM-only, lost on relaunch),
/// this ring-buffers to a file that survives restarts, captures fatal crashes, and can be exported
/// off-device ("Share log") so a developer can see how the app behaved before a problem.
///
/// Privacy: this is a DEVELOPER tool. It records event lines the app already surfaces (the same
/// `add(...)` feed) — NOT keys, plaintext, message contents, or raw sensor signals. It is opt-in to
/// export (the file never leaves the device unless the user shares it).
final class DevLog: @unchecked Sendable {
    static let shared = DevLog()

    enum Level: String { case debug = "DBG", info = "INF", warn = "WRN", error = "ERR" }

    private let q = DispatchQueue(label: "inc.clockworktree.atlas.devlog")
    private let maxBytes = 2 * 1024 * 1024          // rotate the current file past ~2 MB
    private let fm = FileManager.default

    private var dir: URL { fm.urls(for: .documentDirectory, in: .userDomainMask)[0] }
    private var current: URL { dir.appendingPathComponent("atlas-dev.log") }
    private var rotated: URL { dir.appendingPathComponent("atlas-dev.1.log") }   // keep one previous file

    private init() {}

    // MARK: writing

    func log(_ level: Level = .info, _ category: String = "app", _ message: String) {
        let line = "\(Self.stamp()) [\(level.rawValue)] \(category): \(message)\n"
        q.async { [weak self] in self?.append(line) }
    }
    func debug(_ c: String = "app", _ m: String) { log(.debug, c, m) }
    func info(_ c: String = "app", _ m: String)  { log(.info, c, m) }
    func warn(_ c: String = "app", _ m: String)  { log(.warn, c, m) }
    func error(_ c: String = "app", _ m: String) { log(.error, c, m) }

    /// Synchronous append — for the uncaught-exception handler, which runs just before abort.
    func logSync(_ level: Level, _ category: String, _ message: String) {
        q.sync { append("\(Self.stamp()) [\(level.rawValue)] \(category): \(message)\n") }
    }

    private func append(_ line: String) {
        guard let data = line.data(using: .utf8) else { return }
        rotateIfNeeded(adding: data.count)
        if let fh = try? FileHandle(forWritingTo: current) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd(); try? fh.write(contentsOf: data)
        } else {
            try? data.write(to: current)
        }
    }

    private func rotateIfNeeded(adding: Int) {
        let attrs = try? fm.attributesOfItem(atPath: current.path)
        let size = (attrs?[.size] as? Int) ?? 0
        guard size + adding > maxBytes else { return }
        try? fm.removeItem(at: rotated)
        try? fm.moveItem(at: current, to: rotated)
    }

    // MARK: reading / export

    /// The most recent lines (rotated file then current), newest last.
    func tail(_ maxLines: Int = 800) -> [String] {
        q.sync {
            var text = ""
            if let r = try? String(contentsOf: rotated, encoding: .utf8) { text += r }
            if let c = try? String(contentsOf: current, encoding: .utf8) { text += c }
            let lines = text.split(whereSeparator: \.isNewline).map(String.init)
            return Array(lines.suffix(maxLines))
        }
    }

    /// Write the full log (both files) to a single temp file and return it for ShareLink.
    func exportURL() -> URL? {
        q.sync {
            let out = fm.temporaryDirectory.appendingPathComponent("atlas-dev-export.log")
            var text = "ATLAS developer log export — \(Self.stamp())\n\n"
            if let r = try? String(contentsOf: rotated, encoding: .utf8) { text += r }
            if let c = try? String(contentsOf: current, encoding: .utf8) { text += c }
            guard let data = text.data(using: .utf8), (try? data.write(to: out)) != nil else { return nil }
            return out
        }
    }

    func clear() {
        q.sync {
            try? fm.removeItem(at: current)
            try? fm.removeItem(at: rotated)
        }
    }

    // MARK: crash capture

    /// Install ObjC-exception + fatal-signal handlers that leave a marker in the log, so a crash is
    /// visible on next launch. Call once at app start. Best-effort; re-raises so the OS still reports.
    func installCrashHandlers() {
        // Ensure the file exists, then keep an append fd open for the signal handler.
        if !fm.fileExists(atPath: current.path) { fm.createFile(atPath: current.path, contents: nil) }
        gCrashFD = open(current.path, O_WRONLY | O_APPEND | O_CREAT, 0o644)

        NSSetUncaughtExceptionHandler { ex in
            let frames = ex.callStackSymbols.prefix(24).joined(separator: " | ")
            DevLog.shared.logSync(.error, "crash",
                "uncaught \(ex.name.rawValue): \(ex.reason ?? "—") :: \(frames)")
        }
        for sig in [SIGABRT, SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGTRAP] {
            signal(sig, atlasSignalHandler)
        }
        info("devlog", "session start — crash handlers armed")
    }

    private static func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: Date())
    }
}
