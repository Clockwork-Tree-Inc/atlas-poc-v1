import AppIntents
import Foundation

/// Siri / Shortcuts entry point for panic. The user assigns their OWN spoken phrase to this intent
/// in the Shortcuts app (e.g. "Hey Siri, I'm in trouble 2456"), so Siri's always-on listening fires
/// Atlas panic even when the phone is locked — the one always-on path iOS actually allows a third
/// party (Siri does the listening). It opens the app so the witness (mic/location) can run, and
/// leaves a pending-panic flag the app acts on at launch.
///
/// Tradeoff (by design): Siri responds audibly/visibly, so this path is NOT covert — it's the
/// hands-free / can't-touch-the-phone case. Covert stays the typed phrase / silent voice listener.
struct AtlasPanicIntent: AppIntent {
    static var title: LocalizedStringResource { "Atlas Panic" }
    static var description: IntentDescription { IntentDescription("Trigger an Atlas safety panic — starts the witness and alerts your trusted contacts.") }
    static var openAppWhenRun: Bool { true }   // launch Atlas so the witness can run + the flag is consumed

    static let pendingKey = "atlas.panic.pendingAt"

    func perform() async throws -> some IntentResult {
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: Self.pendingKey)
        return .result()
    }
}

/// Exposes the intent to Siri/Shortcuts with a default phrase. Apple requires the app name in the
/// built-in phrase; the user adds their OWN custom "Hey Siri, …" phrase to this shortcut in Settings.
struct AtlasAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: AtlasPanicIntent(),
                    phrases: ["Panic in \(.applicationName)", "\(.applicationName) panic"],
                    shortTitle: "Panic",
                    systemImageName: "exclamationmark.shield.fill")
    }
}
