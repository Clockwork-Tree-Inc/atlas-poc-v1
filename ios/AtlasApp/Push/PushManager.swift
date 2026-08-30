import Foundation
import UserNotifications
#if canImport(UIKit)
import UIKit
#endif

/// Push — a content-free doorbell. The app registers for remote notifications, hands its APNs
/// token to the node (bound to its mailbox), and the node sends a SILENT background wake when a
/// sealed blob lands. On wake the app fetches + decrypts locally and posts a GENERIC local
/// notification ("New activity in Atlas") — Apple never sees content or sender, only a wake.
@MainActor
final class PushManager: NSObject, UNUserNotificationCenterDelegate {
    static let shared = PushManager()
    weak var session: AtlasSession?
    private(set) var tokenHex: String?

    /// Notification posture. DEFAULT = fetch-on-open (no APNs registration at all → Apple gets
    /// ZERO linkage that you're an Atlas user). Push is strictly opt-in.
    func start() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        guard session?.pushEnabled == true else {
            // fetch-on-open: never contact Apple. Messages surface when you open the app.
            return
        }
        // Opt-in push: request local-notification display + register for the silent wake token.
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in
            #if canImport(UIKit)
            DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() }
            #endif
        }
    }

    /// Called by the app delegate once APNs hands back a device token.
    func gotToken(_ token: Data) {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        tokenHex = hex
        session?.registerPushToken(hex)
    }

    /// Re-bind the token to the (possibly new) current persona's mailbox — call when the active
    /// persona changes or a session comes online.
    func reregister() {
        if let hex = tokenHex { session?.registerPushToken(hex) }
    }

    /// A silent wake arrived: fetch the mailbox + surface a generic local notification.
    func handleSilentWake() async {
        await session?.onPushWake()
        let content = UNMutableNotificationContent()
        content.title = "Atlas"
        content.body = "New activity"                 // generic — no content, no sender
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(req)
    }

    // Show banners even while the app is foregrounded (so the demo is visible).
    nonisolated func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                            withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        h([.banner, .sound])
    }
}

#if canImport(UIKit)
/// App delegate purely for APNs callbacks (SwiftUI keeps its lifecycle via the adaptor).
final class AtlasAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in PushManager.shared.gotToken(deviceToken) }
    }
    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("[atlas-push] register failed: \(error.localizedDescription)")
    }
    /// Silent (content-available) wake — background fetch window.
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any]) async
        -> UIBackgroundFetchResult {
        await PushManager.shared.handleSilentWake()
        return .newData
    }
}
#endif
