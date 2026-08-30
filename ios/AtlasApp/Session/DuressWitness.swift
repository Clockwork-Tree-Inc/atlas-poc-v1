import Foundation
import CoreLocation
import Network
#if canImport(UIKit)
import UIKit
#endif

/// Continuous duress WITNESS — a black-box recorder for the worst moment. Once a panic code fires,
/// this streams a full sensor + location + network frame every cycle, sealed, into the user's vault
/// (primary) and off-device to the user's node (durable — survives the phone being destroyed),
/// UNTIL the user-defined vault budget is exhausted or the phone powers off. Not a snapshot: full
/// witness. "That could be the moment of someone's death."
///
/// The Swiss box today is only a RELAY — it forwards the sealed frames toward the user's node and
/// can't read them; a personal node (laptop/home box) is the real home for this stream.

/// One-shot-ish location provider: keeps the latest fix; under duress we start continuous updates
/// (allowed in the background via the `location` UIBackgroundMode).
final class WitnessLocation: NSObject, CLLocationManagerDelegate, @unchecked Sendable {
    private let mgr = CLLocationManager()
    private let lock = NSLock()
    private var last: CLLocation?

    override init() {
        super.init()
        mgr.delegate = self
        mgr.desiredAccuracy = kCLLocationAccuracyBest
        mgr.allowsBackgroundLocationUpdates = true
        mgr.pausesLocationUpdatesAutomatically = false
    }

    func requestAuthorization() { mgr.requestAlwaysAuthorization() }

    func start() {
        mgr.startUpdatingLocation()
        #if os(iOS)
        mgr.startUpdatingHeading()
        #endif
    }
    func stop() {
        mgr.stopUpdatingLocation()
        #if os(iOS)
        mgr.stopUpdatingHeading()
        #endif
    }

    func locationManager(_ m: CLLocationManager, didUpdateLocations locs: [CLLocation]) {
        guard let l = locs.last else { return }
        lock.lock(); last = l; lock.unlock()
    }

    /// A compact location record for the current frame (nil fields when unavailable).
    func snapshot() -> [String: Any] {
        lock.lock(); let l = last; lock.unlock()
        guard let l else { return ["fix": false] }
        return ["fix": true, "lat": l.coordinate.latitude, "lon": l.coordinate.longitude,
                "alt": l.altitude, "h_acc": l.horizontalAccuracy, "v_acc": l.verticalAccuracy,
                "speed": l.speed, "course": l.course, "t": l.timestamp.timeIntervalSince1970]
    }
}

/// Network-path probe (no special entitlement): connection type + constraints. NOTE: the full
/// nearby-WiFi SCAN and current SSID/BSSID need Apple's Access-WiFi-Information / NEHotspotHelper
/// entitlements (approval-gated) — flagged for the witness's fuller build; path type is captured now.
final class WitnessNetwork: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let q = DispatchQueue(label: "inc.clockworktree.atlas.witness.net")
    private let lock = NSLock()
    private var path: NWPath?

    func start() {
        monitor.pathUpdateHandler = { [weak self] p in
            self?.lock.lock(); self?.path = p; self?.lock.unlock()
        }
        monitor.start(queue: q)
    }
    func stop() { monitor.cancel() }

    func snapshot() -> [String: Any] {
        lock.lock(); let p = path; lock.unlock()
        guard let p else { return ["net": "unknown"] }
        let ifaces = p.availableInterfaces.map { "\($0.type)" }
        return ["net": p.status == .satisfied ? "up" : "down",
                "ifaces": ifaces,
                "wifi": p.usesInterfaceType(.wifi),
                "cellular": p.usesInterfaceType(.cellular),
                "expensive": p.isExpensive, "constrained": p.isConstrained]
    }
}
