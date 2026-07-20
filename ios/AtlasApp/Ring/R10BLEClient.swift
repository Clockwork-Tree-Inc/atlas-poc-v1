import Foundation
import Combine
import CoreBluetooth
import AtlasCore

/// Native R10 capture over CoreBluetooth (§1.2). Ring BLE runs on the PHONE —
/// the ring is never connected to the Mac (§1.2). The ring is an UNTRUSTED
/// sensor (§0.3): it streams raw values; all encryption (Enc_stream under
/// DevKey) and all signing happen on the phone, inside the Secure Enclave,
/// immediately on receipt — there is no ring_SE_sig.
///
/// Real-time streaming, not the ~20-minute passive log: we issue the real-time
/// command and consume the notify stream live for the ratchet/liveness loop.
@MainActor
public final class R10BLEClient: NSObject, ObservableObject {

    public enum State: Equatable { case poweredOff, scanning, connecting, ready, disconnected(String) }

    @Published public private(set) var state: State = .poweredOff
    @Published public private(set) var lastReading: String = "—"
    @Published public private(set) var heartRate: Int?
    @Published public private(set) var spo2: Int?

    /// Encrypted-on-receipt raw stream sink. Each notify payload is encrypted
    /// under the DevKey on the phone immediately (Enc_stream, §5.1) before it is
    /// used or stored. The closure receives the ciphertext envelope.
    public var onEncryptedStream: ((Data) -> Void)?
    /// Decoded sensor sample for the liveness gate (stays on-device).
    public var onSample: ((R10.Reading) -> Void)?

    /// DevKey used to encrypt the raw stream on receipt. In the app this comes
    /// from the Secure Enclave-backed key store (see Enclave/SecureEnclaveStore).
    private let devKey: Data

    private var central: CBCentralManager!
    private var ring: CBPeripheral?
    private var rxChar: CBCharacteristic?   // write
    private var txChar: CBCharacteristic?   // notify
    private var keepAliveTimer: Timer?

    private let serviceUUID = CBUUID(string: R10.serviceUUID)
    private let rxUUID = CBUUID(string: R10.rxCharUUID)
    private let txUUID = CBUUID(string: R10.txCharUUID)

    public init(devKey: Data) {
        self.devKey = devKey
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
    }

    public func startScan() {
        guard central.state == .poweredOn else { return }
        state = .scanning
        central.scanForPeripherals(withServices: [serviceUUID], options: nil)
    }

    public func disconnect() {
        keepAliveTimer?.invalidate()
        if let r = ring { central.cancelPeripheralConnection(r) }
    }

    private func sendCommand(_ packet: Data) {
        guard let rx = rxChar, let ring else { return }
        // Nordic-UART RX is typically write-with-response; fall back if needed.
        ring.writeValue(packet, for: rx, type: .withResponse)
    }

    private func beginRealTimeStreaming() {
        sendCommand(R10.startRealTimeHeartRate())
        // The R10 stops streaming if not nudged; keep it live for the ratchet.
        keepAliveTimer?.invalidate()
        keepAliveTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sendCommand(R10.keepAliveRealTime()) }
        }
    }
}

// The CBCentralManager is created with `queue: .main`, so every CoreBluetooth
// delegate callback below is delivered ON THE MAIN QUEUE. The protocol
// requirements are `nonisolated`; marking the conformance `@preconcurrency` lets
// these `@MainActor` methods satisfy them, with the compiler inserting a
// main-actor runtime check (which always holds here because delivery IS on main).
// This keeps `central`/`peripheral`/`@Published` access on the main actor with no
// non-Sendable value crossing an isolation boundary.
extension R10BLEClient: @preconcurrency CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn: startScan()
        case .poweredOff: state = .poweredOff
        default: state = .disconnected("bluetooth unavailable")
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        // Connect to the first R10 advertising the Atlas service.
        central.stopScan()
        ring = peripheral
        peripheral.delegate = self
        state = .connecting
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([serviceUUID])
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                               error: Error?) {
        keepAliveTimer?.invalidate()
        state = .disconnected(error?.localizedDescription ?? "disconnected")
    }
}

extension R10BLEClient: @preconcurrency CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svc = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else { return }
        peripheral.discoverCharacteristics([rxUUID, txUUID], for: svc)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                           error: Error?) {
        for c in service.characteristics ?? [] {
            if c.uuid == rxUUID { rxChar = c }
            if c.uuid == txUUID { txChar = c; peripheral.setNotifyValue(true, for: c) }
        }
        if rxChar != nil && txChar != nil {
            state = .ready
            beginRealTimeStreaming()
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                           error: Error?) {
        guard characteristic.uuid == txUUID, let data = characteristic.value else { return }

        // (1) Encrypt the raw stream under the DevKey ON THE PHONE, immediately
        //     on receipt — the phone is the first trustworthy boundary (§0.3, §5.1).
        if let envelope = try? Primitives.aeadEncrypt(key: devKey, plaintext: data,
                                                      aad: Data("atlas/enc-stream".utf8)) {
            onEncryptedStream?(envelope)
        }

        // (2) Decode for the on-device liveness gate (no raw biometric leaves).
        guard let reading = R10.decodeNotify(data) else { return }
        if let hr = reading.heartRate { heartRate = hr }
        if let s = reading.spo2 { spo2 = s }
        lastReading = "HR \(heartRate.map(String.init) ?? "—")  SpO₂ \(spo2.map { "\($0)%" } ?? "—")"
        onSample?(reading)
    }
}
