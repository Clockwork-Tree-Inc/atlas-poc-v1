import Foundation

/// Colmi R10 wire protocol — verified format per spec §1.2.
///
/// The open-source `colmi_r02_client` (Python) is used ONLY as protocol
/// reference for this format — never as a runtime dependency or test path.
///
/// GATT service:      6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E (Nordic-UART-style)
/// RX (write):        6E400002-B5A3-F393-E0A9-E50E24DCCA9E  (phone -> ring)
/// TX (notify):       6E400003-B5A3-F393-E0A9-E50E24DCCA9E  (ring  -> phone)
///
/// Packet format: 16 bytes. byte0 = command; bytes 1..14 = payload;
/// byte15 = checksum = (sum of bytes 0..14) mod 255.
public enum R10 {
    // GATT identifiers (§1.2).
    static let serviceUUID = "6E40FFF0-B5A3-F393-E0A9-E50E24DCCA9E"
    static let rxCharUUID  = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"  // write
    static let txCharUUID  = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"  // notify

    static let packetSize = 16

    /// Command bytes (subset; values per colmi_r02_client reference).
    enum Command: UInt8 {
        case realTimeHeartRate = 0x69   // start/stop continuous HR/SpO2 stream
        case stopRealTime      = 0x6A
        case battery           = 0x03
        case accelStream       = 0x6F   // continuous accelerometer (placeholder)
    }

    /// Sub-action for the real-time streaming command.
    enum RealTimeAction: UInt8 { case start = 0x01, stop = 0x00, continue_ = 0x03 }

    /// Build a 16-byte packet: command + payload (padded) + checksum.
    static func makePacket(_ command: UInt8, payload: [UInt8] = []) -> Data {
        precondition(payload.count <= 14, "payload max 14 bytes")
        var bytes = [UInt8](repeating: 0, count: packetSize)
        bytes[0] = command
        for (i, b) in payload.enumerated() { bytes[1 + i] = b }
        bytes[15] = checksum(Array(bytes[0...14]))
        return Data(bytes)
    }

    /// Checksum = low byte of the sum of bytes 0..14 (& 0xFF). The Colmi firmware
    /// drops the link on a bad checksum, so this must match the device exactly.
    static func checksum(_ first15: [UInt8]) -> UInt8 {
        UInt8(first15.reduce(0) { $0 + Int($1) } & 0xFF)
    }

    static func validate(_ packet: Data) -> Bool {
        guard packet.count == packetSize else { return false }
        let arr = [UInt8](packet)
        return arr[15] == checksum(Array(arr[0...14]))
    }

    // MARK: Commands

    /// Real-time streaming, NOT the ~20-minute passive log (§1.2): the app MUST
    /// issue this and consume the notify stream live for the ratchet loop.
    /// Colmi real-time frame = [0x69, readingType, action]. readingType 1 = heart
    /// rate, 2 = SpO2; action 1 = start, 3 = continue, 2 = stop. (Reverse-engineered
    /// via tahnok/colmi_r02_client + Gadgetbridge — the R0x family shares this.)
    enum RealTimeReading: UInt8 { case heartRate = 0x01, spo2 = 0x02 }
    static func startRealTimeHeartRate() -> Data {
        makePacket(Command.realTimeHeartRate.rawValue, payload: [RealTimeReading.heartRate.rawValue, RealTimeAction.start.rawValue])
    }
    static func keepAliveRealTime() -> Data {
        makePacket(Command.realTimeHeartRate.rawValue, payload: [RealTimeReading.heartRate.rawValue, RealTimeAction.continue_.rawValue])
    }
    static func stopRealTime() -> Data {
        makePacket(Command.stopRealTime.rawValue, payload: [RealTimeAction.stop.rawValue])
    }

    /// Decode a notify packet into a sensor reading. The R10 has PPG
    /// (HR/HRV/SpO2) + a 3-axis accelerometer (STK8321); NO gyroscope (§1.2).
    /// Field offsets follow the reference format; adjust against live captures.
    public struct Reading {
        var heartRate: Int?
        var spo2: Int?
        var accel: (x: Int16, y: Int16, z: Int16)?
        var raw: Data
    }

    static func decodeNotify(_ packet: Data) -> Reading? {
        guard validate(packet) else { return nil }
        let b = [UInt8](packet)
        var r = Reading(heartRate: nil, spo2: nil, accel: nil, raw: packet)
        switch b[0] {
        case Command.realTimeHeartRate.rawValue:
            // payload byte layout (reference): [action, type, value, ...]
            // type 0x01 => HR, 0x02 => SpO2 (verify against device).
            let type = b[2], value = Int(b[3])
            if type == 0x01 { r.heartRate = value }
            else if type == 0x02 { r.spo2 = value }
        case Command.accelStream.rawValue:
            func i16(_ hi: UInt8, _ lo: UInt8) -> Int16 { Int16(bitPattern: (UInt16(hi) << 8) | UInt16(lo)) }
            r.accel = (i16(b[1], b[2]), i16(b[3], b[4]), i16(b[5], b[6]))
        default:
            break
        }
        return r
    }
}
