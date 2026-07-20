import SwiftUI

/// On-device R10 discovery screen (DEV). Scan → pick the ring → see its real GATT +
/// live raw packets, so the wire format can be confirmed on the phone before the
/// production `R10BLEClient` → `RingSignalSource` path is wired. Read the packet
/// lines back to nail HR / HRV (R-R) / accelerometer offsets.
struct RingDiagnosticsView: View {
    @StateObject private var probe = RingProbe()

    var body: some View {
        NavigationStack {
            List {
                Section("Status") {
                    if !probe.connectedName.isEmpty {
                        HStack(spacing: 12) {
                            Image(systemName: "heart.fill")
                                .font(.system(size: 40))
                                .foregroundStyle(probe.pulsePresent ? .red : .secondary)
                                .symbolEffect(.pulse, isActive: probe.pulsePresent)
                            Text(probe.pulsePresent ? "LIVE PULSE" : "NO PULSE")
                                .font(.title2.bold())
                                .foregroundStyle(probe.pulsePresent ? .green : .secondary)
                            Spacer()
                        }
                        Text("Used for liveness — a live pulse on your finger opens the presence gate; a removed ring fails closed. (Exact bpm isn't shown: this ring's Bluetooth stream is too sparse for an accurate rate.)")
                            .font(.caption2).foregroundStyle(.secondary)
                        Text(probe.reading).font(.footnote.monospaced())
                        // The measured rates — the numbers that decide firmware-vs-hardware.
                        // Flash a faster-raw firmware (e.g. R02 FasterRawValues MOD) and re-read:
                        // if PPG jumps, ~2 Hz was a firmware limit, not the hardware ceiling.
                        Text(String(format: "PPG: %.1f Hz stream · %.1f Hz usable", probe.frameHz, probe.sampleHz))
                            .font(.caption2.monospaced())
                            .foregroundStyle(probe.sampleHz >= 25 ? .green : .orange)
                        Text(probe.accelHz > 0
                             ? String(format: "accel (IMU): %.1f Hz — %@", probe.accelHz,
                                      probe.accelHz < 20 ? "too slow for sharp taps" : "fast enough for taps")
                             : "accel (IMU): not streaming")
                            .font(.caption2.monospaced())
                            .foregroundStyle(probe.accelHz >= 20 ? .green : .orange)
                        Text("Rates to watch: flash a faster-raw firmware and re-read — a jump means the sparse stream was firmware, not silicon.")
                            .font(.caption2).foregroundStyle(.secondary)
                        Text(probe.liveness).font(.footnote.monospaced())
                            .foregroundStyle(probe.liveness.hasPrefix("PRESENT") ? .green : .orange)
                    }
                    Text(probe.status).font(.footnote).foregroundStyle(.secondary)
                    HStack {
                        Button("Scan") { probe.scanAll() }.buttonStyle(.borderedProminent)
                        if !probe.connectedName.isEmpty {
                            Button("Restart stream") { probe.startStream() }
                            Button("Disconnect", role: .destructive) { probe.disconnect() }
                        }
                    }.font(.footnote)
                }

                if probe.connectedName.isEmpty {
                    Section("Devices (tap the ring — look for R10/Colmi, strong RSSI)") {
                        ForEach(probe.devices) { d in
                            Button { probe.connect(d) } label: {
                                HStack {
                                    Text(d.name).font(.callout)
                                    Spacer()
                                    Text("\(d.rssi) dBm").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                } else {
                    Section("GATT — \(probe.connectedName)") {
                        ForEach(probe.chars) { c in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.uuid).font(.system(.caption2, design: .monospaced))
                                Text("svc \(c.service) · \(c.props)").font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Section("Raw notify packets (newest first)") {
                        ForEach(probe.packets) { p in
                            VStack(alignment: .leading, spacing: 1) {
                                Text("\(p.t)  \(p.char)  \(p.hex)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Ring probe")
        }
    }
}
