import SwiftUI
import CryptoKit
import AtlasCore

/// System Health Monitor — runs the in-app conformance engine (Inv 14 "conformance
/// to earn" / Math Spec §38) on THIS device and shows each subsystem green/red, then
/// records the run into a tamper-evident SessionRecorder and (on device) SE-signs the
/// head into a portable, verifiable session proof.
///
/// Tier A (crypto parity vs the Python reference) runs automatically on open — no
/// human, no hardware. Tier B is hardware/human: signing the proof exercises the real
/// Secure Enclave + Face ID (device only), and we surface App Attest support.
///
/// Discipline: every row and every recorded entry is a *verdict* only — no key
/// material, no raw biosignal, no plaintext is ever shown, recorded, or exported.
struct SystemHealthView: View {
    @State private var results: [SystemCheck.Result] = []
    @State private var recorder: SessionRecorder?
    @State private var ran = false
    @State private var attestSupported: Bool? = nil
    @State private var deviceSigned = false
    @State private var proofURL: URL?

    private var allOK: Bool { !results.isEmpty && results.allSatisfy(\.ok) }

    var body: some View {
        NavigationStack {
            List {
                summarySection
                categoriesSection
                sessionProofSection
            }
            .navigationTitle("System Integrity")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Run", systemImage: "arrow.clockwise") { runTierA() }
                }
            }
        }
        .onAppear { if !ran { runTierA() } }
    }

    private var summarySection: some View {
        Section {
            HStack(spacing: 12) {
                Image(systemName: ran ? (allOK ? "checkmark.seal.fill" : "xmark.seal.fill") : "hourglass")
                    .font(.title2)
                    .foregroundStyle(ran ? (allOK ? .green : .red) : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(ran ? (allOK ? "All systems green" : "Attention needed") : "Not run yet")
                        .fontWeight(.semibold)
                    if ran { Text(SystemCheck.summary(results)).font(.caption).foregroundStyle(.secondary) }
                }
            }
        } header: {
            Text("On-device conformance · Tier A (automatic)")
        }
    }

    private var categoriesSection: some View {
        Section {
            ForEach(results) { r in
                HStack {
                    Image(systemName: r.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(r.ok ? .green : .red)
                    Text(r.name)
                    Spacer()
                    Text(r.detail).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Subsystems (crypto parity vs Python reference)")
        } footer: {
            Text("Verdicts only — no keys, no raw signals, no plaintext. Green = this device's Swift crypto is byte-identical to the Python reference-of-record.")
        }
    }

    private var sessionProofSection: some View {
        Section {
            if let attestSupported {
                row(ok: attestSupported, "App Attest",
                    attestSupported ? "DCAppAttestService available" : "unavailable (simulator / no entitlement)")
            }
            if let recorder {
                row(ok: recorder.verifyChain(), "Tamper-evident log",
                    "\(recorder.entries.count) entries · chain \(recorder.verifyChain() ? "valid" : "BROKEN")")
                row(ok: deviceSigned, "Device signature (Secure Enclave)",
                    deviceSigned ? "SE-signed under Face ID ✓" : "unsigned (run Sign & export on device)")
            }
            Button("Sign & export proof", systemImage: "signature") { signAndExport() }
                .disabled(recorder == nil)
            if let proofURL {
                ShareLink("Share session proof", item: proofURL)
            }
        } header: {
            Text("Session proof · Tier B (device + you)")
        } footer: {
            Text("The run is recorded into a hash-chained log; signing the head with the Secure Enclave (Face ID) turns it into a portable proof this device produced — verifiable by anyone, exposing no secrets.")
        }
    }

    private func row(ok: Bool, _ title: String, _ detail: String) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(ok ? .green : .orange)
            Text(title)
            Spacer()
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - actions

    /// Tier A: automatic, no hardware, no Face ID. Runs the conformance engine and
    /// records each verdict into a fresh tamper-evident log.
    private func runTierA() {
        let rs = SystemCheck.run()
        results = rs
        ran = true
        deviceSigned = false
        proofURL = nil

        let rec = SessionRecorder(sessionID: Data(UUID().uuidString.utf8))
        let now = Date().timeIntervalSince1970
        for r in rs {
            rec.record(subsystem: "conformance", event: r.name, ok: r.ok, detail: r.detail, ts: now)
        }
        let attest = AppAttestGate()
        attestSupported = attest.isSupported
        rec.record(subsystem: "attestation", event: "App Attest supported", ok: attest.isSupported,
                   detail: attest.isSupported ? "available" : "simulator / no entitlement", ts: now)
        recorder = rec
        // Write an unsigned proof immediately so it's exportable even without a device.
        writeProof(rec, signatureHex: nil, keyIDHex: nil)
    }

    /// Tier B: on device this triggers the real Secure Enclave + Face ID (the signing
    /// key is user-presence-gated), producing a device-attributed proof. On the
    /// simulator the SE is unavailable, so it stays honestly unsigned.
    private func signAndExport() {
        guard let rec = recorder else { return }
        let now = Date().timeIntervalSince1970
        let store = SecureEnclaveStore()
        if let key = try? store.loadOrCreateEnclaveSigningKey(),
           let sig = try? key.signature(for: rec.headHash) {
            rec.record(subsystem: "enclave", event: "SE signed head under presence", ok: true,
                       detail: "P-256 SE signature", ts: now)
            deviceSigned = true
            writeProof(rec, signatureHex: hexOf(sig.rawRepresentation), keyIDHex: hexOf(key.publicKey.rawRepresentation))
        } else {
            rec.record(subsystem: "enclave", event: "SE sign unavailable", ok: false,
                       detail: "Secure Enclave not present (simulator?)", ts: now)
            deviceSigned = false
            writeProof(rec, signatureHex: nil, keyIDHex: nil)
        }
    }

    private func writeProof(_ rec: SessionRecorder, signatureHex: String?, keyIDHex: String?) {
        let data = rec.exportProof(signatureHex: signatureHex, signerKeyIDHex: keyIDHex)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("atlas_session_proof.json")
        try? data.write(to: url)
        proofURL = url
    }

    private func hexOf(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
}
