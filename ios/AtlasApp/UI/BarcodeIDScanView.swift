import SwiftUI
import AVFoundation

/// Driver's-licence barcode scan — the LOWER Real-ID assurance tier. North American licences carry
/// an AAMVA PDF417 barcode (name, DOB, licence #, expiry) readable with the camera. HONEST TIER:
/// a barcode is DOCUMENT-STATED, not cryptographically verified (anyone can print one) — chip
/// documents (ePassport/eID) remain the strong tier. Nothing from the scan is stored except the
/// verified mark (tier: barcode) + birth year.
struct BarcodeIDScanView: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var status = "Point the camera at the PDF417 barcode on the BACK of the licence."
    @State private var done = false

    var body: some View {
        VStack(spacing: 0) {
            PDF417ScannerView { payload in
                guard !done else { return }
                handle(payload)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            VStack(spacing: 8) {
                Text(status).font(.callout).multilineTextAlignment(.center)
                Text("Lower assurance: the barcode states the data — it isn't cryptographically signed. A chip document (ePassport/eID) gives the strong tier.")
                    .font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .padding()
        }
        .navigationTitle("Scan licence barcode")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func handle(_ payload: String) {
        guard payload.contains("ANSI ") || payload.contains("AAMVA") else { return }
        done = true
        let fields = Self.parseAAMVA(payload)
        let year = fields["DBB"].flatMap(Self.birthYear)
        let first = fields["DAC"] ?? fields["DCT"] ?? ""
        let last = fields["DCS"] ?? ""
        if let persona = session.currentPersona {
            session.markRealIDVerified(persona, birthYear: year, method: "barcode")
        }
        status = "Scanned ✓ — \(first) \(last). Marked ID-scanned (barcode tier)."
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { dismiss() }
    }

    /// AAMVA fields: lines of 3-letter element ids + values (DCS last name, DAC first, DBB DOB,
    /// DBA expiry, DAQ licence number).
    static func parseAAMVA(_ raw: String) -> [String: String] {
        var out: [String: String] = [:]
        let ids = ["DCS", "DAC", "DCT", "DBB", "DBA", "DAQ", "DBC", "DAG", "DAI", "DAJ"]
        for line in raw.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            for id in ids where t.hasPrefix(id) && t.count > 3 {
                out[id] = String(t.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            }
        }
        return out
    }

    /// DBB is CCYYMMDD in Canada, MMDDCCYY in the US — disambiguate by which parse is plausible.
    static func birthYear(from dbb: String) -> Int? {
        let digits = dbb.filter { $0.isNumber }
        guard digits.count == 8 else { return nil }
        let now = Calendar.current.component(.year, from: Date())
        if let y = Int(digits.prefix(4)), y > 1900, y <= now { return y }          // CCYYMMDD (Canada)
        if let y = Int(digits.suffix(4)), y > 1900, y <= now { return y }          // MMDDCCYY (US)
        return nil
    }
}

/// Minimal AVFoundation PDF417 scanner.
private struct PDF417ScannerView: UIViewControllerRepresentable {
    let onPayload: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerVC {
        let vc = ScannerVC()
        vc.onPayload = onPayload
        return vc
    }
    func updateUIViewController(_ vc: ScannerVC, context: Context) {}

    final class ScannerVC: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
        var onPayload: ((String) -> Void)?
        private let sessionQ = DispatchQueue(label: "atlas.pdf417")
        private let capture = AVCaptureSession()

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  capture.canAddInput(input) else { return }
            capture.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard capture.canAddOutput(output) else { return }
            capture.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.pdf417]
            let preview = AVCaptureVideoPreviewLayer(session: capture)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
            sessionQ.async { [capture] in capture.startRunning() }
        }

        override func viewDidDisappear(_ animated: Bool) {
            super.viewDidDisappear(animated)
            sessionQ.async { [capture] in capture.stopRunning() }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
            for o in objects {
                if let code = o as? AVMetadataMachineReadableCodeObject, code.type == .pdf417,
                   let s = code.stringValue {
                    onPayload?(s)
                }
            }
        }
    }
}
