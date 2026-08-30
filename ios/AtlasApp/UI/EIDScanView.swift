import SwiftUI
import NFCPassportReader

/// eID / ePassport NFC scan — the phone reads the document chip directly (ICAO 9303: MRZ-derived
/// key -> secure messaging -> DG1 -> passive authentication). No extra hardware. Enter the three
/// machine-readable-zone facts printed on the document, hold it to the top of the phone, scan.
/// On success the ACTIVE persona is marked Real-ID verified; only the verified mark (+ birth year
/// for the age credential) is kept — document data never leaves the phone and is not stored.
struct EIDScanView: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var docNumber = ""
    @State private var dob = Calendar.current.date(byAdding: .year, value: -25, to: Date()) ?? Date()
    @State private var expiry = Calendar.current.date(byAdding: .year, value: 3, to: Date()) ?? Date()
    @State private var busy = false
    @State private var result = ""
    @State private var failed = false

    var body: some View {
        Form {
            Section("From the document's machine-readable zone") {
                TextField("Document number", text: $docNumber)
                    .textInputAutocapitalization(.characters).autocorrectionDisabled()
                DatePicker("Date of birth", selection: $dob, displayedComponents: .date)
                DatePicker("Expiry date", selection: $expiry, displayedComponents: .date)
            }
            Section {
                Button {
                    Task { await scan() }
                } label: {
                    Label(busy ? "Hold the document to the top of the phone…" : "Scan chip",
                          systemImage: "wave.3.right")
                }
                .disabled(busy || docNumber.trimmingCharacters(in: .whitespaces).isEmpty)
                if !result.isEmpty {
                    Text(result).font(.callout).foregroundStyle(failed ? .orange : .green)
                }
            } footer: {
                Text("The scan runs entirely on this phone. Atlas keeps only the verified mark and your birth year (for age checks) — never the document data.")
            }
        }
        .navigationTitle("Verify Real-ID")
    }

    private func scan() async {
        guard let persona = session.currentPersona else { return }
        busy = true; failed = false; result = ""
        defer { busy = false }

        // A genuine document must be in date — reject an expired one before reading.
        if expiry < Date() {
            failed = true
            result = "This document is expired. A valid, in-date document is required."
            return
        }
        do {
            let key = Self.mrzKey(document: docNumber, dob: dob, expiry: expiry)
            let reader = PassportReader(masterListURL: Self.masterListURL())
            // ACTIVE AUTHENTICATION challenge — a random nonce the chip must sign with a private key it
            // can't export. This is what catches a bit-for-bit CLONE (which passive auth alone can't):
            // a copy has the signed data but not the key. Chip Authentication (skipCA:false, default)
            // is the equivalent anti-clone mechanism on chips that use CA instead of AA.
            let challenge = (0..<8).map { _ in UInt8.random(in: 0...255) }
            let passport = try await reader.readPassport(mrzKey: key, tags: [.DG1], aaChallenge: challenge)

            // PASSIVE AUTHENTICATION — genuine, unaltered, correctly-signed data (never skipped).
            guard passport.passportDataNotTampered else { throw RealIDError.tampered }
            guard passport.passportCorrectlySigned else { throw RealIDError.badSignature }

            // ANTI-CLONE — Active or Chip Authentication proves this is the physical chip, not a copy.
            let aaSupported = passport.activeAuthenticationSupported
            let caSupported = passport.isChipAuthenticationSupported
            if aaSupported && !passport.activeAuthenticationPassed {
                throw RealIDError.cloneSuspected     // an AA-capable chip that fails AA = clone/tamper
            }
            let cloneChecked = (aaSupported && passport.activeAuthenticationPassed)
                || (caSupported && passport.chipAuthenticationStatus == .success)

            // ISSUER-CHAIN trust (documentSigningCertificateVerified) needs the ICAO CSCA master list.
            let issuerConfirmed = passport.documentSigningCertificateVerified
            let year = Self.birthYear(from: passport.dateOfBirth)
            await MainActor.run {
                session.markRealIDVerified(persona, birthYear: year, method: "chip")
                let d = persona.username
                UserDefaults.standard.set(issuerConfirmed, forKey: "atlas.realid.issuerConfirmed.\(d)")
                UserDefaults.standard.set(cloneChecked, forKey: "atlas.realid.cloneChecked.\(d)")
                let issuer = issuerConfirmed ? "issuer confirmed" : "issuer not confirmed (install CSCA master list)"
                let clone = cloneChecked ? "clone-checked (genuine chip)" : "clone-check unavailable on this chip"
                result = "Verified ✓ — \(issuer); \(clone)."
            }
        } catch let e as RealIDError {
            await MainActor.run { failed = true; result = e.message }
        } catch {
            await MainActor.run {
                failed = true
                result = "Scan failed: \(error.localizedDescription). Check the three MRZ facts match the document exactly, and hold it still against the top of the phone."
            }
        }
    }

    private enum RealIDError: Error {
        case tampered, badSignature, cloneSuspected
        var message: String {
            switch self {
            case .tampered:
                return "Rejected — the chip's data does not match its signature (tampered or corrupted). Not marked verified."
            case .badSignature:
                return "Rejected — the document signature did not verify. Not marked verified."
            case .cloneSuspected:
                return "Rejected — the chip failed active authentication (it could not prove it holds the document's private key). This is the signature of a cloned chip. Not marked verified."
            }
        }
    }

    /// The ICAO CSCA master list (issuer-chain trust anchors), if provisioned in the app bundle.
    /// Absent → integrity + signature are still enforced, but the issuing country isn't confirmed.
    static func masterListURL() -> URL? {
        Bundle.main.url(forResource: "masterList", withExtension: "pem")
            ?? Bundle.main.url(forResource: "masterList", withExtension: "ml")
    }

    /// ICAO 9303 BAC key: docNumber + check digit + DOB(YYMMDD) + check + expiry(YYMMDD) + check.
    static func mrzKey(document: String, dob: Date, expiry: Date) -> String {
        let f = DateFormatter(); f.dateFormat = "yyMMdd"
        let doc = document.uppercased().trimmingCharacters(in: .whitespaces)
            .padding(toLength: max(9, document.count), withPad: "<", startingAt: 0)
        let d = f.string(from: dob), e = f.string(from: expiry)
        return "\(doc)\(check(doc))\(d)\(check(d))\(e)\(check(e))"
    }

    /// The 7-3-1 check digit over the MRZ alphabet.
    static func check(_ s: String) -> Int {
        let weights = [7, 3, 1]
        var total = 0
        for (i, c) in s.uppercased().unicodeScalars.enumerated() {
            let v: Int
            switch c {
            case "0"..."9": v = Int(c.value) - 48
            case "A"..."Z": v = Int(c.value) - 55
            default: v = 0                       // '<' filler
            }
            total += v * weights[i % 3]
        }
        return total % 10
    }

    static func birthYear(from icaoDate: String) -> Int? {
        guard icaoDate.count >= 2, let yy = Int(icaoDate.prefix(2)) else { return nil }
        let nowYY = Calendar.current.component(.year, from: Date()) % 100
        return (yy <= nowYY ? 2000 : 1900) + yy
    }
}
