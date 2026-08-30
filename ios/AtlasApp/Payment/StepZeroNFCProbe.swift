import Foundation
#if canImport(CoreNFC)
import CoreNFC
#endif

/// STEP ZERO (Payment spec §1) — gating capability proof. SOURCE ONLY.
///
/// The entire arm-per-use flow depends on the iPhone running a full two-way
/// APDU session with a third-party ISO-7816 JavaCard over NFC — not just reading
/// an NDEF tag. This minimal probe MUST pass on the target device + iOS before
/// any payment code is trusted: open a reader session, SELECT an applet by AID,
/// send one trivial APDU, read the response.
///
/// Entitlement: requires the `com.apple.developer.nfc.readersession.formats`
/// entitlement including `TAG`, and `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
/// listing the applet AID in Info.plist. Confirm the Apple Developer account /
/// provisioning profile grants these BEFORE building (spec §1).
///
/// If this fails on the target iOS: STOP and report. Do NOT substitute a
/// software card and call it air-gapped (spec §1).
nonisolated public final class StepZeroNFCProbe: NSObject {
    public enum Result { case success(response: Data, sw: UInt16), failure(String) }
    public var onResult: ((Result) -> Void)?

    /// The applet AID to SELECT (must also be listed in Info.plist
    /// iso7816.select-identifiers). Replace with the Card 2 applet AID.
    public var appletAID = Data([0xA0, 0x00, 0x00, 0x08, 0x12, 0x01, 0x01])

#if canImport(CoreNFC)
    private var session: NFCTagReaderSession?

    public func run() {
        guard NFCTagReaderSession.readingAvailable else {
            onResult?(.failure("NFC reading not available on this device")); return
        }
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self)
        session?.alertMessage = "Hold the JavaCard to the top of the phone."
        session?.begin()
    }
#else
    public func run() { onResult?(.failure("CoreNFC unavailable in this build environment")) }
#endif
}

#if canImport(CoreNFC)
extension StepZeroNFCProbe: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        onResult?(.failure(error.localizedDescription))
    }
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard case let .iso7816(tag)? = tags.first else {
            session.invalidate(errorMessage: "Not an ISO-7816 card"); return
        }
        session.connect(to: tags.first!) { [weak self] err in
            guard let self, err == nil else { session.invalidate(errorMessage: "connect failed"); return }
            // SELECT by AID, then a trivial APDU (GET DATA 0xCA).
            let select = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4,
                                        p1Parameter: 0x04, p2Parameter: 0x00,
                                        data: self.appletAID, expectedResponseLength: 256)
            tag.sendCommand(apdu: select) { _, sw1, sw2, _ in
                let trivial = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xCA,
                                             p1Parameter: 0x00, p2Parameter: 0x00,
                                             data: Data(), expectedResponseLength: 256)
                tag.sendCommand(apdu: trivial) { resp, rsw1, rsw2, _ in
                    let sw = (UInt16(rsw1) << 8) | UInt16(rsw2)
                    session.invalidate()
                    self.onResult?(.success(response: resp, sw: sw))
                }
            }
        }
    }
}
#endif
