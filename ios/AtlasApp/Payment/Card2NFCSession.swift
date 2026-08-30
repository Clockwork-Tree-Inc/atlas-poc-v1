import Foundation
import AtlasCore
#if canImport(CoreNFC)
import CoreNFC
#endif

/// Card 2 arm-per-use NFC session (Payment spec §4 steps 4–6). SOURCE ONLY —
/// gated on Step Zero passing on real hardware.
///
/// Tap sequence (tap-and-hold; the card is field-powered for the duration):
///   1. SELECT applet by AID.
///   2. GET CHALLENGE → the card returns (card_id, card_nonce) [mutual freshness].
///   3. The Enclave mints the arming bound to descriptor + card_id + card_nonce.
///   4. ARM+SIGN APDU: send {descriptor, arming}; the card verifies and returns
///      payment_sig (one signature), then discards card_nonce.
///
/// APDU layout below is a reference contract with javacard/Card2Applet.java;
/// finalize INS/AID and lengths against the applet + Step-Zero limits (§1).
nonisolated public final class Card2NFCSession: NSObject {
    public struct Result { public let cardID: Data; public let cardNonce: Data; public let paymentSig: Data }
    public enum Outcome { case armed(Data, Data)   // (cardID, cardNonce) after step 2
                          , signed(Result), failure(String) }

    /// Called after step 2 with (cardID, cardNonce) so the caller mints the
    /// arming; the caller then provides it via `provideArming`.
    public var onChallenge: ((Data, Data) -> Void)?
    public var onResult: ((Outcome) -> Void)?

    private var pendingArming: (descriptor: Data, arming: Data)?
    public func provideArming(descriptor: Data, arming: Data) { pendingArming = (descriptor, arming) }

    static let aid = Data([0xA0, 0x00, 0x00, 0x08, 0x12, 0x01, 0x01])
    static let insGetChallenge: UInt8 = 0x84   // returns card_id || card_nonce
    static let insArmAndSign: UInt8 = 0x10     // body: descriptor || arming → payment_sig

#if canImport(CoreNFC)
    private var session: NFCTagReaderSession?
    public func start() {
        guard NFCTagReaderSession.readingAvailable else { onResult?(.failure("NFC unavailable")); return }
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self)
        session?.alertMessage = "Hold Card 2 to the phone to authorize the payment."
        session?.begin()
    }
    // Delegate wiring (SELECT → GET CHALLENGE → ARM+SIGN) is omitted here for
    // brevity; it mirrors StepZeroNFCProbe's connect/sendCommand pattern using
    // the INS bytes above. The card-side verification is in Card2Applet.java.
#else
    public func start() { onResult?(.failure("CoreNFC unavailable in this build environment")) }
#endif
}

#if canImport(CoreNFC)
// Minimal `NFCTagReaderSessionDelegate` conformance. The full SELECT → GET
// CHALLENGE → ARM+SIGN APDU exchange (steps 1–4 above) is intentionally deferred
// (SOURCE ONLY, gated on Step Zero passing on real hardware; the card-side
// contract lives in javacard/Card2Applet.java). Rather than fake a payment
// signature, `didDetect` fails closed with a clear message. NFC delivers these
// callbacks on a private queue, so the (nonisolated) class handles them directly.
extension Card2NFCSession: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        onResult?(.failure(error.localizedDescription))
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        session.invalidate(errorMessage: "Card 2 arm-per-use APDU wiring deferred (see Card2Applet.java)")
    }
}
#endif
