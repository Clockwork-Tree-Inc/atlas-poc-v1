import Foundation

/// Guardian forensic access — a trusted contact can collect your panic forensics ONLY if BOTH of you
/// agreed. Consent is arithmetic, not policy. Parity with `atlas/keys/guardian_forensics.py`.
///
/// The forensic capture is sealed under a `forensicKey`, Shamir 2-of-2 split into:
///   * a CONTACT share — handed to the trusted contact when they ACCEPT the guardian role (consent).
///   * an OWNER share — kept by you, RELEASED ONLY when panic fires (your consent, in the moment).
///
/// Neither share alone opens anything. A stolen contact-share is inert; a foreign owner's share
/// paired with this contact's share reconstructs a WRONG key that fails to open the capture (AEAD
/// rejects it). Shares are per-relationship, so cross-pairing collects nothing.
public enum GuardianForensics {

    public enum GuardianError: Error, Equatable {
        case forensicKeyTooShort
        case consentIncomplete   // missing the contact share (accepted) or the owner share (released)
    }

    /// What each side ends up holding after a mutual guardian setup.
    public struct GuardianGrant: Equatable {
        public let contactShare: Shamir.Share   // given to the contact on accept (standing consent)
        public let ownerShare: Shamir.Share     // kept by the owner; released to the contact on panic
        public init(contactShare: Shamir.Share, ownerShare: Shamir.Share) {
            self.contactShare = contactShare
            self.ownerShare = ownerShare
        }
    }

    /// Split the forensic key 2-of-2 at guardian setup (owner designates + contact accepts).
    public static func setupGuardian(forensicKey: Data) throws -> GuardianGrant {
        guard forensicKey.count >= 16 else { throw GuardianError.forensicKeyTooShort }
        let shares = Shamir.split(forensicKey, n: 2, k: 2)
        return GuardianGrant(contactShare: shares[0], ownerShare: shares[1])
    }

    /// Reconstruct the forensic key — needs BOTH shares (contact accepted + owner released on panic).
    public static func collectForensicKey(contactShare: Shamir.Share, ownerShare: Shamir.Share) throws -> Data {
        guard contactShare.index != ownerShare.index else { throw GuardianError.consentIncomplete }
        return Shamir.combine([contactShare, ownerShare])
    }

    public static func sealForensic(forensicKey: Data, data: Data,
                                    aad: Data = Data("atlas/guardian/forensic".utf8)) throws -> Data {
        try Primitives.aeadEncrypt(key: forensicKey, plaintext: data, aad: aad)
    }

    public static func openForensic(forensicKey: Data, blob: Data,
                                    aad: Data = Data("atlas/guardian/forensic".utf8)) throws -> Data {
        try Primitives.aeadDecrypt(key: forensicKey, blob: blob, aad: aad)
    }

    public static func newForensicKey() -> Data { Primitives.randomBytes(32) }
}
