import Foundation

/// USB DualDrive — the recovery hardware factor. Mirrors
/// `backend/atlas/keys/usb_recovery.py`.
///
/// Carries the recovery Shamir share ENCRYPTED (KEM-wrapped to the user's recovery
/// key) so a lost drive is opaque; and it is one of a 2-of-3 split, so the share
/// alone cannot reconstruct. The physical file I/O on the Lexar D40e is device work;
/// this is the crypto the writer/reader mirrors. The JSON byte format matches the
/// Python reference, so a blob is portable across the phone and the Mac.
public struct USBRecoveryBlob {
    public let mlkemCT: Data
    public let x25519EphPK: Data
    public let sealedShare: Data

    public init(mlkemCT: Data, x25519EphPK: Data, sealedShare: Data) {
        self.mlkemCT = mlkemCT; self.x25519EphPK = x25519EphPK; self.sealedShare = sealedShare
    }

    public func toBytes() -> Data {
        let o: [String: String] = [
            "mlkem_ct": mlkemCT.base64EncodedString(),
            "x25519_eph_pk": x25519EphPK.base64EncodedString(),
            "sealed_share": sealedShare.base64EncodedString(),
        ]
        return (try? JSONSerialization.data(withJSONObject: o)) ?? Data()
    }

    public static func fromBytes(_ blob: Data) throws -> USBRecoveryBlob {
        guard let o = try JSONSerialization.jsonObject(with: blob) as? [String: String],
              let ct = o["mlkem_ct"].flatMap({ Data(base64Encoded: $0) }),
              let ek = o["x25519_eph_pk"].flatMap({ Data(base64Encoded: $0) }),
              let ss = o["sealed_share"].flatMap({ Data(base64Encoded: $0) }) else {
            throw USBRecoveryError.unreadable
        }
        return USBRecoveryBlob(mlkemCT: ct, x25519EphPK: ek, sealedShare: ss)
    }
}

public enum USBRecoveryError: Error { case unreadable }

private let usbAAD = Data("atlas/usb-recovery/share".utf8)

/// Encrypt a recovery Shamir share to the user's recovery key for the drive.
public func writeShareToUSB(_ share: Shamir.Share, recoveryPub: HybridKEM.PublicKey) throws -> USBRecoveryBlob {
    let enc = try HybridKEM.encapsulate(to: recoveryPub)
    let sealed = try Primitives.aeadEncrypt(key: enc.shared, plaintext: share.encode(), aad: usbAAD)
    return USBRecoveryBlob(mlkemCT: enc.mlkemCT, x25519EphPK: enc.x25519EphPK, sealedShare: sealed)
}

/// USER side: unwrap the share with the recovery keypair. Throws if the key is
/// wrong / the blob is tampered (fail-closed).
public func readShareFromUSB(_ blob: USBRecoveryBlob, recoveryKP: HybridKEM.Keypair) throws -> Shamir.Share {
    do {
        let shared = try HybridKEM.decapsulate(recoveryKP, mlkemCT: blob.mlkemCT, x25519EphPK: blob.x25519EphPK)
        return Shamir.Share.decode(try Primitives.aeadDecrypt(key: shared, blob: blob.sealedShare, aad: usbAAD))
    } catch {
        throw USBRecoveryError.unreadable
    }
}
