import Foundation

/// Real-ID VERIFIER SEAM (document front-end) — Swift mirror of `backend/atlas/realid/verifier.py`'s
/// document-verification core. Path A (chip): verify the issuing-country chain (SOD <- DSC <- CSCA)
/// ourselves; Path B (vendor): labeled trust-the-vendor. Liveness-bind + a document nullifier
/// (one document -> one System-ID, no reuse), keeping only the nullifier binding (no PII).
///
/// Credential issuance (AssuranceLevel L1 BBS/PS credential) is the Python reference-of-record and
/// not mirrored here; this Swift seam covers the novel document-chain verification + nullifier.
public enum RealIDVerifier {

    public enum DocPath { case chip, vendor }

    public static func documentNullifier(_ docUnique: Data) -> Data {
        Primitives.H(Data("atlas/realid/doc-nullifier".utf8), docUnique)
    }

    static func sod(_ docUnique: Data) -> Data {
        Primitives.H(Data("atlas/realid/sod".utf8), docUnique)
    }

    public struct DocumentAttestation {
        public var path: DocPath
        public var docUnique: Data
        public var dscPublic: HybridSign.PublicKey?    // chip: the Document Signer public key
        public var sodSig: Data                        // chip: SOD signed by the DSC
        public var dscSig: Data                        // chip: DSC signed by the country CSCA
        public var vendorOk: Bool                      // vendor: the IDV verdict
        public init(path: DocPath, docUnique: Data, dscPublic: HybridSign.PublicKey? = nil,
                    sodSig: Data = Data(), dscSig: Data = Data(), vendorOk: Bool = false) {
            self.path = path; self.docUnique = docUnique; self.dscPublic = dscPublic
            self.sodSig = sodSig; self.dscSig = dscSig; self.vendorOk = vendorOk
        }
    }

    /// Model a country issuing a chip-signed document: CSCA signs the DSC key; the DSC signs the SOD.
    public static func mintChipAttestation(csca: HybridSign.Keypair, dsc: HybridSign.Keypair,
                                           docUnique: Data) throws -> DocumentAttestation {
        let dscSig = try HybridSign.sign(csca, dsc.publicKey.encode())
        let sodSig = try HybridSign.sign(dsc, sod(docUnique))
        return DocumentAttestation(path: .chip, docUnique: docUnique, dscPublic: dsc.publicKey,
                                   sodSig: sodSig, dscSig: dscSig)
    }

    /// Passive-Auth-style chain check: DSC signed by the trusted CSCA, SOD signed by that DSC.
    public static func verifyChip(_ att: DocumentAttestation, cscaPub: HybridSign.PublicKey) -> Bool {
        guard att.path == .chip, let dsc = att.dscPublic else { return false }
        guard HybridSign.verify(cscaPub, dsc.encode(), att.dscSig) else { return false }
        return HybridSign.verify(dsc, sod(att.docUnique), att.sodSig)
    }

    public final class Verifier {
        public enum CertifyError: Error { case livenessRequired, documentInvalid, reuse }
        private let cscaPub: HybridSign.PublicKey
        private var docToRoot: [Data: Data] = [:]      // document nullifier -> System-ID handle (no PII)
        public init(cscaPub: HybridSign.PublicKey) { self.cscaPub = cscaPub }

        private func cryptographicFlag(_ att: DocumentAttestation) -> Bool? {
            switch att.path {
            case .chip: return verifyChip(att, cscaPub: cscaPub) ? true : nil
            case .vendor: return att.vendorOk ? false : nil
            }
        }

        /// Certify iff a live human is present, the document verifies, and it isn't already bound to
        /// another System-ID. Returns (cryptographic, docNullifier). Stores only the nullifier binding.
        @discardableResult
        public func certify(systemIDHandle: Data, _ att: DocumentAttestation,
                            livePresent: Bool) throws -> (cryptographic: Bool, docNullifier: Data) {
            guard livePresent else { throw CertifyError.livenessRequired }
            guard let cryptographic = cryptographicFlag(att) else { throw CertifyError.documentInvalid }
            let nul = documentNullifier(att.docUnique)
            if let bound = docToRoot[nul], bound != systemIDHandle { throw CertifyError.reuse }
            docToRoot[nul] = systemIDHandle
            return (cryptographic, nul)
        }
    }
}
