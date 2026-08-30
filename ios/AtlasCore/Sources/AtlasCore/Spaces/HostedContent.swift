import Foundation

/// Serving layer (hosting piece 2a) — CLIENT side. Seals a hosted artifact for BLIND storage so a
/// host node stores only CIPHERTEXT (never plaintext): the blob is addressed by `H(ciphertext)`,
/// and a fetcher who holds the space/land key decrypts and verifies the plaintext against the
/// land's content commitment (so a swapped or forged blob is rejected). The node stays blind —
/// content confidentiality is the seal; the node only stores + serves opaque bytes per access.
///
/// This is the client half; the node PUT/GET + access enforcement is the node-side of 2a. Planet-
/// scale replication/availability (2b) is the separate distributed-storage build.
extension Spaces {
    public enum HostError: Error, Equatable { case corruptBlob, wrongKey, commitmentMismatch }

    public struct HostedBlob: Equatable {
        public let blobID: Data       // H(ciphertext) — the opaque storage address the node sees
        public let ciphertext: Data   // AES-GCM sealed content; the node stores ONLY this
    }

    fileprivate static let blobDomain = Data("atlas/hosted-blob".utf8)

    /// Seal `content` under `sealKey` (a persona-land or group-space key) for blind hosting.
    /// Returns the blob (addressed by `H(ciphertext)`, bound to `spaceID` via AAD) and the land
    /// content-commitment — the provenance id the land's `SpaceItem` already carries.
    public static func sealHosted(content: Data, sealKey: Data, spaceID: Data, author: Data,
                                  parent: Data = Data()) throws -> (blob: HostedBlob, commitment: Data) {
        let ct = try Primitives.aeadEncrypt(key: sealKey, plaintext: content, aad: spaceID)
        let blobID = Primitives.H(blobDomain, ct)
        let commitment = contentCommitment(spaceID: spaceID, author: author, content: content, parent: parent)
        return (HostedBlob(blobID: blobID, ciphertext: ct), commitment)
    }

    /// Open a fetched blob: verify its address, decrypt with `sealKey`, and verify the plaintext
    /// against `expectCommitment` (the land item's `contentHash`). A tampered ciphertext fails the
    /// address check; a wrong key fails AEAD; a substituted plaintext fails the commitment check.
    public static func openHosted(_ blob: HostedBlob, sealKey: Data, expectCommitment: Data,
                                  spaceID: Data, author: Data, parent: Data = Data()) throws -> Data {
        guard Primitives.H(blobDomain, blob.ciphertext) == blob.blobID else { throw HostError.corruptBlob }
        let content: Data
        do { content = try Primitives.aeadDecrypt(key: sealKey, blob: blob.ciphertext, aad: spaceID) }
        catch { throw HostError.wrongKey }
        guard contentCommitment(spaceID: spaceID, author: author, content: content, parent: parent) == expectCommitment else {
            throw HostError.commitmentMismatch
        }
        return content
    }
}
