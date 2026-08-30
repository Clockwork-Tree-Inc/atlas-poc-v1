import Foundation

/// Crypto-agility seam (TRUST_LAYER.md #10). Mirrors `backend/atlas/crypto/agility.py`.
/// Schemes (KEM / signature / credential) live behind a registry; the active set is a versioned
/// `CryptoSuite` whose `suiteId()` both peers compute independently (parity-critical) so there is
/// no ambiguity about the algorithms in force. Migrating a primitive is a registry + suite-id
/// change, never a call-site change.
public enum CryptoAgility {

    public enum SchemeFamily: String { case kem, signature, credential }
    public enum AgilityError: Error, Equatable { case unknownScheme, noCommonSuite, noDefault }

    public struct SchemeId: Equatable {
        public let family: SchemeFamily
        public let name: String
        public let pq: Bool
        public init(family: SchemeFamily, name: String, pq: Bool) {
            self.family = family; self.name = name; self.pq = pq
        }
    }

    public struct CryptoSuite: Equatable {
        public let version: Int
        public let kem: String
        public let signature: String
        public let credential: String
        public init(version: Int, kem: String, signature: String, credential: String) {
            self.version = version; self.kem = kem; self.signature = signature; self.credential = credential
        }

        static func lp(_ s: String) -> Data {
            let b = Data(s.utf8)
            var n = UInt32(b.count).bigEndian
            return withUnsafeBytes(of: &n) { Data($0) } + b
        }

        /// Byte-exact commitment to the active suite (length-prefixed framing, like Python).
        public func suiteId() -> Data {
            var v = UInt32(version).bigEndian
            return Primitives.H(Data("atlas/crypto-suite".utf8), withUnsafeBytes(of: &v) { Data($0) },
                                Self.lp(kem), Self.lp(signature), Self.lp(credential))
        }
    }

    /// Strongest suite both sides support: the first in the local preference order (best first)
    /// whose id the remote also supports AND that meets the `acceptable` floor. Fail-closed on no
    /// overlap or none meeting the floor — a MITM stripping the remote set to weak suites cannot
    /// force a downgrade below the floor. Run this inside the authenticated channel and bind the
    /// agreed suiteId into the session keys (see the Python reference).
    public static func negotiate(preference: [CryptoSuite], remoteIDs: Set<Data>,
                                 acceptable: ((CryptoSuite) -> Bool)? = nil) throws -> CryptoSuite {
        for suite in preference where remoteIDs.contains(suite.suiteId()) && (acceptable?(suite) ?? true) {
            return suite
        }
        throw AgilityError.noCommonSuite
    }

    /// Named scheme implementations per family, with a default per family.
    public final class SchemeRegistry {
        private var impls: [String: Any] = [:]
        private var ids: [String: SchemeId] = [:]
        private var defaults: [SchemeFamily: String] = [:]
        public init() {}

        private func key(_ f: SchemeFamily, _ n: String) -> String { "\(f.rawValue)/\(n)" }

        public func register(_ id: SchemeId, impl: Any, isDefault: Bool = false) {
            let k = key(id.family, id.name)
            impls[k] = impl; ids[k] = id
            if isDefault || defaults[id.family] == nil { defaults[id.family] = id.name }
        }

        public func schemeId(_ family: SchemeFamily, _ name: String) throws -> SchemeId {
            guard let id = ids[key(family, name)] else { throw AgilityError.unknownScheme }
            return id
        }

        public func defaultName(_ family: SchemeFamily) throws -> String {
            guard let d = defaults[family] else { throw AgilityError.noDefault }
            return d
        }

        public func available(_ family: SchemeFamily) -> [SchemeId] {
            ids.values.filter { $0.family == family }
        }
    }
}
