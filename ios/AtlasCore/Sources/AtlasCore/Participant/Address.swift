import Foundation

/// Addressing + nameplate resolver — how a persona is FOUND, kept separate from how it's REACHED.
/// Swift parity with `backend/atlas/interop/address.py` (Python reference of record).
///
/// An address is `local@place`. `@place` says where to fetch a signed NAMEPLATE; `local` selects which.
/// A nameplate carries the persona key, a display name, a way-to-knock (receptive mode), and optionally
/// its self-published trust bundle — never a mailbox. Signed by the persona key, so the host is
/// untrusted. Findable (is there a nameplate) and receptive (can/how you may open a channel) are two
/// independent switches. Many addresses can point at one persona and converge into one inbox via a
/// PRIVATE owner-held routing table that senders never see.
public enum Address {

    public enum AddressError: Error { case malformed, verificationFailed }

    public enum ReceptiveMode: String, Sendable {
        case open = "open"
        case codeOnly = "code-only"
        case contactsOnly = "contacts-only"
        case closed = "closed"
    }

    public struct Parsed: Equatable {
        public let local: String
        public let place: String
        public var string: String { "\(local)@\(place)" }
    }

    public static func parse(_ s: String) throws -> Parsed {
        let t = s.trimmingCharacters(in: .whitespaces)
        let parts = t.components(separatedBy: "@")
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { throw AddressError.malformed }
        let place = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "/")).lowercased()
        guard !place.isEmpty else { throw AddressError.malformed }
        return Parsed(local: parts[0], place: place)
    }

    public static func nameplateURL(_ a: Parsed) -> String {
        "https://\(a.place)/.well-known/atlas/\(a.local).json"
    }

    public struct DiscoverySettings {
        public let findable: Bool
        public let receptive: ReceptiveMode
        public init(findable: Bool = false, receptive: ReceptiveMode = .closed) {
            self.findable = findable; self.receptive = receptive
        }
        public func acceptsContact(hasValidCode: Bool, isKnownContact: Bool) -> Bool {
            switch receptive {
            case .open: return true
            case .codeOnly: return hasValidCode
            case .contactsOnly: return isKnownContact
            case .closed: return false
            }
        }
    }

    private static func lp(_ b: Data) -> Data {
        var n = UInt32(b.count).bigEndian
        var out = Data(); withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }; out.append(b)
        return out
    }

    public struct Nameplate {
        public let local: String
        public let place: String
        public let key: HybridSign.PublicKey
        public let displayName: String
        public let receptive: ReceptiveMode
        public let trustBundle: TrustPublish.TrustBundle?
        public var sig: Data = Data()

        public init(local: String, place: String, key: HybridSign.PublicKey, displayName: String,
                    receptive: ReceptiveMode, trustBundle: TrustPublish.TrustBundle? = nil, sig: Data = Data()) {
            self.local = local; self.place = place; self.key = key; self.displayName = displayName
            self.receptive = receptive; self.trustBundle = trustBundle; self.sig = sig
        }

        public func body() -> Data {
            let bundleTag = trustBundle?.body() ?? Data()
            return Primitives.H(Data("atlas/nameplate/v1".utf8), Address.lp(Data(local.utf8)),
                                Address.lp(Data(place.utf8)), Address.lp(key.encode()),
                                Address.lp(Data(displayName.utf8)), Address.lp(Data(receptive.rawValue.utf8)),
                                Address.lp(bundleTag))
        }

        public func toJSON() -> Data {
            var obj: [String: Any] = ["local": local, "place": place, "key": key.encode().hexString,
                                      "display_name": displayName, "receptive": receptive.rawValue,
                                      "sig": sig.hexString]
            if let b = trustBundle,
               let sub = try? JSONSerialization.jsonObject(with: b.toJSON()) {
                obj["trust_bundle"] = sub
            }
            return try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        }
    }

    public static func buildNameplate(_ persona: HybridSign.Keypair, address a: Parsed, displayName: String,
                                      settings: DiscoverySettings,
                                      trustBundle: TrustPublish.TrustBundle? = nil) throws -> Nameplate? {
        guard settings.findable else { return nil }
        var np = Nameplate(local: a.local, place: a.place, key: persona.publicKey, displayName: displayName,
                           receptive: settings.receptive, trustBundle: trustBundle)
        np.sig = try HybridSign.sign(persona, np.body())
        return np
    }

    public static func verifyNameplate(_ np: Nameplate) -> Bool {
        HybridSign.verify(np.key, np.body(), np.sig)
    }

    public static func parseNameplate(_ data: Data) throws -> Nameplate {
        guard let d = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let local = d["local"] as? String, let place = d["place"] as? String,
              let keyHex = d["key"] as? String, let key = HybridSign.PublicKey(encoded: Data(hex: keyHex)),
              let displayName = d["display_name"] as? String,
              let recRaw = d["receptive"] as? String, let receptive = ReceptiveMode(rawValue: recRaw),
              let sigHex = d["sig"] as? String else { throw AddressError.malformed }
        var bundle: TrustPublish.TrustBundle? = nil
        if let sub = d["trust_bundle"] {
            let subData = try JSONSerialization.data(withJSONObject: sub)
            bundle = try TrustPublish.parseTrustBundle(subData)
        }
        return Nameplate(local: local, place: place, key: key, displayName: displayName,
                         receptive: receptive, trustBundle: bundle, sig: Data(hex: sigHex))
    }

    public static func resolve(_ addressStr: String, fetch: (String) throws -> Data) throws -> Nameplate {
        let a = try parse(addressStr)
        let np = try parseNameplate(fetch(nameplateURL(a)))
        guard np.local == a.local, np.place == a.place, verifyNameplate(np) else {
            throw AddressError.verificationFailed
        }
        return np
    }

    /// The owner's PRIVATE map: which persona an address points at, and which real inbox a persona
    /// converges into. Never published — senders only see the persona face they were handed.
    public final class RoutingTable {
        private var addrToPersona: [String: Data] = [:]
        private var personaToInbox: [Data: Data] = [:]
        public init() {}

        public func point(_ addressStr: String, persona: HybridSign.PublicKey) {
            addrToPersona[addressStr] = persona.encode()
        }
        public func converge(_ persona: HybridSign.PublicKey, inbox: Data) {
            personaToInbox[persona.encode()] = inbox
        }
        public func personaFor(_ addressStr: String) -> Data? { addrToPersona[addressStr] }
        public func inboxFor(_ persona: HybridSign.PublicKey) -> Data? { personaToInbox[persona.encode()] }
        public func inboxForAddress(_ addressStr: String) -> Data? {
            guard let pk = addrToPersona[addressStr] else { return nil }
            return personaToInbox[pk]
        }
    }
}
