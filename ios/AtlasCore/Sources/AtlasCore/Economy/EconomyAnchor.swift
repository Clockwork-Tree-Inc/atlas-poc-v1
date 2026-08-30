import Foundation

/// Anchor the PUBLIC economics to the accountability log.
/// Swift parity with `backend/atlas/economy/anchor.py` (Python reference of record).
///
/// The public monetary FACTS — per-epoch issuance, the business-transparency head, and governance
/// ratifications — are published as ROOTS through a `LedgerBackend`. What is NOT anchored: individual
/// balances/transfers (those stay private via per-person commitment ledgers). Only roots are
/// published, so even the public anchors reveal facts, not people.
///
/// BYTE-IDENTITY IS LOAD-BEARING: these anchor roots are PUBLIC COMMITMENTS both the Python and
/// Swift implementations must agree on for a future shared chain. The framing below reproduces
/// Python's `_root`/`_i` EXACTLY — SHA3-256 over, for each field, uint32-big-endian(len) || field;
/// ints as 16-byte big-endian; the leading domain tag; controls joined by "|" — so roots match
/// byte-for-byte (asserted against KAT vectors generated from the Python reference).
public enum EconomyAnchor {
    // Distinct public streams on the accountability log.
    public static let economySupply = Data("atlas/economy/supply".utf8)
    public static let economyTransparency = Data("atlas/economy/transparency".utf8)
    public static let economyGovernance = Data("atlas/economy/governance".utf8)

    /// Python `_root`: SHA3-256 over each part length-prefixed with its 4-byte big-endian length.
    static func root(_ parts: [Data]) -> Data {
        var buf = Data()
        for p in parts {
            var n = UInt32(p.count).bigEndian
            withUnsafeBytes(of: &n) { buf.append(contentsOf: $0) }
            buf.append(p)
        }
        return Primitives.H(buf)
    }

    /// Python `_i`: a non-negative int as 16-byte big-endian.
    static func i(_ n: Int) -> Data {
        var be = UInt64(n).bigEndian
        return Data(count: 8) + withUnsafeBytes(of: &be) { Data($0) }
    }

    /// A public commitment to one epoch's issuance facts (supply, minted, UBI/VRP/Foundation,
    /// tithe, controls) — a hash, so the fact is checkpointed without exposing per-account balances.
    public static func issuanceRoot(_ r: IssuanceResult) -> Data {
        root([Data("issuance".utf8), i(r.epoch), i(r.persons), i(r.ubiPerPerson), i(r.ubiTotal),
              i(r.vrpTotal), i(r.foundationTotal), i(r.titheUsed), i(r.minted), i(r.newSupply),
              Data(r.controls.joined(separator: "|").utf8)])
    }

    public static func governanceRoot(epoch: Int, colIndex: Int, valueIndex: Int) -> Data {
        root([Data("governance".utf8), i(epoch), i(colIndex), i(valueIndex)])
    }

    @discardableResult
    public static func anchorIssuance(_ backend: LedgerBackend, _ r: IssuanceResult,
                                      epochRound: Data) throws -> GlobalAnchor.Receipt {
        try backend.publish(ownerID: economySupply, root: issuanceRoot(r), epochRound: epochRound)
    }

    /// Anchor the business-books head — immutably checkpoints all business activity to date.
    @discardableResult
    public static func anchorTransparency(_ backend: LedgerBackend,
                                          _ ledger: Transparency.TransparencyLedger,
                                          epochRound: Data) throws -> GlobalAnchor.Receipt {
        try backend.publish(ownerID: economyTransparency, root: ledger.head(), epochRound: epochRound)
    }

    @discardableResult
    public static func anchorGovernance(_ backend: LedgerBackend, epoch: Int, colIndex: Int,
                                        valueIndex: Int, epochRound: Data) throws -> GlobalAnchor.Receipt {
        try backend.publish(ownerID: economyGovernance,
                            root: governanceRoot(epoch: epoch, colIndex: colIndex, valueIndex: valueIndex),
                            epochRound: epochRound)
    }
}
