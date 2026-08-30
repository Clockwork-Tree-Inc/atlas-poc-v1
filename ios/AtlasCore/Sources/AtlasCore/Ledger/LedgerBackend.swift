import Foundation

/// Pluggable anchor backend — where public roots get published.
/// Swift parity with `backend/atlas/ledger/backend.py` (Python reference of record).
///
/// Both the private per-scope ledgers and the PUBLIC economics ledgers produce commitment ROOTS;
/// a backend publishes those roots to the public accountability log. Only ROOTS cross this
/// boundary — never content — so privacy is preserved regardless of backend.
///
/// Today the default is `LocalBackend` (a `GlobalAnchor.Log`, drand-bound, append-only). Later it
/// swaps for `ChainBackend` — the PoLE-consensus chain (verified-human BFT; consensus weight is
/// PERSONHOOD, never coin) — behind the SAME interface, so adopting the chain is a backend swap.

public protocol LedgerBackend {
    func publish(ownerID: Data, root: Data, epochRound: Data) throws -> GlobalAnchor.Receipt
    func latest(ownerID: Data) throws -> Data?
}

/// Default — a single-operator `GlobalAnchor.Log`: real, drand-bound, append-only. The distributed
/// witnessing is the deployment layer; the interface is already chain-shaped.
public final class LocalBackend: LedgerBackend {
    private let log: GlobalAnchor.Log
    public init(log: GlobalAnchor.Log = GlobalAnchor.Log()) { self.log = log }

    public func publish(ownerID: Data, root: Data, epochRound: Data) throws -> GlobalAnchor.Receipt {
        try log.anchor(ownerID: ownerID, root: root, epochRound: epochRound)
    }

    public func latest(ownerID: Data) -> Data? {
        log.latestRoot(ownerID: ownerID)
    }

    public func head() -> Data { log.head }   // GlobalAnchor.Log.head is a property
}

public enum ChainBackendError: Error, Equatable { case notBuilt }

/// STUB — publishes to the PoLE-consensus chain: a rotating set of verified-human validators
/// running BFT, consensus weight = personhood (one verified human, one vote), NEVER coin-stake.
/// Not built — requires the BFT protocol + validator set. Same interface, so it drops in for
/// `LocalBackend` when the chain is ready. Do not implement the consensus casually; see the design.
public final class ChainBackend: LedgerBackend {
    public init() {}

    public func publish(ownerID: Data, root: Data, epochRound: Data) throws -> GlobalAnchor.Receipt {
        throw ChainBackendError.notBuilt
    }

    public func latest(ownerID: Data) throws -> Data? {
        throw ChainBackendError.notBuilt
    }
}
