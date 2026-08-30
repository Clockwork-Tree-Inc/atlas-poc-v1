import Foundation

/// Proof of Living Entropy (PoLE) — the base participation proof of the economy.
/// Swift parity with `backend/atlas/economy/pole.py` (Python reference of record).
///
/// A device collects entropy from the living universe, authorised by a LIVE, UNIQUE person, and
/// emits a PoLE proof. The server aggregates proofs per epoch; `Policy` then mints APLC from the
/// aggregate. PoLE itself carries NO value. "Only a live unique person can mint": each proof binds
/// a `personTag` (the unlinkable unique-person nullifier) plus liveness. The pool dedupes on
/// (personTag, epoch) so one human counts ONCE per epoch (Sybil-resistant), carrying a uniform
/// PRESENCE unit (→ UBI) and a variable ACTIVITY weight (→ variable rewards).

public enum PoLEError: Error, Equatable {
    case notLive                 // the mint gate: no live unique person
    case activityWeightTooLow    // activity_weight must be >= 1 (presence baseline)
    case multipleEpochs          // a pool aggregates a single epoch
}

public struct PoLEProof: Equatable {
    public let personTag: Data      // unique-person nullifier; the dedupe key
    public let epoch: Int
    public let entropyCommit: Data  // H(collected living/ambient entropy digest)
    public let activityWeight: Int  // >=1; presence baseline = 1

    public init(personTag: Data, epoch: Int, entropyCommit: Data, activityWeight: Int) throws {
        if activityWeight < 1 { throw PoLEError.activityWeightTooLow }
        self.personTag = personTag; self.epoch = epoch
        self.entropyCommit = entropyCommit; self.activityWeight = activityWeight
    }
}

/// Emit a PoLE proof. Throws unless a LIVE unique person authorises it (the mint gate).
public func collectPoLE(personTag: Data, epoch: Int, entropyCommit: Data, live: Bool,
                        activityWeight: Int = 1) throws -> PoLEProof {
    if !live { throw PoLEError.notLive }
    return try PoLEProof(personTag: personTag, epoch: epoch, entropyCommit: entropyCommit,
                         activityWeight: activityWeight)
}

/// Server-side aggregation for one issuance run. Dedupes per (personTag, epoch): one human counts
/// once — re-submission keeps the HIGHEST activity weight, it never inflates presence. Insertion
/// order is preserved to mirror Python's ordered dict (deterministic distribution iteration).
public final class PoLEPool {
    private var order: [Data] = []
    private var byPerson: [Data: Int] = [:]
    public private(set) var epoch: Int?

    public init() {}

    public func add(_ proof: PoLEProof) throws {
        if epoch == nil {
            epoch = proof.epoch
        } else if proof.epoch != epoch {
            throw PoLEError.multipleEpochs
        }
        if let prev = byPerson[proof.personTag] {
            byPerson[proof.personTag] = max(prev, proof.activityWeight)
        } else {
            order.append(proof.personTag)
            byPerson[proof.personTag] = proof.activityWeight
        }
    }

    /// Unique live persons this epoch — the uniform PRESENCE count (→ UBI).
    public var persons: Int { byPerson.count }

    /// Sum of activity weights (→ variable-reward shares).
    public var totalActivity: Int { byPerson.values.reduce(0, +) }

    public func activityOf(_ personTag: Data) -> Int { byPerson[personTag] ?? 0 }

    /// (personTag, weight) pairs in insertion order.
    public func people() -> [(Data, Int)] { order.map { ($0, byPerson[$0]!) } }
}
