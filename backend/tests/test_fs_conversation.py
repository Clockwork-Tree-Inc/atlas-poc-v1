"""Forward-secret conversation: roundtrip + a captured later key can't read earlier."""

from atlas.session.fs_conversation import FSChain, derive_chain, seed_chain


def _seed(direction):
    return seed_chain(channel_key=b"K" * 32, lk=b"L" * 32, drand_round=b"\x00" * 8, direction=direction)


def test_roundtrip_both_directions_in_lockstep():
    epoch, beacon = b"\x00" * 8, b"beacon-1"
    a_send = FSChain(_seed(b"A->B"), drand_round=epoch)
    b_recv = FSChain(_seed(b"A->B"), drand_round=epoch)     # B's copy of the A->B chain
    for text in (b"hi", b"meet at 9", b"bring the ring"):
        blob = a_send.seal(text, beacon_t=beacon)
        assert b_recv.open(blob, beacon_t=beacon) == text  # lockstep, same keys


def test_forward_secrecy_leaked_later_key_cannot_read_earlier():
    """The chain key exposed at step i derives that message onward — but NOT the
    message key of any earlier step (the chain is one-way)."""
    seed, epoch, beacon = _seed(b"A->B"), b"\x00" * 8, b"beacon-1"
    chain = derive_chain(seed, count=8, beacon_t=beacon, drand_round=epoch)
    msg_keys = [mk for (mk, _ck) in chain]
    assert len(set(msg_keys)) == 8                        # every message key distinct

    # Compromise at step 5: attacker learns chain_key BEFORE step 5 onward.
    leaked_ck = chain[5][1]
    forward = derive_chain(leaked_ck, count=3, beacon_t=beacon, drand_round=epoch)
    forward_msg_keys = {mk for (mk, _ck) in forward}      # what the leak yields: msg 5,6,7
    # earlier message keys (0..4) are NOT derivable from the leaked later chain key
    for earlier in msg_keys[:5]:
        assert earlier not in forward_msg_keys


def test_two_directions_are_independent_chains():
    assert _seed(b"A->B") != _seed(b"B->A")
