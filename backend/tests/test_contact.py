"""First-contact bootstrap: rotating connect code, rotating rendezvous, accept gate, pair promotion."""
from atlas.net.privacy import contact as c
from atlas.net.privacy.mailbox import epoch_for_round


def test_connect_code_rotates_each_epoch():
    secret = b"\x07" * 32
    a = c.current_code(secret, 1000)
    b = c.current_code(secret, 1001)
    assert a != b
    assert len(a) == c.CODE_DIGITS and a.isdigit()


def test_code_valid_within_window_dead_outside():
    secret = b"\x07" * 32
    code = c.current_code(secret, 1000)
    assert c.code_valid(secret, code, 1000, window=2)
    assert c.code_valid(secret, code, 1001, window=2)      # a couple epochs of skew ok
    assert not c.code_valid(secret, code, 1010, window=2)   # long past -> dead
    assert not c.code_valid(secret, "00000000", 1000, window=2)  # wrong code


def test_open_rendezvous_rotates_and_is_pubkey_derivable():
    pub = b"PUBKEY-ENC"
    e0, e1 = epoch_for_round(1000), epoch_for_round(1001)
    r0 = c.open_rendezvous(pub, e0)
    r1 = c.open_rendezvous(pub, e1)
    assert r0 != r1 and len(r0) == 16
    assert c.open_rendezvous(pub, e0) == r0                 # both endpoints derive the same


def test_code_rendezvous_needs_the_code():
    secret = b"\x07" * 32
    e = epoch_for_round(1000)
    code = c.current_code(secret, 1000)
    drop = c.code_rendezvous(code, e)
    assert c.code_rendezvous(code, e) == drop               # code-holder + persona agree
    assert c.code_rendezvous("00000000", e) != drop         # without the right code, wrong drop


def test_gate_open_lets_anyone_ring():
    d = c.gate_knock(c.ContactMode.OPEN, caller_pub_enc=b"CALLER", presented_code=None,
                     code_secret=b"", now_round=1, known_contacts=set())
    assert d.allowed and d.caller == b"CALLER"


def test_gate_code_only_requires_a_valid_code():
    secret = b"\x07" * 32
    good = c.current_code(secret, 1000)
    ok = c.gate_knock(c.ContactMode.CODE_ONLY, caller_pub_enc=b"CALLER", presented_code=good,
                      code_secret=secret, now_round=1000, known_contacts=set())
    assert ok.allowed and ok.caller == b"CALLER"
    bad = c.gate_knock(c.ContactMode.CODE_ONLY, caller_pub_enc=b"CALLER", presented_code="00000000",
                       code_secret=secret, now_round=1000, known_contacts=set())
    assert not bad.allowed and bad.caller is None


def test_gate_contacts_only_and_closed():
    known = {b"FRIEND"}
    ok = c.gate_knock(c.ContactMode.CONTACTS_ONLY, caller_pub_enc=b"FRIEND", presented_code=None,
                      code_secret=b"", now_round=1, known_contacts=known)
    assert ok.allowed
    no = c.gate_knock(c.ContactMode.CONTACTS_ONLY, caller_pub_enc=b"STRANGER", presented_code=None,
                      code_secret=b"", now_round=1, known_contacts=known)
    assert not no.allowed
    closed = c.gate_knock(c.ContactMode.CLOSED, caller_pub_enc=b"ANYONE", presented_code=None,
                          code_secret=b"", now_round=1, known_contacts=known)
    assert not closed.allowed


def test_cross_language_known_answers():
    """Pinned vectors — Swift ContactTests asserts the identical values (byte-for-byte parity)."""
    s = bytes([7]) * 32
    assert c.current_code(s, 1000) == "11394522"
    assert c.open_rendezvous(b"PUBKEY-ENC", epoch_for_round(1000)).hex() == "c9cc4e74edf2c8ff576ebb37c14fdb67"
    assert c.promote_pair_secret(bytes([0x22]) * 32).hex() == \
        "4aef3bef4184eeefec827f5f7270c4e4a2a8d2217bcc851853536d44c2692395"


def test_promotion_is_deterministic_and_distinct():
    shared = b"\x22" * 32
    p = c.promote_pair_secret(shared)
    assert p == c.promote_pair_secret(shared)      # both sides derive the same pair secret
    assert p != shared                             # distinct from the raw KEM secret
