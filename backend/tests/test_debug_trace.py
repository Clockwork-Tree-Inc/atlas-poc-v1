"""Debug trace: rich, correlated, replayable capture for bug-finding — that structurally cannot
record secrets (redaction guard) and threads app<->server flows."""
from atlas.debug_trace import DebugTrace


def test_secret_named_fields_are_redacted():
    t = DebugTrace()
    e = t.record(ts=1, correlation_id="f", subsystem="app.session", kind="derive",
                 private_key=b"RAWKEYBYTES", session_secret="hunter2", password="pw",
                 seed=b"seedbytes", biometric_template=b"face", epoch=7)
    assert e.fields["private_key"] == "[redacted]"
    assert e.fields["session_secret"] == "[redacted]"
    assert e.fields["password"] == "[redacted]"
    assert e.fields["seed"] == "[redacted]"
    assert e.fields["biometric_template"] == "[redacted]"
    assert e.fields["epoch"] == 7                     # ordinary field kept


def test_raw_bytes_become_a_hash_commitment_not_raw():
    t = DebugTrace()
    e1 = t.record(ts=1, correlation_id="f", subsystem="s", kind="k", payload=b"ABC")
    e2 = t.record(ts=2, correlation_id="f", subsystem="s", kind="k", payload=b"ABC")
    e3 = t.record(ts=3, correlation_id="f", subsystem="s", kind="k", payload=b"XYZ")
    # correlatable: same bytes -> same commitment; different bytes -> different
    assert e1.fields["payload"] == e2.fields["payload"]
    assert e1.fields["payload"] != e3.fields["payload"]
    assert e1.fields["payload"].startswith("<3B sha256=")


def test_raw_secret_never_appears_in_export():
    t = DebugTrace()
    t.record(ts=1, correlation_id="f", subsystem="s", kind="k",
             private_key=b"SUPERSECRET", payload=b"ALSOSECRETBLOB")
    dump = str(t.export())
    assert "SUPERSECRET" not in dump          # secret-named -> [redacted]
    assert "ALSOSECRETBLOB" not in dump        # raw bytes -> hashed, never raw
    assert "[redacted]" in dump


def test_correlate_reconstructs_app_and_server_flow_in_order():
    t = DebugTrace()
    t.record(ts=2, correlation_id="flow1", subsystem="server.relay", kind="dispatch", path="/mailbox")
    t.record(ts=1, correlation_id="flow1", subsystem="app.session", kind="send", size=100)
    t.record(ts=9, correlation_id="flow2", subsystem="app.session", kind="send")
    flow = t.correlate("flow1")
    assert [e.ts for e in flow] == [1, 2]
    assert [e.subsystem for e in flow] == ["app.session", "server.relay"]   # end-to-end reconstruction


def test_filter_and_replay():
    t = DebugTrace()
    t.record(ts=1, correlation_id="f", subsystem="app.presence", kind="gate_released")
    t.error(ts=2, correlation_id="f", subsystem="server.relay", message="bad body")
    assert len(t.events(subsystem="app.presence")) == 1
    assert len(t.events(kind="error")) == 1
    seen = []
    t.replay(lambda e: seen.append((e.ts, e.kind)))
    assert seen == [(1, "gate_released"), (2, "error")]        # replayed in time order


def test_secret_shaped_string_is_hashed_even_under_a_benign_field_name():
    # Cloud finding: a hex/base64 key as a STRING under a NON-secret field name used to pass raw.
    t = DebugTrace()
    hex_key = "deadbeef" * 8                                  # 64 hex chars (a 32-byte key), as a string
    b64_key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0"      # base64-ish, has digits
    e = t.record(ts=1, correlation_id="f", subsystem="s", kind="k",
                 value=hex_key, opaque=b64_key, note="just a short note")
    assert "sha256=" in e.fields["value"] and hex_key not in e.fields["value"]     # hashed by SHAPE
    assert "sha256=" in str(e.fields["opaque"]) and b64_key not in str(e.fields["opaque"])
    assert e.fields["note"] == "just a short note"           # benign short string kept
    assert hex_key not in str(t.export()) and b64_key not in str(t.export())


def test_benign_long_text_is_not_false_flagged():
    # A long plain word (no digits/symbols/spaces) is NOT secret-shaped -> kept raw (no over-redaction).
    t = DebugTrace()
    word = "internationalization" * 3                        # 60 letters, no digit/symbol
    e = t.record(ts=1, correlation_id="f", subsystem="s", kind="k", label=word)
    assert e.fields["label"] == word
