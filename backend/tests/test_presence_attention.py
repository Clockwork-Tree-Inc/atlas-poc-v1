"""PoLE receipts wallet + paid attention: earn by being a live present human; stores pay you to look."""
import pytest

from atlas.crypto.sign import keypair_from_seed
from atlas.economy.attention import (
    AttentionError, AttentionLedger, claim_attention, make_offer, verify_claim, verify_offer,
)
from atlas.economy.presence_receipt import (
    ReceiptWallet, mint_receipt, verify_receipt,
)


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


SUBJECT = b"persona-handle-01"
COMMIT = b"fused-pole-evidence-commit"


# --------------------------------------------------------------------------- presence receipts
def test_single_signer_receipt_verifies_and_wallet_holds_it():
    persona = kp(2)
    r = mint_receipt([persona], subject=SUBJECT, window_start=100, window_end=200, pole_commit=COMMIT)
    assert verify_receipt(r)
    w = ReceiptWallet()
    assert w.add(r)
    assert len(w.receipts) == 1
    assert w.total_presence() == 100


def test_multi_stream_corroboration_required():
    persona, wearable = kp(2), kp(3)
    solo = mint_receipt([persona], subject=SUBJECT, window_start=1, window_end=2, pole_commit=COMMIT)
    corroborated = mint_receipt([persona, wearable], subject=SUBJECT, window_start=1, window_end=2, pole_commit=COMMIT)
    # a single stream fails the 2-of stream bar; two independent streams pass it
    assert not verify_receipt(solo, min_signers=2)
    assert verify_receipt(corroborated, min_signers=2)


def test_tampered_receipt_fails():
    persona = kp(2)
    r = mint_receipt([persona], subject=SUBJECT, window_start=100, window_end=200, pole_commit=COMMIT)
    forged = type(r)(subject=SUBJECT, window_start=100, window_end=999,   # extend the window post-sign
                     pole_commit=COMMIT, signers=r.signers, sigs=r.sigs)
    assert not verify_receipt(forged)


def test_covering_receipts():
    persona = kp(2)
    r = mint_receipt([persona], subject=SUBJECT, window_start=100, window_end=200, pole_commit=COMMIT)
    w = ReceiptWallet(); w.add(r)
    assert len(w.covering(at=150)) == 1
    assert len(w.covering(at=500)) == 0


# --------------------------------------------------------------------------- paid attention
def _offer(store, reward=10, ws=100, we=200):
    return make_offer(store, product_id=b"prod-1", reward=reward, window_start=ws, window_end=we)


def _receipt(persona, ws=120, we=180):
    return mint_receipt([persona], subject=SUBJECT, window_start=ws, window_end=we, pole_commit=COMMIT)


def test_store_signed_offer_verifies():
    offer = _offer(kp(1))
    assert verify_offer(offer)


def test_live_human_gets_paid_once():
    store, persona = kp(1), kp(2)
    offer = _offer(store)
    receipt = _receipt(persona)          # attended within the offer window
    claim = claim_attention(persona, offer=offer, receipt=receipt)
    assert verify_claim(offer, claim)

    ledger = AttentionLedger()
    assert ledger.redeem(offer, claim) == 10
    # no farming: a second identical claim is rejected
    with pytest.raises(AttentionError):
        ledger.redeem(offer, claim)
    assert ledger.total_paid() == 10


def test_no_presence_receipt_no_pay():
    # a bot with no live-human presence receipt covering the window can't claim
    store, persona = kp(1), kp(2)
    offer = _offer(store)
    out_of_window = _receipt(persona, ws=500, we=600)     # attended outside the offer window
    claim = claim_attention(persona, offer=offer, receipt=out_of_window)
    assert not verify_claim(offer, claim)


def test_claim_must_be_signed_by_a_presence_cosigner():
    store, persona, imposter = kp(1), kp(2), kp(9)
    offer = _offer(store)
    receipt = _receipt(persona)
    # imposter builds a claim for the persona's receipt but signs with their own key
    good = claim_attention(persona, offer=offer, receipt=receipt)
    forged = type(good)(offer_id=good.offer_id, subject=good.subject, receipt=receipt,
                        nullifier=good.nullifier, signer=imposter.public, sig=good.sig)
    assert not verify_claim(offer, forged)


def test_forged_offer_reward_rejected():
    store, persona = kp(1), kp(2)
    offer = _offer(store, reward=10)
    receipt = _receipt(persona)
    claim = claim_attention(persona, offer=offer, receipt=receipt)
    tampered = type(offer)(store=offer.store, product_id=offer.product_id, reward=999,   # inflate reward
                           window_start=offer.window_start, window_end=offer.window_end, sig=offer.sig)
    assert not verify_claim(tampered, claim)
