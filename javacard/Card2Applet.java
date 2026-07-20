// Atlas Card 2 — air-gapped payment applet (Payment spec §2, §4). SOURCE ONLY.
//
// Builds with a JavaCard SDK (3.0.4+) against a physical card; cannot compile in
// the cloud env. This is the actual on-card logic the reviewer/audit assesses.
//
// MUSTs (Payment spec §4/§7, each a review checkpoint):
//   * Card key generated ON-CARD, non-extractable; the card returns signatures,
//     never the private key.
//   * Per tap: issue a fresh card_nonce (GET CHALLENGE) for mutual freshness.
//   * ARM+SIGN: verify the Enclave arming over H(descriptor)||card_id||card_nonce,
//     verify card_nonce matches the one just issued, verify descriptor well-formed;
//     then sign the descriptor ONCE and discard card_nonce.
//
// CRYPTO REVIEW CHECKPOINT (important): Apple Secure Enclave keys are P-256
// (secp256r1) only — there is no Ed25519 in the Enclave. So the arming the card
// verifies MUST be ECDSA-P256 (this applet), OR the phone mints with a dedicated
// non-Enclave Ed25519 key (weaker — not Enclave-bound). The backend model uses
// Ed25519 for simplicity; on hardware, align on ECDSA-P256 here and in
// ArmingMinter. Flagged for the §8 cryptographer review.

package com.clockworktree.atlas;

import javacard.framework.*;
import javacard.security.*;

public class Card2Applet extends Applet {
    // INS bytes (reference contract with Card2NFCSession.swift)
    private static final byte INS_GET_CHALLENGE = (byte) 0x84; // -> card_id || card_nonce
    private static final byte INS_ARM_AND_SIGN  = (byte) 0x10; // body: descriptor||arming -> payment_sig
    private static final byte INS_GET_PUBKEY     = (byte) 0x16; // enrol card public key

    private final KeyPair cardKey;             // on-card payment signer (secp256r1)
    private final ECPublicKey enclaveArmingPub; // enrolled Enclave arming pubkey (P-256)
    private final Signature ecdsa;
    private final MessageDigest sha256;

    private final byte[] cardId = new byte[8];
    private final byte[] cardNonce = new byte[16];
    private boolean armedThisTap = false;

    protected Card2Applet() {
        cardKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        cardKey.genKeyPair();                  // ON-CARD generation; never exported
        enclaveArmingPub = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).nextBytes(cardId, (short) 0, (short) cardId.length);
        register();
    }

    public static void install(byte[] b, short o, byte l) { new Card2Applet(); }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_CHALLENGE: getChallenge(apdu); break;
            case INS_ARM_AND_SIGN:  armAndSign(apdu);  break;
            case INS_GET_PUBKEY:    getPubKey(apdu);   break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // §4 step 4 — issue a fresh card_nonce (mutual freshness).
    private void getChallenge(APDU apdu) {
        RandomData.getInstance(RandomData.ALG_SECURE_RANDOM)
                  .nextBytes(cardNonce, (short) 0, (short) cardNonce.length);
        armedThisTap = true;
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(cardId, (short) 0, buf, (short) 0, (short) cardId.length);
        Util.arrayCopyNonAtomic(cardNonce, (short) 0, buf, (short) cardId.length, (short) cardNonce.length);
        apdu.setOutgoingAndSend((short) 0, (short) (cardId.length + cardNonce.length));
    }

    // §4 step 6 — verify arming, then sign ONE transaction.
    private void armAndSign(APDU apdu) {
        if (!armedThisTap) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // Parse APDU body into: descriptor bytes, enclave arming signature, and the
        // claimed card_id/card_nonce (layout per Card2NFCSession contract).
        // [omitted: exact TLV parsing — finalize with the Swift session + Step-Zero
        //  max-APDU limits]. Pseudocode of the MUST checks:
        //
        //   armMsg = SHA256("atlas/arming" || descriptor) || cardId || cardNonce
        //   require ECDSA_verify(enclaveArmingPub, armMsg, armingSig)        // (a)
        //   require constantTimeEquals(claimedCardNonce, cardNonce)          // (b)
        //   require descriptorWellFormed(descriptor)                         // (c)
        //   paymentSig = ECDSA_sign(cardKey.private, descriptor)
        //   armedThisTap = false; wipe(cardNonce)   // single signature per arming
        //   return paymentSig
        //
        // Verification MUST precede signing; on any failure, refuse and do NOT
        // consume the signing key. (Implemented against the real SDK + applet AID.)
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED); // placeholder until wired
    }

    // Enrol the card's public key with the verifier (returns public point).
    private void getPubKey(APDU apdu) {
        ECPublicKey pk = (ECPublicKey) cardKey.getPublic();
        byte[] buf = apdu.getBuffer();
        short len = pk.getW(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
