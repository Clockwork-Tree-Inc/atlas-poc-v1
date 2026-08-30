package com.clockworktree.atlas.hardware

import android.app.Activity
import android.nfc.NfcAdapter

/**
 * NfcSeam ↔ iOS passport / eID NFC (`Card2NFCSession` / `StepZeroNFCProbe`).
 *
 * Reads an e-passport / national eID over NFC for the (future) Real-ID verification path.
 * Android's NFC is LESS restricted than iOS: `IsoDep` gives raw ISO 7816 APDU exchange with
 * the chip, so the full ICAO 9303 flow (BAC/PACE -> read DG1/DG2 -> passive auth) is doable
 * on-device without Apple's entitlement gating.
 *
 * HONESTY: Real-ID verification is NOT BUILT (mirror of iOS). This seam reads the chip; the
 * verification verdict + binding to a persona require the node and are not implemented. NOTHING
 * in the app shows "verified".
 *
 * STATUS: SCAFFOLD. Reader-mode enable + APDU exchange are stubbed.
 */
class NfcSeam {

    fun isAvailable(activity: Activity): Boolean =
        NfcAdapter.getDefaultAdapter(activity) != null

    /**
     * Read the eID document. `accessKey` is the MRZ-derived key (BAC) or CAN (PACE).
     *
     * TODO:
     *   1. NfcAdapter.enableReaderMode(activity, callback, FLAG_READER_NFC_A|B, null).
     *   2. On a discovered Tag: IsoDep.get(tag).connect().
     *   3. Run PACE/BAC with `accessKey`, then read DG1 (MRZ) / DG2 (face) via SELECT/READ APDUs.
     *   4. Passive authentication (verify the SOD signature chain) — then hand to the node.
     */
    suspend fun readDocument(
        @Suppress("UNUSED_PARAMETER") activity: Activity,
        @Suppress("UNUSED_PARAMETER") accessKey: String,
    ): ByteArray {
        TODO("Wire NfcAdapter reader mode + IsoDep ICAO 9303 (PACE/BAC, DG read, passive auth)")
    }
}
