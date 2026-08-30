package com.clockworktree.atlas.config

/**
 * Build/runtime flags + honest stand-in markers. Mirrors
 * ios/AtlasApp/Config/AtlasFlags.swift so the Android client makes the SAME honesty claims.
 *
 * Nothing here should EVER silently over-claim. If a seam is stubbed, it is listed below.
 */
object AtlasFlags {

    /** The live physical timing/gating signal source for this build. */
    enum class SignalSourceKind { AMBIENT, RING }
    val signalSource = SignalSourceKind.AMBIENT

    const val poCBadge = "PROOF OF CONCEPT — work in progress, not for real use"

    const val disclaimerShort =
        "Atlas is an early proof of concept — a research demonstration on real " +
        "hardware, not a finished, audited, or production app. Don't use it to " +
        "protect anything real."

    const val disclaimer =
        "Atlas is an early PROOF OF CONCEPT and a WORK IN PROGRESS.\n\n" +
        "It demonstrates the protocol running on real hardware. It is NOT a finished " +
        "product, has NOT been independently audited, and is NOT intended to protect " +
        "real identities, messages, money, or data. Some parts are simulated or " +
        "stubbed — see the status breakdown below. Nothing here carries any warranty. " +
        "Please don't rely on it for anything real."

    /**
     * THIN-CLIENT honesty: unlike iOS (which runs the real Swift AtlasCore crypto on-device),
     * this Android client is deliberately a THIN CLIENT. The heavy PQC/identity/session crypto
     * runs on the node/backend; the phone does hardware key-ops, UI, and the tunnel. Every
     * crypto-bearing surface below is therefore either delegated to the node or STUBBED here.
     */
    val honestyBanner: List<String> = listOf(
        "REAL (planned via node): PoLE/session/epoch-wrap/ratchet · PQC ML-KEM tunnel — " +
            "performed by the node/backend, not re-implemented in Kotlin",
        "ANDROID-NATIVE (planned): Keystore/StrongBox key-ops · BiometricPrompt gate · " +
            "Play Integrity attest · BLE/Sensor/NFC seams",
        "STUBBED: every hardware seam and the node tunnel are scaffolds with TODOs — " +
            "no seam is wired end-to-end yet",
        "NOT BUILT: Real-ID verification — NOTHING in this app shows 'verified'",
        "STAND-IN: ambient sensors would TIME + GATE (ambient-not-biological); the ring " +
            "signal is the one deferred input",
    )
}
