package com.clockworktree.atlas.hardware

/**
 * PlayIntegritySeam ↔ iOS `AppAttestGate` (App Attest / DeviceCheck).
 *
 * Proves the app is a genuine, unmodified build on a genuine device — the precondition for
 * enrolment and every recovery path. On Android this is the Play Integrity API: request an
 * integrity token bound to a node-supplied nonce, then have the NODE verify it server-side
 * (never trust a client-side verdict).
 *
 * Honest limit (mirror of iOS §1.1 Tier 3): this proves the protocol on a stock device; it does
 * not prove sovereignty (can't strip telemetry / run alt-OS). Also honest: Play Integrity depends
 * on Google Play services — a de-Googled device would need an alternative attestation path.
 *
 * STATUS: SCAFFOLD. Mirrors iOS `AtlasFlags.appAttestStubbed = true` — attestation is NOT wired.
 */
class PlayIntegritySeam {

    /**
     * Request an integrity token for a node-issued challenge.
     *
     * TODO:
     *   1. IntegrityManagerFactory.createStandard(context) (StandardIntegrityManager).
     *   2. prepareIntegrityToken(cloudProjectNumber) once; cache the token provider.
     *   3. request(requestHash = SHA256(nonceFromNode)) -> token.
     *   4. POST token to the node; the node decodes + verifies the verdict with Google.
     */
    suspend fun attest(@Suppress("UNUSED_PARAMETER") nonceFromNode: ByteArray): ByteArray {
        TODO("Wire Play Integrity StandardIntegrityManager; node verifies the token server-side")
    }

    /** Whether attestation is currently wired. Mirrors iOS `appAttestStubbed`. */
    val isStubbed: Boolean = true
}
