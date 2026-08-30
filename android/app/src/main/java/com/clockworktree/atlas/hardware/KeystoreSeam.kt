package com.clockworktree.atlas.hardware

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * KeystoreSeam ↔ iOS `SecureEnclaveStore` (Secure Enclave).
 *
 * The hardware isolation boundary on Android: keys are generated inside the AndroidKeyStore,
 * backed by the TEE or — where present (API 28+) — a dedicated StrongBox secure element. The
 * private half never leaves the hardware; the app gets only signing/agreement operations.
 *
 * MAPPING to iOS:
 *   loadOrCreateDevKey        ↔ SecureEnclaveStore.loadOrCreateDevKey
 *   createIdentityKey         ↔ loadOrCreateEnclaveSigningKey (P-256, biometric-gated)
 *   sign                      ↔ SecureEnclave signing
 *
 * STATUS: SCAFFOLD. Key generation is wired below; the pieces marked TODO (StrongBox
 * attestation to the node, biometric-gated key-agreement seal/unseal, tick contribution) are
 * NOT implemented. Thin-client note: the SESSION crypto (PoLE/ratchet/PQC KEM) runs on the
 * node — this seam only provides the device-anchored key-ops the node's protocol binds to.
 */
class KeystoreSeam {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** True if this device exposes a StrongBox secure element (dedicated tamper-resistant chip). */
    fun strongBoxAvailable(context: android.content.Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Create the device identity signing key inside the hardware Keystore. Requires user
     * authentication (BiometricPrompt) to use — the on-body / alive gate at the hardware layer.
     *
     * TODO: request a KEY ATTESTATION certificate chain (setAttestationChallenge) and forward it
     *       to the node so the node can prove this key lives in genuine hardware — the Android
     *       analogue of App Attest at the key level.
     */
    fun createIdentityKey(alias: String = IDENTITY_ALIAS, strongBox: Boolean = false) {
        if (keyStore.containsAlias(alias)) return
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setUserAuthenticationRequired(true)      // gate use behind BiometricSeam
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(true)
            }
            // TODO: setAttestationChallenge(challengeFromNode) for hardware key attestation.
        }.build()
        gen.initialize(spec)
        gen.generateKeyPair()
    }

    /** Sign under the hardware identity key. TODO: surface the biometric prompt via BiometricSeam
     *  and hand the signature to the node's session handshake. */
    fun sign(@Suppress("UNUSED_PARAMETER") data: ByteArray): ByteArray {
        TODO("Wire AndroidKeyStore Signature(SHA256withECDSA) under a BiometricPrompt CryptoObject")
    }

    /** DevKey analogue: a device-bound random secret sealed by a Keystore-wrapped key.
     *  TODO: generate + persist under an AES/GCM Keystore key (setUnlockedDeviceRequired). */
    fun loadOrCreateDevKey(): ByteArray {
        TODO("Generate 32B, seal under an AndroidKeyStore AES key, persist ciphertext")
    }

    companion object { const val IDENTITY_ALIAS = "atlas.identity.ec.p256" }
}
